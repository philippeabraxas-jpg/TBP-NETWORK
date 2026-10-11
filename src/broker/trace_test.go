package broker

// trace_test.go — issue #329 : la trace de décision d'un banc d'essai (devtrace).
// Ce qu'elle doit montrer : pour chaque requête, qui l'a faite, ce qui a été décidé, pourquoi, avec le même
// identifiant de bout en bout. Ce qu'elle ne doit JAMAIS faire : changer une décision, ni contenir un jeton.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	devtrace "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devtrace"
)

func traceFixture(t *testing.T, allow bool, withTrace bool) (*httptest.Server, string) {
	t.Helper()
	opa := opaServer(t, func(map[string]any) bool { return allow }, 0)
	t.Cleanup(opa.Close)
	b, _, _, _ := newTestBroker(t, opa.URL, StructuredTranslator{})
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	opts := ServerOptions{Broker: b}
	if withTrace {
		sink, err := devtrace.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sink.Close() })
		opts.Trace = sink
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, path
}

func postWithTraceID(t *testing.T, url, body, id string) (int, actionResponseJSON) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/v1/actions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if id != "" {
		req.Header.Set(devtrace.Header, id)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out actionResponseJSON
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func traceEvents(t *testing.T, path string) []devtrace.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []devtrace.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e devtrace.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("ligne de trace illisible: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestTraceShowsAllowAndDenyWithTheCallersID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allow   bool
		outcome string
		reason  string
	}{{"accord", true, "allow", "ok"}, {"refus de la politique", false, "deny", "opa-deny"}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, path := traceFixture(t, tc.allow, true)
			intent := fmt.Sprintf("%q", simpleIntent(t, "read", "doc-1"))
			status, out := postWithTraceID(t, srv.URL, `{"subject":"agent-1","intent":`+intent+`}`, "t-42")
			if status != http.StatusOK || out.Allow != tc.allow || out.Reason != tc.reason {
				t.Fatalf("la réponse a changé: %d %+v", status, out)
			}
			ev := traceEvents(t, path)
			if len(ev) != 1 {
				t.Fatalf("%d événements, voulu 1", len(ev))
			}
			e := ev[0]
			if e.TraceID != "t-42" || e.Component != "brokerd" || e.Stage != "decision" || e.Outcome != tc.outcome ||
				e.Reason != tc.reason || e.Subject != "agent-1" || e.Transport != "unix" || e.TS == "" {
				t.Fatalf("événement: %+v", e)
			}
			if !strings.Contains(e.Intent, "doc-1") {
				t.Fatalf("l'intention reçue doit figurer en clair dans la trace d'un banc d'essai: %q", e.Intent)
			}
		})
	}
}

func TestTraceNeverContainsTheToken(t *testing.T) {
	srv, path := traceFixture(t, true, true)
	intent := fmt.Sprintf("%q", simpleIntent(t, "read", "doc-1"))
	_, out := postWithTraceID(t, srv.URL, `{"subject":"agent-1","intent":`+intent+`}`, "t-1")
	if out.Token == "" {
		t.Fatal("pas de jeton à chercher")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), out.Token[:40]) {
		t.Fatal("la trace contient le jeton")
	}
	if !strings.Contains(string(raw), out.JTI) {
		t.Fatal("la trace doit porter le jti, qui relie la requête à ses feuilles")
	}
}

func TestTraceRecordsAMalformedRequest(t *testing.T) {
	srv, path := traceFixture(t, true, true)
	status, _ := postWithTraceID(t, srv.URL, `{"subject":"a","subject":"b","intent":"x"}`, "t-bad")
	if status != http.StatusBadRequest {
		t.Fatalf("statut %d", status)
	}
	ev := traceEvents(t, path)
	if len(ev) != 1 || ev[0].Stage != "request" || ev[0].Outcome != "deny" || ev[0].Reason != ReasonRequestInvalid ||
		ev[0].Detail != "duplicate-key" || ev[0].TraceID != "t-bad" {
		t.Fatalf("événement: %+v", ev)
	}
}

func TestTraceIgnoresAMalformedID(t *testing.T) {
	srv, path := traceFixture(t, true, true)
	intent := fmt.Sprintf("%q", simpleIntent(t, "read", "doc-1"))
	_, _ = postWithTraceID(t, srv.URL, `{"subject":"agent-1","intent":`+intent+`}`, "bad id with spaces")
	if ev := traceEvents(t, path); len(ev) != 1 || ev[0].TraceID != "" {
		t.Fatalf("un identifiant mal formé ne doit pas être recopié: %+v", ev)
	}
}

// Le verdict est le même avec ou sans trace : la trace n'est qu'un témoin.
func TestTraceDoesNotChangeTheVerdict(t *testing.T) {
	for _, allow := range []bool{true, false} {
		intent := fmt.Sprintf("%q", simpleIntent(t, "read", "doc-1"))
		body := `{"subject":"agent-1","intent":` + intent + `}`
		with, _ := traceFixture(t, allow, true)
		without, _ := traceFixture(t, allow, false)
		s1, o1 := postWithTraceID(t, with.URL, body, "t-1")
		s2, o2 := postWithTraceID(t, without.URL, body, "")
		if s1 != s2 || o1.Allow != o2.Allow || o1.Reason != o2.Reason {
			t.Fatalf("allow=%v: avec trace %d/%+v, sans %d/%+v", allow, s1, o1, s2, o2)
		}
	}
}
