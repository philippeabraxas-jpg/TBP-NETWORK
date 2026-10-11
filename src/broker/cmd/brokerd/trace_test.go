package main

// trace_test.go — issue #329 : la trace de décision du banc d'essai est une échappatoire DEV, au même titre que la
// graine d'émetteur : sentinel exigé (#113), listée dans les échappatoires actives (#208), et sans effet sur le verdict.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	devmode "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devmode"
	devtrace "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devtrace"
)

func TestDecisionTraceIsADevEscapeHatch(t *testing.T) {
	if got := devEscapeHatchFlags(false, "", false, ""); len(got) != 0 {
		t.Fatalf("sans trace, aucune échappatoire: %v", got)
	}
	flags := devEscapeHatchFlags(false, "", false, "/tmp/trace.jsonl")
	if len(flags) != 1 || flags[0] != "TBP_DECISION_TRACE_DEV" {
		t.Fatalf("la trace doit être listée: %v", flags)
	}
	err := devmode.RequireDeclared(devmode.DefaultSentinelPath, statAbsent, flags)
	if err == nil || !strings.Contains(err.Error(), "TBP_DECISION_TRACE_DEV") {
		t.Fatalf("la trace sans sentinel doit être refusée en la nommant: %v", err)
	}
	if err := devmode.RequireDeclared(devmode.DefaultSentinelPath, statPresent, flags); err != nil {
		t.Fatalf("la trace avec sentinel est permise: %v", err)
	}
}

func TestLoadConfigDecisionTraceNeedsTheSentinel(t *testing.T) {
	env := validConfigEnv()
	env["TBP_DECISION_TRACE_DEV"] = filepath.Join(t.TempDir(), "trace.jsonl")
	if _, err := loadConfig(mapGetenv(env), statAbsent); err == nil || !strings.Contains(err.Error(), "TBP_DECISION_TRACE_DEV") {
		t.Fatalf("sans sentinel, la trace doit être nommée dans le refus: %v", err)
	}
	cfg, err := loadConfig(mapGetenv(env), statPresent)
	if err != nil {
		t.Fatalf("avec sentinel: %v", err)
	}
	found := false
	for _, f := range cfg.devFlags {
		found = found || f == "TBP_DECISION_TRACE_DEV"
	}
	if !found {
		t.Fatalf("la trace doit figurer parmi les échappatoires consignées en feuille: %v", cfg.devFlags)
	}
}

func TestOpenDecisionTraceInactiveByDefault(t *testing.T) {
	s, err := openDecisionTrace("")
	if err != nil || s != nil {
		t.Fatalf("sans chemin: sink=%v err=%v, voulu nul", s, err)
	}
	if _, err := openDecisionTrace(filepath.Join(t.TempDir(), "absent-dir", "t.jsonl")); err == nil {
		t.Fatal("un chemin inutilisable doit faire échouer le démarrage, pas le taire")
	}
}

// Le démon assemblé écrit une ligne par décision, avec l'identifiant de l'appelant, sans changer le verdict.
func TestBrokerdWritesTheDecisionTrace(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	tracePath := filepath.Join(t.TempDir(), "trace.jsonl")
	fx.env["TBP_DECISION_TRACE_DEV"] = tracePath

	var allow atomic.Bool
	allow.Store(true)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			fmt.Fprintf(w, `{"result":{"allow":%t},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":%q}}}}`, allow.Load(), fx.env["TBP_POLICY_ID"])
			return
		}
		fmt.Fprintf(w, `{"result":{"allow":%t}}`, allow.Load())
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock)
	hc := unixClient(t, sock)

	post := func(id, intent string) actionResp {
		body, _ := json.Marshal(map[string]string{"subject": "agent-1", "intent": intent})
		req, _ := http.NewRequest("POST", "http://brokerd/v1/actions", strings.NewReader(string(body)))
		req.Header.Set(devtrace.Header, id)
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var ar actionResp
		_ = json.NewDecoder(resp.Body).Decode(&ar)
		return ar
	}
	ok := post("e2e-1", `{"action":"read","resource":"doc-1","class":0}`)
	allow.Store(false)
	denied := post("e2e-2", `{"action":"write","resource":"doc-2","class":0}`)
	if !ok.Allow || denied.Allow || denied.Reason != "opa-deny" {
		t.Fatalf("verdicts changés par la trace: %+v / %+v", ok, denied)
	}

	cancel()
	<-runErr

	f, err := os.Open(tracePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	byID := map[string]devtrace.Event{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e devtrace.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		byID[e.TraceID] = e
	}
	if e := byID["e2e-1"]; e.Outcome != "allow" || e.Reason != "ok" || e.JTI != ok.JTI || e.Component != "brokerd" {
		t.Fatalf("trace de l'accord: %+v", e)
	}
	if e := byID["e2e-2"]; e.Outcome != "deny" || e.Reason != "opa-deny" || !strings.Contains(e.Intent, "doc-2") {
		t.Fatalf("trace du refus: %+v", e)
	}
	if st, _ := os.Stat(tracePath); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode de la trace %v, voulu 0600", st.Mode().Perm())
	}
}
