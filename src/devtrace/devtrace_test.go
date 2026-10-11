package devtrace

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("ligne illisible %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestNilSinkDoesNothing(t *testing.T) {
	var s *Sink
	s.Emit(Event{Component: "x"})
	if s.Dropped() != 0 || s.Close() != nil {
		t.Fatal("un Sink nul doit être inerte")
	}
}

func TestEmitWritesOneJSONLinePerEventAnd0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), "trace.jsonl")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	s.Emit(Event{Component: "brokerd", Stage: "decision", Outcome: "deny", Reason: "opa-deny", TraceID: "t-1"})
	s.Emit(Event{Component: "brokerd", Stage: "decision", Outcome: "allow", Reason: "ok"})
	_ = s.Close()
	ev := readEvents(t, p)
	if len(ev) != 2 || ev[0].Reason != "opa-deny" || ev[0].TraceID != "t-1" || ev[0].TS == "" {
		t.Fatalf("événements: %+v", ev)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, voulu 0600", st.Mode().Perm())
	}
}

func TestControlCharactersCannotForgeALine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "trace.jsonl")
	s, _ := Open(p)
	s.Emit(Event{Component: "brokerd", Stage: "decision", Outcome: "deny", Intent: "x\n{\"component\":\"forged\"}", Subject: "a\r\nb"})
	_ = s.Close()
	raw, _ := os.ReadFile(p)
	if n := strings.Count(string(raw), "\n"); n != 1 {
		t.Fatalf("%d lignes, voulu 1 : %q", n, raw)
	}
	if ev := readEvents(t, p); len(ev) != 1 || ev[0].Component != "brokerd" {
		t.Fatalf("événement forgé: %+v", ev)
	}
}

func TestFieldsAreBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "trace.jsonl")
	s, _ := Open(p)
	s.Emit(Event{Component: "c", Intent: strings.Repeat("a", 5000)})
	_ = s.Close()
	if ev := readEvents(t, p); len(ev[0].Intent) != maxField {
		t.Fatalf("intention de %d octets", len(ev[0].Intent))
	}
}

func TestOpenRefusesASymlink(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("un lien symbolique doit être refusé")
	}
	if _, err := Open(""); err == nil {
		t.Fatal("un chemin vide doit être refusé")
	}
}

func TestIDAcceptsOnlyAWellFormedHeader(t *testing.T) {
	for v, want := range map[string]string{"t-123.a_b": "t-123.a_b", "": "", "a b": "", "a\nb": "", strings.Repeat("a", 65): "", "ok": "ok"} {
		r, _ := http.NewRequest("POST", "/", nil)
		if v != "" {
			r.Header.Set(Header, v)
		}
		if got := ID(r); got != want {
			t.Errorf("ID(%q) = %q, voulu %q", v, got, want)
		}
	}
}

func TestConcurrentEmitsKeepWholeLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "trace.jsonl")
	s, _ := Open(p)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Emit(Event{Component: "c", Reason: strings.Repeat("r", 200)}) }()
	}
	wg.Wait()
	_ = s.Close()
	if ev := readEvents(t, p); len(ev) != 50 {
		t.Fatalf("%d événements, voulu 50", len(ev))
	}
}
