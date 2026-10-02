package broker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeGate struct {
	err     error
	calls   int
	subject string
	natural bool
}

func (f *fakeGate) Admit(_ context.Context, subject string, natural bool) error {
	f.calls++
	f.subject, f.natural = subject, natural
	return f.err
}

var (
	errGateDenied  = errors.New("garde : refus")
	errGateDegrade = errors.New("garde : dégradé")
)

type countTranslator struct{ calls int }

func (c *countTranslator) Translate(context.Context, string, string) (Translation, error) {
	c.calls++
	return Translation{Action: "read", Resource: "r"}, nil
}

func TestGuardedTranslatorRefusesWithoutDelegating(t *testing.T) {
	inner := &countTranslator{}
	for _, gerr := range []error{errGateDenied, errGateDegrade} {
		gate := &fakeGate{err: gerr}
		g, err := NewGuardedTranslator(inner, gate, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = g.Translate(context.Background(), "agent-1", `{}`)
		if !errors.Is(err, gerr) {
			t.Fatalf("refus de la garde %v attendu, got %v", gerr, err)
		}
		if inner.calls != 0 {
			t.Fatalf("le traducteur interne ne doit JAMAIS être atteint quand la garde refuse (%v)", gerr)
		}
		if refusalDetailOf(err) != nil {
			t.Fatalf("aucun détail vers l'agent : l'état de santé n'est pas un oracle (%v)", gerr)
		}
	}
}

func TestGuardedTranslatorAdmitsAndDescribesTheRequest(t *testing.T) {
	inner := &countTranslator{}
	gate := &fakeGate{}
	g, _ := NewGuardedTranslator(inner, gate, true)
	tr, err := g.Translate(context.Background(), "agent-7", "intent")
	if err != nil || tr.Action != "read" || inner.calls != 1 {
		t.Fatalf("admission : tr=%+v err=%v délégations=%d", tr, err, inner.calls)
	}
	if gate.subject != "agent-7" || !gate.natural {
		t.Fatalf("la garde doit recevoir le sujet et la nature de l'entrée : %+v", gate)
	}
	gate2 := &fakeGate{}
	g2, _ := NewGuardedTranslator(inner, gate2, false)
	_, _ = g2.Translate(context.Background(), "a", "i")
	if gate2.natural {
		t.Fatal("un traducteur structuré ne doit pas être déclaré langage naturel")
	}
}

func TestNewGuardedTranslatorFailClosed(t *testing.T) {
	if _, err := NewGuardedTranslator(nil, &fakeGate{}, false); err == nil {
		t.Fatal("traducteur interne nil accepté")
	}
	if _, err := NewGuardedTranslator(&countTranslator{}, nil, false); err == nil {
		t.Fatal("garde nil acceptée : la dégradation ne se présume pas absente")
	}
}

func TestHTTPProbeURLValidation(t *testing.T) {
	for _, bad := range []string{
		"https://127.0.0.1:8000/health",    // schéma
		"http://example.com/health",        // nom
		"http://localhost:8000/health",     // nom, même « localhost »
		"http://10.0.0.5:8000/health",      // hors loopback
		"http://user:pw@127.0.0.1:8000/h",  // identifiants
		"http://[2001:db8::1]:8000/health", // IPv6 non loopback
		"://",                              // illisible
		"",                                 // vide
		"http://0.0.0.0:8000/health",       // non-spécifiée ≠ loopback
	} {
		if _, err := NewHTTPProbe(bad, time.Second); err == nil {
			t.Errorf("URL %q acceptée", bad)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:8000/health", "http://[::1]:8000/health", "http://127.1.2.3/h"} {
		if _, err := NewHTTPProbe(ok, time.Second); err != nil {
			t.Errorf("URL %q refusée : %v", ok, err)
		}
	}
	if _, err := NewHTTPProbe("http://127.0.0.1:8000/h", 0); err == nil {
		t.Error("délai nul accepté")
	}
}

func TestHTTPProbeHealthy(t *testing.T) {
	var status = http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/health", http.StatusFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(strings.Repeat("x", 200<<10))) // corps énorme : borné
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "localhost", "127.0.0.1", 1)

	p, err := NewHTTPProbe(base+"/health", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Healthy(context.Background()); err != nil {
		t.Fatalf("200 refusé : %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := p.Healthy(context.Background()); err == nil {
		t.Fatal("503 pris pour sain")
	}
	status = http.StatusNoContent
	if err := p.Healthy(context.Background()); err == nil {
		t.Fatal("seul 200 est sain (204 accepté)")
	}
	status = http.StatusOK // la cible de la redirection est SAINE : seul le refus de la suivre peut échouer la sonde
	pr, _ := NewHTTPProbe(base+"/redir", time.Second)
	if err := pr.Healthy(context.Background()); err == nil {
		t.Fatal("une redirection ne doit pas être suivie (302 pris pour sain)")
	}
	srv.Close()
	if err := p.Healthy(context.Background()); err == nil {
		t.Fatal("service arrêté pris pour sain")
	}
}

func TestHTTPProbeTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	p, _ := NewHTTPProbe(srv.URL+"/h", 100*time.Millisecond)
	start := time.Now()
	if err := p.Healthy(context.Background()); err == nil {
		t.Fatal("sonde muette prise pour saine")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("le délai de sonde n'est pas appliqué")
	}
}
