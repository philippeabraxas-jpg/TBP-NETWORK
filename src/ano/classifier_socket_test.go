package ano

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serveClassifier(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cls")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestSocketClassifierContract(t *testing.T) {
	var seen struct{ Path, Value string }
	sock := serveClassifier(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		switch seen.Value {
		case "oui":
			_, _ = w.Write([]byte(`{"mask":true}`))
		case "non":
			_, _ = w.Write([]byte(`{"mask":false}`))
		case "500":
			w.WriteHeader(500)
		case "vide":
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`pas du json`))
		}
	})
	c := NewSocketClassifier(sock)
	ctx := context.Background()
	if m, err := c.Decide(ctx, "a.b", "oui"); err != nil || !m {
		t.Fatalf("oui: %v %v", m, err)
	}
	if seen.Path != "a.b" || seen.Value != "oui" {
		t.Fatalf("contrat de requête: %+v", seen)
	}
	if m, err := c.Decide(ctx, "a", "non"); err != nil || m {
		t.Fatalf("non: %v %v", m, err)
	}
	for _, v := range []string{"500", "vide", "junk"} {
		if _, err := c.Decide(ctx, "a", v); err == nil {
			t.Errorf("%s: doit être une erreur (donc un masquage)", v)
		}
	}
	// classifieur absent
	if _, err := NewSocketClassifier("/nonexistent/x.sock").Decide(ctx, "a", "v"); err == nil {
		t.Fatal("socket absent: doit être une erreur")
	}
}

func TestSocketClassifierIntegratesWithAnoFailClosed(t *testing.T) {
	sock := serveClassifier(t, func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Path, Value string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in.Value == "lent" {
			time.Sleep(250 * time.Millisecond)
		}
		_, _ = w.Write([]byte(`{"mask":` + map[bool]string{true: "true", false: "false"}[strings.HasPrefix(in.Value, "secret")] + `}`))
	})
	// Délai explicite (50 ms) : le défaut de 5 ms rend « oui » et « public » tributaires
	// de l'ordonnancement d'un runner chargé (faute de délai inattendue, CI #223) ; le cas
	// « lent » dort bien au-delà (250 ms) pour rester une vraie faute de délai.
	a := newAno(t, Options{Classifier: NewSocketClassifier(sock), ClassifierTimeout: 50 * time.Millisecond})
	open(t, a, "ex")
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(`{"a":"secret-1","b":"public","c":"lent"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "secret-1") || strings.Contains(s, `"lent"`) || !strings.Contains(s, `"b":"public"`) {
		t.Fatalf("classifieur socket: %s", s)
	}
	if rep.MaskedClassifier != 1 || rep.ClassifierFaults != 1 {
		t.Fatalf("rapport: %+v (un « oui », une faute de délai)", rep)
	}
}
