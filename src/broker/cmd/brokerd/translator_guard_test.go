package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func TestTranslatorGuardFromEnv(t *testing.T) {
	cfg, err := translatorGuardFromEnv(mapGetenv(map[string]string{}))
	if err != nil || cfg.enabled {
		t.Fatalf("garde absente : %+v %v", cfg, err)
	}
	if cfg, err = translatorGuardFromEnv(mapGetenv(map[string]string{"TBP_TRANSLATOR_GUARD": "0"})); err != nil || cfg.enabled {
		t.Fatalf("garde =0 : %+v %v", cfg, err)
	}
	ok := map[string]string{"TBP_TRANSLATOR_GUARD": "1", "TBP_TRANSLATOR_PROBE_URL": "http://127.0.0.1:8000/health"}
	cfg, err = translatorGuardFromEnv(mapGetenv(ok))
	if err != nil || !cfg.enabled || cfg.interval != 5*time.Second || cfg.timeout != 2*time.Second || cfg.probeURL == "" {
		t.Fatalf("défauts : %+v %v", cfg, err)
	}
	with := func(kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range ok {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	cfg, err = translatorGuardFromEnv(mapGetenv(with("TBP_TRANSLATOR_PROBE_INTERVAL_MS", "500", "TBP_TRANSLATOR_PROBE_TIMEOUT_MS", "100")))
	if err != nil || cfg.interval != 500*time.Millisecond || cfg.timeout != 100*time.Millisecond {
		t.Fatalf("bornes basses : %+v %v", cfg, err)
	}
	bad := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"guard_invalide", map[string]string{"TBP_TRANSLATOR_GUARD": "oui"}, "TBP_TRANSLATOR_GUARD invalide"},
		{"url_sans_guard", map[string]string{"TBP_TRANSLATOR_PROBE_URL": "http://127.0.0.1:1/h"}, "sans TBP_TRANSLATOR_GUARD=1"},
		{"intervalle_sans_guard", map[string]string{"TBP_TRANSLATOR_PROBE_INTERVAL_MS": "1000"}, "sans TBP_TRANSLATOR_GUARD=1"},
		{"delai_sans_guard", map[string]string{"TBP_TRANSLATOR_PROBE_TIMEOUT_MS": "1000"}, "sans TBP_TRANSLATOR_GUARD=1"},
		{"guard_sans_url", map[string]string{"TBP_TRANSLATOR_GUARD": "1"}, "TBP_TRANSLATOR_PROBE_URL requis"},
		{"url_hors_loopback", with("TBP_TRANSLATOR_PROBE_URL", "http://10.0.0.1:8000/h"), "loopback"},
		{"url_nom", with("TBP_TRANSLATOR_PROBE_URL", "http://localhost:8000/h"), "loopback"},
		{"intervalle_trop_bas", with("TBP_TRANSLATOR_PROBE_INTERVAL_MS", "499"), "TBP_TRANSLATOR_PROBE_INTERVAL_MS invalide"},
		{"intervalle_trop_haut", with("TBP_TRANSLATOR_PROBE_INTERVAL_MS", "60001"), "TBP_TRANSLATOR_PROBE_INTERVAL_MS invalide"},
		{"intervalle_texte", with("TBP_TRANSLATOR_PROBE_INTERVAL_MS", "vite"), "TBP_TRANSLATOR_PROBE_INTERVAL_MS invalide"},
		{"delai_trop_bas", with("TBP_TRANSLATOR_PROBE_TIMEOUT_MS", "99"), "TBP_TRANSLATOR_PROBE_TIMEOUT_MS invalide"},
		{"delai_trop_haut", with("TBP_TRANSLATOR_PROBE_TIMEOUT_MS", "10001"), "TBP_TRANSLATOR_PROBE_TIMEOUT_MS invalide"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := translatorGuardFromEnv(mapGetenv(c.env))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refus %q attendu, got %v", c.want, err)
			}
		})
	}
	// la validation de bout en bout passe par loadConfig : un démarrage incohérent est refusé tôt
	env := validConfigEnv()
	env["TBP_TRANSLATOR_PROBE_URL"] = "http://127.0.0.1:8000/h"
	if _, err := loadConfig(mapGetenv(env), statPresent); err == nil || !strings.Contains(err.Error(), "sans TBP_TRANSLATOR_GUARD=1") {
		t.Fatalf("loadConfig doit refuser un réglage de sonde sans garde : %v", err)
	}
}

// TestBrokerdTranslatorGuardEndToEnd : la garde est effective de bout en bout. Le contrôleur démarre dégradé ;
// une sonde verte ouvre le chemin, une sonde qui retombe le referme — chaque fois par un refus sain
// (translation-failed), jamais une admission.
func TestBrokerdTranslatorGuardEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)

	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			_, _ = w.Write([]byte(`{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":"` + fx.env["TBP_POLICY_ID"] + `"}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL

	var healthy atomic.Bool
	tr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer tr.Close()
	fx.env["TBP_TRANSLATOR_GUARD"] = "1"
	fx.env["TBP_TRANSLATOR_PROBE_URL"] = tr.URL + "/health"
	fx.env["TBP_TRANSLATOR_PROBE_INTERVAL_MS"] = "500"

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock)
	hc := unixClient(t, sock)

	const act = `{"action":"read","resource":"doc-1","class":0}`
	// 1. Sonde rouge dès le départ : refus sain, sans jeton.
	res := postAction(t, hc, "agent-1", act)
	if res.Allow || res.Reason != "translation-failed" || res.Token != "" {
		t.Fatalf("traducteur dégradé : refus translation-failed attendu, got %+v", res)
	}

	// 2. Sonde verte : la reprise ouvre le chemin (sans redémarrage).
	healthy.Store(true)
	waitFor(t, 10*time.Second, "reprise après sonde verte", func() bool {
		return postAction(t, hc, "agent-1", act).Allow
	})

	// 3. Le traducteur retombe : le chemin se referme.
	healthy.Store(false)
	waitFor(t, 10*time.Second, "refermeture après sonde rouge", func() bool {
		r := postAction(t, hc, "agent-1", act)
		return !r.Allow && r.Reason == "translation-failed"
	})

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestBrokerdTranslatorGuardProbesBeforeServing : l'état est établi par une sonde SYNCHRONE avant que le broker ne
// serve — avec une cadence de 60 s (le maximum), la toute première demande est déjà admise si le traducteur est sain.
func TestBrokerdTranslatorGuardProbesBeforeServing(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			_, _ = w.Write([]byte(`{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":"` + fx.env["TBP_POLICY_ID"] + `"}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	tr := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tr.Close()
	fx.env["TBP_TRANSLATOR_GUARD"] = "1"
	fx.env["TBP_TRANSLATOR_PROBE_URL"] = tr.URL + "/health"
	fx.env["TBP_TRANSLATOR_PROBE_INTERVAL_MS"] = "60000"

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock)
	if res := postAction(t, unixClient(t, sock), "agent-1", `{"action":"read","resource":"doc-1","class":0}`); !res.Allow {
		t.Fatalf("traducteur sain dès le démarrage : la première demande doit être admise (sonde synchrone), got %+v", res)
	}
	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}

type sinkLeaves struct{ n atomic.Int64 }

func (s *sinkLeaves) Append(context.Context, registry.Leaf) (uint64, error) {
	return uint64(s.n.Add(1)), nil
}

// TestTranslatorGuardDegradedStructuredIsDefaultDeny : un traducteur STRUCTURÉ dégradé est refusé en default-deny
// (feuille « default-deny »), pas déclaré langage naturel — la nature de l'entrée est celle du traducteur interne.
func TestTranslatorGuardDegradedStructuredIsDefaultDeny(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	var alarms []string
	var mu sync.Mutex
	cfg := translatorGuardConfig{enabled: true, probeURL: down.URL + "/h", interval: time.Hour, timeout: time.Second}
	tr, start, err := setupTranslatorGuard(cfg, broker.StructuredTranslator{}, "cell-a", make([]byte, 16), &sinkLeaves{}, nil,
		func(r string) { mu.Lock(); alarms = append(alarms, r); mu.Unlock() }, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start(ctx)
	if _, err := tr.Translate(ctx, "agent-1", `{"action":"read","resource":"r"}`); err == nil {
		t.Fatal("traducteur dégradé : demande admise")
	}
	mu.Lock()
	defer mu.Unlock()
	got := strings.Join(alarms, ",")
	if !strings.Contains(got, "translator-down") || !strings.Contains(got, "translator-default-deny") || strings.Contains(got, "nl-rejected") {
		t.Fatalf("alarmes = %q, attendu translator-down puis translator-default-deny (structuré, pas langage naturel)", got)
	}
}

// TestBrokerdWithoutGuardIsUnchanged : garde absente ⇒ comportement historique (pas de sonde, admission directe).
func TestBrokerdWithoutGuardIsUnchanged(t *testing.T) {
	cfg := translatorGuardConfig{}
	tr, start, err := setupTranslatorGuard(cfg, nil, "cell-a", make([]byte, 16), nil, nil, nil, nil, nil, nil)
	if err != nil || tr != nil {
		t.Fatalf("garde désactivée : le traducteur doit passer tel quel (%v, %v)", tr, err)
	}
	start(context.Background()) // no-op
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}
