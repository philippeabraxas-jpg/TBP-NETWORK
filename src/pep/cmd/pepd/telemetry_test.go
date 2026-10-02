package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestTelemetryFromEnv(t *testing.T) {
	// désactivée par défaut, et « 0 » aussi
	for _, v := range []string{"", "0"} {
		cfg, err := telemetryFromEnv(envMap(map[string]string{"TBP_TELEMETRY": v}))
		if err != nil || cfg.enabled {
			t.Fatalf("TBP_TELEMETRY=%q : %+v, %v — doit rester éteinte", v, cfg, err)
		}
	}
	// activée : défauts
	cfg, err := telemetryFromEnv(envMap(map[string]string{"TBP_TELEMETRY": "1"}))
	if err != nil || !cfg.enabled || cfg.interval != 10*time.Second || cfg.window != time.Minute || cfg.collector != "" {
		t.Fatalf("défauts : %+v, %v", cfg, err)
	}
	cfg, err = telemetryFromEnv(envMap(map[string]string{
		"TBP_TELEMETRY": "1", "TBP_TELEMETRY_INTERVAL_MS": "2500", "TBP_TELEMETRY_WINDOW_S": "30", "TBP_TELEMETRY_COLLECTOR": "10.99.99.9:4739",
	}))
	if err != nil || cfg.interval != 2500*time.Millisecond || cfg.window != 30*time.Second || cfg.collector != "10.99.99.9:4739" {
		t.Fatalf("valeurs : %+v, %v", cfg, err)
	}
	// fail-closed : valeur inconnue, bornes, collecteur mal formé, réglage sans activation
	for name, env := range map[string]map[string]string{
		"valeur inconnue":       {"TBP_TELEMETRY": "oui"},
		"intervalle trop court": {"TBP_TELEMETRY": "1", "TBP_TELEMETRY_INTERVAL_MS": "999"},
		"intervalle non num.":   {"TBP_TELEMETRY": "1", "TBP_TELEMETRY_INTERVAL_MS": "vite"},
		"fenêtre nulle":         {"TBP_TELEMETRY": "1", "TBP_TELEMETRY_WINDOW_S": "0"},
		"fenêtre trop longue":   {"TBP_TELEMETRY": "1", "TBP_TELEMETRY_WINDOW_S": "3601"},
		"collecteur sans port":  {"TBP_TELEMETRY": "1", "TBP_TELEMETRY_COLLECTOR": "10.99.99.9"},
		"réglage sans activer":  {"TBP_TELEMETRY_WINDOW_S": "30"},
		"collecteur sans activ": {"TBP_TELEMETRY": "0", "TBP_TELEMETRY_COLLECTOR": "10.0.0.1:4739"},
	} {
		if _, err := telemetryFromEnv(envMap(env)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func TestSetupTelemetryRequiresTheJournalAndTheLedger(t *testing.T) {
	cfg := telemetryConfig{enabled: true, interval: time.Second, window: time.Second}
	if _, _, err := setupTelemetry(cfg, "cell-a", bytes.Repeat([]byte{1}, 16), &stubLeaves{}, nil, nil); err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("sans journal : %v", err)
	}
	// éteinte : aucun journal exigé, rien ne tourne
	start, stop, err := setupTelemetry(telemetryConfig{}, "cell-a", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("éteinte : %v", err)
	}
	start(context.Background())
	stop()
}

type stubLeaves struct{}

func (stubLeaves) Append(context.Context, registry.Leaf) (uint64, error) { return 0, nil }

// De bout en bout : un vrai QuotaLedger, un vrai registre et un vrai journal. Un passeport consommé produit,
// une fenêtre plus tard, une feuille d'agrégat dont le clair est dans le journal ; l'arrêt est propre et
// ne dépend pas de l'annulation du contexte du démon (retour de run() sur erreur).
func TestTelemetryRunsInPepdAndJournalsItsLeaves(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	jpath := filepath.Join(t.TempDir(), "records.jsonl")
	jkey := bytes.Repeat([]byte{9}, registry.RecordKeyLen)
	journal, err := registry.OpenRecordStore(jpath, jkey)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ledger, err := pep.NewQuotaLedger(pep.QuotaLedgerOptions{MaxPassports: 16, CellID: fx.cellID, Salt: fx.salt, Leaves: fx.cellLog, Journal: journal})
	if err != nil {
		t.Fatal(err)
	}
	counter, err := ledger.Open(&pep.Token{
		JTI: [16]byte{7}, Exp: time.Now().Add(time.Hour).Unix(),
		Quota: &pep.Quota{Resource: "10.0.0.7", Operation: "send", VolumeMax: 1 << 20, WindowS: 3600},
	})
	if err != nil {
		t.Fatalf("Open : %v", err)
	}
	start, stop, err := setupTelemetry(telemetryConfig{enabled: true, interval: 20 * time.Millisecond, window: time.Second}, fx.cellID, fx.salt, fx.cellLog, journal, ledger)
	if err != nil {
		t.Fatal(err)
	}
	start(context.Background()) // contexte JAMAIS annulé : stop() doit suffire
	deadline := time.Now().Add(8 * time.Second)
	var aggregates int
	for time.Now().Before(deadline) && aggregates == 0 {
		_ = counter.Consume(100) // du trafic : un delta à chaque cycle
		time.Sleep(50 * time.Millisecond)
		recs, err := registry.ReadRecords(jpath, jkey)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if bytes.HasPrefix(r.Record, []byte("TBAG1")) {
				if r.VerifyHash() != nil || r.Leaf.Kind != registry.KindTelemetry {
					t.Fatalf("clair d'agrégat incohérent : %+v", r)
				}
				aggregates++
			}
		}
	}
	if aggregates == 0 {
		t.Fatal("aucune feuille d'agrégat journalisée : la télémétrie ne tourne pas dans pepd")
	}
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() ne rend pas la main (Run attend l'annulation du contexte du démon)")
	}
}
