// harness_test.go — T27 (issue #29) : tests du harnais de friction.
//
// Doctrine : les mutations sont prouvées LÉTALES de bout en bout — chaque
// test de mutation exécute le harnais réel puis le verdict python réel
// (leading_indicators.py) et exige le rouge/l'alarme attendue. Un garde-fou
// qui ne voit pas sa mutation ne vaut rien.
package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// testConfig : profil réduit mais non trivial (le bras durabilité paie le
// plancher checkpoint POSIX sur chaque opération — ~150-300 ms × ops).
func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Tier1Samples = 60
	cfg.Tier2Plans = 6
	cfg.Workers = 8
	cfg.DurTier1 = 4
	cfg.DurTier2 = 2
	cfg.OutDir = t.TempDir()
	return cfg
}

// pythonVerdict exécute leading_indicators.py sur l'out dir et rend le code
// de sortie + le rapport. python3 absent ⇒ Skip (la CI l'a toujours).
func pythonVerdict(t *testing.T, outDir string) (exitCode int, report map[string]any) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 absent — verdict python non testable ici")
	}
	cmd := exec.Command("python3", "leading_indicators.py", "--in", outDir)
	cmd.Dir = "." // go test s'exécute dans le répertoire du paquet
	out, err := cmd.Output()
	t.Logf("leading_indicators.py:\n%s", out)
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("python3: %v", err)
		}
		exitCode = ee.ExitCode()
	}
	data, rerr := os.ReadFile(filepath.Join(outDir, "friction_report.json"))
	if rerr != nil {
		t.Fatalf("rapport: %v", rerr)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("rapport json: %v", err)
	}
	return exitCode, report
}

func indicatorOf(t *testing.T, report map[string]any, name string) map[string]any {
	t.Helper()
	ind, ok := report["indicators"].(map[string]any)[name].(map[string]any)
	if !ok {
		t.Fatalf("indicateur %s absent du rapport", name)
	}
	return ind
}

// TestHarnessNominalPipeline : run complet nominal — seuils tenus (exit 0),
// corrélation feuilles ↔ échantillons exacte (holes = 0), rapport leafé et
// revérifié (D90), notice de production présente (condition A revue #29).
func TestHarnessNominalPipeline(t *testing.T) {
	cfg := testConfig(t)
	m, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Fichiers d'export (D88).
	for _, f := range []string{"measurements.json", "leaves_export.json"} {
		if _, err := os.Stat(filepath.Join(cfg.OutDir, f)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	// Compteurs cohérents avec la config.
	if m.Counters.Tier1DecisionEvals != uint64(cfg.Tier1Samples) {
		t.Fatalf("tier1 evals %d ≠ %d", m.Counters.Tier1DecisionEvals, cfg.Tier1Samples)
	}
	wantContract := uint64(3 * cfg.DurTier2) // submit + approve + verify(ok|refus)
	if m.Counters.LeavesExpectedContract != wantContract {
		t.Fatalf("attendu contract %d ≠ %d", m.Counters.LeavesExpectedContract, wantContract)
	}
	// Verdict python : nominal = vert, holes = 0.
	code, report := pythonVerdict(t, cfg.OutDir)
	if code != 0 {
		t.Fatalf("run nominal rouge (exit %d) — le garde-fou doit être vert au nominal", code)
	}
	if v := indicatorOf(t, report, "uninstrumented_holes")["value"].(float64); v != 0 {
		t.Fatalf("holes %v ≠ 0 au nominal", v)
	}
	if report["production_notice"].(string) == "" {
		t.Fatal("production_notice absente — condition A de la revue #29")
	}
	// D90 : le rapport est leafé et la feuille revérifiée au scan.
	idx, err := LeafReport(context.Background(), cfg, filepath.Join(cfg.OutDir, "friction_report.json"))
	if err != nil {
		t.Fatalf("LeafReport: %v", err)
	}
	leaves, err := exportLeaves(context.Background(), cfg, filepath.Join(cfg.OutDir, "registry"), registryOrigin(cfg))
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if uint64(len(leaves)) != idx+1 || leaves[idx].Kind != 2 { // KindTelemetry
		t.Fatalf("feuille rapport non retrouvée : idx %d, taille %d", idx, len(leaves))
	}
	// Le sel du rapport est conservé à côté (≥ 16 octets = 32 hex), jamais
	// dans le registre.
	salt, err := os.ReadFile(filepath.Join(cfg.OutDir, "report_salt.hex"))
	if err != nil || len(salt) < 32 {
		t.Fatalf("sel rapport : %v (%d octets hex)", err, len(salt))
	}
}

// M-harness : +10 ms injectés sur le chemin tier1 ⇒ p95 ajoutée ≥ 5 ms ⇒
// CI rouge. Prouve que le garde-fou de latence voit une dégradation.
func TestMutationInjectedLatencyLethal(t *testing.T) {
	cfg := testConfig(t)
	cfg.InjectLatency = 10 * time.Millisecond
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	code, report := pythonVerdict(t, cfg.OutDir)
	if code == 0 {
		t.Fatal("M-harness non létale : +10 ms injectés et la CI reste verte")
	}
	ind := indicatorOf(t, report, "tier1_added_latency")
	if ind["severity"] != "alert" || ind["blocking"] != true {
		t.Fatalf("tier1_added_latency devrait être ALERTE bloquante : %v", ind)
	}
}

// M-holes : leaves_export.json tronqué (moitié des feuilles supprimées) ⇒
// trous d'instrumentation > 0 ⇒ CI rouge. Prouve que la corrélation feuilles
// réelles ↔ échantillons mord.
func TestMutationTruncatedLeavesLethal(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	path := filepath.Join(cfg.OutDir, "leaves_export.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("leaves: %v", err)
	}
	var leaves []map[string]any
	if err := json.Unmarshal(data, &leaves); err != nil {
		t.Fatalf("leaves json: %v", err)
	}
	truncated, err := json.Marshal(leaves[:len(leaves)/2])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, truncated, 0o644); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	code, report := pythonVerdict(t, cfg.OutDir)
	if code == 0 {
		t.Fatal("M-holes non létale : feuilles tronquées et la CI reste verte")
	}
	if v := indicatorOf(t, report, "uninstrumented_holes"); v["value"].(float64) == 0 || v["blocking"] != true {
		t.Fatalf("uninstrumented_holes devrait être > 0 bloquant : %v", v)
	}
}

// M-arbitrage : 15 % de vérifications d'étape dévient ⇒ taux d'arbitrage ≥
// 10 % ⇒ CI rouge (§9 : alerte > 10 %).
func TestMutationArbitrationLethal(t *testing.T) {
	cfg := testConfig(t)
	cfg.InjectDenyRate = 0.15
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	code, report := pythonVerdict(t, cfg.OutDir)
	if code == 0 {
		t.Fatal("M-arbitrage non létale : 15 % de refus et la CI reste verte")
	}
	ind := indicatorOf(t, report, "arbitration_rate")
	if ind["value"].(float64) < 0.10 || ind["blocking"] != true {
		t.Fatalf("arbitration_rate devrait être ≥ 10%% bloquante : %v", ind)
	}
}

// M-ttl : TTL émis étirés ×3 ⇒ alarme ttl_drift (avertissement — tracée et
// leafée, non bloquante D89).
func TestMutationTTLStretchAlarmed(t *testing.T) {
	cfg := testConfig(t)
	cfg.TTLStretch = 3
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	code, report := pythonVerdict(t, cfg.OutDir)
	if code != 0 {
		t.Fatalf("M-ttl devrait rester non bloquante (avertissement), exit %d", code)
	}
	if ind := indicatorOf(t, report, "ttl_drift"); ind["severity"] != "warning" {
		t.Fatalf("ttl_drift devrait être WARNING : %v", ind)
	}
}

// TestConfigFailClosed : configurations invalides refusées d'entrée.
func TestConfigFailClosed(t *testing.T) {
	base := testConfig(t)
	cases := []func(*Config){
		func(c *Config) { c.Tier1Samples = 0 },
		func(c *Config) { c.Tier2Plans = 0 },
		func(c *Config) { c.Workers = 0 },
		func(c *Config) { c.DurTier1 = 0 },
		func(c *Config) { c.InjectDenyRate = 1.5 },
		func(c *Config) { c.TTLStretch = 0 },
		func(c *Config) { c.TTLBase = time.Second },
		func(c *Config) { c.OutDir = "" },
	}
	for i, mutate := range cases {
		cfg := base
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("cas %d : config invalide acceptée", i)
		}
	}
}

// TestVerifyRefusalComptabilise : la déviation injectée est bien un refus
// tracé (KindContract) — l'échantillon Denied correspond à une feuille
// réelle, pas à un trou.
func TestVerifyRefusalComptabilise(t *testing.T) {
	cfg := testConfig(t)
	cfg.InjectDenyRate = 0.5 // 1 refus sur 2 plans durabilité
	m, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Chaque refus a écrit sa feuille KindContract : l'attendu inclut les
	// refus et holes reste 0.
	leaves, err := exportLeaves(context.Background(), cfg, filepath.Join(cfg.OutDir, "registry"), registryOrigin(cfg))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var contract int
	for _, l := range leaves {
		if l.Kind == 10 {
			contract++
		}
	}
	if uint64(contract) != m.Counters.LeavesExpectedContract {
		t.Fatalf("KindContract réels %d ≠ attendus %d (refus tracés compris)",
			contract, m.Counters.LeavesExpectedContract)
	}
}
