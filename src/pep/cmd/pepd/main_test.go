package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// envOf construit un getenv à partir d'une table.
func envOf(table map[string]string) func(string) string {
	return func(k string) string { return table[k] }
}

func TestDurabilityFromEnvDefaults(t *testing.T) {
	async, window, err := durabilityFromEnv(envOf(nil))
	if err != nil {
		t.Fatalf("défaut: erreur inattendue: %v", err)
	}
	if !async {
		t.Fatal("défaut: async attendu (async borné = défaut #71)")
	}
	if window != registry.DefaultOpposabilityWindow {
		t.Fatalf("défaut: fenêtre %v, attendu %v", window, registry.DefaultOpposabilityWindow)
	}
}

func TestDurabilityFromEnvModes(t *testing.T) {
	cases := []struct {
		name      string
		value     string
		wantAsync bool
		wantErr   bool
	}{
		{"async explicite", "async-bounded", true, false},
		{"sync", "sync", false, false},
		{"mode invalide", "fire-and-forget", false, true},
		{"casse non normalisée", "ASYNC-BOUNDED", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			async, window, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY": tc.value}))
			if tc.wantErr {
				if err == nil {
					t.Fatal("erreur attendue, obtenu nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("erreur inattendue: %v", err)
			}
			if async != tc.wantAsync {
				t.Fatalf("async=%v, attendu %v", async, tc.wantAsync)
			}
			if window != registry.DefaultOpposabilityWindow {
				t.Fatalf("fenêtre %v, attendu défaut %v", window, registry.DefaultOpposabilityWindow)
			}
		})
	}
}

func TestDurabilityFromEnvWindow(t *testing.T) {
	async, window, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY_WINDOW_MS": "250"}))
	if err != nil {
		t.Fatalf("fenêtre 250: erreur inattendue: %v", err)
	}
	if !async {
		t.Fatal("fenêtre 250: async attendu")
	}
	if window != 250*time.Millisecond {
		t.Fatalf("fenêtre %v, attendu 250ms", window)
	}
}

func TestDurabilityFromEnvWindowInvalid(t *testing.T) {
	for _, value := range []string{"0", "-5", "abc", "1.5"} {
		if _, _, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY_WINDOW_MS": value})); err == nil {
			t.Fatalf("fenêtre %q: erreur attendue, obtenu nil", value)
		}
	}
}

func TestDurabilityFromEnvErrorMentionsVariable(t *testing.T) {
	_, _, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY": "nope"}))
	if err == nil || !strings.Contains(err.Error(), "TBP_DURABILITY") {
		t.Fatalf("erreur doit nommer la variable: %v", err)
	}
}

// ---------------------------------------------------------------------------
// checkDevEscapeHatches (revue #113) : TBP_OPA_DISABLED_DEV_UNSAFE et
// TBP_OPA_INSECURE_TCP_DEV exigent le sentinel devmode, indépendant du
// fichier d'environnement qui les porte.
// ---------------------------------------------------------------------------

func statAbsent(string) (os.FileInfo, error)  { return nil, os.ErrNotExist }
func statPresent(string) (os.FileInfo, error) { return nil, nil }

func TestCheckDevEscapeHatchesNoFlagsNoSentinelRequired(t *testing.T) {
	if err := checkDevEscapeHatches(envOf(nil), statAbsent); err != nil {
		t.Fatalf("erreur inattendue (aucun drapeau actif): %v", err)
	}
}

func TestCheckDevEscapeHatchesOPADisabledRefusedWithoutSentinel(t *testing.T) {
	err := checkDevEscapeHatches(envOf(map[string]string{"TBP_OPA_DISABLED_DEV_UNSAFE": "1"}), statAbsent)
	if err == nil || !strings.Contains(err.Error(), "TBP_OPA_DISABLED_DEV_UNSAFE") {
		t.Fatalf("erreur attendue nommant TBP_OPA_DISABLED_DEV_UNSAFE, obtenu: %v", err)
	}
}

func TestCheckDevEscapeHatchesOPAInsecureTCPRefusedWithoutSentinel(t *testing.T) {
	err := checkDevEscapeHatches(envOf(map[string]string{"TBP_OPA_INSECURE_TCP_DEV": "1"}), statAbsent)
	if err == nil || !strings.Contains(err.Error(), "TBP_OPA_INSECURE_TCP_DEV") {
		t.Fatalf("erreur attendue nommant TBP_OPA_INSECURE_TCP_DEV, obtenu: %v", err)
	}
}

func TestCheckDevEscapeHatchesBothAllowedWithSentinel(t *testing.T) {
	env := envOf(map[string]string{
		"TBP_OPA_DISABLED_DEV_UNSAFE": "1",
		"TBP_OPA_INSECURE_TCP_DEV":    "1",
	})
	if err := checkDevEscapeHatches(env, statPresent); err != nil {
		t.Fatalf("erreur inattendue (sentinel présent): %v", err)
	}
}

// ---------------------------------------------------------------------------
// detectRestart (revue #93 + revue #111) : cell_log.key ET le manifeste
// measured boot sont deux témoins INDÉPENDANTS de redémarrage — un seul
// suffit ; celui measured boot doit vivre HORS de regDir.
// ---------------------------------------------------------------------------

func TestDetectRestartFreshDeploymentNoMeasuredBoot(t *testing.T) {
	regDir := t.TempDir()
	isRestart, err := detectRestart(regDir, "")
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
	if isRestart {
		t.Fatal("isRestart=true, veut false (ni cell_log.key ni measured boot configuré)")
	}
}

func TestDetectRestartCellLogKeyPresent(t *testing.T) {
	regDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(regDir, "cell_log.key"), []byte("k"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	isRestart, err := detectRestart(regDir, "")
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
	if !isRestart {
		t.Fatal("isRestart=false, veut true (cell_log.key présent)")
	}
}

// TestDetectRestartMeasuredBootWitnessSurvivesRegistryWipe : le scénario
// central de #111 — cell_log.key a disparu (registre effacé/déplacé) mais
// le manifeste measured boot, à un chemin INDÉPENDANT, existe toujours :
// il doit à lui seul établir isRestart=true.
func TestDetectRestartMeasuredBootWitnessSurvivesRegistryWipe(t *testing.T) {
	regDir := t.TempDir()
	mbDir := t.TempDir()
	mbPath := filepath.Join(mbDir, "manifest.json")
	if err := os.WriteFile(mbPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// regDir est VIDE (pas de cell_log.key) — simule un registre effacé.
	isRestart, err := detectRestart(regDir, mbPath)
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
	if !isRestart {
		t.Fatal("isRestart=false, veut true (témoin measured boot indépendant présent malgré registre vidé — §111)")
	}
}

func TestDetectRestartMeasuredBootAbsentNoWitness(t *testing.T) {
	regDir := t.TempDir()
	mbDir := t.TempDir()
	mbPath := filepath.Join(mbDir, "manifest.json") // n'existe pas
	isRestart, err := detectRestart(regDir, mbPath)
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
	if isRestart {
		t.Fatal("isRestart=true, veut false (ni cell_log.key ni manifeste measured boot n'existent)")
	}
}

// TestDetectRestartRefusesMeasuredBootManifestUnderRegDir : un manifeste
// measured boot configuré SOUS regDir serait effacé par le même
// effacement du registre qu'il est censé détecter — §111 exige un refus
// au démarrage plutôt qu'une protection silencieusement annulée.
func TestDetectRestartRefusesMeasuredBootManifestUnderRegDir(t *testing.T) {
	regDir := t.TempDir()
	mbPath := filepath.Join(regDir, "sub", "manifest.json")
	_, err := detectRestart(regDir, mbPath)
	if err == nil {
		t.Fatal("erreur attendue (manifeste measured boot sous regDir), obtenu nil")
	}
	if !strings.Contains(err.Error(), "SOUS TBP_REGISTRY_DIR") {
		t.Fatalf("erreur doit signaler l'imbrication sous regDir: %v", err)
	}
}

func TestDetectRestartRefusesMeasuredBootManifestEqualToRegDir(t *testing.T) {
	regDir := t.TempDir()
	_, err := detectRestart(regDir, regDir)
	if err == nil {
		t.Fatal("erreur attendue (manifeste measured boot == regDir), obtenu nil")
	}
}

func TestDetectRestartBothWitnessesPresent(t *testing.T) {
	regDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(regDir, "cell_log.key"), []byte("k"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	mbDir := t.TempDir()
	mbPath := filepath.Join(mbDir, "manifest.json")
	if err := os.WriteFile(mbPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	isRestart, err := detectRestart(regDir, mbPath)
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
	if !isRestart {
		t.Fatal("isRestart=false, veut true (les deux témoins présents)")
	}
}
