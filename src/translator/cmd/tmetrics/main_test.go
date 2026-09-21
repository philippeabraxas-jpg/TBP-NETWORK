// main_test.go — T26 (issue #22) : non-vacuité du CLI tmetrics (§4.5).
// Fail-closed à la configuration, inscription réelle au registre tessera,
// clés JAMAIS générées ici.
package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

const testReportJSON = `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",` +
	`"classes":[{"class":"F","positives":1000,"negatives":500,"false_negatives":0,"false_positives":3}]}`

// writeReport dépose un rapport measure.py factice mais bien formé.
func writeReport(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("rapport: %v", err)
	}
	return path
}

// initRegistry crée l'identité du registre comme pepd le ferait (clé
// privée 0600 + clé publique) — tmetrics l'EXIGE, il ne la crée pas.
func initRegistry(t *testing.T, dir string) {
	t.Helper()
	skey, vkey, err := registry.GenerateCellKey("cell-t26")
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	if err := registry.SaveSignerKey(dir, skey); err != nil {
		t.Fatalf("SaveSignerKey: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cell_log.vkey"), []byte(vkey), 0o644); err != nil {
		t.Fatalf("vkey: %v", err)
	}
}

func TestRunFailClosedEnv(t *testing.T) {
	dir := t.TempDir()
	report := writeReport(t, dir, testReportJSON)
	t.Setenv("TBP_CELL_ID", "")
	t.Setenv("TBP_SALT", "")
	t.Setenv("TBP_REGISTRY_DIR", "")

	if err := run([]string{}); err == nil {
		t.Fatal("sans --report : accepté")
	}
	if err := run([]string{"--report", report}); err == nil {
		t.Fatal("sans TBP_CELL_ID : accepté")
	}
	t.Setenv("TBP_CELL_ID", "cell-t26")
	if err := run([]string{"--report", report}); err == nil {
		t.Fatal("sans TBP_SALT : accepté")
	}
	t.Setenv("TBP_SALT", "zz") // non hex
	if err := run([]string{"--report", report}); err == nil {
		t.Fatal("TBP_SALT non hexadécimal : accepté")
	}
	t.Setenv("TBP_SALT", hex.EncodeToString([]byte("court")))
	if err := run([]string{"--report", report}); err == nil {
		t.Fatal("TBP_SALT < 16 octets : accepté")
	}
	t.Setenv("TBP_SALT", strings.Repeat("ab", 16))
	if err := run([]string{"--report", report}); err == nil {
		t.Fatal("sans TBP_REGISTRY_DIR : accepté")
	}
}

// Le registre sans identité (pas de cell_log.key) est REFUSÉ : tmetrics ne
// forge jamais une identité fraîche — ce serait une fourche silencieuse.
func TestRunRefusesKeylessRegistry(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatal(err)
	}
	report := writeReport(t, dir, testReportJSON)
	t.Setenv("TBP_CELL_ID", "cell-t26")
	t.Setenv("TBP_SALT", strings.Repeat("ab", 16))
	t.Setenv("TBP_REGISTRY_DIR", regDir)
	err := run([]string{"--report", report})
	if err == nil {
		t.Fatal("registre sans clés accepté — identité forgée en silence")
	}
	if !strings.Contains(err.Error(), "cell_log.key") {
		t.Fatalf("erreur inattendue : %v", err)
	}
}

func TestRunRefusesBadReport(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatal(err)
	}
	initRegistry(t, regDir)
	t.Setenv("TBP_CELL_ID", "cell-t26")
	t.Setenv("TBP_SALT", strings.Repeat("ab", 16))
	t.Setenv("TBP_REGISTRY_DIR", regDir)

	bad := writeReport(t, dir, `{"version":2,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[]}`)
	if err := run([]string{"--report", bad}); err == nil {
		t.Fatal("rapport version inconnue accepté")
	}
	inconsistent := writeReport(t, dir, `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",`+
		`"classes":[{"class":"F","positives":1,"negatives":1,"false_negatives":2,"false_positives":0}]}`)
	if err := run([]string{"--report", inconsistent}); err == nil {
		t.Fatal("rapport incohérent (FN > positifs) accepté")
	}
}

// Inscription RÉELLE : la feuille ressort par scan vérifié (ChainWatcher
// T34) avec le hash exact du record TBTM1.
func TestRunAppendsToRealRegistry(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatal(err)
	}
	initRegistry(t, regDir)
	salt := []byte(strings.Repeat("ab", 16)[:16]) // 16 octets effectifs
	saltHex := hex.EncodeToString(salt)
	report := writeReport(t, dir, testReportJSON)
	t.Setenv("TBP_CELL_ID", "cell-t26")
	t.Setenv("TBP_SALT", saltHex)
	t.Setenv("TBP_REGISTRY_DIR", regDir)

	if err := run([]string{"--report", report}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Scan vérifié (checkpoint signé + Merkle) — jamais une lecture naïve.
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		t.Fatalf("vkey: %v", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	ctx := context.Background()
	boot, w, err := supervision.NewChainWatcher(ctx, "cell-t26", regDir, "cell-t26", verifier, 0)
	if err != nil {
		t.Fatalf("watcher: %v", err)
	}
	more, err := w.Tick(ctx)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	leaves := append(boot, more...)
	if len(leaves) != 1 {
		t.Fatalf("%d feuilles au registre, attendu 1", len(leaves))
	}
	if leaves[0].Kind != registry.KindTelemetry {
		t.Fatalf("kind %d, attendu KindTelemetry", leaves[0].Kind)
	}
	// L'engagement correspond à UN record TBTM1 valide pour ce sel : la
	// preuve de format détaillée est dans metrics_test.go ; ici on vérifie
	// que la feuille n'est pas vide et que son hash se re-vérifie avec le
	// même sel + un corpus_hash du rapport (préfixe du record).
	if leaves[0].PayloadHash == [32]byte{} {
		t.Fatal("feuille à hash nul — engagement vide")
	}
	corpusHash, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	record := append([]byte("TBTM1"), corpusHash...)
	record = append(record, 1) // 1 classe
	record = append(record, 1, 'F')
	record = append(record, 0, 0, 3, 232) // pos=1000
	record = append(record, 0, 0, 1, 244) // neg=500
	record = append(record, 0, 0, 0, 0)   // fn=0
	record = append(record, 0, 0, 0, 3)   // fp=3
	if want := registry.HashPayload(salt, record); leaves[0].PayloadHash != want {
		t.Fatalf("hash feuille %x, attendu %x (record TBTM1 reconstruit à la main)",
			leaves[0].PayloadHash, want)
	}
}
