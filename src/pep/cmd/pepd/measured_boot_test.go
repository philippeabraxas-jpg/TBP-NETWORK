package main

// Revue de sécurité #96 : registry.CheckBoot existait depuis T31 (issue
// #32) mais aucun démon ne l'appelait jamais — ces tests prouvent que
// pepd l'appelle RÉELLEMENT (genèse au premier démarrage, refus sur
// divergence, transition sur déclaration explicite), pas seulement que le
// code compile.

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type measuredBootFixture struct {
	ctx            context.Context
	cellLog        *registry.CellLog
	cellID         string
	regDir         string
	salt           []byte
	manifest       string
	rootFile       string
	env            map[string]string
	getenv         func(string) string
	componentPaths []string
}

func newMeasuredBootFixture(t *testing.T) *measuredBootFixture {
	t.Helper()
	dir := t.TempDir()
	cellID := "cell-measured-boot"
	regDir := filepath.Join(dir, "registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatalf("registry dir: %v", err)
	}
	signer, vkey, err := loadOrGenerateCellKey(regDir, cellID)
	if err != nil {
		t.Fatalf("loadOrGenerateCellKey: %v", err)
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()
	cellLog, err := registry.Open(ctx, registry.Options{Dir: regDir, Signer: signer, Verifier: verifier})
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() { _ = cellLog.Close(context.Background()) })

	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	// Quatre composants + fichier de racine, contenu initial connu.
	componentPaths := make([]string, 4)
	names := []string{"policy.bundle", "opa.yaml", "brokerd.bin", "ai.container"}
	for i, name := range names {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("contenu initial de "+name), 0o600); err != nil {
			t.Fatalf("écriture %s: %v", name, err)
		}
		componentPaths[i] = p
	}
	rootFile := filepath.Join(dir, "root.hex")
	rootHash := make([]byte, 32)
	for i := range rootHash {
		rootHash[i] = 0xAB
	}
	rootHex := hex.EncodeToString(rootHash)
	if err := os.WriteFile(rootFile, []byte(rootHex), 0o600); err != nil {
		t.Fatalf("root file: %v", err)
	}

	manifest := filepath.Join(dir, "manifest.json")
	env := map[string]string{
		"TBP_MEASURED_BOOT_MANIFEST_FILE": manifest,
		"TBP_MEASURED_BOOT_ROOT_FILE":     rootFile,
		"TBP_MEASURED_BOOT_EXPECTED_ROOT": rootHex,
		"TBP_MEASURED_BOOT_POLICY_BUNDLE": componentPaths[0],
		"TBP_MEASURED_BOOT_OPA_CONFIG":    componentPaths[1],
		"TBP_MEASURED_BOOT_BROKER_BINARY": componentPaths[2],
		"TBP_MEASURED_BOOT_AI_CONTAINER":  componentPaths[3],
	}
	return &measuredBootFixture{
		ctx: ctx, cellLog: cellLog, cellID: cellID, regDir: regDir, salt: salt,
		manifest: manifest, rootFile: rootFile, env: env,
		getenv:         func(k string) string { return env[k] },
		componentPaths: componentPaths,
	}
}

// run simule un démarrage : recharge la clé de cellule depuis le disque
// (même geste qu'un vrai redémarrage de process) et appelle
// setupMeasuredBoot.
func (fx *measuredBootFixture) run(t *testing.T) error {
	t.Helper()
	signer, err := registry.LoadSigner(fx.regDir)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	vkeyB, err := os.ReadFile(filepath.Join(fx.regDir, "cell_log.vkey"))
	if err != nil {
		t.Fatalf("vkey: %v", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return setupMeasuredBoot(fx.ctx, fx.cellID, fx.salt, signer, verifier, fx.cellLog, fx.getenv)
}

func TestSetupMeasuredBootDisabledByDefault(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	fx.env["TBP_MEASURED_BOOT_MANIFEST_FILE"] = ""
	if err := fx.run(t); err != nil {
		t.Fatalf("measured boot désactivé refusé: %v", err)
	}
	if _, err := os.Stat(fx.manifest); !os.IsNotExist(err) {
		t.Fatalf("manifeste écrit alors que measured boot est désactivé")
	}
}

func TestSetupMeasuredBootMissingRequiredVar(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	delete(fx.env, "TBP_MEASURED_BOOT_EXPECTED_ROOT")
	if err := fx.run(t); err == nil {
		t.Fatal("configuration incomplète acceptée (manifest file présent, expected_root absent)")
	}
}

// TestSetupMeasuredBootGenesisThenCheck : premier démarrage = genèse
// (manifeste écrit) ; second démarrage, état inchangé = CheckBoot admet.
func TestSetupMeasuredBootGenesisThenCheck(t *testing.T) {
	fx := newMeasuredBootFixture(t)

	if err := fx.run(t); err != nil {
		t.Fatalf("genèse refusée: %v", err)
	}
	if _, err := os.Stat(fx.manifest); err != nil {
		t.Fatalf("manifeste non écrit après genèse: %v", err)
	}

	if err := fx.run(t); err != nil {
		t.Fatalf("CheckBoot refusé sur état inchangé: %v", err)
	}
}

// TestSetupMeasuredBootDivergenceRefuses : revue #96 — c'est LE test qui
// prouve que measured boot protège réellement quelque chose : un
// composant modifié après la genèse fait refuser le démarrage suivant.
func TestSetupMeasuredBootDivergenceRefuses(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	if err := fx.run(t); err != nil {
		t.Fatalf("genèse refusée: %v", err)
	}

	// Le binaire broker déployé change SANS déclaration (attaque ou
	// altération accidentelle) — pas de TBP_MEASURED_BOOT_TRANSITION.
	if err := os.WriteFile(fx.componentPaths[2], []byte("binaire altéré"), 0o600); err != nil {
		t.Fatalf("altération: %v", err)
	}

	err := fx.run(t)
	if err == nil {
		t.Fatal("démarrage admis malgré un composant modifié — measured boot ne protège rien")
	}
}

// TestSetupMeasuredBootRootDivergenceRefuses : racine mesurée ≠ racine
// attendue — refusé, même si les composants n'ont pas bougé.
func TestSetupMeasuredBootRootDivergenceRefuses(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	if err := fx.run(t); err != nil {
		t.Fatalf("genèse refusée: %v", err)
	}

	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xCD
	}
	if err := os.WriteFile(fx.rootFile, []byte(hex.EncodeToString(other)), 0o600); err != nil {
		t.Fatalf("root file: %v", err)
	}

	if err := fx.run(t); err == nil {
		t.Fatal("démarrage admis malgré une racine mesurée différente de la référence")
	}
}

// TestSetupMeasuredBootTransitionReEngagesReference : un changement de
// composant DÉCLARÉ (TBP_MEASURED_BOOT_TRANSITION=1) ré-engage une
// nouvelle référence — le démarrage suivant, non déclaré, admet le
// nouvel état.
func TestSetupMeasuredBootTransitionReEngagesReference(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	if err := fx.run(t); err != nil {
		t.Fatalf("genèse refusée: %v", err)
	}

	if err := os.WriteFile(fx.componentPaths[0], []byte("nouveau bundle de règles, mise à jour légitime"), 0o600); err != nil {
		t.Fatalf("mise à jour: %v", err)
	}

	// Sans déclaration : refusé (même test que la divergence).
	if err := fx.run(t); err == nil {
		t.Fatal("mise à jour non déclarée admise")
	}

	// Avec déclaration explicite : admis, nouvelle référence engagée.
	fx.env["TBP_MEASURED_BOOT_TRANSITION"] = "1"
	if err := fx.run(t); err != nil {
		t.Fatalf("transition déclarée refusée: %v", err)
	}
	delete(fx.env, "TBP_MEASURED_BOOT_TRANSITION")

	// Démarrage suivant, état désormais stable : admis.
	if err := fx.run(t); err != nil {
		t.Fatalf("CheckBoot refusé après ré-engagement de la référence: %v", err)
	}
}
