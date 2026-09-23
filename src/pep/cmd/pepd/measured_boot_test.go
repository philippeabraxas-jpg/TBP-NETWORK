package main

// Revue de sécurité #96 : registry.CheckBoot existait depuis T31 (issue
// #32) mais aucun démon ne l'appelait jamais — ces tests prouvent que
// pepd l'appelle RÉELLEMENT (genèse au premier démarrage, refus sur
// divergence, transition sur quorum vérifié), pas seulement que le code
// compile.
//
// Revue de sécurité post-#86 (issue #112) : measured boot est désormais
// ACTIF PAR DÉFAUT (refus de démarrer sans lui, sauf opt-out dev EXPLICITE)
// et sa ré-engagement de référence exige une preuve de quorum
// cryptographique — ces deux défauts sont couverts par les tests ajoutés
// ici, en plus des tests §96 déjà présents.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
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

	quorumKeyring map[[16]byte]ed25519.PublicKey
	quorumPrivs   map[[16]byte]ed25519.PrivateKey
	quorumMin     int
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

	// Trousseau de contrôleurs (même patron que /v1/mode, §89/§112) —
	// deux contrôleurs, k=2.
	quorumKeyring := map[[16]byte]ed25519.PublicKey{}
	quorumPrivs := map[[16]byte]ed25519.PrivateKey{}
	for i := 1; i <= 2; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		var kid [16]byte
		kid[0] = byte(i)
		quorumKeyring[kid] = pub
		quorumPrivs[kid] = priv
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
		quorumKeyring:  quorumKeyring, quorumPrivs: quorumPrivs, quorumMin: 2,
	}
}

// writeTransitionProof signe une preuve de quorum de transition measured
// boot (k=2, deux contrôleurs distincts) et pointe
// TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE dessus. wrongKey=true signe avec
// une clé HORS du trousseau (imposteur) ; kOnly=1 ne fournit qu'une seule
// signature (quorum insuffisant).
func (fx *measuredBootFixture) writeTransitionProof(t *testing.T, nSigs int, wrongKey bool, expiry time.Time) string {
	t.Helper()
	msg := pep.QuorumMessage(reasonMeasuredBootTransition, fx.cellID, expiry)
	var sigs []measuredBootTransitionSigWire
	i := 0
	for kid, priv := range fx.quorumPrivs {
		if i >= nSigs {
			break
		}
		signKey, signKid := priv, kid
		if wrongKey {
			_, wp, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signKey = wp
		}
		sig := ed25519.Sign(signKey, msg)
		sigs = append(sigs, measuredBootTransitionSigWire{
			KeyID:     hex.EncodeToString(signKid[:]),
			Signature: hex.EncodeToString(sig),
		})
		i++
	}
	pf := measuredBootTransitionProofFile{Expiry: expiry.Unix(), Signatures: sigs}
	data, err := json.Marshal(pf)
	if err != nil {
		t.Fatalf("marshal preuve: %v", err)
	}
	path := filepath.Join(t.TempDir(), "transition-proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("écriture preuve: %v", err)
	}
	fx.env["TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE"] = path
	return path
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
	return setupMeasuredBoot(fx.ctx, fx.cellID, fx.salt, signer, verifier, fx.cellLog, fx.quorumKeyring, fx.quorumMin, fx.getenv)
}

// TestSetupMeasuredBootRequiredByDefault : revue #112 — measured boot est
// désormais ACTIF par défaut. Sans TBP_MEASURED_BOOT_MANIFEST_FILE ET sans
// l'opt-out dev explicite, le démarrage est refusé (avant #112, ce même
// scénario démarrait silencieusement sans AUCUNE protection).
func TestSetupMeasuredBootRequiredByDefault(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	fx.env["TBP_MEASURED_BOOT_MANIFEST_FILE"] = ""
	if err := fx.run(t); err == nil {
		t.Fatal("measured boot absent accepté sans opt-out dev explicite — #112 non fermé")
	}
	if _, err := os.Stat(fx.manifest); !os.IsNotExist(err) {
		t.Fatalf("manifeste écrit alors que le démarrage aurait dû être refusé")
	}
}

// TestSetupMeasuredBootDevUnsafeOptOut : l'opt-out EXPLICITE
// (TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1) reste possible — dev/lab
// uniquement, jamais silencieux (même doctrine que
// TBP_OPA_DISABLED_DEV_UNSAFE, #92).
func TestSetupMeasuredBootDevUnsafeOptOut(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	fx.env["TBP_MEASURED_BOOT_MANIFEST_FILE"] = ""
	fx.env["TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE"] = "1"
	if err := fx.run(t); err != nil {
		t.Fatalf("opt-out dev explicite refusé: %v", err)
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
	// altération accidentelle) — pas de preuve de transition.
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

// TestSetupMeasuredBootTransitionRequiresQuorumProof : revue #112 — un
// changement de composant DÉCLARÉ sans preuve de quorum reste refusé
// (l'ancien TBP_MEASURED_BOOT_TRANSITION=1, un simple drapeau, ne suffit
// plus).
func TestSetupMeasuredBootTransitionRequiresQuorumProof(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	if err := fx.run(t); err != nil {
		t.Fatalf("genèse refusée: %v", err)
	}
	if err := os.WriteFile(fx.componentPaths[0], []byte("nouveau bundle, sans preuve"), 0o600); err != nil {
		t.Fatalf("mise à jour: %v", err)
	}
	if err := fx.run(t); err == nil {
		t.Fatal("mise à jour non déclarée admise")
	}
}

// TestSetupMeasuredBootTransitionInvalidProofRefused : preuve de quorum
// INSUFFISANTE (une seule signature, k=2 exigé) ou signée par une clé HORS
// trousseau (imposteur) — refusée, jamais un demi-quorum accepté.
func TestSetupMeasuredBootTransitionInvalidProofRefused(t *testing.T) {
	cases := []struct {
		name      string
		nSigs     int
		wrongKey  bool
		expiryAgo time.Duration
	}{
		{"une seule signature (k=2 exigé)", 1, false, 0},
		{"signée par une clé hors trousseau", 2, true, 0},
		{"preuve déjà expirée", 2, false, -1 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newMeasuredBootFixture(t)
			if err := fx.run(t); err != nil {
				t.Fatalf("genèse refusée: %v", err)
			}
			if err := os.WriteFile(fx.componentPaths[0], []byte("nouveau bundle, preuve invalide"), 0o600); err != nil {
				t.Fatalf("mise à jour: %v", err)
			}
			expiry := time.Now().Add(time.Minute + tc.expiryAgo)
			fx.writeTransitionProof(t, tc.nSigs, tc.wrongKey, expiry)
			if err := fx.run(t); err == nil {
				t.Fatalf("%s: preuve invalide acceptée — #112 non fermé", tc.name)
			}
		})
	}
}

// TestSetupMeasuredBootTransitionValidProofReEngagesReference : une preuve
// de quorum VALIDE (k=2 signatures distinctes du trousseau épinglé)
// ré-engage une nouvelle référence — le démarrage suivant, non déclaré,
// admet le nouvel état.
func TestSetupMeasuredBootTransitionValidProofReEngagesReference(t *testing.T) {
	fx := newMeasuredBootFixture(t)
	if err := fx.run(t); err != nil {
		t.Fatalf("genèse refusée: %v", err)
	}

	if err := os.WriteFile(fx.componentPaths[0], []byte("nouveau bundle de règles, mise à jour légitime"), 0o600); err != nil {
		t.Fatalf("mise à jour: %v", err)
	}

	// Sans preuve : refusé (même test que la divergence).
	if err := fx.run(t); err == nil {
		t.Fatal("mise à jour non déclarée admise")
	}

	// Avec preuve de quorum valide : admis, nouvelle référence engagée.
	fx.writeTransitionProof(t, 2, false, time.Now().Add(time.Minute))
	if err := fx.run(t); err != nil {
		t.Fatalf("transition à quorum valide refusée: %v", err)
	}
	delete(fx.env, "TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE")

	// Démarrage suivant, état désormais stable : admis.
	if err := fx.run(t); err != nil {
		t.Fatalf("CheckBoot refusé après ré-engagement de la référence: %v", err)
	}
}
