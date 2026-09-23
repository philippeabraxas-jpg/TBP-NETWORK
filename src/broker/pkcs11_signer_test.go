package broker

// Revue de sécurité #90, point 5 : la promesse « la couture Signer est
// déjà HSM-ready » n'avait jamais été VÉRIFIÉE EN EXÉCUTION contre un
// module PKCS#11 réel — même discipline que le reste de cette revue
// (confirmer en exécution, pas seulement par lecture du code). Ce test
// provisionne une paire de clés Ed25519 dans un jeton SoftHSM2 EPHÉMÈRE
// (bibliothèque système /usr/lib/softhsm/libsofthsm2.so), signe avec
// PKCS11Signer, et vérifie la signature avec le paquet ed25519 standard —
// la preuve que la clé privée n'a jamais quitté le module et que le
// résultat est un Ed25519 RFC 8032 authentique, pas un artefact
// spécifique à ce fournisseur.
//
// Nécessite SoftHSM2 installé (/usr/lib/softhsm/libsofthsm2.so) — sauté
// proprement sinon (CI sans SoftHSM2), jamais un test qui passe pour de
// mauvaises raisons.

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

const softHSM2ModulePath = "/usr/lib/softhsm/libsofthsm2.so"

// provisionSoftHSM2Key initialise un jeton SoftHSM2 EPHÉMÈRE (répertoire
// temporaire, détruit à la fin du test) et y génère une paire de clés
// Ed25519 sous l'étiquette donnée. Rend (tokenLabel, keyLabel, userPIN).
func provisionSoftHSM2Key(t *testing.T, keyLabel string) (tokenLabel, pin string) {
	return provisionSoftHSM2KeyWithAttrs(t, keyLabel, true, false)
}

// provisionSoftHSM2KeyWithAttrs est provisionSoftHSM2Key avec CKA_SENSITIVE
// et CKA_EXTRACTABLE explicites — revue de sécurité #114 : exerce les
// clés MAL provisionnées (extractibles ou non sensibles) que
// requireNonExtractableKey doit refuser, pas seulement le cas nominal.
func provisionSoftHSM2KeyWithAttrs(t *testing.T, keyLabel string, sensitive, extractable bool) (tokenLabel, pin string) {
	t.Helper()
	if _, err := os.Stat(softHSM2ModulePath); err != nil {
		t.Skipf("SoftHSM2 absent (%s) — témoin HSM sauté", softHSM2ModulePath)
	}

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0o700); err != nil {
		t.Fatalf("mkdir tokens: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("softhsm2.conf: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	tokenLabel = "tbp-test-" + keyLabel
	soPIN, userPIN := "12345678", "87654321"

	module, err := p11.OpenModule(softHSM2ModulePath)
	if err != nil {
		t.Fatalf("OpenModule: %v", err)
	}
	// SoftHSM2 garde un état C_Initialize GLOBAL AU PROCESSUS (pas par
	// Module) — sans Destroy() explicite ici, le prochain test de ce
	// binaire qui pointe SOFTHSM2_CONF vers un AUTRE répertoire temporaire
	// hérite silencieusement de l'init précédente et échoue à
	// InitToken (CKR_GENERAL_ERROR), découvert en écrivant les témoins
	// négatifs de la revue #114 (deux provisionnements dans le même
	// process de test).
	t.Cleanup(module.Destroy)
	slots, err := module.Slots()
	if err != nil || len(slots) == 0 {
		t.Fatalf("Slots: %v (n=%d)", err, len(slots))
	}
	slot := slots[0]
	if err := slot.InitToken(soPIN, tokenLabel); err != nil {
		t.Fatalf("InitToken: %v", err)
	}

	soSession, err := slot.OpenWriteSession()
	if err != nil {
		t.Fatalf("OpenWriteSession (SO): %v", err)
	}
	if err := soSession.LoginSecurityOfficer(soPIN); err != nil {
		t.Fatalf("LoginSecurityOfficer: %v", err)
	}
	if err := soSession.InitPIN(userPIN); err != nil {
		t.Fatalf("InitPIN: %v", err)
	}
	if err := soSession.Logout(); err != nil {
		t.Fatalf("Logout SO: %v", err)
	}
	if err := soSession.Close(); err != nil {
		t.Fatalf("Close SO session: %v", err)
	}

	// Ré-énumère les slots : SoftHSM2 déplace le jeton initialisé vers un
	// nouveau slot après InitToken (comportement documenté).
	slots, err = module.Slots()
	if err != nil {
		t.Fatalf("Slots (post-init): %v", err)
	}
	var target *p11.Slot
	for i := range slots {
		info, err := slots[i].TokenInfo()
		if err == nil && info.Label == tokenLabel {
			s := slots[i]
			target = &s
			break
		}
	}
	if target == nil {
		t.Fatalf("jeton %q introuvable après InitToken", tokenLabel)
	}

	genSession, err := target.OpenWriteSession()
	if err != nil {
		t.Fatalf("OpenWriteSession (gen): %v", err)
	}
	defer func() { _ = genSession.Close() }()
	if err := genSession.Login(userPIN); err != nil {
		t.Fatalf("Login (gen): %v", err)
	}
	_, err = genSession.GenerateKeyPair(p11.GenerateKeyPairRequest{
		Mechanism: *pkcs11.NewMechanism(CkmEcEdwardsKeyPairGen, nil),
		PublicKeyAttributes: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CkkEcEdwards),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oidEd25519),
		},
		PrivateKeyAttributes: []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CkkEcEdwards),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, sensitive),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		},
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair (CKM_EC_EDWARDS_KEY_PAIR_GEN): %v", err)
	}
	return tokenLabel, userPIN
}

// TestPKCS11SignerSignsVerifiableEd25519 : preuve d'exécution — une clé
// Ed25519 provisionnée dans un jeton SoftHSM2 réel signe via PKCS11Signer,
// et la signature vérifie avec crypto/ed25519 (RFC 8032 pur, aucun artifact
// propriétaire). La clé privée n'a jamais existé en clair côté process Go.
func TestPKCS11SignerSignsVerifiableEd25519(t *testing.T) {
	keyLabel := "issuer-key-1"
	tokenLabel, pin := provisionSoftHSM2Key(t, keyLabel)

	signer, err := NewPKCS11Signer(PKCS11SignerOptions{
		ModulePath: softHSM2ModulePath,
		TokenLabel: tokenLabel,
		KeyLabel:   keyLabel,
		PIN:        pin,
	})
	if err != nil {
		t.Fatalf("NewPKCS11Signer: %v", err)
	}
	defer func() { _ = signer.Close() }()

	pub := signer.Public()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("clé publique de %d octets, veut %d", len(pub), ed25519.PublicKeySize)
	}

	msg := []byte("TBP §12 — preuve d'exécution PKCS#11 (revue #90 point 5)")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature de %d octets, veut %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature PKCS#11 invalide contre crypto/ed25519 — pas un Ed25519 RFC 8032 authentique")
	}

	// Témoin : un message altéré ne doit PAS vérifier (la primitive est
	// réellement liée au contenu, pas une signature constante rejouée).
	if ed25519.Verify(pub, append(append([]byte{}, msg...), 0x00), sig) {
		t.Fatal("signature vérifie sur un message altéré — témoin non-vacuole violé")
	}

	// Deux signatures du même message doivent être identiques (Ed25519
	// est déterministe, RFC 8032) — un second appel au module le confirme.
	sig2, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign (2e appel): %v", err)
	}
	if string(sig) != string(sig2) {
		t.Fatal("deux signatures Ed25519 du même message diffèrent — la primitive n'est pas RFC 8032 pure")
	}
}

// TestPKCS11SignerRefusesExtractableKey : preuve d'exécution — revue de
// sécurité #114. Une clé provisionnée CKA_EXTRACTABLE=true (exportable du
// jeton, contrairement à la custody HSM promise par §12) est refusée par
// NewPKCS11Signer AVANT toute signature, jamais silencieusement acceptée.
func TestPKCS11SignerRefusesExtractableKey(t *testing.T) {
	keyLabel := "issuer-key-extractable"
	tokenLabel, pin := provisionSoftHSM2KeyWithAttrs(t, keyLabel, true, true) // CKA_SENSITIVE=true, CKA_EXTRACTABLE=true

	_, err := NewPKCS11Signer(PKCS11SignerOptions{
		ModulePath: softHSM2ModulePath,
		TokenLabel: tokenLabel,
		KeyLabel:   keyLabel,
		PIN:        pin,
	})
	if err == nil {
		t.Fatal("clé CKA_EXTRACTABLE=true acceptée — #114 non détecté")
	}
	if !strings.Contains(err.Error(), "EXTRACTIBLE") {
		t.Fatalf("erreur=%v, veut mention de clé EXTRACTIBLE (§114)", err)
	}
}

// TestPKCS11SignerRefusesNonSensitiveKey : même preuve pour
// CKA_SENSITIVE=false — une clé dont la VALEUR peut être lue directement
// du jeton n'est pas non plus une custody HSM valide, même si elle n'est
// pas marquée extractible par ailleurs.
func TestPKCS11SignerRefusesNonSensitiveKey(t *testing.T) {
	keyLabel := "issuer-key-nonsensitive"
	tokenLabel, pin := provisionSoftHSM2KeyWithAttrs(t, keyLabel, false, false) // CKA_SENSITIVE=false, CKA_EXTRACTABLE=false

	_, err := NewPKCS11Signer(PKCS11SignerOptions{
		ModulePath: softHSM2ModulePath,
		TokenLabel: tokenLabel,
		KeyLabel:   keyLabel,
		PIN:        pin,
	})
	if err == nil {
		t.Fatal("clé CKA_SENSITIVE=false acceptée — #114 non détecté")
	}
	if !strings.Contains(err.Error(), "CKA_SENSITIVE") {
		t.Fatalf("erreur=%v, veut mention de CKA_SENSITIVE (§114)", err)
	}
}

// TestPKCS11SignerFailClosedConfig : configuration incomplète refusée dès
// la construction (§1) — jamais un signataire à moitié résolu.
func TestPKCS11SignerFailClosedConfig(t *testing.T) {
	if _, err := os.Stat(softHSM2ModulePath); err != nil {
		t.Skipf("SoftHSM2 absent (%s) — témoin HSM sauté", softHSM2ModulePath)
	}
	base := PKCS11SignerOptions{ModulePath: softHSM2ModulePath, TokenLabel: "x", KeyLabel: "y", PIN: "1234"}

	bad := base
	bad.ModulePath = ""
	if _, err := NewPKCS11Signer(bad); err == nil {
		t.Fatal("ModulePath vide accepté")
	}
	bad = base
	bad.TokenLabel = ""
	if _, err := NewPKCS11Signer(bad); err == nil {
		t.Fatal("TokenLabel vide accepté — résolution implicite de jeton interdite")
	}
	bad = base
	bad.KeyLabel = ""
	if _, err := NewPKCS11Signer(bad); err == nil {
		t.Fatal("KeyLabel vide accepté")
	}
	bad = base
	bad.PIN = ""
	if _, err := NewPKCS11Signer(bad); err == nil {
		t.Fatal("PIN vide accepté")
	}

	// Jeton inexistant : refusé, jamais un repli sur "le premier slot".
	if _, err := NewPKCS11Signer(base); err == nil {
		t.Fatal("jeton inexistant (TokenLabel=\"x\") accepté")
	}
}
