package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func keyFile(t *testing.T, dir, name string, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = seedByte
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), p
}

func keyringOf(keys ...ed25519.PrivateKey) map[[16]byte]ed25519.PublicKey {
	kr := map[[16]byte]ed25519.PublicKey{}
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		kr[pep.KeyIDFromPublicKey(pub)] = pub
	}
	return kr
}

// La preuve produite par l'outil est acceptée par le VRAI vérificateur des démons —
// et refusée dès qu'on change la condition, la cellule ou le nombre de signataires.
func TestSignedProofIsAcceptedByTheDaemonsVerifier(t *testing.T) {
	dir := t.TempDir()
	k1, f1 := keyFile(t, dir, "k1", 1)
	k2, f2 := keyFile(t, dir, "k2", 2)
	out := filepath.Join(dir, "proof.json")
	const cond, cell = "provisioning-transition-brokerd", "cell-a"

	if err := cmdSign([]string{"-condition", cond, "-cell", cell, "-key", f1, "-key", f2, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions de la preuve = %v", st.Mode().Perm())
	}
	kr := keyringOf(k1, k2)
	if err := pep.VerifyQuorumProofFile(out, cond, cell, kr, 2); err != nil {
		t.Fatalf("preuve valide refusée : %v", err)
	}
	// cas voisins refusés
	if err := pep.VerifyQuorumProofFile(out, "mode-closed", cell, kr, 2); err == nil {
		t.Fatal("la preuve vaut pour une autre condition")
	}
	if err := pep.VerifyQuorumProofFile(out, cond, "cell-b", kr, 2); err == nil {
		t.Fatal("la preuve vaut pour une autre cellule")
	}
	if err := pep.VerifyQuorumProofFile(out, cond, cell, kr, 3); err == nil {
		t.Fatal("2 signatures suffisent pour k = 3")
	}
}

func TestScaleOneAdminAloneIsQuorumOfOne(t *testing.T) {
	dir := t.TempDir()
	admin, f := keyFile(t, dir, "admin", 9)
	out := filepath.Join(dir, "proof.json")
	if err := cmdSign([]string{"-condition", "provisioning-transition-pepd", "-cell", "cell-a", "-key", f, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(out, "provisioning-transition-pepd", "cell-a", keyringOf(admin), 1); err != nil {
		t.Fatalf("l'admin seul (k = 1) refusé : %v", err)
	}
}

func TestSameKeyTwiceIsNotTwoSigners(t *testing.T) {
	dir := t.TempDir()
	_, f := keyFile(t, dir, "k", 3)
	err := cmdSign([]string{"-condition", "c", "-cell", "x", "-key", f, "-key", f, "-out", filepath.Join(dir, "p.json")})
	if err == nil || !strings.Contains(err.Error(), "deux fois") {
		t.Fatalf("même clé comptée deux fois : %v", err)
	}
}

// Le flux HSM : on récupère le message, on signe AILLEURS, on assemble.
func TestMessageThenAssembleMatchesDirectSigning(t *testing.T) {
	dir := t.TempDir()
	k, _ := keyFile(t, dir, "k", 4)
	exp := time.Now().Add(120 * time.Second)
	msg := pep.QuorumMessage("mode-closed", "cell-a", exp)
	kid := pep.KeyIDFromPublicKey(k.Public().(ed25519.PublicKey))
	out := filepath.Join(dir, "proof.json")
	err := cmdAssemble([]string{"-expiry", strconv.FormatInt(exp.Unix(), 10), "-sig", hex.EncodeToString(kid[:]) + "=" + hex.EncodeToString(ed25519.Sign(k, msg)), "-out", out})
	if err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(out, "mode-closed", "cell-a", keyringOf(k), 1); err != nil {
		t.Fatalf("preuve assemblée refusée : %v", err)
	}
}

func TestBadInputsAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("aucune clé acceptée")
	}
	_, f := keyFile(t, dir, "k", 5)
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-ttl", "5", "-key", f, "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("ttl trop court accepté")
	}
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-ttl", "100000", "-key", f, "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("ttl trop long accepté")
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("zz"), 0o600)
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-key", bad, "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("clé illisible acceptée")
	}
	if err := cmdAssemble([]string{"-expiry", "12", "-sig", "nokid", "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("signature mal formée acceptée")
	}
}

// keygen produit une clé et un trousseau que le VRAI vérificateur accepte (k = 1),
// n'écrase jamais une clé existante, et complète un trousseau sans le réécrire à l'aveugle.
func TestKeygenBuildsAKeyringTheVerifierAccepts(t *testing.T) {
	dir := t.TempDir()
	keyPath, ringPath := filepath.Join(dir, "admin.key"), filepath.Join(dir, "quorum-keyring.json")
	sink, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()

	if err := cmdKeygen([]string{"-key", keyPath, "-keyring", ringPath}, sink); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions de la clé = %v", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(ringPath)
	var wire map[string]string
	if err := json.Unmarshal(raw, &wire); err != nil || len(wire) != 1 {
		t.Fatalf("trousseau = %s (%v)", raw, err)
	}
	kr := map[[16]byte]ed25519.PublicKey{}
	for kidHex, pubHex := range wire {
		kid, _ := hex.DecodeString(kidHex)
		pub, _ := hex.DecodeString(pubHex)
		var k [16]byte
		copy(k[:], kid)
		kr[k] = ed25519.PublicKey(pub)
	}
	proof := filepath.Join(dir, "proof.json")
	if err := cmdSign([]string{"-condition", "mode-closed", "-cell", "cell-a", "-key", keyPath, "-out", proof}); err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(proof, "mode-closed", "cell-a", kr, 1); err != nil {
		t.Fatalf("la clé générée n'ouvre pas le trousseau généré : %v", err)
	}

	// jamais d'écrasement d'une clé existante
	if err := cmdKeygen([]string{"-key", keyPath, "-keyring", ringPath}, sink); err == nil {
		t.Fatal("keygen a écrasé une clé existante")
	}
	// une seconde clé complète le trousseau (k-of-n pour les échelles supérieures)
	if err := cmdKeygen([]string{"-key", filepath.Join(dir, "admin2.key"), "-keyring", ringPath}, sink); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(ringPath)
	_ = json.Unmarshal(raw, &wire)
	if len(wire) != 2 {
		t.Fatalf("trousseau après 2 keygen = %d clé(s)", len(wire))
	}
	// un trousseau illisible n'est pas réécrit
	if err := os.WriteFile(ringPath, []byte("pas du json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdKeygen([]string{"-key", filepath.Join(dir, "admin3.key"), "-keyring", ringPath}, sink); err == nil {
		t.Fatal("trousseau corrompu réécrit à l'aveugle")
	}
	if got, _ := os.ReadFile(ringPath); string(got) != "pas du json" {
		t.Fatal("trousseau corrompu modifié")
	}
}
