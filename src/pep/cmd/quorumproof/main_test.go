package main

import (
	"crypto/ed25519"
	"encoding/hex"
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
