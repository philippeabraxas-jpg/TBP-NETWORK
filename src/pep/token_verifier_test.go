package pep

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func testVerifierKeyring() map[[16]byte]ed25519.PublicKey {
	return map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)}
}

func TestPossessionVerifierAuthenticAndFresh(t *testing.T) {
	now := time.Unix(testIAT+30, 0)
	pv, err := NewPossessionVerifier(testVerifierKeyring(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	wire := mintToken(t, nominalClaims())
	tok, err := pv.Verify(wire)
	if err != nil {
		t.Fatalf("jeton authentique refusé: %v", err)
	}
	if tok.JTI != testJTI {
		t.Fatalf("jti = %x", tok.JTI)
	}
	if err := pv.Fresh(tok); err != nil {
		t.Fatalf("jeton frais refusé: %v", err)
	}
	// après exp : authentique mais plus frais (la décision d'ouvrir un échange
	// est à l'appelant)
	now = time.Unix(testEXP+1, 0)
	if err := pv.Fresh(tok); err == nil {
		t.Fatal("un jeton expiré ne doit pas être frais")
	}
	if _, err := pv.Verify(wire); err != nil {
		t.Fatalf("Verify ne juge pas la fraîcheur: %v", err)
	}
}

func TestPossessionVerifierRejectsForgeries(t *testing.T) {
	pv, err := NewPossessionVerifier(testVerifierKeyring(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := mintToken(t, nominalClaims())
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := pv.Verify(tampered); err == nil {
		t.Fatal("signature altérée acceptée")
	}
	if _, err := pv.Verify([]byte("pas un jeton")); err == nil {
		t.Fatal("charge quelconque acceptée")
	}
	// clé inconnue : trousseau épinglé différent
	other := map[[16]byte]ed25519.PublicKey{{1}: ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)}
	pv2, err := NewPossessionVerifier(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pv2.Verify(wire); err == nil {
		t.Fatal("jeton signé par une clé hors trousseau accepté")
	}
	if err := pv.Fresh(nil); err == nil {
		t.Fatal("Fresh(nil) doit refuser")
	}
}

func TestPossessionVerifierRequiresKeyring(t *testing.T) {
	if _, err := NewPossessionVerifier(nil, nil); err == nil {
		t.Fatal("trousseau vide accepté")
	}
}
