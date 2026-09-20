package pep

// plan_seal_test.go — tests du claim −8 « plan_seal » (schéma v2, §4.2, T30).
//
// Couverture :
//   - un jeton v2 portant −8 est accepté ; le sceau survit dans Token.PlanSeal
//     et est RECOPIÉ dans la feuille d'exécution (record « TBPD2 ») ;
//   - un jeton v2 sans −8 reste accepté (v2 = v1 + clé optionnelle) et produit
//     une feuille « TBPD1 » inchangée ;
//   - un −8 mal formé (mauvaise taille, mauvais type) = violation de schéma ;
//   - −8 en v1 est une violation de schéma (cas couvert par la batterie
//     TestFailClosedBattery — « v = 1 avec plan_seal »).
//
// Le vecteur doré §9 reste v1 et ne change JAMAIS (TestGoldenVectorT8).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/veraison/go-cose"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// mintPayload signe un payload brut (pour porter un −8 d'un type que
// testClaims ne sait pas exprimer — ex. un texte).
func mintPayload(t *testing.T, payload map[int]any) []byte {
	t.Helper()
	raw, err := testCanonicalEnc.Marshal(payload)
	if err != nil {
		t.Fatalf("payload cbor: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(testSeed)
	signer, err := cose.NewSigner(cose.AlgorithmEd25519, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = raw
	msg.Headers.Protected = map[any]any{int64(1): int64(-8), int64(4): testKID[:]}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wire
}

// claimsV2 retourne des claims nominaux en schéma v2.
func claimsV2() testClaims {
	c := nominalClaims()
	c.version = 2
	return c
}

// TestValidatorAcceptsV2PlanSeal : jeton v2 + −8 ⇒ allow, le sceau est exposé
// au PEP et recopié dans la feuille (critère « jeton opposable » de #31).
func TestValidatorAcceptsV2PlanSeal(t *testing.T) {
	sink := &stubSink{}
	v := newValidator(t, sink, &stubAntiReplay{}, nil)

	c := claimsV2()
	c.planSeal = sealOK
	d := v.Validate(context.Background(), mintToken(t, c), nominalRequest())
	if !d.Allow || d.Reason != ReasonOK {
		t.Fatalf("v2 + plan_seal refusé : %q", d.Reason)
	}
	if d.Token == nil || d.Token.PlanSeal == nil {
		t.Fatal("PlanSeal absent du jeton décodé")
	}
	if *d.Token.PlanSeal != arr32(sealOK) {
		t.Fatalf("PlanSeal=%x, veut %x", *d.Token.PlanSeal, sealOK)
	}

	// La feuille d'exécution porte le record « TBPD2 » :
	// "TBPD2" ‖ jti(16) ‖ verdict(1) ‖ u8 len(reason) ‖ reason ‖ planSeal(32).
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d", sink.count())
	}
	leaf := sink.leaves[0]
	if leaf.Kind != registry.KindDecision {
		t.Fatalf("kind=%v, veut KindDecision", leaf.Kind)
	}
	record := append([]byte("TBPD2"), testJTI[:]...)
	record = append(record, 0x01, byte(len("ok")))
	record = append(record, "ok"...)
	record = append(record, sealOK...)
	want := registry.HashPayload(testSalt, record)
	if leaf.PayloadHash != want {
		t.Fatalf("payloadHash=%x, veut %x (record TBPD2)", leaf.PayloadHash, want)
	}
	// Ni le jti ni le sceau ne fuient en clair dans la charge hashée (§6.2).
	h := strings.ToLower(hexOf(leaf.PayloadHash[:]))
	if strings.Contains(h, hexOf(testJTI[:])) || strings.Contains(h, hexOf(sealOK)) {
		t.Fatal("fuite de jti ou de sceau dans la feuille")
	}
}

// TestValidatorV2WithoutPlanSeal : v2 sans −8 ⇒ allow et feuille « TBPD1 »
// (le format v1 inchangé reste celui des exécutions hors contrat de plan).
func TestValidatorV2WithoutPlanSeal(t *testing.T) {
	sink := &stubSink{}
	v := newValidator(t, sink, &stubAntiReplay{}, nil)

	d := v.Validate(context.Background(), mintToken(t, claimsV2()), nominalRequest())
	if !d.Allow || d.Reason != ReasonOK {
		t.Fatalf("v2 sans plan_seal refusé : %q", d.Reason)
	}
	if d.Token == nil || d.Token.PlanSeal != nil {
		t.Fatal("PlanSeal devrait être nil")
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d", sink.count())
	}
	record := append([]byte("TBPD1"), testJTI[:]...)
	record = append(record, 0x01, byte(len("ok")))
	record = append(record, "ok"...)
	want := registry.HashPayload(testSalt, record)
	if sink.leaves[0].PayloadHash != want {
		t.Fatalf("v2 sans −8 doit produire une feuille TBPD1")
	}
}

// TestValidatorPlanSealMalformed : −8 présent mais mal formé (taille ≠ 32,
// type non-bstr) ⇒ violation de schéma, même en v2. Chaque refus laisse sa
// feuille (§4.1).
func TestValidatorPlanSealMalformed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*testClaims)
	}{
		{"sceau de 31 octets", func(c *testClaims) { c.planSeal = sealOK[:31] }},
		{"sceau de 33 octets", func(c *testClaims) { c.planSeal = append(append([]byte{}, sealOK...), 0x00) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &stubSink{}
			v := newValidator(t, sink, &stubAntiReplay{}, nil)
			c := claimsV2()
			tc.mut(&c)
			d := v.Validate(context.Background(), mintToken(t, c), nominalRequest())
			if d.Allow || d.Reason != ReasonSchemaViolation {
				t.Fatalf("−8 mal formé : reason=%q, veut schema-violation", d.Reason)
			}
			if !d.LeafWritten || sink.count() != 1 {
				t.Fatalf("refus sans feuille : written=%v feuilles=%d", d.LeafWritten, sink.count())
			}
		})
	}

	// Type non-bstr : un texte à la place du sceau.
	sink := &stubSink{}
	v := newValidator(t, sink, &stubAntiReplay{}, nil)
	payload := claimsPayload(claimsV2())
	payload[-8] = "pas-un-sceau"
	d := v.Validate(context.Background(), mintPayload(t, payload), nominalRequest())
	if d.Allow || d.Reason != ReasonSchemaViolation {
		t.Fatalf("−8 textuel : reason=%q, veut schema-violation", d.Reason)
	}
}
