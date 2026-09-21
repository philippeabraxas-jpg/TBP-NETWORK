// mint.go — T35 (issue #61) : menthe de jetons de test pour la phase mono.
// Réplique du format COSE_Sign1 / CBOR canonique attendu par le validateur
// T9 (mêmes claims, mêmes clés entières, même protected header
// {1: -8 (Ed25519), 4: kid}) — §12 : Ed25519 partout. Même motif que
// tests/p2_redteam/runner/mint.go (T28) — répliqué, non importé
// (package main).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// claims de test : même layout que src/pep/validator_test.go (schéma
// src/pep/token/schema.cddl). Les clés négatives sont les claims TBP :
// −1 policyID, −2 action, −3 resource, −4 classe, −6 époque, −9 version.
type mintClaims struct {
	iss      string
	sub      string
	exp      int64
	iat      int64
	jti      []byte
	policyID []byte
	action   string
	resource string
	class    int
	epoch    int
	version  int
	kid      []byte
}

var mintCanonicalEnc, _ = cbor.CanonicalEncOptions().EncMode()

// mintToken produit un jeton COSE_Sign1 signé Ed25519 (§12). Le kid doit
// correspondre au trousseau du validateur, la policy à son PolicyID épinglé.
func mintToken(priv ed25519.PrivateKey, c mintClaims) ([]byte, error) {
	payload, err := mintCanonicalEnc.Marshal(map[int]any{
		1:  c.iss,
		2:  c.sub,
		4:  c.exp,
		6:  c.iat,
		7:  c.jti,
		-1: c.policyID,
		-2: c.action,
		-3: c.resource,
		-4: c.class,
		-6: c.epoch,
		-9: c.version,
	})
	if err != nil {
		return nil, fmt.Errorf("payload cbor: %w", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmEd25519, priv)
	if err != nil {
		return nil, fmt.Errorf("signer: %w", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected = map[any]any{int64(1): int64(-8), int64(4): c.kid}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return wire, nil
}
