package arbiter

// arbiter_roles_test.go — le rôle d'arbitrage : présence et décision sur les demandes dégradées ne sont ouvertes qu'aux clés
// qui le tiennent. Une clé du trousseau sans ce rôle est refusée AVEC UN NOM (ErrRoleDenied), pas confondue avec un intrus.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// rolesHarness : le trousseau compte deux clés ; seule h.op tient le rôle d'arbitrage, « night » ne fait que révoquer des plans.
func rolesHarness(t *testing.T) (*harness, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("night"))
	night := ed25519.NewKeyFromSeed(seed[:])
	var op ed25519.PublicKey
	h := newHarness(t, func(o *Options) {
		op = o.OperatorKeys[0]
		o.OperatorKeys = []ed25519.PublicKey{op, night.Public().(ed25519.PublicKey)}
		o.ArbiterKeys = []ed25519.PublicKey{op}
	})
	return h, night
}

func TestPresenceRefusesAKeyWithoutTheArbiterRole(t *testing.T) {
	h, night := rolesHarness(t)
	now := h.clock()
	if err := h.beat(t, night, now); !errors.Is(err, ErrRoleDenied) {
		t.Fatalf("battement d'une clé sans le rôle d'arbitrage : %v", err)
	}
	if h.q.Reachable(context.Background()) {
		t.Fatal("joignable après un battement d'une clé sans le rôle")
	}
	// un intrus reste « signature invalide » : le refus nomme ce qui s'est passé
	if err := h.beat(t, h.other, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("intrus : %v", err)
	}
	// voisin autorisé
	if err := h.beat(t, h.op, now); err != nil {
		t.Fatalf("battement d'un arbitre : %v", err)
	}
}

func TestDecideRefusesAKeyWithoutTheArbiterRole(t *testing.T) {
	h, night := rolesHarness(t)
	ctx := context.Background()
	it := item("agent-1", `{"action":"read","resource":"r"}`)
	id := IntentID(it.SystemID, it.Payload)
	if err := h.q.Enqueue(ctx, it); err != nil {
		t.Fatal(err)
	}
	exp := h.clock().Add(5 * time.Minute)
	msg := h.msg(t, id, VerdictApprove, exp)
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, ed25519.Sign(night, msg)); !errors.Is(err, ErrRoleDenied) {
		t.Fatalf("décision d'une clé sans le rôle : %v", err)
	}
	// la demande est toujours en attente, voisin autorisé : un arbitre la tranche
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomePending {
		t.Fatalf("la demande n'est plus en attente : %v", out)
	}
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, ed25519.Sign(h.op, msg)); err != nil {
		t.Fatalf("décision d'un arbitre : %v", err)
	}
}

func TestArbiterRolesFailClosedAtConfiguration(t *testing.T) {
	var op ed25519.PublicKey
	h := newHarness(t, nil)
	op = h.op.Public().(ed25519.PublicKey)
	stranger := h.other.Public().(ed25519.PublicKey)
	for name, keys := range map[string][]ed25519.PublicKey{
		"rôle vide":       {},
		"arbitre inconnu": {op, stranger},
	} {
		if _, err := NewQueue(Options{
			CellID: "cell-a", Salt: make([]byte, 16), Leaves: h.leaves,
			OperatorKeys: []ed25519.PublicKey{op}, ArbiterKeys: keys,
		}); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
