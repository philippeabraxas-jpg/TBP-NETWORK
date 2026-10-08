package pep

// plan_approvals_test.go — issue #196 : approuver un plan de classe F ou W exige k signatures
// DISTINCTES d'opérateurs (1 pour la classe I). Chaque refus a son cas voisin accepté, et chaque test
// échoue si on retire la vérification qu'il couvre.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// opKey3 : un troisième opérateur (RFC 8032 §7.1, clé 1 — publique par construction).
func opKey3() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
}

// newQuorumStore : trousseau de trois opérateurs, k = 2 pour l'agent « agent-w » (classe W ou F),
// 1 pour tous les autres (classe I).
func newQuorumStore(t *testing.T, mut func(*ContractOptions)) (*ContractStore, *stubSink, *contractClock) {
	t.Helper()
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, func(o *ContractOptions) {
		o.OperatorKeys = []ed25519.PublicKey{
			opKey1().Public().(ed25519.PublicKey),
			opKey2().Public().(ed25519.PublicKey),
			opKey3().Public().(ed25519.PublicKey),
		}
		o.ApprovalsRequired = func(subject string) int {
			if subject == "agent-w" {
				return 2
			}
			return 1
		}
		if mut != nil {
			mut(o)
		}
	})
	return s, sink, clock
}

func submitFor(t *testing.T, s *ContractStore, subject string) [32]byte {
	t.Helper()
	h, err := s.Submit(context.Background(), subject, []PlanStep{stepOf("pay", "invoice-42", []byte("1200"))})
	if err != nil {
		t.Fatalf("Submit(%s): %v", subject, err)
	}
	return h
}

func TestPlanApprovalNeedsKDistinctOperators(t *testing.T) {
	ctx := context.Background()
	s, sink, clock := newQuorumStore(t, nil)
	h := submitFor(t, s, "agent-w")
	exp := clock.now().Add(30 * time.Minute)
	sig1 := signApproval(opKey1(), h, exp)
	sig2 := signApproval(opKey2(), h, exp)

	// k - 1 signatures : refusé, le plan reste en attente
	if err := s.ApproveAll(ctx, h, exp, [][]byte{sig1}); !errors.Is(err, ErrPlanApprovalQuorum) {
		t.Fatalf("1 signature sur 2 exigées : %v", err)
	}
	// le chemin à une signature (Approve) est refusé de la même façon
	if err := s.Approve(ctx, h, exp, sig1); !errors.Is(err, ErrPlanApprovalQuorum) {
		t.Fatalf("Approve à une signature sur un plan à k = 2 : %v", err)
	}
	if pend, _ := s.Snapshot(); len(pend) != 1 {
		t.Fatalf("le plan doit rester en attente après un refus : %d en attente", len(pend))
	}

	// k signatures dont deux de la même clé : refusé
	if err := s.ApproveAll(ctx, h, exp, [][]byte{sig1, sig1}); !errors.Is(err, ErrPlanApprovalDuplicateSigner) {
		t.Fatalf("deux fois la même clé : %v", err)
	}
	// ... même noyées parmi des signatures valides
	if err := s.ApproveAll(ctx, h, exp, [][]byte{sig1, sig2, sig1}); !errors.Is(err, ErrPlanApprovalDuplicateSigner) {
		t.Fatalf("doublon parmi des signatures valides : %v", err)
	}
	// une signature qui ne vérifie contre aucune clé refuse l'ensemble
	bad := signApproval(ed25519.NewKeyFromSeed(mustHex("0000000000000000000000000000000000000000000000000000000000000001")), h, exp)
	if err := s.ApproveAll(ctx, h, exp, [][]byte{sig1, bad}); !errors.Is(err, ErrPlanApprovalSignature) {
		t.Fatalf("signature d'un inconnu : %v", err)
	}
	// une signature d'un AUTRE plan ne compte pas
	other := signApproval(opKey2(), [32]byte{9}, exp)
	if err := s.ApproveAll(ctx, h, exp, [][]byte{sig1, other}); !errors.Is(err, ErrPlanApprovalSignature) {
		t.Fatalf("signature d'un autre plan : %v", err)
	}

	before := len(sink.leaves)
	// cas voisin : k = 2 clés distinctes ⇒ approuvé, une feuille attribuée par signataire
	if err := s.ApproveAll(ctx, h, exp, [][]byte{sig1, sig2}); err != nil {
		t.Fatalf("2 clés distinctes refusées : %v", err)
	}
	if got := len(sink.leaves) - before; got != 2 {
		t.Fatalf("une feuille par signataire attendue : %d écrites", got)
	}
	expectApprovalLeaf(t, sink.leaves[before], h, opKey1(), exp)
	expectApprovalLeaf(t, sink.leaves[before+1], h, opKey2(), exp)
	if pend, _ := s.Snapshot(); len(pend) != 0 {
		t.Fatal("le plan approuvé ne doit plus être en attente")
	}
}

func TestPlanApprovalClassIKeepsOneSignature(t *testing.T) {
	s, _, clock := newQuorumStore(t, nil)
	h := submitFor(t, s, "agent-i")
	exp := clock.now().Add(30 * time.Minute)
	if err := s.Approve(context.Background(), h, exp, signApproval(opKey1(), h, exp)); err != nil {
		t.Fatalf("une signature suffit pour la classe I : %v", err)
	}
}

func TestPlanApprovalMoreThanKIsAccepted(t *testing.T) {
	s, _, clock := newQuorumStore(t, nil)
	h := submitFor(t, s, "agent-w")
	exp := clock.now().Add(30 * time.Minute)
	sigs := [][]byte{signApproval(opKey1(), h, exp), signApproval(opKey2(), h, exp), signApproval(opKey3(), h, exp)}
	if err := s.ApproveAll(context.Background(), h, exp, sigs); err != nil {
		t.Fatalf("3 signatures distinctes pour k = 2 : %v", err)
	}
}

func TestPlanApprovalNoSignatureIsRefused(t *testing.T) {
	s, _, clock := newQuorumStore(t, nil)
	h := submitFor(t, s, "agent-i")
	exp := clock.now().Add(30 * time.Minute)
	if err := s.ApproveAll(context.Background(), h, exp, nil); !errors.Is(err, ErrPlanApprovalSignature) {
		t.Fatalf("aucune signature : %v", err)
	}
}

// Le k est SCELLÉ à la soumission : changer la fonction après coup ne baisse pas l'exigence d'un plan en attente.
func TestPlanApprovalRequirementIsSealedAtSubmission(t *testing.T) {
	required := 2
	s, _, clock := newQuorumStore(t, func(o *ContractOptions) {
		o.ApprovalsRequired = func(string) int { return required }
	})
	h := submitFor(t, s, "agent-w")
	required = 1 // la classe de l'agent est « abaissée » après la soumission
	exp := clock.now().Add(30 * time.Minute)
	if err := s.Approve(context.Background(), h, exp, signApproval(opKey1(), h, exp)); !errors.Is(err, ErrPlanApprovalQuorum) {
		t.Fatalf("l'exigence d'un plan déjà soumis a baissé : %v", err)
	}
}

// Un plan qu'aucun ensemble de signataires ne peut approuver n'est pas mis en attente.
func TestPlanSubmitRefusedWhenApprovalIsUnreachable(t *testing.T) {
	s, sink, _ := newQuorumStore(t, func(o *ContractOptions) {
		o.OperatorKeys = []ed25519.PublicKey{opKey1().Public().(ed25519.PublicKey)}
	})
	before := len(sink.leaves)
	if _, err := s.Submit(context.Background(), "agent-w", []PlanStep{stepOf("pay", "invoice-42", nil)}); !errors.Is(err, ErrPlanApprovalUnreachable) {
		t.Fatalf("2 approbations exigées pour 1 clé : %v", err)
	}
	if len(sink.leaves) != before+1 {
		t.Fatal("le refus doit laisser une feuille")
	}
	if pend, _ := s.Snapshot(); len(pend) != 0 {
		t.Fatal("un plan inapprouvable ne doit pas être en attente")
	}
	// cas voisin : un agent qui n'exige qu'une approbation passe
	if _, err := s.Submit(context.Background(), "agent-i", []PlanStep{stepOf("read", "doc-1", nil)}); err != nil {
		t.Fatalf("classe I avec un trousseau d'une clé : %v", err)
	}
}

// Un trousseau qui répète la même clé n'a qu'UNE clé distincte : il ne rend pas k = 2 atteignable.
func TestPlanApprovalDuplicateKeysInKeyringDoNotCount(t *testing.T) {
	s, _, _ := newQuorumStore(t, func(o *ContractOptions) {
		k := opKey1().Public().(ed25519.PublicKey)
		o.OperatorKeys = []ed25519.PublicKey{k, k}
	})
	if _, err := s.Submit(context.Background(), "agent-w", []PlanStep{stepOf("pay", "invoice-42", nil)}); !errors.Is(err, ErrPlanApprovalUnreachable) {
		t.Fatalf("une clé répétée deux fois compte comme un quorum : %v", err)
	}
}

// Par défaut (aucune fonction), une signature suffit : le comportement historique est inchangé.
func TestPlanApprovalDefaultIsOneSignature(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	s := newContractStore(t, sink, clock, &contractTrips{}, nil)
	h := submitFor(t, s, "agent-w")
	approveNominal(t, s, clock, h)
}
