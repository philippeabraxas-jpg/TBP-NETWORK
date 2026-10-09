package pep

// plan_roles_test.go — les rôles du trousseau d'opérateurs : approuver un plan, le révoquer. Approuver ÉLARGIT ce que la
// cellule autorise, révoquer RESTREINT : une clé peut tenir le droit de couper sans tenir celui d'approuver. Chaque refus
// a son cas voisin accepté, et chaque test échoue si on retire la vérification qu'il couvre.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// newRoleStore : trois clés au trousseau ; key1 et key2 approuvent, key3 (l'astreinte de nuit) ne fait que révoquer.
func newRoleStore(t *testing.T, mut func(*ContractOptions)) (*ContractStore, *stubSink, *contractClock) {
	t.Helper()
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	return newQuorumStore(t, func(o *ContractOptions) {
		o.ApproverKeys = []ed25519.PublicKey{pub(opKey1()), pub(opKey2())}
		o.RevokerKeys = []ed25519.PublicKey{pub(opKey3())}
		if mut != nil {
			mut(o)
		}
	})
}

func TestPlanApprovalRefusesAKeyWithoutTheApproverRole(t *testing.T) {
	ctx := context.Background()
	s, sink, clock := newRoleStore(t, nil)
	h := submitFor(t, s, "agent-i") // k = 1
	exp := clock.now().Add(30 * time.Minute)

	before := len(contractLeaves(sink))
	if err := s.ApproveAll(ctx, h, exp, [][]byte{signApproval(opKey3(), h, exp)}); !errors.Is(err, ErrPlanApprovalRole) {
		t.Fatalf("approbation par une clé qui ne fait que révoquer : %v", err)
	}
	leaves := contractLeaves(sink)
	if len(leaves) != before+1 {
		t.Fatal("un refus de rôle est un événement de sécurité : il laisse une feuille")
	}
	expectLeafHash(t, leaves[len(leaves)-1], planEventApprove, h, planStepNA, 0, "plan-approval-role-denied")
	if pend, _ := s.Snapshot(); len(pend) != 1 {
		t.Fatal("le plan doit rester en attente après un refus de rôle")
	}

	// une clé inconnue reste « signature invalide », pas « rôle » : le refus nomme ce qui s'est passé
	stranger := ed25519.NewKeyFromSeed(bytesOf(0x42, 32))
	if err := s.ApproveAll(ctx, h, exp, [][]byte{signApproval(stranger, h, exp)}); !errors.Is(err, ErrPlanApprovalSignature) {
		t.Fatalf("clé inconnue : %v", err)
	}

	// voisin autorisé : une clé qui tient le rôle approuve
	if err := s.ApproveAll(ctx, h, exp, [][]byte{signApproval(opKey1(), h, exp)}); err != nil {
		t.Fatalf("approbation par une clé qui tient le rôle : %v", err)
	}
}

// Une signature sans le rôle refuse l'ENSEMBLE, même noyée parmi des signatures valides : un quorum ne se complète pas
// avec une clé qui n'a pas le droit d'approuver.
func TestPlanApprovalQuorumIsNotCompletedByAKeyWithoutTheRole(t *testing.T) {
	ctx := context.Background()
	s, _, clock := newRoleStore(t, nil)
	h := submitFor(t, s, "agent-w") // k = 2
	exp := clock.now().Add(30 * time.Minute)
	good, wrongRole := signApproval(opKey1(), h, exp), signApproval(opKey3(), h, exp)
	if err := s.ApproveAll(ctx, h, exp, [][]byte{good, wrongRole}); !errors.Is(err, ErrPlanApprovalRole) {
		t.Fatalf("quorum complété par une clé sans le rôle : %v", err)
	}
	// voisin : deux approbateurs distincts complètent le quorum
	if err := s.ApproveAll(ctx, h, exp, [][]byte{good, signApproval(opKey2(), h, exp)}); err != nil {
		t.Fatalf("deux approbateurs : %v", err)
	}
}

func TestPlanRevocationRefusesAKeyWithoutTheRevokerRole(t *testing.T) {
	ctx := context.Background()
	s, sink, clock := newRoleStore(t, nil)
	h := submitFor(t, s, "agent-i")
	exp := clock.now().Add(5 * time.Minute)

	before := len(contractLeaves(sink))
	if err := s.Revoke(ctx, h, exp, signRevocation(opKey1(), h, exp)); !errors.Is(err, ErrPlanRevocationRole) {
		t.Fatalf("révocation par une clé qui ne fait qu'approuver : %v", err)
	}
	leaves := contractLeaves(sink)
	if len(leaves) != before+1 {
		t.Fatal("un refus de rôle est un événement de sécurité : il laisse une feuille")
	}
	expectLeafHash(t, leaves[len(leaves)-1], planEventRevoke, h, planStepNA, 0, "plan-revocation-role-denied")

	stranger := ed25519.NewKeyFromSeed(bytesOf(0x42, 32))
	if err := s.Revoke(ctx, h, exp, signRevocation(stranger, h, exp)); !errors.Is(err, ErrPlanRevocationSignature) {
		t.Fatalf("clé inconnue : %v", err)
	}

	// voisin autorisé : l'astreinte de nuit coupe, sans pouvoir approuver
	if err := s.Revoke(ctx, h, exp, signRevocation(opKey3(), h, exp)); err != nil {
		t.Fatalf("révocation par une clé qui tient le rôle : %v", err)
	}
}

// Le quorum atteignable se compte sur les clés qui ONT le rôle d'approbation : trois clés au trousseau dont une seule
// approuve ne rendent pas k = 2 atteignable.
func TestPlanApprovalReachabilityCountsApproversOnly(t *testing.T) {
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	s, _, _ := newRoleStore(t, func(o *ContractOptions) {
		o.ApproverKeys = []ed25519.PublicKey{pub(opKey1())}
		o.RevokerKeys = []ed25519.PublicKey{pub(opKey2()), pub(opKey3())}
	})
	if _, err := s.Submit(context.Background(), "agent-w", []PlanStep{stepOf("pay", "invoice-42", nil)}); !errors.Is(err, ErrPlanApprovalUnreachable) {
		t.Fatalf("k = 2 avec un seul approbateur : %v", err)
	}
	// voisin : un agent qui n'exige qu'une approbation passe
	if _, err := s.Submit(context.Background(), "agent-i", []PlanStep{stepOf("read", "doc-1", nil)}); err != nil {
		t.Fatalf("k = 1 avec un approbateur : %v", err)
	}
}

func TestContractRolesFailClosedAtConfiguration(t *testing.T) {
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	stranger := ed25519.NewKeyFromSeed(bytesOf(0x42, 32)).Public().(ed25519.PublicKey)
	for name, mut := range map[string]func(*ContractOptions){
		"approbateurs : liste vide":     func(o *ContractOptions) { o.ApproverKeys = []ed25519.PublicKey{} },
		"révocateurs : liste vide":      func(o *ContractOptions) { o.RevokerKeys = []ed25519.PublicKey{} },
		"approbateur hors du trousseau": func(o *ContractOptions) { o.ApproverKeys = []ed25519.PublicKey{stranger} },
		"révocateur hors du trousseau":  func(o *ContractOptions) { o.RevokerKeys = []ed25519.PublicKey{pub(opKey1()), stranger} },
	} {
		_, err := NewContractStore(ContractOptions{
			CellID: "cell-a", OperatorKeys: []ed25519.PublicKey{pub(opKey1()), pub(opKey2())},
			Salt: contractSalt, Leaves: &stubSink{},
			ApproverKeys: nil,
		}.with(mut))
		if err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	// voisin : aucun rôle déclaré = historique, toute clé fait tout
	if _, err := NewContractStore(ContractOptions{
		CellID: "cell-a", OperatorKeys: []ed25519.PublicKey{pub(opKey1())}, Salt: contractSalt, Leaves: &stubSink{},
	}); err != nil {
		t.Fatalf("configuration historique refusée : %v", err)
	}
}

// with applique mut à une copie : l'aide des tests de configuration, qui construisent chaque cas depuis la même base.
func (o ContractOptions) with(mut func(*ContractOptions)) ContractOptions {
	mut(&o)
	return o
}
