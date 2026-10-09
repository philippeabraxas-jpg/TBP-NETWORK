package pep

// plan_submission_test.go — la soumission SIGNÉE et la règle « soumetteur ≠ approbateur » : celui qui propose un plan n'est pas
// celui qui l'approuve. Sans signature, on ne sait pas qui a soumis, et la règle ne tiendrait pas : une cellule qui sépare les
// tâches refuse donc la soumission non signée. Chaque refus a son cas voisin accepté, et chaque test échoue si on retire la
// vérification qu'il couvre.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// opKey4 : le soumetteur dédié (graine de test, aucune valeur de production).
func opKey4() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytesOf(0x77, 32))
}

func signSubmission(priv ed25519.PrivateKey, subject string, steps []PlanStep, expiry time.Time) []byte {
	return ed25519.Sign(priv, SubmissionMessage("cell-alpha-01", subject, steps, expiry))
}

// newSeparationStore : key1, key2 et key3 approuvent ; key4 ne fait que soumettre. k = 2 pour « agent-w », 1 pour les autres.
func newSeparationStore(t *testing.T, mut func(*ContractOptions)) (*ContractStore, *stubSink, *contractClock) {
	t.Helper()
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	return newQuorumStore(t, func(o *ContractOptions) {
		o.OperatorKeys = []ed25519.PublicKey{pub(opKey1()), pub(opKey2()), pub(opKey3()), pub(opKey4())}
		o.ApproverKeys = []ed25519.PublicKey{pub(opKey1()), pub(opKey2()), pub(opKey3())}
		o.SubmitterKeys = []ed25519.PublicKey{pub(opKey4())}
		o.SeparateDuties = true
		if mut != nil {
			mut(o)
		}
	})
}

func TestSeparateDutiesRefusesAnUnsignedSubmission(t *testing.T) {
	ctx := context.Background()
	s, sink, clock := newSeparationStore(t, nil)
	steps := []PlanStep{stepOf("pay", "invoice-42", []byte("1200"))}

	before := len(contractLeaves(sink))
	if _, err := s.Submit(ctx, "agent-i", steps); !errors.Is(err, ErrPlanSubmissionUnsigned) {
		t.Fatalf("soumission non signée sur une cellule qui sépare les tâches : %v", err)
	}
	leaves := contractLeaves(sink)
	if len(leaves) != before+1 {
		t.Fatal("un refus de soumission est un événement de sécurité : il laisse une feuille")
	}
	if pend, _ := s.Snapshot(); len(pend) != 0 {
		t.Fatal("une soumission refusée ne doit pas mettre de plan en attente")
	}
	// voisin autorisé : la même soumission, signée
	exp := clock.now().Add(5 * time.Minute)
	if _, err := s.SubmitSigned(ctx, "agent-i", steps, exp, signSubmission(opKey4(), "agent-i", steps, exp)); err != nil {
		t.Fatalf("soumission signée : %v", err)
	}
	if pend, _ := s.Snapshot(); len(pend) != 1 {
		t.Fatal("le plan signé doit être en attente")
	}
}

func TestSignedSubmissionRefusals(t *testing.T) {
	ctx := context.Background()
	s, sink, clock := newSeparationStore(t, nil)
	steps := []PlanStep{stepOf("pay", "invoice-42", []byte("1200"))}
	other := []PlanStep{stepOf("pay", "invoice-42", []byte("9999"))}
	stranger := ed25519.NewKeyFromSeed(bytesOf(0x42, 32))
	exp := clock.now().Add(5 * time.Minute)

	cases := []struct {
		name   string
		expiry time.Time
		sig    []byte
		want   error
		reason string
	}{
		{"clé inconnue", exp, signSubmission(stranger, "agent-i", steps, exp), ErrPlanSubmissionSignature, "plan-submission-signature-invalid"},
		{"sans signature", exp, nil, ErrPlanSubmissionSignature, "plan-submission-signature-invalid"},
		// une clé du trousseau qui n'a pas le rôle de soumission : refus NOMMÉ
		{"approbateur sans rôle de soumission", exp, signSubmission(opKey1(), "agent-i", steps, exp), ErrPlanSubmissionRole, "plan-submission-role-denied"},
		{"signée pour un autre contenu", exp, signSubmission(opKey4(), "agent-i", other, exp), ErrPlanSubmissionSignature, "plan-submission-signature-invalid"},
		{"signée pour un autre agent", exp, signSubmission(opKey4(), "agent-other", steps, exp), ErrPlanSubmissionSignature, "plan-submission-signature-invalid"},
		{"échéance présentée ≠ signée", exp.Add(time.Second), signSubmission(opKey4(), "agent-i", steps, exp), ErrPlanSubmissionSignature, "plan-submission-signature-invalid"},
		// une approbation ou une révocation de l'opérateur légitime ne vaut pas soumission (domaines distincts)
		{"signature d'approbation réutilisée", exp, ed25519.Sign(opKey4(), ApprovalMessage([32]byte{1}, exp)), ErrPlanSubmissionSignature, "plan-submission-signature-invalid"},
		{"échéance échue", clock.now().Add(-time.Second), signSubmission(opKey4(), "agent-i", steps, clock.now().Add(-time.Second)), ErrPlanSubmissionExpiryInvalid, "plan-submission-expiry-invalid"},
		{"échéance au-delà de MaxSubmissionTTL", clock.now().Add(MaxSubmissionTTL + time.Second), signSubmission(opKey4(), "agent-i", steps, clock.now().Add(MaxSubmissionTTL+time.Second)), ErrPlanSubmissionExpiryInvalid, "plan-submission-expiry-invalid"},
	}
	for _, c := range cases {
		before := len(contractLeaves(sink))
		if _, err := s.SubmitSigned(ctx, "agent-i", steps, c.expiry, c.sig); !errors.Is(err, c.want) {
			t.Fatalf("%s : %v, veut %v", c.name, err, c.want)
		}
		if got := len(contractLeaves(sink)); got != before+1 {
			t.Fatalf("%s : %d feuilles de plus, veut 1", c.name, got-before)
		}
	}
	if pend, _ := s.Snapshot(); len(pend) != 0 {
		t.Fatal("aucun refus ne doit mettre de plan en attente")
	}
	// voisin autorisé : la bonne signature, après tous ces refus
	if _, err := s.SubmitSigned(ctx, "agent-i", steps, exp, signSubmission(opKey4(), "agent-i", steps, exp)); err != nil {
		t.Fatalf("soumission valide : %v", err)
	}
}

func TestSignedSubmissionIsNotReplayable(t *testing.T) {
	ctx := context.Background()
	s, _, clock := newSeparationStore(t, nil)
	steps := []PlanStep{stepOf("pay", "invoice-42", nil)}
	exp := clock.now().Add(5 * time.Minute)
	sig := signSubmission(opKey4(), "agent-i", steps, exp)
	h1, err := s.SubmitSigned(ctx, "agent-i", steps, exp, sig)
	if err != nil {
		t.Fatal(err)
	}
	// une seconde plus tard : la même soumission, rejouée, ne recrée pas de plan
	clock.advance(time.Second)
	if _, err := s.SubmitSigned(ctx, "agent-i", steps, exp, sig); !errors.Is(err, ErrPlanSubmissionReplayed) {
		t.Fatalf("soumission rejouée : %v", err)
	}
	if pend, _ := s.Snapshot(); len(pend) != 1 || pend[0].Hash != h1 {
		t.Fatalf("le rejeu a créé un second plan : %d en attente", len(pend))
	}
	// voisin : une nouvelle signature (autre échéance) est une nouvelle soumission
	exp2 := clock.now().Add(6 * time.Minute)
	if _, err := s.SubmitSigned(ctx, "agent-i", steps, exp2, signSubmission(opKey4(), "agent-i", steps, exp2)); err != nil {
		t.Fatalf("nouvelle soumission : %v", err)
	}
}

func TestSubmitterCannotApproveOwnPlan(t *testing.T) {
	ctx := context.Background()
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	// key1 soumet ET peut approuver : c'est ce que la règle doit empêcher
	s, sink, clock := newSeparationStore(t, func(o *ContractOptions) {
		o.SubmitterKeys = []ed25519.PublicKey{pub(opKey1())}
	})
	steps := []PlanStep{stepOf("pay", "invoice-42", nil)}
	exp := clock.now().Add(5 * time.Minute)
	h, err := s.SubmitSigned(ctx, "agent-w", steps, exp, signSubmission(opKey1(), "agent-w", steps, exp)) // k = 2
	if err != nil {
		t.Fatal(err)
	}
	ex := clock.now().Add(30 * time.Minute)
	self, k2, k3 := signApproval(opKey1(), h, ex), signApproval(opKey2(), h, ex), signApproval(opKey3(), h, ex)

	before := len(contractLeaves(sink))
	// le quorum complété avec la signature du soumetteur est refusé EN ENTIER
	if err := s.ApproveAll(ctx, h, ex, [][]byte{self, k2}); !errors.Is(err, ErrPlanApprovalSelf) {
		t.Fatalf("approbation par le soumetteur : %v", err)
	}
	leaves := contractLeaves(sink)
	if len(leaves) != before+1 {
		t.Fatal("le refus laisse une feuille")
	}
	expectLeafHash(t, leaves[len(leaves)-1], planEventApprove, h, planStepNA, 0, "plan-approval-self")
	if pend, _ := s.Snapshot(); len(pend) != 1 {
		t.Fatal("le plan doit rester en attente")
	}
	// voisin autorisé : deux autres approbateurs
	if err := s.ApproveAll(ctx, h, ex, [][]byte{k2, k3}); err != nil {
		t.Fatalf("deux approbateurs autres que le soumetteur : %v", err)
	}
}

// Quand seul le soumetteur pourrait approuver, le plan n'est pas mis en attente : le refus est net, à la soumission.
func TestSubmissionRefusedWhenNoOtherApproverCouldApprove(t *testing.T) {
	ctx := context.Background()
	pub := func(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
	s, _, clock := newSeparationStore(t, func(o *ContractOptions) {
		o.ApproverKeys = []ed25519.PublicKey{pub(opKey1()), pub(opKey2())} // k = 2 : il faut les deux
		o.SubmitterKeys = []ed25519.PublicKey{pub(opKey1()), pub(opKey4())}
	})
	steps := []PlanStep{stepOf("pay", "invoice-42", nil)}
	exp := clock.now().Add(5 * time.Minute)
	if _, err := s.SubmitSigned(ctx, "agent-w", steps, exp, signSubmission(opKey1(), "agent-w", steps, exp)); !errors.Is(err, ErrPlanApprovalUnreachable) {
		t.Fatalf("soumetteur qui est aussi l'un des deux seuls approbateurs : %v", err)
	}
	// voisin : le soumetteur dédié (qui n'approuve pas) laisse les deux approbateurs entiers
	if _, err := s.SubmitSigned(ctx, "agent-w", steps, exp, signSubmission(opKey4(), "agent-w", steps, exp)); err != nil {
		t.Fatalf("soumetteur dédié : %v", err)
	}
}

// Sans SeparateDuties (historique), la soumission non signée reste ouverte ; un plan soumis SIGNÉ garde pourtant sa protection.
func TestUnsignedSubmissionStaysOpenWithoutSeparateDuties(t *testing.T) {
	ctx := context.Background()
	s, _, clock := newSeparationStore(t, func(o *ContractOptions) { o.SeparateDuties = false })
	steps := []PlanStep{stepOf("read", "doc-1", nil)}
	h, err := s.Submit(ctx, "agent-i", steps)
	if err != nil {
		t.Fatalf("soumission non signée sans SeparateDuties : %v", err)
	}
	ex := clock.now().Add(30 * time.Minute)
	if err := s.Approve(ctx, h, ex, signApproval(opKey1(), h, ex)); err != nil {
		t.Fatalf("un plan non signé s'approuve comme avant : %v", err)
	}
}
