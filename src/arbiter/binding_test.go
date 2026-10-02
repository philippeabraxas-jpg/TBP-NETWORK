package arbiter

// binding_test.go — la décision signée ne vaut que pour UNE mise en file de UNE cellule (revue tierce du 2 octobre :
// rejeu après consommation ; battement et décision non liés à la cellule).

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Rejeu : approbation signée, consommée ; la même demande revient en file ; la MÊME signature ne la rouvre pas.
func TestSignedDecisionCannotBeReplayedAfterConsumption(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	it := item("agent-1", `{"action":"read","resource":"r"}`)
	id := IntentID(it.SystemID, it.Payload)

	if err := h.q.Enqueue(ctx, it); err != nil {
		t.Fatal(err)
	}
	exp := h.clock().Add(5 * time.Minute)
	sig := ed25519.Sign(h.op, h.msg(t, id, VerdictApprove, exp))
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, sig); err != nil {
		t.Fatal(err)
	}
	if out, _, err := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeApproved || err != nil {
		t.Fatalf("approbation : %v %v", out, err)
	}

	// une minute plus tard la même demande revient en file (même identifiant)
	h.now.Add(60)
	if err := h.q.Enqueue(ctx, it); err != nil {
		t.Fatal(err)
	}
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("la décision déjà consommée a rouvert la demande : %v (attendu ErrBadSignature)", err)
	}
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomePending {
		t.Fatalf("la demande doit rester en attente : %v", out)
	}
	// une NOUVELLE signature, sur le ticket de la nouvelle mise en file, est acceptée
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, ed25519.Sign(h.op, h.msg(t, id, VerdictApprove, exp))); err != nil {
		t.Fatalf("la signature fraîche doit passer : %v", err)
	}
}

func TestRefusalIsNotReplayableEither(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	it := item("agent-1", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = h.q.Enqueue(ctx, it)
	exp := h.clock().Add(5 * time.Minute)
	sig := ed25519.Sign(h.op, h.msg(t, id, VerdictRefuse, exp))
	if err := h.q.Decide(ctx, id, VerdictRefuse, exp, sig); err != nil {
		t.Fatal(err)
	}
	_, _, _ = h.q.Take(ctx, it.SystemID, it.Payload)
	_ = h.q.Enqueue(ctx, it)
	if err := h.q.Decide(ctx, id, VerdictRefuse, exp, sig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("un refus consommé rejoué : %v", err)
	}
}

// Chaque mise en file a son ticket ; une remise en file d'une demande EN ATTENTE garde le sien (idempotence).
func TestTicketsAreUniquePerEnqueueAndStableWhilePending(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	it := item("agent-1", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = h.q.Enqueue(ctx, it)
	t1 := h.ticketOf(t, id)
	_ = h.q.Enqueue(ctx, it)
	if h.ticketOf(t, id) != t1 {
		t.Fatal("le ticket d'une demande en attente ne doit pas changer")
	}
	if t1 == (Ticket{}) {
		t.Fatal("ticket nul")
	}
	exp := h.clock().Add(5 * time.Minute)
	_ = h.q.Decide(ctx, id, VerdictRefuse, exp, ed25519.Sign(h.op, h.msg(t, id, VerdictRefuse, exp)))
	_, _, _ = h.q.Take(ctx, it.SystemID, it.Payload)
	_ = h.q.Enqueue(ctx, it)
	if h.ticketOf(t, id) == t1 {
		t.Fatal("deux mises en file distinctes ont le même ticket")
	}
}

// Cellule : un battement ou une décision signés pour A ne valent rien pour B (même trousseau d'opérateurs).
func TestHeartbeatAndDecisionAreBoundToTheCell(t *testing.T) {
	h := newHarness(t, nil) // cellule « cell-a »
	ctx := context.Background()
	at := h.clock()
	if err := h.q.Heartbeat(ctx, at, ed25519.Sign(h.op, PresenceMessage("cell-b", at))); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("battement signé pour une autre cellule accepté : %v", err)
	}
	if h.q.Reachable(ctx) {
		t.Fatal("un arbitre déclaré joignable par un battement d'une autre cellule")
	}
	if err := h.q.Heartbeat(ctx, at, ed25519.Sign(h.op, PresenceMessage("cell-a", at))); err != nil {
		t.Fatalf("battement de la bonne cellule : %v", err)
	}

	it := item("agent-1", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = h.q.Enqueue(ctx, it)
	exp := h.clock().Add(5 * time.Minute)
	foreign := ed25519.Sign(h.op, DecisionMessage("cell-b", id, h.ticketOf(t, id), VerdictApprove, exp))
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, foreign); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("décision signée pour une autre cellule acceptée : %v", err)
	}
}

// Les messages sont sans ambiguïté : cellule « a » ‖ « bc » ≠ « ab » ‖ « c », et les domaines sont distincts.
func TestMessagesAreUnambiguousAndDomainSeparated(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	if string(PresenceMessage("a", at)) == string(PresenceMessage("b", at)) {
		t.Fatal("deux cellules, même message de présence")
	}
	var id [32]byte
	var tk Ticket
	if string(DecisionMessage("cell-a", id, tk, VerdictApprove, at)) == string(DecisionMessage("cell-a", id, tk, VerdictRefuse, at)) {
		t.Fatal("le verdict n'entre pas dans le message")
	}
	tk2 := Ticket{1}
	if string(DecisionMessage("cell-a", id, tk, VerdictApprove, at)) == string(DecisionMessage("cell-a", id, tk2, VerdictApprove, at)) {
		t.Fatal("le ticket n'entre pas dans le message")
	}
	if string(PresenceMessage("cell-a", at)[:5]) != "TBAH2" || string(DecisionMessage("cell-a", id, tk, VerdictApprove, at)[:5]) != "TBAV2" {
		t.Fatal("domaines attendus TBAH2 / TBAV2 (les signatures de l'ancien format ne valent plus)")
	}
	// une signature de l'ANCIEN format (sans cellule ni ticket) ne passe plus
	h := newHarness(t, nil)
	it := item("agent-1", "x")
	oldID := IntentID(it.SystemID, it.Payload)
	_ = h.q.Enqueue(context.Background(), it)
	exp := h.clock().Add(5 * time.Minute)
	legacy := append([]byte("TBAV1"), byte(VerdictApprove))
	legacy = append(legacy, oldID[:]...)
	legacy = append(legacy, 0, 0, 0, 0, 0, 0, 0, 0)
	if err := h.q.Decide(context.Background(), oldID, VerdictApprove, exp, ed25519.Sign(h.op, legacy)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signature de l'ancien format acceptée : %v", err)
	}
}

// Restauration : le ticket est restauré ; l'approbation d'une mise en file ANTÉRIEURE n'approuve pas la suivante.
func TestRestoreKeepsTicketsAndRefusesCrossTicketDecisions(t *testing.T) {
	j := newJournalHarness(t)
	ctx := context.Background()
	it := item("a", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = j.q.Enqueue(ctx, it)
	t1 := j.ticketOf(t, id)
	e := j.clock().Add(5 * time.Minute)
	_ = j.q.Decide(ctx, id, VerdictApprove, e, ed25519.Sign(j.op, j.msg(t, id, VerdictApprove, e)))
	_, _, _ = j.q.Take(ctx, it.SystemID, it.Payload)
	_ = j.q.Enqueue(ctx, it) // 2e mise en file, autre ticket, en attente
	t2 := j.ticketOf(t, id)
	if t1 == t2 {
		t.Fatal("tickets identiques")
	}

	q := j.fresh(t)
	if st := q.Restore(j.records(t), always); st.Pending != 1 || st.Approved != 0 {
		t.Fatalf("seule la 2e mise en file vit, en attente : %+v", st)
	}
	snap := q.Snapshot()
	if len(snap) != 1 || snap[0].Ticket != t2 {
		t.Fatalf("le ticket restauré doit être celui de la mise en file vivante : %+v", snap)
	}
	// et la file restaurée refuse la signature de la 1re mise en file
	oldSig := ed25519.Sign(j.op, DecisionMessage("cell-a", id, t1, VerdictApprove, e))
	if err := q.Decide(ctx, id, VerdictApprove, e, oldSig); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("après restauration : %v", err)
	}
}

// Restauration : une décision ou une consommation d'une AUTRE mise en file (autre ticket) ne s'applique pas à la mise en
// file vivante. Journal fabriqué : l'enqueue de l'une, les événements d'une autre.
func TestRestoreIgnoresEventsOfAnotherQueueing(t *testing.T) {
	ctx := context.Background()
	it := item("a", "x")
	id := IntentID(it.SystemID, it.Payload)
	pick := func(recs []registry.SealedRecord, act byte) registry.SealedRecord {
		for _, r := range recs {
			if a, _, _, _, _, _, _, _ := parseLeafRecord(r.Record); a == act {
				return r
			}
		}
		t.Fatalf("aucun enregistrement d'action %d", act)
		return registry.SealedRecord{}
	}

	// 1re mise en file : approuvée puis consommée ; une autre : refusée
	j1 := newJournalHarness(t)
	_ = j1.q.Enqueue(ctx, it)
	e := j1.clock().Add(5 * time.Minute)
	_ = j1.q.Decide(ctx, id, VerdictApprove, e, ed25519.Sign(j1.op, j1.msg(t, id, VerdictApprove, e)))
	_, _, _ = j1.q.Take(ctx, it.SystemID, it.Payload)
	j1b := newJournalHarness(t)
	_ = j1b.q.Enqueue(ctx, it)
	_ = j1b.q.Decide(ctx, id, VerdictRefuse, e, ed25519.Sign(j1b.op, j1b.msg(t, id, VerdictRefuse, e)))
	// la mise en file VIVANTE : un autre ticket
	j2 := newJournalHarness(t)
	_ = j2.q.Enqueue(ctx, it)
	live := pick(j2.records(t), actEnqueue)
	foreign := map[string]registry.SealedRecord{
		"approbation": pick(j1.records(t), actApprove),
		"refus":       pick(j1b.records(t), actRefuse),
	}
	for name, ev := range foreign {
		q := j2.fresh(t)
		st := q.Restore([]registry.SealedRecord{live, ev}, always)
		if st.Pending != 1 || st.Approved != 0 || st.Refused != 0 {
			t.Errorf("%s d'une autre mise en file appliquée à la vivante : %+v", name, st)
		}
	}
	q := j2.fresh(t)
	if st := q.Restore([]registry.SealedRecord{live, pick(j1.records(t), actConsume)}, always); st.Pending != 1 {
		t.Errorf("la consommation d'une autre mise en file a retiré la vivante : %+v", st)
	}
}
