package arbiter

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	translator "github.com/philippeabraxas-jpg/TBP-NETWORK/src/translator"
)

type leafLog struct {
	n    atomic.Int64
	fail atomic.Bool
}

func (l *leafLog) Append(context.Context, registry.Leaf) (uint64, error) {
	if l.fail.Load() {
		return 0, errors.New("registre indisponible")
	}
	return uint64(l.n.Add(1)), nil
}

type harness struct {
	q      *Queue
	leaves *leafLog
	op     ed25519.PrivateKey
	other  ed25519.PrivateKey
	now    atomic.Int64
	alarms []string
}

func (h *harness) clock() time.Time { return time.Unix(h.now.Load(), 0) }

func newHarness(t *testing.T, mod func(*Options)) *harness {
	t.Helper()
	h := &harness{leaves: &leafLog{}}
	s1, s2 := sha256.Sum256([]byte("op")), sha256.Sum256([]byte("intrus"))
	h.op, h.other = ed25519.NewKeyFromSeed(s1[:]), ed25519.NewKeyFromSeed(s2[:])
	h.now.Store(1_800_000_000)
	o := Options{
		CellID: "cell-a", Salt: make([]byte, 16), Leaves: h.leaves,
		OperatorKeys: []ed25519.PublicKey{h.op.Public().(ed25519.PublicKey)},
		OnAlarm:      func(r string) { h.alarms = append(h.alarms, r) }, Now: h.clock,
	}
	if mod != nil {
		mod(&o)
	}
	q, err := NewQueue(o)
	if err != nil {
		t.Fatal(err)
	}
	h.q = q
	return h
}

// ticketOf rend le ticket de la mise en file vivante de id (ce que l'opérateur lit dans GET /v1/supervision/degraded).
func (h *harness) ticketOf(t testing.TB, id [32]byte) Ticket {
	t.Helper()
	for _, e := range h.q.Snapshot() {
		if e.ID == id {
			return e.Ticket
		}
	}
	t.Fatalf("aucune mise en file vivante pour %x", id[:4])
	return Ticket{}
}

// msg : le message de décision que signerait l'opérateur pour la mise en file vivante de id, dans la cellule de la file.
func (h *harness) msg(t testing.TB, id [32]byte, v Verdict, exp time.Time) []byte {
	t.Helper()
	return DecisionMessage("cell-a", id, h.ticketOf(t, id), v, exp)
}

func (h *harness) beat(t *testing.T, key ed25519.PrivateKey, at time.Time) error {
	return h.q.Heartbeat(context.Background(), at, ed25519.Sign(key, PresenceMessage("cell-a", at)))
}

func item(subject, intent string) translator.ArbitrationItem {
	return translator.ArbitrationItem{SystemID: subject, Payload: []byte(intent)}
}

func TestIntentIDIsDeterministicAndDiscriminating(t *testing.T) {
	a := IntentID("agent-1", []byte(`{"action":"read"}`))
	if a != IntentID("agent-1", []byte(`{"action":"read"}`)) {
		t.Fatal("non déterministe")
	}
	for name, b := range map[string][32]byte{
		"autre_sujet":      IntentID("agent-2", []byte(`{"action":"read"}`)),
		"un_octet_de_plus": IntentID("agent-1", []byte(`{"action":"read"} `)),
		// frontière sujet/intention : « ab » + « c » ≠ « a » + « bc »
		"frontiere": IntentID("agent-", []byte(`1{"action":"read"}`)),
	} {
		if a == b {
			t.Errorf("%s : collision", name)
		}
	}
	if IntentID("ab", []byte("c")) == IntentID("a", []byte("bc")) {
		t.Fatal("frontière sujet/intention ambiguë")
	}
}

func TestNewQueueFailClosed(t *testing.T) {
	good := func() Options {
		pub, _, _ := ed25519.GenerateKey(nil)
		return Options{CellID: "c", Salt: make([]byte, 16), Leaves: &leafLog{}, OperatorKeys: []ed25519.PublicKey{pub}}
	}
	for name, mod := range map[string]func(*Options){
		"cell_vide":      func(o *Options) { o.CellID = "" },
		"sel_court":      func(o *Options) { o.Salt = make([]byte, 8) },
		"sans_feuilles":  func(o *Options) { o.Leaves = nil },
		"sans_operateur": func(o *Options) { o.OperatorKeys = nil },
		"cle_courte":     func(o *Options) { o.OperatorKeys = []ed25519.PublicKey{{1, 2}} },
		"presence_basse": func(o *Options) { o.PresenceTTL = time.Second },
		"presence_haute": func(o *Options) { o.PresenceTTL = time.Hour },
		"entree_basse":   func(o *Options) { o.EntryTTL = time.Second },
		"entree_haute":   func(o *Options) { o.EntryTTL = 24 * time.Hour },
		"file_negative":  func(o *Options) { o.MaxEntries = -1 },
		"file_enorme":    func(o *Options) { o.MaxEntries = MaxMaxEntries + 1 },
	} {
		o := good()
		mod(&o)
		if _, err := NewQueue(o); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if _, err := NewQueue(good()); err != nil {
		t.Fatal(err)
	}
}

func TestPresenceIsProvenFreshAndMonotone(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	if h.q.Reachable(ctx) {
		t.Fatal("joignable sans battement")
	}
	now := h.clock()
	// signature d'un intrus
	if err := h.beat(t, h.other, now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("intrus : %v", err)
	}
	if h.q.Reachable(ctx) {
		t.Fatal("joignable après un battement d'intrus")
	}
	// horodatage hors de la fraîcheur (passé et futur)
	if err := h.beat(t, h.op, now.Add(-HeartbeatSkew-time.Second)); !errors.Is(err, ErrHeartbeatStale) {
		t.Fatalf("périmé : %v", err)
	}
	if err := h.beat(t, h.op, now.Add(HeartbeatSkew+time.Second)); !errors.Is(err, ErrHeartbeatStale) {
		t.Fatalf("futur : %v", err)
	}
	// battement valide
	if err := h.beat(t, h.op, now); err != nil {
		t.Fatal(err)
	}
	if !h.q.Reachable(ctx) {
		t.Fatal("injoignable après un battement valide")
	}
	// rejeu du même battement, puis d'un plus ancien
	if err := h.beat(t, h.op, now); !errors.Is(err, ErrHeartbeatReplayed) {
		t.Fatalf("rejeu : %v", err)
	}
	h.now.Add(10)
	if err := h.beat(t, h.op, now.Add(-5*time.Second)); !errors.Is(err, ErrHeartbeatReplayed) {
		t.Fatalf("plus ancien : %v", err)
	}
	// la présence s'éteint après PresenceTTL
	h.now.Add(int64(DefaultPresenceTTL/time.Second) + 1)
	if h.q.Reachable(ctx) {
		t.Fatal("présence non expirée")
	}
	// un nouveau battement la rétablit
	if err := h.beat(t, h.op, h.clock()); err != nil {
		t.Fatal(err)
	}
	if !h.q.Reachable(ctx) {
		t.Fatal("présence non rétablie")
	}
}

func TestEnqueueDecideTakeLifecycle(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	it := item("agent-1", `{"action":"read","resource":"r"}`)
	id := IntentID(it.SystemID, it.Payload)

	if out, _, err := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeNone || err != nil {
		t.Fatalf("inconnue : %v %v", out, err)
	}
	if err := h.q.Enqueue(ctx, it); err != nil {
		t.Fatal(err)
	}
	leavesAfterEnqueue := h.leaves.n.Load()
	if err := h.q.Enqueue(ctx, it); err != nil || h.leaves.n.Load() != leavesAfterEnqueue {
		t.Fatalf("la remise en file d'une demande en attente doit être idempotente (sans nouvelle feuille) : %v", err)
	}
	if out, gotID, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomePending || gotID != id {
		t.Fatalf("en attente : %v", out)
	}
	snap := h.q.Snapshot()
	if len(snap) != 1 || snap[0].ID != id || snap[0].Subject != "agent-1" || snap[0].Status != "pending" {
		t.Fatalf("snapshot : %+v", snap)
	}

	exp := h.clock().Add(5 * time.Minute)
	good := ed25519.Sign(h.op, h.msg(t, id, VerdictApprove, exp))
	// mauvaise signature / signature d'un autre acte / autre échéance / mauvais verdict
	for name, c := range map[string]struct {
		v   Verdict
		exp time.Time
		sig []byte
		err error
	}{
		"intrus":          {VerdictApprove, exp, ed25519.Sign(h.other, h.msg(t, id, VerdictApprove, exp)), ErrBadSignature},
		"verdict_inverse": {VerdictRefuse, exp, good, ErrBadSignature},
		"autre_echeance":  {VerdictApprove, exp.Add(time.Second), good, ErrBadSignature},
		"autre_domaine":   {VerdictApprove, exp, ed25519.Sign(h.op, append([]byte("TBPA1"), id[:]...)), ErrBadSignature},
		"echeance_proche": {VerdictApprove, h.clock().Add(time.Second), ed25519.Sign(h.op, h.msg(t, id, VerdictApprove, h.clock().Add(time.Second))), ErrDecisionExpiry},
		"echeance_longue": {VerdictApprove, h.clock().Add(DefaultEntryTTL + time.Minute), nil, ErrDecisionExpiry},
	} {
		if err := h.q.Decide(ctx, id, c.v, c.exp, c.sig); !errors.Is(err, c.err) {
			t.Errorf("%s : %v, attendu %v", name, err, c.err)
		}
	}
	if err := h.q.Decide(ctx, [32]byte{9}, VerdictApprove, exp, good); !errors.Is(err, ErrUnknownEntry) {
		t.Fatalf("inconnue : %v", err)
	}
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomePending {
		t.Fatal("une décision invalide ne doit rien changer")
	}
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, good); err != nil {
		t.Fatal(err)
	}
	// une seconde décision sur une demande déjà tranchée : refus
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, good); !errors.Is(err, ErrUnknownEntry) {
		t.Fatalf("redécision : %v", err)
	}
	// l'approbation vaut pour CETTE demande exacte : un octet de plus n'est pas approuvé
	if out, _, _ := h.q.Take(ctx, it.SystemID, append([]byte(nil), append(it.Payload, ' ')...)); out != OutcomeNone {
		t.Fatalf("une autre demande ne doit pas bénéficier de l'approbation : %v", out)
	}
	if out, _, _ := h.q.Take(ctx, "agent-2", it.Payload); out != OutcomeNone {
		t.Fatal("un autre sujet ne doit pas bénéficier de l'approbation")
	}
	// consommation : UNE fois
	if out, _, err := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeApproved || err != nil {
		t.Fatalf("approbation : %v %v", out, err)
	}
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeNone {
		t.Fatal("approbation consommée deux fois")
	}
	if len(h.q.Snapshot()) != 0 {
		t.Fatal("entrée consommée encore visible")
	}
}

func TestRefusalIsConsumedOnceAndExpiryHolds(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	it := item("agent-1", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = h.q.Enqueue(ctx, it)
	exp := h.clock().Add(2 * time.Minute)
	if err := h.q.Decide(ctx, id, VerdictRefuse, exp, ed25519.Sign(h.op, h.msg(t, id, VerdictRefuse, exp))); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeRefused {
		t.Fatalf("refus : %v", out)
	}
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeNone {
		t.Fatal("refus consommé deux fois")
	}

	// approbation non consommée avant son échéance : elle meurt
	_ = h.q.Enqueue(ctx, it)
	exp2 := h.clock().Add(2 * time.Minute)
	_ = h.q.Decide(ctx, id, VerdictApprove, exp2, ed25519.Sign(h.op, h.msg(t, id, VerdictApprove, exp2)))
	h.now.Add(121)
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeNone {
		t.Fatalf("approbation échue encore valable : %v", out)
	}
	// une demande en attente expire aussi (file bornée dans le temps)
	_ = h.q.Enqueue(ctx, it)
	h.now.Add(int64(DefaultEntryTTL/time.Second) + 1)
	if len(h.q.Snapshot()) != 0 {
		t.Fatal("entrée en attente jamais purgée")
	}
	if err := h.q.Decide(ctx, id, VerdictApprove, h.clock().Add(time.Minute), nil); !errors.Is(err, ErrUnknownEntry) {
		t.Fatalf("décision sur une demande échue : %v", err)
	}
}

func TestQueueIsBounded(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxEntries = 3 })
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := h.q.Enqueue(ctx, item("a", string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.q.Enqueue(ctx, item("a", "z")); !errors.Is(err, ErrFull) {
		t.Fatalf("file pleine : %v", err)
	}
	if len(h.alarms) == 0 || h.alarms[len(h.alarms)-1] != "arbiter-queue-full" {
		t.Fatalf("alarme attendue : %v", h.alarms)
	}
	// une demande déjà en file reste idempotente même pleine
	if err := h.q.Enqueue(ctx, item("a", "a")); err != nil {
		t.Fatalf("idempotence en file pleine : %v", err)
	}
	// l'échéance libère de la place
	h.now.Add(int64(DefaultEntryTTL/time.Second) + 1)
	if err := h.q.Enqueue(ctx, item("a", "z")); err != nil {
		t.Fatalf("place libérée : %v", err)
	}
	if err := h.q.Enqueue(ctx, translator.ArbitrationItem{SystemID: string(make([]byte, 300)), Payload: []byte("x")}); err == nil {
		t.Fatal("sujet démesuré accepté")
	}
}

// Sans feuille, pas d'effet : fail-closed sur les trois événements.
func TestLeafFailureMeansNoEffect(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	it := item("agent-1", "x")
	id := IntentID(it.SystemID, it.Payload)

	h.leaves.fail.Store(true)
	if err := h.q.Enqueue(ctx, it); !errors.Is(err, ErrLeaf) {
		t.Fatalf("mise en file sans feuille : %v", err)
	}
	if len(h.q.Snapshot()) != 0 {
		t.Fatal("entrée créée sans feuille")
	}
	h.leaves.fail.Store(false)
	_ = h.q.Enqueue(ctx, it)
	exp := h.clock().Add(5 * time.Minute)
	sig := ed25519.Sign(h.op, h.msg(t, id, VerdictApprove, exp))
	h.leaves.fail.Store(true)
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, sig); !errors.Is(err, ErrLeaf) {
		t.Fatalf("décision sans feuille : %v", err)
	}
	if out, _, _ := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomePending {
		t.Fatal("décision non tracée appliquée")
	}
	h.leaves.fail.Store(false)
	if err := h.q.Decide(ctx, id, VerdictApprove, exp, sig); err != nil {
		t.Fatal(err)
	}
	h.leaves.fail.Store(true)
	if out, _, err := h.q.Take(ctx, it.SystemID, it.Payload); out == OutcomeApproved || !errors.Is(err, ErrLeaf) {
		t.Fatalf("consommation sans feuille : %v %v", out, err)
	}
	h.leaves.fail.Store(false)
	if out, _, err := h.q.Take(ctx, it.SystemID, it.Payload); out != OutcomeApproved || err != nil {
		t.Fatalf("l'approbation doit survivre à une consommation échouée : %v %v", out, err)
	}
	found := false
	for _, a := range h.alarms {
		found = found || a == "arbiter-leaf-write-failed"
	}
	if !found {
		t.Fatalf("alarme d'écriture de feuille absente : %v", h.alarms)
	}
}
