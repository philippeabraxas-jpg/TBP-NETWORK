package arbiter

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// journalHarness : une file qui journalise pour de vrai (RecordStore chiffré), relue ensuite par ReadRecords.
type journalHarness struct {
	*harness
	path string
	key  []byte
	st   *registry.RecordStore
}

func newJournalHarness(t *testing.T) *journalHarness {
	t.Helper()
	dir := t.TempDir()
	kf := filepath.Join(dir, "k")
	if err := registry.GenerateRecordKey(kf); err != nil {
		t.Fatal(err)
	}
	key, err := registry.LoadRecordKey(kf)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "r.jsonl")
	st, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := newHarness(t, func(o *Options) { o.Journal = st })
	return &journalHarness{harness: h, path: path, key: key, st: st}
}

func (j *journalHarness) records(t *testing.T) []registry.SealedRecord {
	t.Helper()
	recs, err := registry.ReadRecords(j.path, j.key)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

// fresh : une file NEUVE (le « redémarrage ») sur le même sel et les mêmes clés d'opérateur.
func (j *journalHarness) fresh(t *testing.T) *Queue {
	t.Helper()
	q, err := NewQueue(Options{
		CellID: "cell-a", Salt: make([]byte, 16), Leaves: &leafLog{},
		OperatorKeys: []ed25519.PublicKey{j.op.Public().(ed25519.PublicKey)}, Now: j.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func always(registry.SealedRecord) bool { return true }
func never(registry.SealedRecord) bool  { return false }

func TestRestoreRebuildsPendingApprovedAndRefused(t *testing.T) {
	j := newJournalHarness(t)
	ctx := context.Background()
	exp := func() time.Time { return j.clock().Add(5 * time.Minute) }
	decide := func(it translatorItem, v Verdict) {
		id := IntentID(it.s, []byte(it.i))
		e := exp()
		if err := j.q.Decide(ctx, id, v, e, ed25519.Sign(j.op, j.msg(t, id, v, e))); err != nil {
			t.Fatal(err)
		}
	}
	pend, appr, refu, used := translatorItem{"a", "pend"}, translatorItem{"a", "appr"}, translatorItem{"a", "refu"}, translatorItem{"a", "used"}
	for _, it := range []translatorItem{pend, appr, refu, used} {
		if err := j.q.Enqueue(ctx, item(it.s, it.i)); err != nil {
			t.Fatal(err)
		}
	}
	decide(appr, VerdictApprove)
	decide(refu, VerdictRefuse)
	decide(used, VerdictApprove)
	if out, _, _ := j.q.Take(ctx, used.s, []byte(used.i)); out != OutcomeApproved { // consommée AVANT l'arrêt
		t.Fatal("consommation de préparation")
	}

	q2 := j.fresh(t)
	st := q2.Restore(j.records(t), always)
	if st.Pending != 1 || st.Approved != 1 || st.Refused != 1 {
		t.Fatalf("stats : %+v", st)
	}
	if out, _, _ := q2.Take(ctx, pend.s, []byte(pend.i)); out != OutcomePending {
		t.Fatalf("en attente : %v", out)
	}
	if out, _, _ := q2.Take(ctx, used.s, []byte(used.i)); out != OutcomeNone {
		t.Fatalf("une approbation CONSOMMÉE avant l'arrêt ne doit pas ressusciter : %v", out)
	}
	if out, _, _ := q2.Take(ctx, refu.s, []byte(refu.i)); out != OutcomeRefused {
		t.Fatalf("refus : %v", out)
	}
	// l'approbation restaurée est à usage unique, comme avant l'arrêt
	if out, _, _ := q2.Take(ctx, appr.s, []byte(appr.i)); out != OutcomeApproved {
		t.Fatalf("approbation : %v", out)
	}
	if out, _, _ := q2.Take(ctx, appr.s, []byte(appr.i)); out != OutcomeNone {
		t.Fatal("approbation restaurée consommée deux fois")
	}
	// la présence n'est PAS restaurée : un arbitre doit se manifester de nouveau
	if q2.Reachable(ctx) {
		t.Fatal("présence restaurée : la joignabilité se prouve, elle ne se présume pas")
	}
}

type translatorItem struct{ s, i string }

// Ce qui ACCORDE (approbation) exige l'ancrage au log ; sans lui, la demande reste en attente — jamais admise.
func TestRestoreRequiresLogInclusionForApprovals(t *testing.T) {
	j := newJournalHarness(t)
	ctx := context.Background()
	it := item("a", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = j.q.Enqueue(ctx, it)
	e := j.clock().Add(5 * time.Minute)
	if err := j.q.Decide(ctx, id, VerdictApprove, e, ed25519.Sign(j.op, j.msg(t, id, VerdictApprove, e))); err != nil {
		t.Fatal(err)
	}
	for name, inLog := range map[string]func(registry.SealedRecord) bool{"jamais": never, "nil": nil} {
		q := j.fresh(t)
		st := q.Restore(j.records(t), inLog)
		if st.Approved != 0 || st.Pending != 1 {
			t.Fatalf("%s : %+v", name, st)
		}
		if out, _, _ := q.Take(ctx, "a", []byte("x")); out != OutcomePending {
			t.Fatalf("%s : une approbation non ancrée ne doit rien admettre : %v", name, out)
		}
	}
}

// Une consommation non vérifiée s'applique QUAND MÊME : elle ne retire que des droits.
func TestRestoreAppliesConsumptionWithoutLogInclusion(t *testing.T) {
	j := newJournalHarness(t)
	ctx := context.Background()
	it := item("a", "x")
	id := IntentID(it.SystemID, it.Payload)
	_ = j.q.Enqueue(ctx, it)
	e := j.clock().Add(5 * time.Minute)
	_ = j.q.Decide(ctx, id, VerdictApprove, e, ed25519.Sign(j.op, j.msg(t, id, VerdictApprove, e)))
	_, _, _ = j.q.Take(ctx, "a", []byte("x"))
	// inLog vrai pour l'approbation seulement (la feuille de consommation n'a pas atteint le checkpoint)
	onlyApprove := func(r registry.SealedRecord) bool {
		act, _, _, _, _, _, _, _ := parseLeafRecord(r.Record)
		return act == actApprove
	}
	q := j.fresh(t)
	if st := q.Restore(j.records(t), onlyApprove); st.Approved != 0 {
		t.Fatalf("approbation ressuscitée : %+v", st)
	}
	if out, _, _ := q.Take(ctx, "a", []byte("x")); out != OutcomeNone {
		t.Fatalf("consommée avant l'arrêt : %v", out)
	}
}

func TestRestoreDropsExpiredAndForeignAndLegacyRecords(t *testing.T) {
	j := newJournalHarness(t)
	ctx := context.Background()
	_ = j.q.Enqueue(ctx, item("a", "old"))
	j.now.Add(int64(DefaultEntryTTL/time.Second) + 1) // l'entrée échoit
	_ = j.q.Enqueue(ctx, item("a", "fresh"))
	recs := j.records(t)
	q := j.fresh(t)
	if st := q.Restore(recs, always); st.Pending != 1 {
		t.Fatalf("échues écartées : %+v", st)
	}
	if out, _, _ := q.Take(ctx, "a", []byte("old")); out != OutcomeNone {
		t.Fatal("entrée échue restaurée")
	}

	// autre cellule / autre sel : ignorés
	other, _ := NewQueue(Options{CellID: "cell-b", Salt: make([]byte, 16), Leaves: &leafLog{}, OperatorKeys: j.q.keys, Now: j.clock})
	if st := other.Restore(recs, always); st.Pending != 0 {
		t.Fatalf("autre cellule : %+v", st)
	}
	salted, _ := NewQueue(Options{CellID: "cell-a", Salt: append([]byte{1}, make([]byte, 15)...), Leaves: &leafLog{}, OperatorKeys: j.q.keys, Now: j.clock})
	if st := salted.Restore(recs, always); st.Pending != 0 || st.Skipped == 0 {
		t.Fatalf("autre sel : %+v", st)
	}
	// format antérieur : « enqueue » sans échéance ⇒ non restaurable
	legacy := recs[0]
	rec := append([]byte(nil), legacy.Record...)
	for i := len(rec) - 8; i < len(rec); i++ {
		rec[i] = 0
	}
	legacy.Record = rec
	legacy.Leaf.PayloadHash = registry.HashPayload(legacy.Salt, rec)
	if st := j.fresh(t).Restore([]registry.SealedRecord{legacy}, always); st.Pending != 0 || st.Skipped != 1 {
		t.Fatalf("format antérieur : %+v", st)
	}
	// enregistrement dont le hash ne correspond pas à la feuille
	bad := recs[0]
	bad.Record = append([]byte(nil), bad.Record...)
	bad.Record[10] ^= 0xff
	if st := j.fresh(t).Restore([]registry.SealedRecord{bad}, always); st.Pending != 0 || st.Skipped != 1 {
		t.Fatalf("hash incohérent : %+v", st)
	}
}

func TestRestoreIsBounded(t *testing.T) {
	j := newJournalHarness(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = j.q.Enqueue(ctx, item("a", string(rune('a'+i))))
	}
	q, _ := NewQueue(Options{CellID: "cell-a", Salt: make([]byte, 16), Leaves: &leafLog{}, OperatorKeys: j.q.keys, Now: j.clock, MaxEntries: 2})
	if st := q.Restore(j.records(t), always); st.Pending != 2 || st.Skipped != 3 {
		t.Fatalf("la file restaurée reste bornée : %+v", st)
	}
}

func TestParseLeafRecordIsStrict(t *testing.T) {
	good := make([]byte, 0, 64)
	good = append(good, "TBAR2"...)
	good = append(good, actEnqueue)
	good = append(good, make([]byte, 32)...)
	good = append(good, make([]byte, 16)...) // ticket
	good = append(good, 1, 'a')
	good = append(good, make([]byte, 16)...)
	good = append(good, 0)
	good = append(good, make([]byte, 8)...)
	if _, _, _, subj, _, _, _, ok := parseLeafRecord(good); !ok || subj != "a" {
		t.Fatalf("valide refusé : %v %q", ok, subj)
	}
	for name, b := range map[string][]byte{
		"court":                     good[:10],
		"tronque":                   good[:len(good)-1],
		"trop_long":                 append(append([]byte(nil), good...), 0),
		"longueur_sujet_mensongere": func() []byte { c := append([]byte(nil), good...); c[54] = 200; return c }(),
	} {
		if _, _, _, _, _, _, _, ok := parseLeafRecord(b); ok {
			t.Errorf("%s : accepté", name)
		}
	}
}
