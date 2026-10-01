package pep

// journal_test.go — #275 : les feuilles de décision du PEP laissent leur clair
// dans le journal d'enregistrements, ET un journal qui refuse d'écrire
// n'inscrit aucune feuille (un allow devient un deny, comme pour toute feuille
// non écrite).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func testJournal(t *testing.T) (*registry.RecordStore, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{9}, registry.RecordKeyLen)
	st, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path, key
}

// assertJournaled vérifie que chaque feuille du sink a SON clair dans le
// journal (même feuille, hash recalculé, record préfixé par prefix).
func assertJournaled(t *testing.T, path string, key []byte, sink *stubSink, prefix string) {
	t.Helper()
	recs, err := registry.ReadRecords(path, key)
	if err != nil {
		t.Fatalf("ReadRecords: %v", err)
	}
	sink.mu.Lock()
	leaves := append([]registry.Leaf(nil), sink.leaves...)
	sink.mu.Unlock()
	if len(recs) != len(leaves) || len(leaves) == 0 {
		t.Fatalf("%d enregistrements pour %d feuilles", len(recs), len(leaves))
	}
	for i, r := range recs {
		if r.Leaf != leaves[i] {
			t.Fatalf("enregistrement %d : feuille journalisée ≠ feuille inscrite", i)
		}
		if err := r.VerifyHash(); err != nil {
			t.Fatalf("enregistrement %d : %v", i, err)
		}
		if !bytes.HasPrefix(r.Record, []byte(prefix)) {
			t.Fatalf("enregistrement %d : record %q, préfixe %q attendu", i, r.Record, prefix)
		}
	}
}

func newJournaledValidator(t *testing.T, sink LeafSink, j *registry.RecordStore) *Validator {
	t.Helper()
	v, err := NewValidator(ValidatorOptions{
		CellID:     "tbp/registry/cell-alpha-01",
		Keyring:    map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)},
		PolicyID:   arr32(policyV1),
		Salt:       testSalt,
		Leaves:     sink,
		Journal:    j,
		AntiReplay: &stubAntiReplay{},
		Now:        func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestValidatorDecisionLeavesAreJournaled(t *testing.T) {
	sink := &stubSink{}
	j, path, key := testJournal(t)
	v := newJournaledValidator(t, sink, j)
	tok := mintToken(t, nominalClaims())

	if d := v.Validate(context.Background(), tok, nominalRequest()); !d.Allow {
		t.Fatalf("allow attendu: %s", d.Reason)
	}
	if d := v.Validate(context.Background(), tok, nominalRequest()); d.Allow || d.Reason != "replay" {
		t.Fatalf("rejeu: allow=%v reason=%q", d.Allow, d.Reason)
	}
	assertJournaled(t, path, key, sink, "TBPD")
}

func TestValidatorJournalRefusesNoLeafAndAllowBecomesDeny(t *testing.T) {
	sink := &stubSink{}
	j, _, _ := testJournal(t)
	_ = j.Close() // l'écriture du clair échouera
	v := newJournaledValidator(t, sink, j)

	d := v.Validate(context.Background(), mintToken(t, nominalClaims()), nominalRequest())
	if d.Allow || d.Reason != ReasonLeafWriteFailed || d.LeafWritten || d.LeafErr == nil {
		t.Fatalf("allow=%v reason=%q written=%v err=%v, veut deny/%s", d.Allow, d.Reason, d.LeafWritten, d.LeafErr, ReasonLeafWriteFailed)
	}
	if sink.count() != 0 {
		t.Fatalf("%d feuille(s) inscrite(s) sans clair journalisé", sink.count())
	}
}

func TestOPADecisionLeavesAreJournaled(t *testing.T) {
	sink := &stubSink{}
	j, path, key := testJournal(t)
	c, err := NewOPAClient(OPAOptions{
		Endpoint: allowServer(t, true).URL, CellID: opaTestCellID, Salt: testSalt,
		Leaves: sink, Journal: j,
		Now: func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := c.Eval(context.Background(), opaNominalInput()); !d.Allow {
		t.Fatalf("allow attendu: %s", d.Reason)
	}
	assertJournaled(t, path, key, sink, "TBPD1")

	// journal HS ⇒ aucune feuille, allow → deny
	_ = j.Close()
	before := sink.count()
	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonLeafWriteFailed || sink.count() != before {
		t.Fatalf("allow=%v reason=%q feuilles %d→%d, veut deny/%s sans nouvelle feuille", d.Allow, d.Reason, before, sink.count(), ReasonLeafWriteFailed)
	}
}

func TestQuotaCutLeafIsJournaled(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	j, path, key := testJournal(t)
	clock := time.Unix(1_800_000_000, 0)
	l, err := NewQuotaLedger(QuotaLedgerOptions{
		MaxPassports: 4, CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Journal: j,
		OnTrip: rec.trip, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	jti := jtiOf(0x11)
	c := openPassport(t, l, jti, clock.Unix()+120, 4, 60)
	if err := c.Consume(5); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err=%v", err)
	}
	assertJournaled(t, path, key, sink, "TBPD1")

	// journal HS : la coupure a eu lieu (fail-closed) mais la feuille manquante est alarmée
	_ = j.Close()
	before := sink.count()
	jti2 := jtiOf(0x12)
	c2 := openPassport(t, l, jti2, clock.Unix()+120, 4, 60)
	if err := c2.Consume(5); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err=%v", err)
	}
	if sink.count() != before {
		t.Fatalf("feuille inscrite sans clair journalisé (%d → %d)", before, sink.count())
	}
	if rec.count() == 0 || rec.reasons[len(rec.reasons)-1] != ReasonLeafWriteFailed {
		t.Fatalf("alarmes=%v, veut %s", rec.reasons, ReasonLeafWriteFailed)
	}
}

func TestDryRunDenyLeafIsJournaled(t *testing.T) {
	sink := &stubSink{}
	j, path, key := testJournal(t)
	g, err := NewDryRunGate(DryRunGateOptions{
		Runner: &stubRunner{err: errors.New("composant en panne")}, CellID: "cell-a", Salt: testSalt,
		Leaves: sink, Journal: j,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := g.Execute(context.Background(), [16]byte{1}, "transfer", "account/42"); reason != ReasonDryRunFailed {
		t.Fatalf("reason=%q", reason)
	}
	// feuilles : télémétrie (hors périmètre, feuille nue) + refus (journalisé)
	kinds := sinkKinds(sink)
	if len(kinds) != 2 || kinds[1] != registry.KindDecision {
		t.Fatalf("feuilles=%v", kinds)
	}
	recs, err := registry.ReadRecords(path, key)
	if err != nil || len(recs) != 1 {
		t.Fatalf("journal: %d enregistrements, err=%v, veut 1 (la feuille de refus)", len(recs), err)
	}
	sink.mu.Lock()
	want := sink.leaves[1]
	sink.mu.Unlock()
	if recs[0].Leaf != want || recs[0].VerifyHash() != nil || !bytes.HasPrefix(recs[0].Record, []byte("TBPD1")) {
		t.Fatalf("enregistrement de refus inattendu: %+v", recs[0])
	}
}

// Sans journal (bibliothèque, historique) : la feuille est inchangée.
func TestAppendLeafWithoutJournalIsBareLeaf(t *testing.T) {
	sink := &stubSink{}
	rec := []byte("TBPD1-test")
	if _, err := appendLeaf(context.Background(), sink, nil, registry.KindDecision, "c", testSalt, rec, 42); err != nil {
		t.Fatal(err)
	}
	want := registry.Leaf{Kind: registry.KindDecision, CellID: "c", PayloadHash: registry.HashPayload(testSalt, rec), Timestamp: 42}
	if sink.count() != 1 || sink.leaves[0] != want {
		t.Fatalf("feuille %+v, veut %+v", sink.leaves, want)
	}
}

func TestContractLeavesAreJournaled(t *testing.T) {
	sink := &stubSink{}
	j, path, key := testJournal(t)
	clock := &contractClock{t: contractEpochT0}
	s := newContractStore(t, sink, clock, &contractTrips{}, func(o *ContractOptions) { o.Journal = j })

	hash, err := s.Submit(context.Background(), contractSubject, []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
	if err != nil {
		t.Fatal(err)
	}
	expiry := clock.now().Add(30 * time.Minute)
	if err := s.Approve(context.Background(), hash, expiry, signApproval(opKey1(), hash, expiry)); err != nil {
		t.Fatal(err)
	}
	// soumission (TBPL1) + approbation attribuée (TBPL2, signature comprise)
	assertJournaled(t, path, key, sink, "TBPL")
	recs, _ := registry.ReadRecords(path, key)
	if len(recs) != 2 || !bytes.HasPrefix(recs[1].Record, []byte("TBPL2")) {
		t.Fatalf("%d enregistrements, le second doit être TBPL2 (approbation attribuée)", len(recs))
	}

	// journal HS : aucune feuille, la soumission échoue (pas de preuve, pas de contrat)
	_ = j.Close()
	before := sink.count()
	if _, err := s.Submit(context.Background(), contractSubject, []PlanStep{stepOf("a", "r", nil)}); !errors.Is(err, ErrPlanStoreFault) {
		t.Fatalf("soumission sans clair journalisé : %v", err)
	}
	if sink.count() != before {
		t.Fatalf("feuille inscrite sans clair journalisé (%d → %d)", before, sink.count())
	}
}
