package cluster

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// #275 : la décision de quorum laisse son clair dans le journal AVANT sa
// feuille ; un journal qui refuse d'écrire ⇒ aucune feuille ⇒ refus.
func TestQuorumDecisionIsJournaled(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{3}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	g := newGate(t, clk, leaves, func(c *QuorumGateConfig) { c.Journal = j })

	proof := mintQuorumProof(t, privs, "shutdown.cluster", "prod/eu-west", testPolicyID, 7, t0.Add(60*1e9), 1, 3)
	if err := g.VerifyClassW(context.Background(), proof, "shutdown.cluster", "prod/eu-west", 7); err != nil {
		t.Fatalf("preuve valide refusée : %v", err)
	}
	recs, err := registry.ReadRecords(path, key)
	ls := leaves.all()
	if err != nil || len(recs) != 1 || len(ls) != 1 {
		t.Fatalf("journal %d enregistrements (err=%v), %d feuilles", len(recs), err, len(ls))
	}
	if recs[0].Leaf != ls[0] || recs[0].VerifyHash() != nil || !bytes.HasPrefix(recs[0].Record, []byte("TBPQ1")) {
		t.Fatalf("enregistrement inattendu : %+v", recs[0])
	}

	// journal HS : aucune feuille, l'admission redevient un refus
	_ = j.Close()
	proof2 := mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(60*1e9), 1, 2)
	if err := g.VerifyClassW(context.Background(), proof2, "a", "r", 7); err == nil {
		t.Fatal("quorum admis sans clair journalisé — fail-closed violé")
	}
	if n := len(leaves.all()); n != 1 {
		t.Fatalf("%d feuilles, une feuille a été inscrite sans clair journalisé", n)
	}
}

func openTestJournal(t *testing.T) (*registry.RecordStore, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{5}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path, key
}

// #275 : la décision de fencing (acceptation d'une époque) laisse son clair dans le journal AVANT sa
// feuille, vérifiable ; journal refusé ⇒ pas de feuille et le jeton n'est pas accepté.
func TestEpochDecisionIsJournaled(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	j, path, key := openTestJournal(t)
	tr := newTracker(t, "cell-a", []string{"cell-a", "cell-b"}, clk, leaves, &alarmRecorder{}, func(c *TrackerConfig) { c.Journal = j })

	tok := mintEpochToken(t, privs, EpochPayload{N: 0, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60})
	if err := tr.Accept(context.Background(), tok); err != nil {
		t.Fatalf("époque 0 refusée : %v", err)
	}
	recs, err := registry.ReadRecords(path, key)
	ls := leaves.all()
	if err != nil || len(recs) != 1 || len(ls) != 1 {
		t.Fatalf("journal %d enregistrements (err=%v), %d feuilles", len(recs), err, len(ls))
	}
	if recs[0].Leaf != ls[0] || recs[0].VerifyHash() != nil || !bytes.HasPrefix(recs[0].Record, []byte("TBPE1")) {
		t.Fatalf("enregistrement inattendu : %+v", recs[0])
	}

	// journal HS : aucune feuille ; on ne tranche pas sans preuve (§4.1)
	_ = j.Close()
	tok2 := mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60})
	if err := tr.Accept(context.Background(), tok2); err == nil {
		t.Fatal("époque acceptée sans clair journalisé — fail-closed violé")
	}
	if n := len(leaves.all()); n != 1 {
		t.Fatalf("%d feuilles : une feuille a été inscrite sans clair journalisé", n)
	}
}

// #275 : idem pour la décision de promotion (le refus est lui aussi tracé et journalisé).
func TestPromotionDecisionIsJournaled(t *testing.T) {
	_, privs := testCellKeys(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	j, path, key := openTestJournal(t)
	bundle := [32]byte{0x42}
	src := &fakeAnchors{
		bundles: map[uint64][32]byte{2: bundle},
		windows: map[uint64][2]time.Time{2: {t0.Add(-time.Hour), t0.Add(time.Hour)}},
		down:    true, // refus tracé : le master est injoignable
	}
	c := newPromotion(t, clk, leaves, src, func(cfg *PromotionConfig) { cfg.Journal = j })
	receipt := mintReceipt(t, privs, "cell-b", 2, bundle, t0.Add(-time.Minute))
	_ = c.Promote(context.Background(), receipt)

	recs, err := registry.ReadRecords(path, key)
	ls := leaves.all()
	if err != nil || len(recs) != 1 || len(ls) != 1 {
		t.Fatalf("journal %d enregistrements (err=%v), %d feuilles", len(recs), err, len(ls))
	}
	if recs[0].Leaf != ls[0] || recs[0].VerifyHash() != nil || !bytes.HasPrefix(recs[0].Record, []byte("TBPP1")) {
		t.Fatalf("enregistrement inattendu : %+v", recs[0])
	}

	_ = j.Close()
	_ = c.Promote(context.Background(), receipt)
	if n := len(leaves.all()); n != 1 {
		t.Fatalf("%d feuilles : une feuille a été inscrite sans clair journalisé", n)
	}
}
