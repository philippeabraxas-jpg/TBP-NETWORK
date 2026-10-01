package cluster

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

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
