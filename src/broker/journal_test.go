package broker

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// #275 : la feuille de décision propre du broker laisse son clair dans le
// journal ; un journal qui refuse d'écrire ⇒ aucune feuille, allow → deny.
func TestBrokerDecisionLeafIsJournaled(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{4}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	b, _, leaves, _ := newTestBroker(t, srv.URL, staticTranslator{tr: Translation{Action: "a", Resource: "r"}})
	b.journal = j

	var r Result
	r.JTI = [16]byte{1}
	r.Allow = true
	b.writeLeaf(ctx, &r)
	if !r.Allow || !r.LeafWritten {
		t.Fatalf("allow=%v written=%v", r.Allow, r.LeafWritten)
	}
	recs, err := registry.ReadRecords(path, key)
	ls := leaves.all()
	if err != nil || len(recs) != 1 || recs[0].Leaf != ls[len(ls)-1] {
		t.Fatalf("journal %d enregistrements err=%v", len(recs), err)
	}
	if err := recs[0].VerifyHash(); err != nil || !bytes.HasPrefix(recs[0].Record, []byte("TBPD1")) {
		t.Fatalf("enregistrement inattendu : %v %q", err, recs[0].Record)
	}

	// journal HS : aucune feuille, un allow redevient deny sans jeton
	_ = j.Close()
	before := len(leaves.all())
	r2 := Result{Allow: true, JTI: [16]byte{2}}
	b.writeLeaf(ctx, &r2)
	if r2.Allow || r2.LeafWritten || r2.LeafErr == nil {
		t.Fatalf("allow=%v written=%v err=%v, veut deny", r2.Allow, r2.LeafWritten, r2.LeafErr)
	}
	if len(leaves.all()) != before {
		t.Fatal("feuille inscrite sans clair journalisé")
	}
}
