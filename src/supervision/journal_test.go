package supervision

import (
	"bytes"
	"path/filepath"
	"testing"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// #275 : l'alerte du moniteur laisse son clair (record « TBPS1 » + sel) dans le journal AVANT sa feuille ;
// un journal qui refuse ⇒ aucune feuille ET aucune notification d'une alerte non prouvée.
func TestMonitorAlertIsJournaledBeforeItsLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{8}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	fx := newMonitorFixture(t, func(o *MonitorOptions) { o.Journal = j })

	alerts := fx.check(t) // pas d'ancrage frais ⇒ une alerte
	if len(alerts) != 1 {
		t.Fatalf("attendu 1 alerte, %d", len(alerts))
	}
	recs, err := registry.ReadRecords(path, key)
	if err != nil || len(recs) != 1 {
		t.Fatalf("journal : %d enregistrements (err=%v)", len(recs), err)
	}
	a := alerts[0]
	if recs[0].Leaf.PayloadHash != a.LeafHash || recs[0].Leaf.Kind != registry.KindSupervision ||
		recs[0].VerifyHash() != nil || !bytes.Equal(recs[0].Record, a.Raw) || !bytes.Equal(recs[0].Salt, a.Salt) {
		t.Fatalf("enregistrement ≠ alerte : %+v", recs[0])
	}

	// journal HS : le passage échoue (feuillage impossible), rien n'est notifié, aucune feuille de plus
	_ = j.Close()
	fx.clk.advance(1) // l'alerte courante est dédupliquée : on demande une divergence nouvelle
	notified := len(*fx.sink)
	fx.anchorAt(t, fx.clk.t.Add(-20*60*1e9))
	if _, err := fx.monitor.CheckOnce(testCtx); err == nil {
		t.Fatal("alerte feuillée sans clair journalisé — fail-closed violé")
	}
	if len(*fx.sink) != notified {
		t.Fatal("une alerte a été notifiée sans feuille ni clair journalisé")
	}
}
