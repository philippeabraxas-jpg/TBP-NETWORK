package telemetry

// journal_test.go — #275 : les producteurs de feuilles de la télémétrie (exporteur, agrégateur, rétention,
// détecteur anti-dribble) journalisent le clair AVANT la feuille ; journal refusé ⇒ aucune feuille.

import (
	"bytes"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func openTelemetryJournal(t *testing.T) (*registry.RecordStore, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{7}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path, key
}

// requireJournaledLeaves : le journal porte, dans l'ordre, les feuilles inscrites, hash du clair vérifié.
func requireJournaledLeaves(t *testing.T, path string, key []byte, leaves *leafRecorder) []registry.SealedRecord {
	t.Helper()
	recs, err := registry.ReadRecords(path, key)
	if err != nil || len(recs) != len(leaves.leaves) || len(recs) == 0 {
		t.Fatalf("journal %d enregistrements (err=%v), %d feuilles", len(recs), err, len(leaves.leaves))
	}
	for i := range recs {
		if recs[i].Leaf != leaves.leaves[i] || recs[i].VerifyHash() != nil {
			t.Fatalf("enregistrement %d ≠ feuille inscrite (ou hash du clair faux) : %+v", i, recs[i])
		}
	}
	return recs
}

func TestTelemetryLeafSinkIsJournaled(t *testing.T) {
	j, path, key := openTelemetryJournal(t)
	leaves := &leafRecorder{}
	now := &atomic.Int64{}
	now.Store(20_000)
	sink, err := NewTelemetryLeafSink("cell-alpha-01", t22Salt, leaves, func() time.Time { return time.UnixMilli(now.Load()) })
	if err != nil {
		t.Fatal(err)
	}
	sink.WithJournal(j)
	r := aggRec(0x01, "res-a", 100)
	if err := sink.Feed(r); err != nil {
		t.Fatal(err)
	}
	recs := requireJournaledLeaves(t, path, key, leaves)
	if !bytes.Equal(recs[0].Record, telemetryRecord(r)) {
		t.Fatal("le clair journalisé n'est pas le record TBTM1")
	}
	_ = j.Close()
	if err := sink.Feed(r); err == nil || len(leaves.leaves) != 1 {
		t.Fatalf("feuille inscrite sans clair journalisé (err=%v, %d feuilles)", err, len(leaves.leaves))
	}
}

func TestAggregatorAndRetentionAreJournaled(t *testing.T) {
	j, path, key := openTelemetryJournal(t)
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	clock := func() time.Time { return time.UnixMilli(nowMs.Load()) }
	store, err := NewRetentionStore(RetentionOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves, Journal: j,
		TTL: time.Hour, MaxBatches: 8, Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	agg, err := NewAggregator(AggregatorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves, Journal: j,
		Window: time.Second, RetStore: store, Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agg.Feed(aggRec(0x01, "res-a", 100)); err != nil {
		t.Fatal(err)
	}
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	nowMs.Store(1000 + time.Hour.Milliseconds())
	if n := store.PurgeExpired(); n != 1 {
		t.Fatalf("purgés = %d", n)
	}
	recs := requireJournaledLeaves(t, path, key, leaves)
	if len(recs) != 2 || recs[0].Leaf.Kind != registry.KindTelemetry || recs[1].Leaf.Kind != registry.KindRetentionPurge {
		t.Fatalf("attendu agrégat puis purge, reçu %d enregistrements", len(recs))
	}

	// journal HS : la fenêtre n'est PAS scellée (erreur propagée), le lot reste — pas de trace, pas de destruction
	_ = j.Close()
	_ = agg.Feed(aggRec(0x02, "res-b", 50)) // alimente la fenêtre courante (Feed scelle l'échue : erreur possible)
	nowMs.Store(nowMs.Load() + 2000)
	if err := agg.Tick(); err == nil {
		t.Fatal("fenêtre scellée sans clair journalisé — fail-closed violé")
	}
	if len(leaves.leaves) != 2 {
		t.Fatalf("%d feuilles : une feuille a été inscrite sans clair journalisé", len(leaves.leaves))
	}
}

func TestDetectorAlertIsJournaled(t *testing.T) {
	j, path, key := openTelemetryJournal(t)
	leaves := &leafRecorder{}
	var alerts []Alert
	trips := &tripRecorder{}
	d, err := NewDetector(DetectorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves, Journal: j,
		Params: t23Params(), Window: time.Second,
		Now:     func() time.Time { return time.UnixMilli(1_700_000_000_000) },
		OnAlert: func(a Alert) { alerts = append(alerts, a) }, OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatal(err)
	}
	feedDrip(t, d, "exfil.slow-leak.example", 8, 12, 0, 601)
	if err := d.Flush(); err != nil {
		t.Fatal(err)
	}
	recs := requireJournaledLeaves(t, path, key, leaves)
	if len(alerts) != 1 || len(recs) != 1 || recs[0].Leaf.Kind != registry.KindTelemetryAlert {
		t.Fatalf("%d alertes, %d enregistrements", len(alerts), len(recs))
	}

	// journal HS : pas de feuille ⇒ pas d'alerte émise, alarme leaf-write-failed
	_ = j.Close()
	leaves2 := &leafRecorder{}
	var alerts2 []Alert
	trips2 := &tripRecorder{}
	d2, err := NewDetector(DetectorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves2, Journal: j,
		Params: t23Params(), Window: time.Second,
		Now:     func() time.Time { return time.UnixMilli(1_700_000_000_000) },
		OnAlert: func(a Alert) { alerts2 = append(alerts2, a) }, OnTrip: trips2.trip,
	})
	if err != nil {
		t.Fatal(err)
	}
	for k := int64(0); k < 601; k++ {
		for s := 0; s < 8; s++ {
			_ = d2.Feed(dripRecord(byte(s+1), "exfil.slow-leak.example", 12, k))
		}
	}
	_ = d2.Flush()
	if len(leaves2.leaves) != 0 || len(alerts2) != 0 || len(trips2.reasons) == 0 {
		t.Fatalf("journal HS : %d feuilles, %d alertes, alarmes %v", len(leaves2.leaves), len(alerts2), trips2.reasons)
	}
}
