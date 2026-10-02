package devmode

// Issue #208 (red team R-13) : l'alarme « échappatoire dev active » doit
// laisser une feuille opposable dans le registre, pas seulement un log.

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type sinkStub struct {
	leaves []registry.Leaf
	err    error
}

func (s *sinkStub) Append(_ context.Context, l registry.Leaf) (uint64, error) {
	if s.err != nil {
		return 0, s.err
	}
	s.leaves = append(s.leaves, l)
	return uint64(len(s.leaves)), nil
}

var salt16 = []byte("0123456789abcdef")

func TestRecordActiveWritesAProvableTelemetryLeaf(t *testing.T) {
	sink := &sinkStub{}
	now := func() time.Time { return time.Unix(1_800_000_000, 0) }
	flags := []string{"TBP_OPA_INSECURE_TCP_DEV", "TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE"}
	if err := RecordActive(context.Background(), sink, nil, "cell-a", salt16, flags, now); err != nil {
		t.Fatal(err)
	}
	if len(sink.leaves) != 1 {
		t.Fatalf("feuilles = %d, veut 1", len(sink.leaves))
	}
	l := sink.leaves[0]
	if l.Kind != registry.KindTelemetry || l.CellID != "cell-a" {
		t.Fatalf("feuille = kind %d cell %q", l.Kind, l.CellID)
	}
	// Preuve à révélation du sel (§6.2) : qui connaît les noms recalcule le hash.
	if l.PayloadHash != registry.HashPayload(salt16, ActiveRecord(flags)) {
		t.Fatal("la feuille n'est pas prouvable par re-hash des noms d'échappatoires")
	}
	// Et le hash NE révèle PAS les noms sans le sel.
	if l.PayloadHash == registry.HashPayload([]byte("un-autre-sel-16b"), ActiveRecord(flags)) {
		t.Fatal("le hash ne dépend pas du sel")
	}
}

func TestNoFlagsNoLeaf(t *testing.T) {
	sink := &sinkStub{}
	if err := RecordActive(context.Background(), sink, nil, "cell-a", salt16, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(sink.leaves) != 0 {
		t.Fatal("une feuille a été écrite sans aucune échappatoire active")
	}
}

// Le record est déterministe (§11.3) : l'ordre d'entrée et les doublons ne
// changent pas la feuille ; un autre ensemble d'échappatoires la change.
func TestActiveRecordIsCanonical(t *testing.T) {
	a := ActiveRecord([]string{"B", "A", "B"})
	b := ActiveRecord([]string{"A", "B"})
	if string(a) != string(b) {
		t.Fatalf("record non canonique : %q ≠ %q", a, b)
	}
	if string(ActiveRecord([]string{"A"})) == string(b) {
		t.Fatal("deux ensembles différents donnent le même record")
	}
	if string(a[:5]) != "TBDV1" || a[5] != 2 {
		t.Fatalf("en-tête = %q", a[:6])
	}
}

// Fail-closed : un démarrage dev qui ne peut pas laisser de trace est refusé.
func TestRecordActiveFailsClosedWhenTheLeafCannotBeWritten(t *testing.T) {
	sink := &sinkStub{err: errors.New("disque plein")}
	err := RecordActive(context.Background(), sink, nil, "cell-a", salt16, []string{"TBP_OPA_INSECURE_TCP_DEV"}, nil)
	if err == nil {
		t.Fatal("démarrage accepté alors que la feuille n'a pas pu être écrite")
	}
	if err := RecordActive(context.Background(), nil, nil, "cell-a", salt16, []string{"X"}, nil); err == nil {
		t.Fatal("couture feuilles absente acceptée")
	}
	if err := RecordActive(context.Background(), &sinkStub{}, nil, "", salt16, []string{"X"}, nil); err == nil {
		t.Fatal("cellID vide accepté")
	}
	if err := RecordActive(context.Background(), &sinkStub{}, nil, "cell-a", []byte("court"), []string{"X"}, nil); err == nil {
		t.Fatal("sel court accepté")
	}
}

// #275 : le clair de la feuille d'échappatoires dev est journalisé AVANT la feuille ; un journal qui refuse
// ⇒ aucune feuille ⇒ démarrage refusé.
func TestRecordActiveIsJournaled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{6}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	sink := &sinkStub{}
	now := func() time.Time { return time.Unix(1_800_000_000, 0) }
	flags := []string{"TBP_OPA_INSECURE_TCP_DEV"}
	if err := RecordActive(context.Background(), sink, j, "cell-a", salt16, flags, now); err != nil {
		t.Fatal(err)
	}
	recs, err := registry.ReadRecords(path, key)
	if err != nil || len(recs) != 1 || len(sink.leaves) != 1 {
		t.Fatalf("journal %d enregistrements (err=%v), %d feuilles", len(recs), err, len(sink.leaves))
	}
	if recs[0].Leaf != sink.leaves[0] || recs[0].VerifyHash() != nil || !bytes.Equal(recs[0].Record, ActiveRecord(flags)) {
		t.Fatalf("enregistrement inattendu : %+v", recs[0])
	}

	_ = j.Close()
	if err := RecordActive(context.Background(), sink, j, "cell-a", salt16, flags, now); err == nil {
		t.Fatal("démarrage dev accepté sans clair journalisé — fail-closed violé")
	}
	if len(sink.leaves) != 1 {
		t.Fatalf("%d feuilles : une feuille a été inscrite sans clair journalisé", len(sink.leaves))
	}
}
