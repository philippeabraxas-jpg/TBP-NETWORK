// metrics_test.go — T26 (issue #22) : tests du format de feuille de
// métriques du traducteur (§4.5). Non-vacuoles : records reconstruits à la
// main, registre tessera RÉEL en répertoire temporaire, mutations détectées.
package translator

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

// fakeMetricsLeaves capture les feuilles inscrites (couture de test —
// satisfait MetricsLeafSink).
type fakeMetricsLeaves struct {
	mu     sync.Mutex
	leaves []registry.Leaf
}

func (f *fakeMetricsLeaves) Append(_ context.Context, leaf registry.Leaf) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.leaves = append(f.leaves, leaf)
	return uint64(len(f.leaves) - 1), nil
}

func (f *fakeMetricsLeaves) snapshot() []registry.Leaf {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]registry.Leaf, len(f.leaves))
	copy(out, f.leaves)
	return out
}

var (
	metricsSalt  = []byte("t26-metrics-test-salt-32o!!") // ≥ 16 octets
	metricsCell  = "cell-t26"
	metricsClock = time.Date(2026, 9, 22, 14, 0, 0, 0, time.UTC)
)

func sampleReport(t *testing.T) MetricsReport {
	t.Helper()
	var hash [32]byte
	if _, err := hex.Decode(hash[:], []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")); err != nil {
		t.Fatalf("hash fixture: %v", err)
	}
	return MetricsReport{
		CorpusHash: hash,
		Classes: []ClassMetrics{
			{Class: "F", Positives: 1000, Negatives: 500, FalseNegatives: 0, FalsePositives: 3},
			{Class: "I", Positives: 200, Negatives: 100, FalseNegatives: 1, FalsePositives: 0},
			{Class: "W", Positives: 50, Negatives: 40, FalseNegatives: 0, FalsePositives: 1},
			{Class: "OUT", Positives: 30, Negatives: 20, FalseNegatives: 2, FalsePositives: 1},
		},
	}
}

// Le record est au format versionné EXACT : reconstruit à la main octet
// par octet (mutation du format ⇒ échec).
func TestMetricsLeafRecordExactFormat(t *testing.T) {
	report := sampleReport(t)
	record, err := MetricsLeafRecord(report)
	if err != nil {
		t.Fatalf("MetricsLeafRecord: %v", err)
	}
	want := []byte{'T', 'B', 'T', 'M', '1'}
	want = append(want, report.CorpusHash[:]...)
	want = append(want, 4) // 4 classes, triées : F, I, OUT, W
	type cls struct {
		name             string
		pos, neg, fn, fp uint32
	}
	for _, c := range []cls{
		{"F", 1000, 500, 0, 3},
		{"I", 200, 100, 1, 0},
		{"OUT", 30, 20, 2, 1},
		{"W", 50, 40, 0, 1},
	} {
		want = append(want, byte(len(c.name)))
		want = append(want, c.name...)
		for _, v := range []uint32{c.pos, c.neg, c.fn, c.fp} {
			want = append(want, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
		}
	}
	if len(record) != len(want) {
		t.Fatalf("record %d octets, attendu %d", len(record), len(want))
	}
	for i := range want {
		if record[i] != want[i] {
			t.Fatalf("record[%d] = %d, attendu %d (record %x)", i, record[i], want[i], record)
		}
	}
}

// Ordre d'entrée quelconque ⇒ même record (déterminisme du hash).
func TestMetricsLeafRecordSortedDeterministic(t *testing.T) {
	report := sampleReport(t)
	first, err := MetricsLeafRecord(report)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	// Renverse l'ordre des classes.
	for i, j := 0, len(report.Classes)-1; i < j; i, j = i+1, j-1 {
		report.Classes[i], report.Classes[j] = report.Classes[j], report.Classes[i]
	}
	second, err := MetricsLeafRecord(report)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(first) != len(second) {
		t.Fatal("records de longueurs différentes selon l'ordre d'entrée")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("record non déterministe à l'octet %d", i)
		}
	}
}

// TestMetricsLeafRecordDuplicateClassRejected : deux classes de même nom
// sont une entrée ambiguë (revue de PR #80) — le comparateur de tri ne les
// départage jamais (il ne compare que Class), donc sort.Slice (non
// documenté stable) peut les laisser dans un ordre qui dépend de l'ordre
// d'ENTRÉE. Prouvé empiriquement avant fix : le même rapport « dupliqué »
// fourni dans deux ordres produisait deux records (et deux hash)
// DIFFÉRENTS — violation directe de la garantie documentée par
// MetricsLeafRecord (« quiconque reconstruit le record retrouve le même
// hash »). Fail-closed : rejet explicite plutôt qu'un ordre arbitraire.
func TestMetricsLeafRecordDuplicateClassRejected(t *testing.T) {
	var hash [32]byte
	hash[0] = 0xAB
	a := ClassMetrics{Class: "F", Positives: 10, Negatives: 5, FalseNegatives: 1, FalsePositives: 1}
	b := ClassMetrics{Class: "F", Positives: 20, Negatives: 8, FalseNegatives: 2, FalsePositives: 2}

	if _, err := MetricsLeafRecord(MetricsReport{CorpusHash: hash, Classes: []ClassMetrics{a, b}}); !errors.Is(err, ErrMetricsDuplicateClass) {
		t.Fatalf("err=%v, attendu ErrMetricsDuplicateClass", err)
	}
	if _, err := MetricsLeafRecord(MetricsReport{CorpusHash: hash, Classes: []ClassMetrics{b, a}}); !errors.Is(err, ErrMetricsDuplicateClass) {
		t.Fatalf("ordre inversé : err=%v, attendu ErrMetricsDuplicateClass", err)
	}
}

func TestMetricsReportFromJSON(t *testing.T) {
	// Forme exacte de la sortie measure.py --out.
	raw := `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",` +
		`"classes":[{"class":"F","positives":1000,"negatives":500,"false_negatives":0,"false_positives":3}]}`
	report, err := MetricsReportFromJSON([]byte(raw))
	if err != nil {
		t.Fatalf("MetricsReportFromJSON: %v", err)
	}
	if report.Classes[0].Class != "F" || report.Classes[0].FalsePositives != 3 {
		t.Fatalf("rapport mal parsé : %+v", report.Classes[0])
	}

	cases := []struct {
		name string
		json string
	}{
		{"version inconnue", `{"version":2,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[]}`},
		{"hash trop court", `{"version":1,"corpus_hash":"abcd","classes":[]}`},
		{"hash non hex", `{"version":1,"corpus_hash":"zz3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[]}`},
		{"classe vide", `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[{"class":"","positives":1,"negatives":1,"false_negatives":0,"false_positives":0}]}`},
		{"classe trop longue", `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[{"class":"TROPLONGUE","positives":1,"negatives":1,"false_negatives":0,"false_positives":0}]}`},
		{"FN > positifs", `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[{"class":"F","positives":1,"negatives":1,"false_negatives":2,"false_positives":0}]}`},
		{"FP > négatifs", `{"version":1,"corpus_hash":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","classes":[{"class":"F","positives":1,"negatives":1,"false_negatives":0,"false_positives":2}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MetricsReportFromJSON([]byte(tc.json)); err == nil {
				t.Fatalf("rapport %q accepté — fail-open", tc.name)
			}
		})
	}
}

func TestAppendMetricsLeafFailClosedConfig(t *testing.T) {
	report := sampleReport(t)
	sink := &fakeMetricsLeaves{}
	ctx := context.Background()
	if _, err := AppendMetricsLeaf(ctx, sink, "", metricsSalt, report, metricsClock); err == nil {
		t.Fatal("cellID vide accepté")
	}
	if _, err := AppendMetricsLeaf(ctx, sink, metricsCell, []byte("court"), report, metricsClock); err == nil {
		t.Fatal("sel < 16 octets accepté")
	}
	if _, err := AppendMetricsLeaf(ctx, nil, metricsCell, metricsSalt, report, metricsClock); err == nil {
		t.Fatal("couture feuilles absente acceptée")
	}
}

// La feuille inscrite est hash-only au hash EXACT du record (reconstruit
// par une voie indépendante) — mutation du sel ou du record ⇒ échec.
func TestAppendMetricsLeafHashOnlyExact(t *testing.T) {
	report := sampleReport(t)
	sink := &fakeMetricsLeaves{}
	at := metricsClock
	if _, err := AppendMetricsLeaf(context.Background(), sink, metricsCell, metricsSalt, report, at); err != nil {
		t.Fatalf("AppendMetricsLeaf: %v", err)
	}
	leaves := sink.snapshot()
	if len(leaves) != 1 {
		t.Fatalf("%d feuilles, attendu 1", len(leaves))
	}
	leaf := leaves[0]
	if leaf.Kind != registry.KindTelemetry {
		t.Fatalf("kind %d, attendu KindTelemetry", leaf.Kind)
	}
	if leaf.CellID != metricsCell {
		t.Fatalf("cellID %q, attendu %q", leaf.CellID, metricsCell)
	}
	if leaf.Timestamp != at.UnixNano() {
		t.Fatalf("timestamp %d, attendu %d", leaf.Timestamp, at.UnixNano())
	}
	record, err := MetricsLeafRecord(report)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if want := registry.HashPayload(metricsSalt, record); leaf.PayloadHash != want {
		t.Fatalf("hash feuille %x, attendu %x", leaf.PayloadHash, want)
	}
	// Le record ne contient AUCUN contenu de corpus : seuls comptages et
	// hash — vérifié structurellement par la taille maximale du record.
	if len(record) > 5+32+1+len(report.Classes)*(1+8+16) {
		t.Fatalf("record anormalement gros (%d octets) — du contenu s'y serait glissé", len(record))
	}
}

// Intégration registre RÉEL : la feuille entre dans un log tessera en
// répertoire temporaire et ressort par un scan VÉRIFIÉ (ChainWatcher T34 :
// checkpoint signé + cohérence Merkle) — jamais une lecture naïve.
func TestAppendMetricsLeafRealRegistry(t *testing.T) {
	dir := t.TempDir()
	skey, vkey, err := registry.GenerateCellKey(metricsCell)
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	if err := registry.SaveSignerKey(dir, skey); err != nil {
		t.Fatalf("SaveSignerKey: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cell_log.vkey"), []byte(vkey), 0o644); err != nil {
		t.Fatalf("vkey: %v", err)
	}
	signer, err := registry.LoadSigner(dir)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	ctx := context.Background()
	log, err := registry.Open(ctx, registry.Options{Dir: dir, Signer: signer, Verifier: verifier})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = log.Close(context.Background()) }()

	report := sampleReport(t)
	idx, err := AppendMetricsLeaf(ctx, log, metricsCell, metricsSalt, report, metricsClock)
	if err != nil {
		t.Fatalf("AppendMetricsLeaf: %v", err)
	}

	// Scan vérifié (checkpoint signé + Merkle) — même motif que le selftest.
	verifier2, err := registry.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	boot, w, err := supervision.NewChainWatcher(ctx, metricsCell, dir, metricsCell, verifier2, 0)
	if err != nil {
		t.Fatalf("NewChainWatcher: %v", err)
	}
	more, err := w.Tick(ctx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	leaves := append(boot, more...)
	if int(idx) >= len(leaves) {
		t.Fatalf("indice %d hors du log scanné (%d feuilles)", idx, len(leaves))
	}
	record, err := MetricsLeafRecord(report)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	want := registry.HashPayload(metricsSalt, record)
	found := false
	for _, l := range leaves {
		if l.Kind == registry.KindTelemetry && l.PayloadHash == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("feuille de métriques absente du scan vérifié (%d feuilles)", len(leaves))
	}
}
