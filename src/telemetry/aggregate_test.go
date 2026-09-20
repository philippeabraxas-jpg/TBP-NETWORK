package telemetry

// Tests du pipeline d'agrégation télémétrie → feuilles registre (T22).
//
// Critères d'acceptation de l'issue :
//   - chaque fenêtre agrégée produit EXACTEMENT une feuille (agrégats +
//     hash salé, rien en clair) — TestExactlyOneLeafPerWindow,
//     TestAggregateHashMatchesRecompute, TestEmptyWindowLeafHashOnly ;
//   - la purge de rétention est effective et tracée —
//     TestRetentionPurgeEffectiveAndTraced, TestPurgeFailureKeepsBatch ;
//   - un auditeur peut re-vérifier la correspondance agrégat ↔ records
//     bruts tant qu'ils existent — TestVerifyBeforeAndAfterPurge.
//
// Les helpers (fakeSource, sinkRecorder, leafRecorder, tripRecorder,
// jtiOf, newTestExporter) sont partagés avec exporter_test.go.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

var t22Salt = []byte("sel-de-test-32-octets-pour-t22!!!")

func aggRec(b byte, resource string, octets uint64) Record {
	return Record{
		JTI: jtiOf(b), CellID: "cell-alpha-01", Resource: resource, Operation: "op",
		OctetDelta: octets, FlowStart: 0, FlowEnd: 500,
	}
}

func newTestAgg(t *testing.T, leaves *leafRecorder, store *RetentionStore, nowMs *atomic.Int64, window time.Duration) *Aggregator {
	t.Helper()
	a, err := NewAggregator(AggregatorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves,
		Window: window, RetStore: store,
		Now: func() time.Time { return time.UnixMilli(nowMs.Load()) },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	return a
}

func newTestStore(t *testing.T, leaves *leafRecorder, nowMs *atomic.Int64, ttl time.Duration, maxBatches int, trips *tripRecorder) *RetentionStore {
	t.Helper()
	s, err := NewRetentionStore(RetentionOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves,
		TTL: ttl, MaxBatches: maxBatches,
		Now:    func() time.Time { return time.UnixMilli(nowMs.Load()) },
		OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewRetentionStore: %v", err)
	}
	return s
}

// ---------------------------------------------------------------------------
// Constructeurs fail-closed (§1).
// ---------------------------------------------------------------------------

func TestAggregatorOptionsFailClosed(t *testing.T) {
	leaves := &leafRecorder{}
	cases := []struct {
		name string
		mut  func(*AggregatorOptions)
		want error
	}{
		{"cellID manquant", func(o *AggregatorOptions) { o.CellID = "" }, ErrCellIDRequired},
		{"sel < 16 o", func(o *AggregatorOptions) { o.Salt = make([]byte, 8) }, ErrSaltTooShort},
		{"registre manquant", func(o *AggregatorOptions) { o.Leaves = nil }, ErrLeavesRequired},
		{"fenêtre négative", func(o *AggregatorOptions) { o.Window = -time.Second }, ErrWindowInvalid},
		// revue T22 : positive mais < 1 ms (typo d'unité plausible, ex.
		// time.Microsecond au lieu de time.Millisecond) — passait la seule
		// borne "< 0" pour ensuite paniquer (division par zéro) au premier
		// Feed()/Tick()/Seal(), au lieu d'un refus net à la configuration.
		{"fenêtre positive mais < 1 ms", func(o *AggregatorOptions) { o.Window = 500 * time.Microsecond }, ErrWindowInvalid},
		{"top-k négatif", func(o *AggregatorOptions) { o.TopK = -1 }, ErrTopKInvalid},
		{"top-k > 255", func(o *AggregatorOptions) { o.TopK = 256 }, ErrTopKInvalid},
	}
	for _, tc := range cases {
		opts := AggregatorOptions{CellID: "c", Salt: t22Salt, Leaves: leaves}
		tc.mut(&opts)
		if _, err := NewAggregator(opts); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, attendu %v", tc.name, err, tc.want)
		}
	}
	// défauts documentés : fenêtre 60 s, k = 10
	a, err := NewAggregator(AggregatorOptions{CellID: "c", Salt: t22Salt, Leaves: leaves})
	if err != nil {
		t.Fatalf("défauts: %v", err)
	}
	if a.window != defaultWindow || a.topK != defaultTopK {
		t.Errorf("défauts = %v / %d, attendu %v / %d", a.window, a.topK, defaultWindow, defaultTopK)
	}
}

func TestRetentionOptionsFailClosed(t *testing.T) {
	leaves := &leafRecorder{}
	cases := []struct {
		name string
		mut  func(*RetentionOptions)
		want error
	}{
		{"cellID manquant", func(o *RetentionOptions) { o.CellID = "" }, ErrCellIDRequired},
		{"sel < 16 o", func(o *RetentionOptions) { o.Salt = make([]byte, 8) }, ErrSaltTooShort},
		{"registre manquant", func(o *RetentionOptions) { o.Leaves = nil }, ErrLeavesRequired},
		{"TTL négatif", func(o *RetentionOptions) { o.TTL = -time.Hour }, ErrTTLInvalid},
		// revue T22 : positif mais < 1 ms — même piège que le TTL négatif,
		// mais silencieux : PurgeExpired() (comparaison en millisecondes)
		// purgeait alors tout lot dès son premier appel, quel que soit son
		// âge réel — la politique de rétention (§6.2) annulée sans le
		// moindre refus à la configuration. Ex. réaliste : "TTL: 24" en
		// voulant 24h, en oubliant "* time.Hour" (24 devient 24 ns).
		{"TTL positif mais < 1 ms", func(o *RetentionOptions) { o.TTL = 24 }, ErrTTLInvalid},
		{"borne négative", func(o *RetentionOptions) { o.MaxBatches = -1 }, ErrMaxBatchesInvalid},
	}
	for _, tc := range cases {
		opts := RetentionOptions{CellID: "c", Salt: t22Salt, Leaves: leaves}
		tc.mut(&opts)
		if _, err := NewRetentionStore(opts); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, attendu %v", tc.name, err, tc.want)
		}
	}
	s, err := NewRetentionStore(RetentionOptions{CellID: "c", Salt: t22Salt, Leaves: leaves})
	if err != nil {
		t.Fatalf("défauts: %v", err)
	}
	if s.ttl != defaultRetentionTTL || s.max != defaultMaxBatches {
		t.Errorf("défauts = %v / %d, attendu %v / %d", s.ttl, s.max, defaultRetentionTTL, defaultMaxBatches)
	}
}

// ---------------------------------------------------------------------------
// EXACTEMENT une feuille par fenêtre, y compris vide (D22).
// ---------------------------------------------------------------------------

func TestExactlyOneLeafPerWindow(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{} // t = 0
	agg := newTestAgg(t, leaves, nil, nowMs, time.Second)

	agg.Feed(aggRec(0x01, "res-a", 100))
	agg.Feed(aggRec(0x02, "res-b", 200))
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick même fenêtre: %v", err)
	}
	if len(leaves.leaves) != 0 {
		t.Fatalf("fenêtre courante scellée prématurément : %d feuilles", len(leaves.leaves))
	}

	nowMs.Store(1000) // fenêtre 0 écoulée
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(leaves.leaves) != 1 {
		t.Fatalf("feuilles = %d, attendu 1", len(leaves.leaves))
	}
	if leaves.leaves[0].Kind != registry.KindTelemetry || leaves.leaves[0].CellID != "cell-alpha-01" {
		t.Errorf("feuille = %+v", leaves.leaves[0])
	}

	// trois fenêtres vides consécutives : trois feuilles — la continuité
	// de la piste est un signal (D22), le volume est négligeable.
	nowMs.Store(4000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick vides: %v", err)
	}
	if len(leaves.leaves) != 4 {
		t.Fatalf("feuilles = %d, attendu 4 (1 pleine + 3 vides)", len(leaves.leaves))
	}
	st := agg.Stats()
	if st.WindowsSealed != 4 || st.LeavesWritten != 4 || st.RecordsIn != 2 {
		t.Errorf("stats = %+v", st)
	}
	// Tick idempotent : rien de plus tant que la fenêtre n'a pas basculé
	if err := agg.Tick(); err != nil || len(leaves.leaves) != 4 {
		t.Errorf("Tick idempotent : err=%v feuilles=%d", err, len(leaves.leaves))
	}
}

// Une fenêtre vide produit une feuille d'agrégat NUL — racine de Merkle
// nulle, aucun lot brut à retenir.
func TestEmptyWindowLeafHashOnly(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	trips := &tripRecorder{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 8, trips)
	agg := newTestAgg(t, leaves, store, nowMs, time.Second)

	agg.Feed(aggRec(0x01, "res-a", 10)) // ouvre la fenêtre 0
	nowMs.Store(2000)                   // scelle 0 et 1 (vide)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(leaves.leaves) != 2 {
		t.Fatalf("feuilles = %d", len(leaves.leaves))
	}
	// feuille de la fenêtre vide : rejouer l'agrégat nul
	empty := buildAggregate("cell-alpha-01", 1, 1000, 2000, nil, t22Salt, defaultTopK)
	if empty.RecordsRoot != [32]byte{} || empty.Flows != 0 || len(empty.DstTop) != 0 {
		t.Fatalf("agrégat vide = %+v", empty)
	}
	if want := registry.HashPayload(t22Salt, aggregateBytes(empty)); leaves.leaves[1].PayloadHash != want {
		t.Errorf("feuille fenêtre vide ≠ hash(agrégat nul)")
	}
	// rien à retenir pour une fenêtre vide
	if _, ok := store.Batch(1); ok {
		t.Errorf("fenêtre vide : un lot brut ne devrait pas exister")
	}
	if st := agg.Stats(); st.BatchesStored != 1 {
		t.Errorf("BatchesStored = %d, attendu 1 (fenêtre 0 uniquement)", st.BatchesStored)
	}
}

// ---------------------------------------------------------------------------
// Correspondance agrégat ↔ hash de feuille (critère d'acceptation).
// ---------------------------------------------------------------------------

func TestAggregateHashMatchesRecompute(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 8, &tripRecorder{})
	agg := newTestAgg(t, leaves, store, nowMs, time.Second)

	recs := []Record{
		aggRec(0x01, "res-a", 100),
		aggRec(0x02, "res-b", 200),
		aggRec(0x03, "res-a", 50),
	}
	for _, r := range recs {
		if err := agg.Feed(r); err != nil {
			t.Fatalf("Feed: %v", err)
		}
	}
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	leaf := leaves.leaves[0]

	// re-vérification auditeur (D25) : le store recalcule tout depuis les bruts
	ok, err := store.Verify(0, leaf.PayloadHash)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}

	// recompute manuel indépendant
	batch, exists := store.Batch(0)
	if !exists {
		t.Fatal("lot brut absent")
	}
	rebuilt := buildAggregate("cell-alpha-01", 0, 0, 1000, recs, t22Salt, len(batch.Aggregate.DstTop))
	if rebuilt.Flows != 3 || rebuilt.BytesOut != 350 {
		t.Errorf("agrégat = %d flux / %d octets", rebuilt.Flows, rebuilt.BytesOut)
	}
	if want := registry.HashPayload(t22Salt, aggregateBytes(rebuilt)); leaf.PayloadHash != want {
		t.Errorf("feuille ≠ sha256(sel ‖ TBAG1) recalculé")
	}
	// le hash de la feuille est bien celui stocké comme lien d'audit
	if batch.LeafHash != leaf.PayloadHash {
		t.Errorf("LeafHash du lot ≠ payload de la feuille")
	}
	// RIEN EN CLAIR : les destinations ne sont pas dans la sérialisation
	if bytes.Contains(aggregateBytes(rebuilt), []byte("res-a")) {
		t.Errorf("TBAG1 contient une destination en clair")
	}
}

// La racine de Merkle réutilise l'engagement TBTM1 de T21 : un record
// seul ⇒ racine == HashPayload(sel, TBTM1(record)) — la feuille record
// de T21 et la fenêtre T22 portent le MÊME engagement.
func TestMerkleMatchesT21Commitment(t *testing.T) {
	r := aggRec(0x0A, "res-x", 42)
	agg := buildAggregate("cell-alpha-01", 0, 0, 1000, []Record{r}, t22Salt, 10)
	if want := registry.HashPayload(t22Salt, telemetryRecord(r)); agg.RecordsRoot != want {
		t.Errorf("racine (1 record) ≠ engagement T21")
	}

	// trois records : h(h(c1,c2), h(c3,c3)) — feuille impaire dupliquée
	recs := []Record{aggRec(0x01, "a", 1), aggRec(0x02, "b", 2), aggRec(0x03, "c", 3)}
	agg3 := buildAggregate("cell-alpha-01", 0, 0, 1000, recs, t22Salt, 10)
	pair := func(x, y [32]byte) [32]byte {
		h := sha256.New()
		h.Write(x[:])
		h.Write(y[:])
		var o [32]byte
		copy(o[:], h.Sum(nil))
		return o
	}
	c := make([][32]byte, 3)
	for i, rr := range recs {
		c[i] = registry.HashPayload(t22Salt, telemetryRecord(rr))
	}
	if want := pair(pair(c[0], c[1]), pair(c[2], c[2])); agg3.RecordsRoot != want {
		t.Errorf("racine (3 records) ≠ arbre attendu")
	}
}

// ---------------------------------------------------------------------------
// Top-k : haché+salé, déterministe (§11.3), rien en clair.
// ---------------------------------------------------------------------------

func TestDstTopHashedSaltedDeterministic(t *testing.T) {
	recs := make([]Record, 0, 12)
	for i := 0; i < 12; i++ {
		// octets décroissants : le gagnant attendu est dst-00 … dst-09
		recs = append(recs, aggRec(byte(i+1), fmt.Sprintf("dst-alpha-unique-%02d", i), uint64(1200-100*i)))
	}
	a1 := buildAggregate("cell-alpha-01", 0, 0, 1000, recs, t22Salt, 10)
	a2 := buildAggregate("cell-alpha-01", 0, 0, 1000, recs, t22Salt, 10)
	if len(a1.DstTop) != 10 {
		t.Fatalf("top-k = %d, attendu 10", len(a1.DstTop))
	}
	for i := 0; i < 10; i++ {
		want := hashDestination(t22Salt, fmt.Sprintf("dst-alpha-unique-%02d", i))
		if a1.DstTop[i] != want {
			t.Errorf("DstTop[%d] ≠ sha256(sel ‖ dst-%02d)", i, i)
		}
		if a1.DstTop[i] != a2.DstTop[i] {
			t.Errorf("top-k non déterministe à l'indice %d", i)
		}
	}
	// la destination en clair n'apparaît NULLE PART dans la feuille
	if strings.Contains(string(aggregateBytes(a1)), "dst-alpha-unique") {
		t.Errorf("destination en clair dans TBAG1")
	}
	// égalité d'octets : tie-break déterministe par hash croissant
	tie := []Record{
		aggRec(0x21, "tie-b", 100), aggRec(0x22, "tie-a", 100),
	}
	ta := buildAggregate("cell-alpha-01", 0, 0, 1000, tie, t22Salt, 10)
	tb := buildAggregate("cell-alpha-01", 0, 0, 1000, []Record{tie[1], tie[0]}, t22Salt, 10)
	if ta.DstTop[0] != tb.DstTop[0] || ta.DstTop[1] != tb.DstTop[1] {
		t.Errorf("tie-break non déterministe")
	}
	hb, ha := hashDestination(t22Salt, "tie-b"), hashDestination(t22Salt, "tie-a")
	first, second := ha, hb
	if bytes.Compare(hb[:], ha[:]) < 0 {
		first, second = hb, ha
	}
	if ta.DstTop[0] != first || ta.DstTop[1] != second {
		t.Errorf("ordre de tie-break ≠ hash croissant")
	}
}

// ---------------------------------------------------------------------------
// Bout en bout : exporteur T21 réel → agrégateur via la couture RecordSink
// (D21 — l'exporteur n'est pas modifié).
// ---------------------------------------------------------------------------

func TestEndToEndExporterToAggregator(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x01), Resource: "10.20.30.40", Operation: "egress", Consumed: 1500},
		{JTI: jtiOf(0x02), Resource: "https://api.example.com/v1/messages", Operation: "POST", Consumed: 42},
	}}
	nowMs := &atomic.Int64{}
	nowMs.Store(1_700_000_000_000)
	leaves := &leafRecorder{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 8, &tripRecorder{})
	agg := newTestAgg(t, leaves, store, nowMs, time.Second)

	// l'exporteur T21 alimente l'agrégateur comme n'importe quel sink
	e := newTestExporter(src, agg, nowMs)
	if n := e.ExportOnce(); n != 2 {
		t.Fatalf("records exportés = %d", n)
	}
	if st := agg.Stats(); st.RecordsIn != 2 {
		t.Fatalf("records reçus = %d", st.RecordsIn)
	}

	nowMs.Add(1000) // fenêtre écoulée
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(leaves.leaves) != 1 {
		t.Fatalf("feuilles = %d", len(leaves.leaves))
	}
	leaf := leaves.leaves[0]
	wid := int64(1_700_000_000_000) / 1000
	batch, ok := store.Batch(wid)
	if !ok {
		t.Fatalf("lot brut fenêtre %d absent", wid)
	}
	if len(batch.Records) != 2 {
		t.Fatalf("records du lot = %d", len(batch.Records))
	}
	if batch.Records[0].OctetDelta != 1500 || batch.Records[0].Resource != "10.20.30.40" {
		t.Errorf("record 0 = %+v", batch.Records[0])
	}
	if ok, err := store.Verify(wid, leaf.PayloadHash); err != nil || !ok {
		t.Errorf("Verify = %v, %v", ok, err)
	}
	if batch.Aggregate.BytesOut != 1542 || batch.Aggregate.Flows != 2 {
		t.Errorf("agrégat = %d octets / %d flux", batch.Aggregate.BytesOut, batch.Aggregate.Flows)
	}
}

// ---------------------------------------------------------------------------
// Rétention : purge EFFECTIVE et TRACÉE (§6.2) — critère d'acceptation.
// ---------------------------------------------------------------------------

func TestRetentionPurgeEffectiveAndTraced(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 8, &tripRecorder{})
	agg := newTestAgg(t, leaves, store, nowMs, time.Second)

	agg.Feed(aggRec(0x01, "res-a", 100))
	agg.Feed(aggRec(0x02, "res-b", 200))
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	batch, ok := store.Batch(0)
	if !ok {
		t.Fatal("lot brut absent avant purge")
	}

	// pas encore expiré : purge sans effet
	nowMs.Store(1000 + time.Hour.Milliseconds() - 1)
	if n := store.PurgeExpired(); n != 0 {
		t.Fatalf("purge prématurée : %d", n)
	}
	if _, ok := store.Batch(0); !ok {
		t.Fatal("lot détruit avant expiration du TTL")
	}

	// TTL écoulé : purge effective + feuille KindRetentionPurge
	nowMs.Store(1000 + time.Hour.Milliseconds())
	purgeAt := nowMs.Load()
	if n := store.PurgeExpired(); n != 1 {
		t.Fatalf("purgés = %d, attendu 1", n)
	}
	if _, ok := store.Batch(0); ok {
		t.Fatal("lot encore présent après purge — purge non effective")
	}
	if len(leaves.leaves) != 2 {
		t.Fatalf("feuilles = %d, attendu 2 (agrégat + purge)", len(leaves.leaves))
	}
	pl := leaves.leaves[1]
	if pl.Kind != registry.KindRetentionPurge {
		t.Fatalf("kind = %d, attendu KindRetentionPurge", pl.Kind)
	}
	if pl.CellID != "cell-alpha-01" {
		t.Errorf("cellID purge = %q", pl.CellID)
	}
	// la feuille de purge prouve QUOI a été détruit — hash salé du manifeste
	want := registry.HashPayload(t22Salt, purgeManifest("cell-alpha-01", batch, purgeAt))
	if pl.PayloadHash != want {
		t.Errorf("feuille de purge ≠ sha256(sel ‖ manifeste TBRP1)")
	}
	// la feuille de purge sérialise au format registre standard
	if _, err := pl.Marshal(); err != nil {
		t.Errorf("feuille de purge non sérialisable: %v", err)
	}
	st := store.Stats()
	if st.BatchesPurged != 1 || st.PurgeLeaves != 1 || st.BatchesStored != 0 {
		t.Errorf("stats = %+v", st)
	}
}

// Registre en panne pendant la purge : le lot N'EST PAS détruit —
// pas de trace, pas de destruction (§9.1) ; échec compté et alarmé (§5.3).
func TestPurgeFailureKeepsBatch(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	trips := &tripRecorder{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 8, trips)
	agg := newTestAgg(t, leaves, store, nowMs, time.Second)

	agg.Feed(aggRec(0x01, "res-a", 100))
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	nowMs.Store(1000 + time.Hour.Milliseconds())

	leaves.err = errors.New("registre en panne")
	if n := store.PurgeExpired(); n != 0 {
		t.Fatalf("purgés = %d malgré la panne", n)
	}
	if _, ok := store.Batch(0); !ok {
		t.Fatal("lot détruit sans trace — interdit (§9.1)")
	}
	if len(trips.reasons) != 1 || trips.reasons[0] != pep.ReasonLeafWriteFailed {
		t.Errorf("alarmes = %v", trips.reasons)
	}
	if st := store.Stats(); st.PurgeFailures != 1 {
		t.Errorf("PurgeFailures = %d", st.PurgeFailures)
	}

	// registre rétabli : la purge reprend, tracée
	leaves.err = nil
	if n := store.PurgeExpired(); n != 1 {
		t.Fatalf("purge après rétablissement = %d", n)
	}
	if leaves.leaves[len(leaves.leaves)-1].Kind != registry.KindRetentionPurge {
		t.Error("la purge reprend sans feuille de trace")
	}
}

// Store plein : fail-closed — ErrStoreFull, alarme, et le lot existant
// n'est JAMAIS détruit pour faire de la place (§4.3).
func TestStoreFullAlarms(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	trips := &tripRecorder{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 1, trips) // borne à 1 lot
	agg, err := NewAggregator(AggregatorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves,
		Window: time.Second, RetStore: store,
		Now:    func() time.Time { return time.UnixMilli(nowMs.Load()) },
		OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	agg.Feed(aggRec(0x01, "res-a", 100))
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick 1: %v", err)
	}
	agg.Feed(aggRec(0x02, "res-b", 200)) // fenêtre 1
	nowMs.Store(2000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick 2: %v", err)
	}

	// la feuille de la fenêtre 1 EST écrite (l'agrégat ne dépend pas du
	// store) mais le brut n'est pas retenu : compté et alarmé.
	if len(leaves.leaves) != 2 {
		t.Fatalf("feuilles = %d", len(leaves.leaves))
	}
	if len(trips.reasons) != 1 || trips.reasons[0] != ReasonStoreFull {
		t.Errorf("alarmes = %v, attendu [%s]", trips.reasons, ReasonStoreFull)
	}
	if st := agg.Stats(); st.StoreFailures != 1 || st.BatchesStored != 1 {
		t.Errorf("stats = %+v", st)
	}
	if _, ok := store.Batch(0); !ok {
		t.Error("lot 0 détruit pour faire de la place — interdit")
	}
	if _, ok := store.Batch(1); ok {
		t.Error("lot 1 retenu malgré ErrStoreFull")
	}
}

// ---------------------------------------------------------------------------
// Vérifiabilité auditeur — avant purge OK, après purge impossible (§6.2).
// ---------------------------------------------------------------------------

func TestVerifyBeforeAndAfterPurge(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	store := newTestStore(t, leaves, nowMs, time.Hour, 8, &tripRecorder{})
	agg := newTestAgg(t, leaves, store, nowMs, time.Second)

	agg.Feed(aggRec(0x01, "res-a", 100))
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	leaf := leaves.leaves[0]

	if ok, err := store.Verify(0, leaf.PayloadHash); err != nil || !ok {
		t.Fatalf("Verify avant purge = %v, %v", ok, err)
	}
	// hash falsifié : rejeté
	bad := leaf.PayloadHash
	bad[0] ^= 0xFF
	if ok, err := store.Verify(0, bad); err != nil || ok {
		t.Errorf("Verify(hash falsifié) = %v, %v — devrait être false", ok, err)
	}
	// fenêtre inconnue : non re-vérifiable
	if _, err := store.Verify(999, leaf.PayloadHash); !errors.Is(err, ErrBatchGone) {
		t.Errorf("Verify fenêtre inconnue: %v", err)
	}
	// après purge : la correspondance n'est plus re-vérifiable — c'est le
	// sens de la rétention (§6.2)
	nowMs.Store(1000 + time.Hour.Milliseconds())
	store.PurgeExpired()
	if _, err := store.Verify(0, leaf.PayloadHash); !errors.Is(err, ErrBatchGone) {
		t.Errorf("Verify après purge: %v, attendu ErrBatchGone", err)
	}
}

// ---------------------------------------------------------------------------
// Déterminisme §11.3 : mêmes entrées ⇒ même feuille, à l'octet près.
// ---------------------------------------------------------------------------

func TestDeterministicAggregateAndLeaf(t *testing.T) {
	recs := []Record{
		aggRec(0x01, "res-a", 100),
		aggRec(0x02, "res-b", 200),
		aggRec(0x03, "res-a", 50),
	}
	a := buildAggregate("cell-alpha-01", 7, 7000, 8000, recs, t22Salt, 10)
	b := buildAggregate("cell-alpha-01", 7, 7000, 8000, recs, t22Salt, 10)
	if !bytes.Equal(aggregateBytes(a), aggregateBytes(b)) {
		t.Fatal("aggregateBytes non déterministe")
	}
	if string(aggregateBytes(a)[:5]) != "TBAG1" {
		t.Errorf("préfixe = %q", aggregateBytes(a)[:5])
	}
	if a.RecordsRoot != b.RecordsRoot {
		t.Fatal("racine de Merkle non déterministe")
	}

	// deux agrégateurs alimentés à l'identique ⇒ même payload de feuille
	leaves1, leaves2 := &leafRecorder{}, &leafRecorder{}
	nowMs := &atomic.Int64{}
	agg1 := newTestAgg(t, leaves1, nil, nowMs, time.Second)
	agg2 := newTestAgg(t, leaves2, nil, nowMs, time.Second)
	for _, r := range recs {
		agg1.Feed(r)
		agg2.Feed(r)
	}
	nowMs.Store(1000)
	agg1.Tick()
	agg2.Tick()
	if leaves1.leaves[0].PayloadHash != leaves2.leaves[0].PayloadHash {
		t.Error("deux pipelines identiques ⇒ feuilles différentes")
	}
}

// ---------------------------------------------------------------------------
// La feuille d'agrégat passe par le format registre standard (T4) —
// kind KindTelemetry accepté, sérialisation ronde.
// ---------------------------------------------------------------------------

func TestAggregateLeafMarshalsThroughRegistry(t *testing.T) {
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	agg := newTestAgg(t, leaves, nil, nowMs, time.Second)
	agg.Feed(aggRec(0x01, "res-a", 100))
	nowMs.Store(1000)
	if err := agg.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	raw, err := leaves.leaves[0].Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := registry.UnmarshalLeaf(raw)
	if err != nil {
		t.Fatalf("UnmarshalLeaf: %v", err)
	}
	if back.Kind != registry.KindTelemetry || back.CellID != "cell-alpha-01" ||
		back.PayloadHash != leaves.leaves[0].PayloadHash {
		t.Errorf("round-trip feuille = %+v", back)
	}
}
