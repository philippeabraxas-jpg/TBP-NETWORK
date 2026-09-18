// src/registry/anchor_test.go — T6 (issue #6)
//
// Tests de l'ancrage master chain contre de VRAIS CellLog Tessera POSIX
// (cellule ET master chain — même mécanique §7.1) et un TSA factice
// déterministe. Le client TSA fil est testé séparément (tsa_test.go)
// contre une fixture réelle.
package registry

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Factices de test
// ---------------------------------------------------------------------------

// fakeClock est une horloge contrôlée — la couture Clock de l'ancreur.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeTSA est un TSAClient déterministe : genTime et erreur pilotés par
// le test, compteur d'appels pour vérifier les cadences.
type fakeTSA struct {
	mu      sync.Mutex
	genTime func() time.Time
	err     error
	token   []byte
	calls   int
}

func (f *fakeTSA) Timestamp(_ context.Context, _ [32]byte) (Stamp, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return Stamp{}, f.err
	}
	token := f.token
	if token == nil {
		token = []byte("jeton-tsa-de-test")
	}
	return Stamp{
		GenTime: f.genTime().UTC(),
		Policy:  "1.2.3.4.1",
		Serial:  []byte{0x01},
		Token:   token,
		Source:  "fake-tsa",
	}, nil
}

func (f *fakeTSA) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// stubMaster est une MasterChain pilotable : échec tant que failing est
// vrai, puis inscription en mémoire avec indices contigus.
type stubMaster struct {
	mu      sync.Mutex
	failing atomic.Bool
	leaves  []Leaf
}

func (s *stubMaster) Append(_ context.Context, leaf Leaf) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failing.Load() {
		return 0, errors.New("master chain injoignable")
	}
	idx := uint64(len(s.leaves))
	s.leaves = append(s.leaves, leaf)
	return idx, nil
}

func (s *stubMaster) taken() []Leaf {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Leaf(nil), s.leaves...)
}

// anchorTripLog capture les alarmes pour les assertions exactly-once.
type anchorTripLog struct {
	mu     sync.Mutex
	alarms []AnchorAlarm
}

func (l *anchorTripLog) add(a AnchorAlarm) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.alarms = append(l.alarms, a)
}

func (l *anchorTripLog) count(reason string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, a := range l.alarms {
		if a.Reason == reason {
			n++
		}
	}
	return n
}

func (l *anchorTripLog) has(reason string) bool { return l.count(reason) > 0 }

// newTestAnchorer câble un ancreur sur des logs réels (cellule + master
// dans des répertoires distincts) avec horloge et TSA factices.
func newTestAnchorer(t *testing.T, ctx context.Context, clock *fakeClock, tsa *fakeTSA, trips, alarms *anchorTripLog) (*Anchorer, *CellLog, *CellLog) {
	t.Helper()
	cell, _ := openTestLog(t, ctx, t.TempDir(), nil)
	master, _ := openTestLog(t, ctx, t.TempDir(), nil)
	a, err := NewAnchorer(AnchorerOptions{
		BrokerID: "broker-test",
		CellID:   "cell-test",
		Cell:     cell,
		Master:   master,
		TSA:      tsa,
		Interval: time.Second, // ≫ cadence réelle — les tests pilotent AnchorOnce
		MaxLag:   MaxAnchorLag,
		Clock:    clock.now,
		OnTrip:   trips.add,
		OnAlarm:  alarms.add,
	})
	if err != nil {
		t.Fatalf("NewAnchorer: %v", err)
	}
	return a, cell, master
}

// seedCell écrit une feuille de décision — la tête ancrée est réelle.
func seedCell(t *testing.T, ctx context.Context, cell *CellLog) ([32]byte, uint64) {
	t.Helper()
	if _, err := cell.Append(ctx, Leaf{
		Kind:        KindDecision,
		CellID:      "cell-test",
		PayloadHash: sha256.Sum256([]byte("decision de test")),
	}); err != nil {
		t.Fatalf("seed cell: %v", err)
	}
	root, size, err := cell.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	return root, size
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestAnchorRecordMarshal : sérialisation déterministe (§11.3) et
// discriminante — deux enregistrements différents, deux empreintes
// différentes.
func TestAnchorRecordMarshal(t *testing.T) {
	rec := AnchorRecord{
		BrokerID:  "broker-a",
		CellID:    "cell-a",
		HeadRoot:  sha256.Sum256([]byte("racine")),
		HeadSize:  42,
		TSATime:   time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC),
		TokenHash: sha256.Sum256([]byte("jeton")),
	}
	if !strings.HasPrefix(string(rec.Marshal()), "TBPA1") {
		t.Error("magie absente")
	}
	if len(rec.Marshal()) != 5+2+8+2+6+32+8+8+32 {
		t.Errorf("longueur canonique %d inattendue", len(rec.Marshal()))
	}
	again := rec.Marshal()
	if string(again) != string(rec.Marshal()) {
		t.Error("sérialisation non déterministe")
	}
	other := rec
	other.HeadSize = 43
	if string(other.Marshal()) == string(again) {
		t.Error("deux enregistrements distincts partagent la même sérialisation")
	}
	// Fuseau horaire : l'UTC est canonique.
	recTZ := rec
	loc := time.FixedZone("UTC+2", 2*3600)
	recTZ.TSATime = rec.TSATime.In(loc)
	if string(recTZ.Marshal()) != string(again) {
		t.Error("le fuseau horaire ne doit pas changer la sérialisation")
	}
}

// TestAnchorerValidation : options invalides refusées à la construction.
func TestAnchorerValidation(t *testing.T) {
	ctx := context.Background()
	cell, _ := openTestLog(t, ctx, t.TempDir(), nil)
	master, _ := openTestLog(t, ctx, t.TempDir(), nil)
	tsa := &fakeTSA{genTime: time.Now}

	base := AnchorerOptions{
		BrokerID: "b", CellID: "c", Cell: cell, Master: master, TSA: tsa,
		Interval: time.Second, MaxLag: MaxAnchorLag,
	}
	for name, mutate := range map[string]func(*AnchorerOptions){
		"BrokerID vide":     func(o *AnchorerOptions) { o.BrokerID = "" },
		"CellID vide":       func(o *AnchorerOptions) { o.CellID = "" },
		"Cell nil":          func(o *AnchorerOptions) { o.Cell = nil },
		"Master nil":        func(o *AnchorerOptions) { o.Master = nil },
		"TSA nil":           func(o *AnchorerOptions) { o.TSA = nil },
		"Interval ≥ MaxLag": func(o *AnchorerOptions) { o.Interval = 2 * time.Minute; o.MaxLag = time.Minute },
		"MaxBacklog < 1":    func(o *AnchorerOptions) { o.MaxBacklog = -1 },
	} {
		opts := base
		mutate(&opts)
		if _, err := NewAnchorer(opts); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if _, err := NewAnchorer(base); err != nil {
		t.Errorf("options valides refusées: %v", err)
	}
}

// TestAnchorerHappyPath : un ancrage bout en bout — tête réelle, jeton
// TSA, feuille KindAnchor RELUE depuis le bundle Tessera de la master
// chain, fraîcheur OK, snapshot cohérent.
func TestAnchorerHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, cell, master := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)

	root, size := seedCell(t, ctx, cell)

	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}

	// Fraîcheur : lag nul → Check passe, aucune alarme.
	if err := a.Check(); err != nil {
		t.Fatalf("Check après ancrage: %v", err)
	}
	if trips.count(AnchorReasonLag) != 0 {
		t.Error("trip de lag intempestif")
	}

	// Snapshot : hash = hash salé de l'enregistrement attendu.
	snap, ok := a.Snapshot()
	if !ok {
		t.Fatal("snapshot absent après ancrage")
	}
	if !snap.At.Equal(t0) {
		t.Errorf("snapshot.At %s, attendu %s", snap.At, t0)
	}
	if snap.MasterIndex != 0 {
		t.Errorf("index maître %d, attendu 0", snap.MasterIndex)
	}
	wantRec := AnchorRecord{
		BrokerID:  "broker-test",
		CellID:    "cell-test",
		HeadRoot:  root,
		HeadSize:  size,
		TSATime:   t0,
		TokenHash: sha256.Sum256([]byte("jeton-tsa-de-test")),
	}
	if want := HashPayload(a.salt, wantRec.Marshal()); snap.Hash != want {
		t.Error("hash du snapshot ≠ hash salé de l'enregistrement ancré")
	}

	// La feuille RÉELLEMENT inscrite dans la master chain.
	_, msize, err := master.Head(ctx)
	if err != nil {
		t.Fatalf("master.Head: %v", err)
	}
	if msize != 1 {
		t.Fatalf("master chain taille %d, attendu 1", msize)
	}
	leaf := readLeafAt(t, master, msize, 0)
	if leaf.Kind != KindAnchor {
		t.Errorf("kind %d, attendu KindAnchor", leaf.Kind)
	}
	if leaf.CellID != "cell-test" {
		t.Errorf("cellID %q", leaf.CellID)
	}
	if leaf.Timestamp != t0.UnixNano() {
		t.Errorf("timestamp feuille %d, attendu genTime TSA %d", leaf.Timestamp, t0.UnixNano())
	}
	if leaf.PayloadHash != snap.Hash {
		t.Error("payload de la feuille ≠ hash du snapshot")
	}
}

// TestAnchorerNeverAnchored : avant tout ancrage, Check refuse — défaut
// §1 (aucun jeton sans preuve externe), alarmé une seule fois.
func TestAnchorerNeverAnchored(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clock := newFakeClock(time.Now())
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, _, _ := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)

	if err := a.Check(); !errors.Is(err, ErrAnchorNeverAnchored) {
		t.Fatalf("Check = %v, attendu ErrAnchorNeverAnchored", err)
	}
	if trips.count(AnchorReasonNever) != 1 {
		t.Fatalf("trips never = %d, attendu 1", trips.count(AnchorReasonNever))
	}
	// Deuxième refus : pas de répétition d'alarme.
	if err := a.Check(); !errors.Is(err, ErrAnchorNeverAnchored) {
		t.Fatal("Check devrait toujours refuser")
	}
	if trips.count(AnchorReasonNever) != 1 {
		t.Fatalf("alarme répétée : trips = %d", trips.count(AnchorReasonNever))
	}
	if !alarms.has(AnchorReasonNever) {
		t.Error("alarme class-W absente")
	}
}

// TestAnchorerLagTrips est le CRITÈRE D'ACCEPTATION de l'issue #6 :
// un ancrage en retard de > 120 s provoque le refus de nouveaux jetons.
func TestAnchorerLagTrips(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, cell, _ := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)
	seedCell(t, ctx, cell)

	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}
	if err := a.Check(); err != nil {
		t.Fatalf("Check à t0: %v", err)
	}

	// Juste sous la borne : encore valide.
	clock.advance(MaxAnchorLag - time.Second)
	if err := a.Check(); err != nil {
		t.Fatalf("Check à 119 s: %v", err)
	}
	if trips.count(AnchorReasonLag) != 0 {
		t.Fatal("trip avant la borne")
	}

	// Au-delà : refus.
	clock.advance(2 * time.Second)
	if err := a.Check(); !errors.Is(err, ErrAnchorStale) {
		t.Fatalf("Check à 121 s = %v, attendu ErrAnchorStale", err)
	}
	if trips.count(AnchorReasonLag) != 1 {
		t.Fatalf("trips lag = %d, attendu 1 (exactly-once)", trips.count(AnchorReasonLag))
	}
	// Le refus persiste sans ré-alarme.
	if err := a.Check(); !errors.Is(err, ErrAnchorStale) {
		t.Fatal("le refus doit persister tant que le lag dépasse")
	}
	if trips.count(AnchorReasonLag) != 1 {
		t.Fatal("répétition d'alarme de lag")
	}
}

// TestAnchorerRecovery : la reprise après retour du TSA est propre — un
// nouvel ancrage vérifié referme la fenêtre, la reprise est alarmée, et
// un dépassement ultérieur re-déclenche normalement.
func TestAnchorerRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, cell, _ := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)
	seedCell(t, ctx, cell)

	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}
	clock.advance(MaxAnchorLag + time.Second)
	if err := a.Check(); !errors.Is(err, ErrAnchorStale) {
		t.Fatal("lag attendu")
	}

	// Le TSA revient : nouvel ancrage au temps courant.
	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("AnchorOnce de reprise: %v", err)
	}
	if err := a.Check(); err != nil {
		t.Fatalf("Check après reprise: %v", err)
	}
	if !alarms.has(AnchorReasonRecovered) {
		t.Error("reprise non alarmée")
	}
	snap, _ := a.Snapshot()
	if !snap.At.Equal(clock.now()) {
		t.Errorf("snapshot.At %s, attendu %s", snap.At, clock.now())
	}

	// Nouveau dépassement : nouveau trip (exactly-once par épisode).
	clock.advance(MaxAnchorLag + time.Second)
	if err := a.Check(); !errors.Is(err, ErrAnchorStale) {
		t.Fatal("second lag attendu")
	}
	if trips.count(AnchorReasonLag) != 2 {
		t.Fatalf("trips lag = %d, attendu 2 (un par épisode)", trips.count(AnchorReasonLag))
	}
}

// TestAnchorerStoreAndForward : master chain injoignable → backlog borné ;
// au retour, rattrapage DANS L'ORDRE (continuité depuis le dernier
// ancrage vérifié) puis ancrage courant.
func TestAnchorerStoreAndForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}

	cell, _ := openTestLog(t, ctx, t.TempDir(), nil)
	master := &stubMaster{}
	master.failing.Store(true)
	a, err := NewAnchorer(AnchorerOptions{
		BrokerID: "broker-test", CellID: "cell-test",
		Cell: cell, Master: master, TSA: tsa,
		Interval: time.Second, MaxLag: MaxAnchorLag,
		Clock: clock.now, OnTrip: trips.add, OnAlarm: alarms.add,
	})
	if err != nil {
		t.Fatalf("NewAnchorer: %v", err)
	}
	seedCell(t, ctx, cell)

	// Trois ancrages pendant la panne : tous échouent, tous en backlog.
	for i := 0; i < 3; i++ {
		if err := a.AnchorOnce(ctx); err == nil {
			t.Fatalf("ancrage %d accepté malgré la panne", i)
		}
		clock.advance(time.Second)
	}
	if got := a.BacklogDepth(); got != 3 {
		t.Fatalf("backlog = %d, attendu 3", got)
	}
	if _, ok := a.Snapshot(); ok {
		t.Fatal("aucun ancrage vérifié ne doit exister pendant la panne")
	}

	// Retour de la master chain : le prochain cycle vide le backlog puis
	// ancre la tête courante.
	master.failing.Store(false)
	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("AnchorOnce de rattrapage: %v", err)
	}
	if got := a.BacklogDepth(); got != 0 {
		t.Fatalf("backlog = %d après rattrapage", got)
	}

	leaves := master.taken()
	if len(leaves) != 4 {
		t.Fatalf("master chain : %d feuilles, attendu 4 (3 rattrapages + 1 courant)", len(leaves))
	}
	for i, leaf := range leaves {
		if leaf.Kind != KindAnchor {
			t.Errorf("feuille %d : kind %d", i, leaf.Kind)
		}
		if i > 0 && leaf.Timestamp < leaves[i-1].Timestamp {
			t.Errorf("feuille %d : ordre temporel rompu", i)
		}
	}
	// Le dernier ancrage vérifié est le plus récent.
	snap, ok := a.Snapshot()
	if !ok || !snap.At.Equal(clock.now()) {
		t.Fatalf("snapshot après rattrapage : %+v ok=%v", snap, ok)
	}
	if snap.MasterIndex != 3 {
		t.Errorf("index maître %d, attendu 3", snap.MasterIndex)
	}
	if err := a.Check(); err != nil {
		t.Fatalf("Check après rattrapage: %v", err)
	}
}

// TestAnchorerBacklogOverflow : inondation prolongée — le backlog plafonne,
// l'alarme part (DoS alarmé), les plus ANCIENS enregistrements survivent
// (continuité), et le refus vient ensuite du lag, jamais du silence.
func TestAnchorerBacklogOverflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t0 := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	clock := newFakeClock(t0)
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}

	cell, _ := openTestLog(t, ctx, t.TempDir(), nil)
	master := &stubMaster{}
	master.failing.Store(true)
	a, err := NewAnchorer(AnchorerOptions{
		BrokerID: "broker-test", CellID: "cell-test",
		Cell: cell, Master: master, TSA: tsa,
		Interval: time.Second, MaxLag: MaxAnchorLag, MaxBacklog: 2,
		Clock: clock.now, OnTrip: trips.add, OnAlarm: alarms.add,
	})
	if err != nil {
		t.Fatalf("NewAnchorer: %v", err)
	}
	seedCell(t, ctx, cell)

	// Premier ancrage AVANT la panne... non : master déjà en panne — les
	// 4 tentatives remplissent puis débordent le backlog de 2.
	for i := 0; i < 4; i++ {
		_ = a.AnchorOnce(ctx)
		clock.advance(time.Second)
	}
	if got := a.BacklogDepth(); got != 2 {
		t.Fatalf("backlog = %d, attendu plafond 2", got)
	}
	if !alarms.has(AnchorReasonBacklogOverflow) {
		t.Fatal("débordement non alarmé")
	}

	// Rattrapage : ce sont les PLUS ANCIENS (t0, t0+1s) qui ont survécu.
	master.failing.Store(false)
	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("rattrapage: %v", err)
	}
	leaves := master.taken()
	if len(leaves) != 3 {
		t.Fatalf("%d feuilles, attendu 3 (2 backlog + 1 courant)", len(leaves))
	}
	if leaves[0].Timestamp != t0.UnixNano() || leaves[1].Timestamp != t0.Add(time.Second).UnixNano() {
		t.Errorf("continuité perdue : t0=%d t1=%d", leaves[0].Timestamp, leaves[1].Timestamp)
	}
}

// TestAnchorerTSAFutureRejected : un TSA datant au-delà de la dérive
// admise est rejeté (fail-closed) — sinon la fenêtre de fraîcheur serait
// gonflable artificiellement.
func TestAnchorerTSAFutureRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clock := newFakeClock(time.Now())
	tsa := &fakeTSA{genTime: func() time.Time { return clock.now().Add(time.Hour) }}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, cell, _ := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)
	seedCell(t, ctx, cell)

	if err := a.AnchorOnce(ctx); err == nil || !strings.Contains(err.Error(), "futur") {
		t.Fatalf("attendu un rejet de genTime futur, obtenu %v", err)
	}
	if !alarms.has(AnchorReasonTSAFuture) {
		t.Error("TSA futur non alarmé")
	}
	if _, ok := a.Snapshot(); ok {
		t.Error("un ancrage futur ne doit jamais être vérifié")
	}
}

// TestAnchorerTSADownKeepsStale : TSA injoignable → pas d'ancrage, pas de
// snapshot, le refus suit la doctrine (never, puis lag).
func TestAnchorerTSADownKeepsStale(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clock := newFakeClock(time.Now())
	tsa := &fakeTSA{genTime: clock.now, err: errors.New("tsa injoignable")}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, cell, _ := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)
	seedCell(t, ctx, cell)

	if err := a.AnchorOnce(ctx); err == nil {
		t.Fatal("ancrage accepté sans TSA")
	}
	if _, ok := a.Snapshot(); ok {
		t.Fatal("snapshot sans ancrage vérifié")
	}
	if err := a.Check(); !errors.Is(err, ErrAnchorNeverAnchored) {
		t.Fatalf("Check = %v, attendu ErrAnchorNeverAnchored", err)
	}
}

// TestAnchorerRun : la boucle périodique ancre seule, s'arrête proprement
// sur annulation, et l'ancreur fermé refuse tout nouvel ancrage.
func TestAnchorerRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Horloge et TSA réels : la boucle tourne en vrai temps — avec une
	// horloge figée, les genTime identiques ne feraient jamais avancer le
	// snapshot (garde monotone), ce qui testerait autre chose que Run.
	tsa := &fakeTSA{genTime: time.Now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	cell, _ := openTestLog(t, ctx, t.TempDir(), nil)
	master, _ := openTestLog(t, ctx, t.TempDir(), nil)
	a, err := NewAnchorer(AnchorerOptions{
		BrokerID: "broker-test", CellID: "cell-test",
		Cell: cell, Master: master, TSA: tsa,
		Interval: 50 * time.Millisecond, MaxLag: MaxAnchorLag,
		Clock: time.Now, OnTrip: trips.add, OnAlarm: alarms.add,
	})
	if err != nil {
		t.Fatalf("NewAnchorer: %v", err)
	}
	seedCell(t, ctx, cell)

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- a.Run(runCtx) }()

	// Au moins deux ancrages espacés (la boucle tourne seule).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if snap, ok := a.Snapshot(); ok && snap.MasterIndex >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	snap, ok := a.Snapshot()
	if !ok || snap.MasterIndex < 1 {
		t.Fatal("la boucle n'a pas ancré deux fois en 10 s")
	}
	if err := a.Check(); err != nil {
		t.Fatalf("Check pendant la boucle: %v", err)
	}

	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run ne s'est pas arrêté après annulation")
	}

	a.Close()
	if err := a.AnchorOnce(ctx); !errors.Is(err, ErrAnchorerClosed) {
		t.Fatalf("AnchorOnce après Close = %v", err)
	}
	if err := a.Run(ctx); !errors.Is(err, ErrAnchorerClosed) {
		t.Fatalf("Run après Close = %v", err)
	}
	// Check reste fonctionnel sur l'ancrage existant (lecture seule).
	if err := a.Check(); err != nil {
		t.Fatalf("Check après Close: %v", err)
	}
}

// TestAnchorerConcurrentCheck : Check et Snapshot pendant AnchorOnce —
// sûr en concurrence (-race).
func TestAnchorerConcurrentCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	clock := newFakeClock(time.Now())
	tsa := &fakeTSA{genTime: clock.now}
	trips, alarms := &anchorTripLog{}, &anchorTripLog{}
	a, cell, _ := newTestAnchorer(t, ctx, clock, tsa, trips, alarms)
	seedCell(t, ctx, cell)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = a.Check()
					_, _ = a.Snapshot()
				}
			}
		}()
	}
	for i := 0; i < 5; i++ {
		if err := a.AnchorOnce(ctx); err != nil {
			t.Errorf("AnchorOnce %d: %v", i, err)
		}
		clock.advance(100 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if tsa.callCount() != 5 {
		t.Errorf("appels TSA = %d, attendu 5", tsa.callCount())
	}
}
