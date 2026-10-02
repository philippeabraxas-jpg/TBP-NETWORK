package telemetry

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// fakeLedger : une source de sessions dont le test pilote le compteur monotone.
type fakeLedger struct {
	mu       sync.Mutex
	sessions map[[16]byte]*Session
}

func (f *fakeLedger) set(jti byte, resource string, consumed uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sessions == nil {
		f.sessions = map[[16]byte]*Session{}
	}
	f.sessions[jtiOf(jti)] = &Session{JTI: jtiOf(jti), Resource: resource, Operation: "send", Consumed: consumed}
}

func (f *fakeLedger) Snapshot() []Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Session, 0, len(f.sessions))
	for _, s := range f.sessions {
		out = append(out, *s)
	}
	return out
}

func newTestPipeline(t *testing.T, src SessionSource, leaves *leafRecorder, nowMs *atomic.Int64, mut ...func(*PipelineOptions)) (*Pipeline, *tripRecorder) {
	t.Helper()
	trips := &tripRecorder{}
	opts := PipelineOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves, Source: src,
		Window: time.Second, RetentionTTL: 5 * time.Second,
		Now: func() time.Time { return time.UnixMilli(nowMs.Load()) }, OnTrip: trips.trip,
	}
	for _, f := range mut {
		f(&opts)
	}
	p, err := NewPipeline(opts)
	if err != nil {
		t.Fatalf("NewPipeline : %v", err)
	}
	return p, trips
}

func TestPipelineConfigFailClosed(t *testing.T) {
	nowMs := &atomic.Int64{}
	leaves := &leafRecorder{}
	good := PipelineOptions{CellID: "c", Salt: t22Salt, Leaves: leaves, Source: &fakeLedger{}, Now: func() time.Time { return time.UnixMilli(nowMs.Load()) }}
	if _, err := NewPipeline(good); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	for name, mut := range map[string]func(*PipelineOptions){
		"source absente":    func(o *PipelineOptions) { o.Source = nil },
		"cellule absente":   func(o *PipelineOptions) { o.CellID = "" },
		"sel court":         func(o *PipelineOptions) { o.Salt = []byte("court") },
		"feuilles absentes": func(o *PipelineOptions) { o.Leaves = nil },
		"fenêtre < 1 ms":    func(o *PipelineOptions) { o.Window = time.Microsecond },
		"TTL < 1 ms":        func(o *PipelineOptions) { o.RetentionTTL = time.Microsecond },
	} {
		o := good
		mut(&o)
		if _, err := NewPipeline(o); err == nil {
			t.Errorf("%s : configuration acceptée", name)
		}
	}
}

// Le pipeline écrit ses feuilles (agrégat, purge) et chacune laisse son clair dans le journal AVANT elle.
func TestPipelineLeavesAreJournaled(t *testing.T) {
	j, path, key := openTelemetryJournal(t)
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	src := &fakeLedger{}
	p, trips := newTestPipeline(t, src, leaves, nowMs, func(o *PipelineOptions) { o.Journal = j })

	src.set(1, "10.0.0.7", 100)
	p.Step() // t = 0 : première mesure, fenêtre 0 ouverte
	src.set(1, "10.0.0.7", 350)
	nowMs.Store(500)
	p.Step() // delta 250 dans la fenêtre 0
	nowMs.Store(1500)
	p.Step() // la fenêtre 0 est écoulée : sa feuille d'agrégat part

	if len(leaves.leaves) != 1 || leaves.leaves[0].Kind != registry.KindTelemetry {
		t.Fatalf("%d feuilles après la fenêtre 0 (attendu 1 agrégat)", len(leaves.leaves))
	}
	nowMs.Store(7000) // TTL (5 s) écoulé : le brut de la fenêtre 0 est purgé, tracé
	p.Step()
	var purge bool
	for _, l := range leaves.leaves {
		if l.Kind == registry.KindRetentionPurge {
			purge = true
		}
	}
	if !purge {
		t.Fatalf("aucune feuille de purge : %d feuilles", len(leaves.leaves))
	}
	recs := requireJournaledLeaves(t, path, key, leaves) // chaque feuille a son clair, hash vérifié, même ordre
	if string(recs[0].Record[:5]) != "TBAG1" {
		t.Fatalf("premier clair %q, attendu un agrégat TBAG1", recs[0].Record[:5])
	}
	if len(trips.reasons) != 0 {
		t.Fatalf("alarmes inattendues : %v", trips.reasons)
	}

	// journal HS : aucune feuille de plus, et l'échec est SIGNALÉ (jamais silencieux)
	_ = j.Close()
	before := len(leaves.leaves)
	nowMs.Store(9000)
	p.Step()
	if len(leaves.leaves) != before {
		t.Fatalf("%d feuille(s) inscrite(s) sans clair journalisé", len(leaves.leaves)-before)
	}
	if len(trips.reasons) == 0 {
		t.Fatal("échec du journal non signalé")
	}
}

// Une alerte anti-dribble passe aussi par le journal, et la destination n'y est que hachée.
func TestPipelineAlertIsJournaled(t *testing.T) {
	j, path, key := openTelemetryJournal(t)
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	src := &fakeLedger{}
	var alerts []Alert
	p, _ := newTestPipeline(t, src, leaves, nowMs, func(o *PipelineOptions) {
		o.Journal = j
		o.Window = time.Minute
		o.RetentionTTL = 24 * time.Hour
		o.Params = t23Params()
		o.OnAlert = func(a Alert) { alerts = append(alerts, a) }
	})
	consumed := make([]uint64, 8)
	for minute := int64(0); minute <= 601; minute++ {
		nowMs.Store(minute * 60_000)
		for s := 0; s < 8; s++ {
			consumed[s] += 12
			src.set(byte(s+1), "exfil.slow-leak.example", consumed[s])
		}
		p.Step()
	}
	if len(alerts) != 1 {
		t.Fatalf("alertes = %d, attendu 1", len(alerts))
	}
	var alertLeaf bool
	for _, l := range leaves.leaves {
		if l.Kind == registry.KindTelemetryAlert {
			alertLeaf = true
		}
	}
	if !alertLeaf {
		t.Fatal("aucune feuille d'alerte")
	}
	recs := requireJournaledLeaves(t, path, key, leaves)
	for _, r := range recs {
		if r.Leaf.Kind == registry.KindTelemetryAlert && string(r.Record[:5]) != "TBAD1" {
			t.Fatalf("clair d'alerte %q", r.Record[:5])
		}
	}
}

func TestPipelineCloseSealsTheCurrentWindow(t *testing.T) {
	j, path, key := openTelemetryJournal(t)
	leaves := &leafRecorder{}
	nowMs := &atomic.Int64{}
	src := &fakeLedger{}
	p, _ := newTestPipeline(t, src, leaves, nowMs, func(o *PipelineOptions) { o.Journal = j })
	src.set(1, "10.0.0.7", 100)
	p.Step()
	src.set(1, "10.0.0.7", 200)
	nowMs.Store(300)
	p.Step()
	if len(leaves.leaves) != 0 {
		t.Fatalf("fenêtre scellée avant son terme : %d feuilles", len(leaves.leaves))
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close : %v", err)
	}
	if len(leaves.leaves) != 1 {
		t.Fatalf("%d feuilles après Close, attendu l'agrégat de la fenêtre en cours", len(leaves.leaves))
	}
	requireJournaledLeaves(t, path, key, leaves)
}
