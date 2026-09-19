package pep

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures T13
// ---------------------------------------------------------------------------

const localTestIssuer = "tbp-cell-maitresse"

// stubProbe est la sonde d'horloge simulée — l'état noyau est injecté.
type stubProbe struct{ v atomic.Value } // probeState

type probeState struct {
	sample ClockSample
	err    error
}

func (p *stubProbe) set(s ClockSample, err error) { p.v.Store(probeState{sample: s, err: err}) }

func (p *stubProbe) probe() (ClockSample, error) {
	st := p.v.Load().(probeState)
	return st.sample, st.err
}

func healthyClock() ClockSample { return ClockSample{Unsync: false, EstError: time.Millisecond} }

func newTestWatchdog(t *testing.T, p *stubProbe, sink *stubSink, rec *tripRecorder) *ClockWatchdog {
	t.Helper()
	opts := ClockOptions{
		Probe:       p.probe,
		LocalIssuer: localTestIssuer,
		CellID:      opaTestCellID,
		Salt:        testSalt,
		Leaves:      sink,
		Now:         func() time.Time { return time.Unix(testIAT+30, 0) },
	}
	if rec != nil {
		opts.OnTrip = rec.trip
	}
	w, err := NewClockWatchdog(opts)
	if err != nil {
		t.Fatalf("NewClockWatchdog: %v", err)
	}
	return w
}

// alarmLeafHash re-compute le hash attendu d'une feuille d'alarme horloge.
func alarmLeafHash(reason string, priority byte) [32]byte {
	return registry.HashPayload(testSalt, clockAlarmRecord(reason, priority))
}

// ---------------------------------------------------------------------------
// Nominal : horloge saine ⇒ mode normal, rien n'est tracé, tout passe.
// ---------------------------------------------------------------------------

func TestClockNormalMode(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	p := &stubProbe{}
	p.set(healthyClock(), nil)
	w := newTestWatchdog(t, p, sink, rec)

	if got := w.Check(); got != ClockModeNormal {
		t.Fatalf("mode=%v, veut normal", got)
	}
	if w.Degraded() {
		t.Fatal("dégradé sur horloge saine")
	}
	if !w.NaturalLanguageAllowed() {
		t.Fatal("langage naturel refusé en mode normal")
	}
	if !w.IssuerAllowed("tbp-cell-etrangere") || !w.IssuerAllowed(localTestIssuer) {
		t.Fatal("émetteur refusé en mode normal")
	}
	if sink.count() != 0 || rec.count() != 0 {
		t.Fatalf("tracé intempestif: feuilles=%d alarmes=%d", sink.count(), rec.count())
	}
}

// ---------------------------------------------------------------------------
// Critère 1 : perte de lock ⇒ mode dégradé EXPLICITE et ALARMÉ (feuille
// prioritaire), jamais silencieux. Pendant la dégradation : NL rejeté (§4.5),
// seuls les jetons locaux-signés passent.
// ---------------------------------------------------------------------------

func TestClockUnsyncEntersDegraded(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	p := &stubProbe{}
	p.set(ClockSample{Unsync: true, EstError: time.Millisecond}, nil)
	w := newTestWatchdog(t, p, sink, rec)

	if got := w.Check(); got != ClockModeDegraded {
		t.Fatalf("mode=%v, veut dégradé", got)
	}
	if w.Reason() != ReasonClockUnsync {
		t.Fatalf("reason=%q, veut %q", w.Reason(), ReasonClockUnsync)
	}
	if w.NaturalLanguageAllowed() {
		t.Fatal("langage naturel accepté en mode dégradé (§4.5)")
	}
	if w.IssuerAllowed("tbp-cell-etrangere") {
		t.Fatal("jeton non local accepté en mode dégradé")
	}
	if !w.IssuerAllowed(localTestIssuer) {
		t.Fatal("jeton local-signé refusé en mode dégradé")
	}

	// Feuille d'alarme prioritaire — KindTelemetry, hash-only, vérifiée.
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1 (alarme prioritaire)", sink.count())
	}
	leaf := sink.leaves[0]
	if leaf.Kind != registry.KindTelemetry {
		t.Fatalf("kind=%d, veut KindTelemetry (alarme, pas décision)", leaf.Kind)
	}
	if got := leaf.PayloadHash; got != alarmLeafHash(ReasonClockUnsync, ClockPriorityHigh) {
		t.Fatalf("hash=%x, veut alarme %q priorité haute", got, ReasonClockUnsync)
	}
	if rec.count() != 0 {
		t.Fatalf("unsync = alarme feuille, pas trip T14: %v", rec.reasons)
	}

	// Persistance du flag : pas de feuille en double, pas de bascule.
	w.Check()
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d après 2e Check, veut 1 (pas de doublon)", sink.count())
	}
}

// ---------------------------------------------------------------------------
// Critère 3 : skew au-delà de la borne ⇒ trip fail-closed (T14) immédiat.
// La borne est un paramètre déclaré, stricte.
// ---------------------------------------------------------------------------

func TestClockSkewTrips(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	p := &stubProbe{}
	p.set(ClockSample{Unsync: false, EstError: 60 * time.Millisecond}, nil)
	w := newTestWatchdog(t, p, sink, rec)

	if got := w.Check(); got != ClockModeDegraded {
		t.Fatalf("mode=%v, veut dégradé (fraîcheur refusée)", got)
	}
	if w.Reason() != ReasonClockSkew {
		t.Fatalf("reason=%q, veut %q", w.Reason(), ReasonClockSkew)
	}
	if rec.count() != 1 || lastReason(rec) != ReasonClockSkew {
		t.Fatalf("alarmes=%v, veut 1 × %s (T14)", rec.reasons, ReasonClockSkew)
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
}

func TestClockSkewBoundary(t *testing.T) {
	sink := &stubSink{}
	p := &stubProbe{}
	w := newTestWatchdog(t, p, sink, nil)

	if w.SkewBound() != DefaultSkewBound {
		t.Fatalf("borne=%v, veut %v (paramètre déclaré §6.2)", w.SkewBound(), DefaultSkewBound)
	}
	// Exactement à la borne : accepté (le dépassement est strict).
	p.set(ClockSample{EstError: DefaultSkewBound}, nil)
	if got := w.Check(); got != ClockModeNormal {
		t.Fatalf("mode=%v à la borne exacte, veut normal", got)
	}
	// 1 µs au-delà : refus immédiat.
	p.set(ClockSample{EstError: DefaultSkewBound + time.Microsecond}, nil)
	if got := w.Check(); got != ClockModeDegraded {
		t.Fatalf("mode=%v au-delà de la borne, veut dégradé", got)
	}
}

// ---------------------------------------------------------------------------
// Critère 4 : disparition du flag ⇒ retour à la normale automatique et TRACÉ.
// ---------------------------------------------------------------------------

func TestClockResyncTraced(t *testing.T) {
	sink := &stubSink{}
	p := &stubProbe{}
	w := newTestWatchdog(t, p, sink, nil)

	p.set(ClockSample{Unsync: true, EstError: time.Millisecond}, nil)
	w.Check()
	if !w.Degraded() {
		t.Fatal("pas dégradé après unsync")
	}

	p.set(healthyClock(), nil)
	if got := w.Check(); got != ClockModeNormal {
		t.Fatalf("mode=%v après resync, veut normal", got)
	}
	if !w.NaturalLanguageAllowed() {
		t.Fatal("langage naturel toujours refusé après resync")
	}
	if sink.count() != 2 {
		t.Fatalf("feuilles=%d, veut 2 (alarme + resync tracé)", sink.count())
	}
	if got := sink.leaves[1].PayloadHash; got != alarmLeafHash(ReasonClockResync, ClockPriorityInfo) {
		t.Fatalf("2e feuille hash=%x, veut %q", got, ReasonClockResync)
	}
}

// ---------------------------------------------------------------------------
// Sonde en échec : impossible de prouver l'heure ⇒ dégradé (fail-closed),
// jamais de passage silencieux.
// ---------------------------------------------------------------------------

func TestClockProbeErrorDegraded(t *testing.T) {
	sink := &stubSink{}
	p := &stubProbe{}
	p.set(ClockSample{}, errors.New("ntp_adjtime: EPERM"))
	w := newTestWatchdog(t, p, sink, nil)

	if got := w.Check(); got != ClockModeDegraded {
		t.Fatalf("mode=%v, veut dégradé sur sonde en échec", got)
	}
	if w.Reason() != ReasonClockProbeError {
		t.Fatalf("reason=%q, veut %q", w.Reason(), ReasonClockProbeError)
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
}

// ---------------------------------------------------------------------------
// Soudure T9↔T13 : le validateur est précédé du portillon horloge — en
// dégradé, un jeton non local est barré AVANT validation ; un jeton
// local-signé suit son chemin normal et est accepté.
// ---------------------------------------------------------------------------

func TestClockGateWithValidator(t *testing.T) {
	sink := &stubSink{}
	p := &stubProbe{}
	p.set(healthyClock(), nil)
	w := newTestWatchdog(t, p, sink, nil)

	ar, err := NewAntiReplay(AntiReplayOptions{
		Capacity: 16,
		Now:      func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	v := newValidator(t, sink, ar, nil)

	localClaims := nominalClaims() // iss = tbp-cell-maitresse
	foreignClaims := nominalClaims()
	foreignClaims.iss = "tbp-cell-etrangere"
	fjti := jtiOf(0xF0)
	foreignClaims.jti = fjti[:]
	localTok := mintToken(t, localClaims)
	foreignTok := mintToken(t, foreignClaims)

	// Mode normal : le portillon laisse tout passer, le validateur décide.
	if !w.IssuerAllowed(foreignClaims.iss) {
		t.Fatal("émetteur étranger barré en mode normal")
	}
	if d := v.Validate(t.Context(), foreignTok, nominalRequest()); !d.Allow {
		t.Fatalf("jeton étranger refusé en mode normal: %s", d.Reason)
	}

	// Perte de lock ⇒ dégradé : NL rejeté, étranger barré au portillon.
	p.set(ClockSample{Unsync: true, EstError: time.Millisecond}, nil)
	w.Check()
	if w.NaturalLanguageAllowed() {
		t.Fatal("NL accepté en dégradé")
	}
	if w.IssuerAllowed(foreignClaims.iss) {
		t.Fatal("jeton non local admis en dégradé (le portillon doit barrer)")
	}

	// Jeton local-signé : passe le portillon ET le validateur.
	if !w.IssuerAllowed(localClaims.iss) {
		t.Fatal("jeton local-signé barré en dégradé")
	}
	if d := v.Validate(t.Context(), localTok, nominalRequest()); !d.Allow {
		t.Fatalf("jeton local refusé en dégradé: %s", d.Reason)
	}
}

// ---------------------------------------------------------------------------
// Boucle de polling : Run suit les transitions d'état noyau et s'arrête
// proprement au contexte.
// ---------------------------------------------------------------------------

func TestClockWatchdogLoop(t *testing.T) {
	sink := &stubSink{}
	p := &stubProbe{}
	p.set(healthyClock(), nil)
	opts := ClockOptions{
		Probe:       p.probe,
		Interval:    2 * time.Millisecond,
		LocalIssuer: localTestIssuer,
		CellID:      opaTestCellID,
		Salt:        testSalt,
		Leaves:      sink,
	}
	w, err := NewClockWatchdog(opts)
	if err != nil {
		t.Fatalf("NewClockWatchdog: %v", err)
	}
	if w.Interval() != 2*time.Millisecond {
		t.Fatalf("interval=%v", w.Interval())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.Run(ctx)
	}()

	// Bascule dégradé puis retour : la boucle trace les deux transitions.
	p.set(ClockSample{Unsync: true, EstError: time.Millisecond}, nil)
	deadline := time.Now().Add(2 * time.Second)
	for w.Mode() != ClockModeDegraded && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if w.Mode() != ClockModeDegraded {
		t.Fatal("la boucle n'a pas vu la perte de lock")
	}
	p.set(healthyClock(), nil)
	for w.Mode() != ClockModeNormal && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if w.Mode() != ClockModeNormal {
		t.Fatal("la boucle n'a pas vu la resynchronisation")
	}

	cancel()
	wg.Wait() // arrêt propre au contexte
	if sink.count() < 2 {
		t.Fatalf("feuilles=%d, veut ≥ 2 (dégradé + resync)", sink.count())
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration + paramètres déclarés par défaut.
// ---------------------------------------------------------------------------

func TestNewClockWatchdogFailClosed(t *testing.T) {
	base := ClockOptions{
		Probe:       func() (ClockSample, error) { return healthyClock(), nil },
		LocalIssuer: localTestIssuer,
		CellID:      opaTestCellID,
		Salt:        testSalt,
		Leaves:      &stubSink{},
	}
	w, err := NewClockWatchdog(base)
	if err != nil {
		t.Fatalf("config nominale refusée: %v", err)
	}
	// Défauts déclarés : intervalle 1 s (pseudo-code), borne 50 ms (§6.2).
	if w.Interval() != DefaultClockInterval {
		t.Fatalf("interval=%v, veut %v", w.Interval(), DefaultClockInterval)
	}
	if w.SkewBound() != DefaultSkewBound {
		t.Fatalf("borne=%v, veut %v", w.SkewBound(), DefaultSkewBound)
	}

	bad := base
	bad.Interval = -time.Second
	if _, err := NewClockWatchdog(bad); err == nil {
		t.Fatal("intervalle négatif accepté")
	}
	bad = base
	bad.SkewBound = -time.Millisecond
	if _, err := NewClockWatchdog(bad); err == nil {
		t.Fatal("borne négative acceptée")
	}
	bad = base
	bad.LocalIssuer = ""
	if _, err := NewClockWatchdog(bad); err == nil {
		t.Fatal("émetteur local vide accepté (sinon « local-signé » ne veut rien dire)")
	}
	bad = base
	bad.CellID = ""
	if _, err := NewClockWatchdog(bad); err == nil {
		t.Fatal("CellID vide accepté")
	}
	bad = base
	bad.Salt = []byte("court")
	if _, err := NewClockWatchdog(bad); err == nil {
		t.Fatal("sel < 16 o accepté (§6.2)")
	}
	bad = base
	bad.Leaves = nil
	if _, err := NewClockWatchdog(bad); err == nil {
		t.Fatal("Leaves nil accepté (l'alarme doit être tracée)")
	}
}

// ---------------------------------------------------------------------------
// Sonde noyau réelle (smoke) : la couture ntp_adjtime répond sous Linux.
// ---------------------------------------------------------------------------

func TestKernelClockProbe(t *testing.T) {
	sample, err := kernelClockProbe()
	if err != nil {
		t.Skipf("ntp_adjtime indisponible dans ce conteneur: %v", err)
	}
	if sample.EstError < 0 {
		t.Fatalf("EstError=%v négatif", sample.EstError)
	}
	t.Logf("état noyau: unsync=%v esterror=%v", sample.Unsync, sample.EstError)
}
