// degradation_test.go — T25 (issue #26) : tests de la machine d'états des
// modes dégradés du traducteur (§4.5). Chaque test est non-vacuole : la
// mutation correspondante DOIT le faire échouer.
package translator

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// --- Fakes de coutures ---------------------------------------------------

type fakeProbe struct {
	mu      sync.Mutex
	err     error
	history []string // tous les diagnostics posés (candidats de records down)
}

func (p *fakeProbe) Healthy(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *fakeProbe) set(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
	if err != nil {
		p.history = append(p.history, err.Error())
	}
}

type fakeMirror struct {
	mu    sync.Mutex
	avail bool
}

func (m *fakeMirror) Available(context.Context) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.avail
}

func (m *fakeMirror) set(avail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.avail = avail
}

type fakeArbitration struct {
	mu         sync.Mutex
	reachable  bool
	enqueueErr error
	items      []ArbitrationItem
}

func (a *fakeArbitration) Reachable(context.Context) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reachable
}

func (a *fakeArbitration) Enqueue(_ context.Context, item ArbitrationItem) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.enqueueErr != nil {
		return a.enqueueErr
	}
	a.items = append(a.items, item)
	return nil
}

func (a *fakeArbitration) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.items)
}

type fakeLeaves struct {
	mu     sync.Mutex
	leaves []registry.Leaf
	err    error
}

func (l *fakeLeaves) Append(_ context.Context, leaf registry.Leaf) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return 0, l.err
	}
	l.leaves = append(l.leaves, leaf)
	return uint64(len(l.leaves)), nil
}

func (l *fakeLeaves) snapshot() []registry.Leaf {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]registry.Leaf, len(l.leaves))
	copy(out, l.leaves)
	return out
}

type fakeAlarm struct {
	mu      sync.Mutex
	reasons []string
}

func (a *fakeAlarm) fire(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reasons = append(a.reasons, reason)
}

func (a *fakeAlarm) snapshot() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.reasons))
	copy(out, a.reasons)
	return out
}

// rig assemble un contrôleur de test et ses coutures.
type rig struct {
	ctrl   *Controller
	probe  *fakeProbe
	mirror *fakeMirror
	arb    *fakeArbitration
	leaves *fakeLeaves
	alarm  *fakeAlarm
	now    time.Time
}

var (
	rigSalt  = []byte("t25-degradation-test-salt-32o!") // ≥ 16 octets
	rigCell  = "cell-t25"
	rigClock = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
)

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		probe:  &fakeProbe{},
		mirror: &fakeMirror{},
		arb:    &fakeArbitration{},
		leaves: &fakeLeaves{},
		alarm:  &fakeAlarm{},
		now:    rigClock,
	}
	ctrl, err := NewController(Options{
		CellID:      rigCell,
		Salt:        rigSalt,
		Leaves:      r.leaves,
		Probe:       r.probe,
		Mirror:      r.mirror,
		Arbitration: r.arb,
		OnAlarm:     r.alarm.fire,
		Now:         func() time.Time { return r.now },
	})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	r.ctrl = ctrl
	return r
}

var (
	criticalSys = System{ID: "sys-billing", Class: SystemCritical}
	standardSys = System{ID: "sys-wiki", Class: SystemStandard}
	nlInput     = Input{JTI: [16]byte{1, 2, 3}, Natural: true, Payload: []byte("fais ceci")}
	stInput     = Input{JTI: [16]byte{4, 5, 6}, Natural: false, Payload: []byte(`{"action":"read","resource":"doc-1"}`)}
)

// --- Configuration fail-closed -------------------------------------------

func TestNewControllerFailClosedConfig(t *testing.T) {
	base := Options{
		CellID: rigCell,
		Salt:   rigSalt,
		Leaves: &fakeLeaves{},
		Probe:  &fakeProbe{},
	}
	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"cellID vide", func(o *Options) { o.CellID = "" }},
		{"sel < 16 octets", func(o *Options) { o.Salt = []byte("court") }},
		{"sans couture feuilles", func(o *Options) { o.Leaves = nil }},
		{"sans sonde", func(o *Options) { o.Probe = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts := base
			tc.mutate(&opts)
			if _, err := NewController(opts); err == nil {
				t.Fatalf("%s : configuration acceptée — fail-open", tc.name)
			}
		})
	}
	// Miroir et arbitrage OPTIONNELS : leur absence restreint les modes,
	// elle ne casse pas la construction.
	if _, err := NewController(base); err != nil {
		t.Fatalf("configuration minimale valide refusée : %v", err)
	}
}

// --- Démarrage dégradé (fail-closed §1) -----------------------------------

func TestStartsDegradedUntilFirstGreenProbe(t *testing.T) {
	r := newRig(t)
	// Sonde saine mais JAMAIS appelée : l'état reste dégradé — la santé ne
	// se présume pas, elle se vérifie.
	if got := r.ctrl.ModeFor(context.Background(), standardSys); got == ModeNormal {
		t.Fatal("mode normal sans aucune sonde verte — confiance présumée")
	}
	up, since := r.ctrl.State()
	if up {
		t.Fatal("état up avant la première sonde")
	}
	if !since.Equal(rigClock) {
		t.Fatalf("downSince = %v, attendu l'horloge de construction %v", since, rigClock)
	}
	// Première sonde verte → mode normal mérité.
	if err := r.ctrl.CheckHealth(context.Background()); err != nil {
		t.Fatalf("CheckHealth: %v", err)
	}
	if got := r.ctrl.ModeFor(context.Background(), standardSys); got != ModeNormal {
		t.Fatalf("mode %s après sonde verte, attendu normal", got)
	}
	// La reprise initiale est tracée (recovered).
	assertLeafActions(t, r, recordActionRecovered)
}

// --- Bascule par classe de système (pseudo-code de l'issue) ----------------

func TestDownCriticalWithMirrorFailover(t *testing.T) {
	r := newRig(t)
	r.mirror.set(true)
	r.probe.set(errors.New("vllm: process mort"))
	if err := r.ctrl.CheckHealth(context.Background()); err == nil {
		t.Fatal("CheckHealth sans erreur alors que la sonde échoue")
	}
	if got := r.ctrl.ModeFor(context.Background(), criticalSys); got != ModeMirrorFailover {
		t.Fatalf("mode %s, attendu %s (critique + miroir sain)", got, ModeMirrorFailover)
	}
	// Structuré : admis sur le chemin déterministe (§7.4).
	if err := r.ctrl.Accept(context.Background(), criticalSys, stInput); err != nil {
		t.Fatalf("structuré refusé en failover : %v", err)
	}
	// Langage naturel : rejet propre, feuille + alarme (§4.5).
	if err := r.ctrl.Accept(context.Background(), criticalSys, nlInput); !errors.Is(err, ErrDegradedMode) {
		t.Fatalf("NL accepté en failover : %v", err)
	}
	assertLeafActions(t, r, recordActionDown, recordActionNLRejected)
	assertAlarms(t, r, ReasonDown, ReasonNLRejected)
}

func TestDownStandardWithArbitrationEscalates(t *testing.T) {
	r := newRig(t)
	r.arb.reachable = true
	r.probe.set(errors.New("vllm: OOM killed"))
	_ = r.ctrl.CheckHealth(context.Background())
	if got := r.ctrl.ModeFor(context.Background(), standardSys); got != ModeHumanEscalation {
		t.Fatalf("mode %s, attendu %s (standard + arbitrage joignable)", got, ModeHumanEscalation)
	}
	// Structuré : remis à l'arbitre — ErrPendingArbitration N'EST PAS un refus.
	err := r.ctrl.Accept(context.Background(), standardSys, stInput)
	if !errors.Is(err, ErrPendingArbitration) {
		t.Fatalf("structuré non escaladé : %v", err)
	}
	if r.arb.count() != 1 {
		t.Fatalf("file d'arbitrage = %d items, attendu 1", r.arb.count())
	}
	item := r.arb.items[0]
	if item.SystemID != standardSys.ID || item.JTI != stInput.JTI {
		t.Fatalf("item d'arbitrage incohérent : %+v", item)
	}
	if string(item.Payload) != string(stInput.Payload) {
		t.Fatal("payload de l'intention altéré en escalade (no-DPI)")
	}
	if !item.At.Equal(rigClock) {
		t.Fatalf("horodatage de l'item = %v, attendu %v", item.At, rigClock)
	}
	// NL : rejet même en escalade (§4.5 — structuré uniquement).
	if err := r.ctrl.Accept(context.Background(), standardSys, nlInput); !errors.Is(err, ErrDegradedMode) {
		t.Fatalf("NL accepté en escalade : %v", err)
	}
	assertLeafActions(t, r, recordActionDown, recordActionEscalated, recordActionNLRejected)
}

func TestDownDefaultDenyWithoutSeams(t *testing.T) {
	r := newRig(t)
	r.probe.set(errors.New("vllm: injoignable"))
	_ = r.ctrl.CheckHealth(context.Background())
	// Ni miroir (critique) ni arbitrage (standard) : default-deny immédiat,
	// y compris pour le STRUCTURÉ.
	for _, sys := range []System{criticalSys, standardSys} {
		if got := r.ctrl.ModeFor(context.Background(), sys); got != ModeDefaultDeny {
			t.Fatalf("%s : mode %s, attendu %s", sys.ID, got, ModeDefaultDeny)
		}
		if err := r.ctrl.Accept(context.Background(), sys, stInput); !errors.Is(err, ErrDefaultDeny) {
			t.Fatalf("%s : structuré admis en default-deny : %v", sys.ID, err)
		}
	}
	assertLeafActions(t, r,
		recordActionDown, recordActionDefaultDeny, recordActionDefaultDeny)
	assertAlarms(t, r, ReasonDown, ReasonDefaultDeny, ReasonDefaultDeny)
}

// Un système CRITIQUE sans miroir n'escalade PAS vers l'humain, même si
// l'arbitrage est joignable (§4.5 : chemin déterministe ou rien).
func TestDownCriticalNeverEscalatesToHuman(t *testing.T) {
	r := newRig(t)
	r.arb.reachable = true // joignable — mais réservé aux systèmes standard
	r.probe.set(errors.New("vllm: down"))
	_ = r.ctrl.CheckHealth(context.Background())
	if got := r.ctrl.ModeFor(context.Background(), criticalSys); got != ModeDefaultDeny {
		t.Fatalf("critique sans miroir : mode %s, attendu %s — l'escalade humaine est interdite (§4.5)",
			got, ModeDefaultDeny)
	}
	if err := r.ctrl.Accept(context.Background(), criticalSys, stInput); !errors.Is(err, ErrDefaultDeny) {
		t.Fatalf("critique sans miroir admis : %v", err)
	}
	if r.arb.count() != 0 {
		t.Fatal("un système critique a rejoint la file d'arbitrage humain")
	}
}

// Échec de la REMISE à l'arbitrage : fail-closed — default-deny tracé,
// jamais une admission silencieuse ni une file implicite.
func TestEscalationEnqueueFailureFailsClosed(t *testing.T) {
	r := newRig(t)
	r.arb.reachable = true
	r.arb.enqueueErr = errors.New("broker: file pleine")
	r.probe.set(errors.New("vllm: down"))
	_ = r.ctrl.CheckHealth(context.Background())
	err := r.ctrl.Accept(context.Background(), standardSys, stInput)
	if !errors.Is(err, ErrDefaultDeny) {
		t.Fatalf("escalade en échec admise : %v — fail-open", err)
	}
	if errors.Is(err, ErrPendingArbitration) {
		t.Fatal("une escalade ÉCHOUÉE déclarée en attente d'arbitrage")
	}
	if r.arb.count() != 0 {
		t.Fatal("item présent malgré l'échec de remise")
	}
	assertLeafActions(t, r, recordActionDown, recordActionDefaultDeny)
	assertAlarms(t, r, ReasonDown, ReasonDefaultDeny)
}

// --- Traçabilité des épisodes ---------------------------------------------

func TestDownTracedOncePerEpisodeAndRecoveryTraced(t *testing.T) {
	r := newRig(t)
	r.probe.set(errors.New("vllm: down"))
	_ = r.ctrl.CheckHealth(context.Background())
	_ = r.ctrl.CheckHealth(context.Background()) // re-sonde en échec : pas de doublon
	_ = r.ctrl.CheckHealth(context.Background())
	leaves := r.leaves.snapshot()
	if len(leaves) != 1 {
		t.Fatalf("%d feuilles pour UN épisode down, attendu 1 (dédupliqué)", len(leaves))
	}
	if got := len(r.alarm.snapshot()); got != 1 {
		t.Fatalf("%d alarmes pour UN épisode, attendu 1", got)
	}
	// Reprise : tracée, et le mode normal revient.
	r.probe.set(nil)
	if err := r.ctrl.CheckHealth(context.Background()); err != nil {
		t.Fatalf("reprise: %v", err)
	}
	if got := r.ctrl.ModeFor(context.Background(), standardSys); got != ModeNormal {
		t.Fatalf("mode %s après reprise, attendu normal", got)
	}
	assertLeafActions(t, r, recordActionDown, recordActionRecovered)
	// Second épisode : nouvelle feuille down (les épisodes ne se fusionnent pas).
	r.probe.set(errors.New("vllm: re-down"))
	_ = r.ctrl.CheckHealth(context.Background())
	assertLeafActions(t, r, recordActionDown, recordActionRecovered, recordActionDown)
}

// Le feuilletage est HASH-ONLY et au format versionné exact : le test
// reconstruit les records À LA MAIN (mutation du format ⇒ échec).
func TestLeavesAreHashOnlyExactRecords(t *testing.T) {
	r := newRig(t)
	r.probe.set(errors.New("boom"))
	_ = r.ctrl.CheckHealth(context.Background())
	_ = r.ctrl.Accept(context.Background(), standardSys, nlInput)

	// Record down attendu, reconstruit à la main.
	detail := "boom"
	wantDown := append([]byte{'T', 'B', 'T', 'D', '1', 1, 0, byte(len(detail))}, detail...)
	// Record nl-rejected attendu, reconstruit à la main.
	wantNL := []byte{'T', 'B', 'T', 'D', '1', 3}
	wantNL = append(wantNL, nlInput.JTI[:]...)
	wantNL = append(wantNL, byte(len(standardSys.ID)))
	wantNL = append(wantNL, standardSys.ID...)

	leaves := r.leaves.snapshot()
	if len(leaves) != 2 {
		t.Fatalf("%d feuilles, attendu 2", len(leaves))
	}
	for i, want := range [][]byte{wantDown, wantNL} {
		leaf := leaves[i]
		if leaf.Kind != registry.KindTelemetry {
			t.Fatalf("feuille %d : kind %d, attendu KindTelemetry", i, leaf.Kind)
		}
		if leaf.CellID != rigCell {
			t.Fatalf("feuille %d : cellID %q, attendu %q", i, leaf.CellID, rigCell)
		}
		if got := registry.HashPayload(rigSalt, want); got != leaf.PayloadHash {
			t.Fatalf("feuille %d : hash %x, attendu %x (record %q)", i, leaf.PayloadHash, got, want)
		}
		if leaf.Timestamp != rigClock.UnixNano() {
			t.Fatalf("feuille %d : timestamp %d, attendu %d", i, leaf.Timestamp, rigClock.UnixNano())
		}
	}
}

// --- Réévaluation live des coutures (§7.4) ---------------------------------

func TestModeReevaluatedOnLiveSeams(t *testing.T) {
	r := newRig(t)
	r.probe.set(errors.New("vllm: down"))
	_ = r.ctrl.CheckHealth(context.Background())
	ctx := context.Background()
	if got := r.ctrl.ModeFor(ctx, criticalSys); got != ModeDefaultDeny {
		t.Fatalf("miroir absent : mode %s, attendu %s", got, ModeDefaultDeny)
	}
	// Le miroir devient sain EN COURS D'ÉPISODE : le failover s'ouvre sans
	// redémarrage ni nouvelle sonde (fenêtre saine ancrée, §7.4).
	r.mirror.set(true)
	if got := r.ctrl.ModeFor(ctx, criticalSys); got != ModeMirrorFailover {
		t.Fatalf("miroir redevenu sain : mode %s, attendu %s", got, ModeMirrorFailover)
	}
	// Et se referme si la fenêtre saine se perd.
	r.mirror.set(false)
	if got := r.ctrl.ModeFor(ctx, criticalSys); got != ModeDefaultDeny {
		t.Fatalf("miroir perdu : mode %s, attendu %s", got, ModeDefaultDeny)
	}
}

// --- Pas de fallback cloud : assertion STRUCTURELLE -------------------------

// Aucun chemin de code du package ne résout un endpoint externe (§4.5 :
// « No unverified cloud fallback is permitted »). Le test scanne les AST
// des sources du package : tout import réseau (mutation) le fait échouer.
func TestNoCloudFallbackStructural(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller indisponible")
	}
	pkgDir := filepath.Dir(thisFile)
	entries, err := filepath.Glob(filepath.Join(pkgDir, "*.go"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("sources du package introuvables : %v", err)
	}
	fset := token.NewFileSet()
	scanned := 0
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s : %v", path, err)
		}
		scanned++
		ast.Inspect(f, func(n ast.Node) bool {
			spec, ok := n.(*ast.ImportSpec)
			if !ok {
				return true
			}
			p := strings.Trim(spec.Path.Value, `"`)
			if p == "net" || strings.HasPrefix(p, "net/") {
				t.Errorf("%s : import réseau %q — le fallback cloud est interdit (§4.5)",
					filepath.Base(path), p)
			}
			return true
		})
	}
	if scanned == 0 {
		t.Fatal("aucun fichier source scanné — test vacuole")
	}
}

// Isolement réseau à l'exécution : tout le scénario « panne traducteur »
// (critère d'acceptation de l'issue) se joue contre des coutures qui
// refuseraient tout appel externe — ici des fakes pures mémoire ; le test
// structurel ci-dessus prouve qu'AUCUN chemin ne peut en faire.
func TestTranslatorDownScenarioEndToEnd(t *testing.T) {
	r := newRig(t)
	r.mirror.set(true)
	r.arb.reachable = true
	ctx := context.Background()

	// 1. Service sain : NL et structuré admis.
	if err := r.ctrl.CheckHealth(ctx); err != nil {
		t.Fatalf("sonde initiale : %v", err)
	}
	if err := r.ctrl.Accept(ctx, standardSys, nlInput); err != nil {
		t.Fatalf("NL refusé en mode normal : %v", err)
	}

	// 2. Arrêt du service → bascule explicite selon la classe.
	r.probe.set(errors.New("vllm: signal killed"))
	if err := r.ctrl.CheckHealth(ctx); err == nil {
		t.Fatal("panne non détectée par CheckHealth")
	}
	if got := r.ctrl.ModeFor(ctx, criticalSys); got != ModeMirrorFailover {
		t.Fatalf("critique : mode %s, attendu %s", got, ModeMirrorFailover)
	}
	if got := r.ctrl.ModeFor(ctx, standardSys); got != ModeHumanEscalation {
		t.Fatalf("standard : mode %s, attendu %s", got, ModeHumanEscalation)
	}

	// 3. Rejet propre du NL avec feuille et alarme ; structuré servi.
	if err := r.ctrl.Accept(ctx, criticalSys, nlInput); !errors.Is(err, ErrDegradedMode) {
		t.Fatalf("NL admis en panne : %v", err)
	}
	if err := r.ctrl.Accept(ctx, criticalSys, stInput); err != nil {
		t.Fatalf("structuré critique refusé en failover : %v", err)
	}
	if err := r.ctrl.Accept(ctx, standardSys, stInput); !errors.Is(err, ErrPendingArbitration) {
		t.Fatalf("structuré standard non escaladé : %v", err)
	}

	// 4. Reprise du service → retour au mode normal TRACÉ.
	r.probe.set(nil)
	if err := r.ctrl.CheckHealth(ctx); err != nil {
		t.Fatalf("reprise : %v", err)
	}
	if err := r.ctrl.Accept(ctx, standardSys, nlInput); err != nil {
		t.Fatalf("NL refusé après reprise : %v", err)
	}
	assertLeafActions(t, r,
		recordActionRecovered, // 1. montée initiale
		recordActionDown,      // 2. panne
		recordActionNLRejected,
		recordActionEscalated,
		recordActionRecovered, // 4. reprise
	)
}

// --- Concurrence (-race) ----------------------------------------------------

func TestControllerConcurrent(t *testing.T) {
	r := newRig(t)
	r.mirror.set(true)
	r.arb.reachable = true
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.probe.set(fmt.Errorf("down %d", j%3))
				_ = r.ctrl.CheckHealth(ctx)
				_ = r.ctrl.ModeFor(ctx, criticalSys)
				_ = r.ctrl.Accept(ctx, standardSys, stInput)
				_ = r.ctrl.Accept(ctx, criticalSys, nlInput)
				r.probe.set(nil)
				_ = r.ctrl.CheckHealth(ctx)
				_, _ = r.ctrl.State()
			}
		}(i)
	}
	wg.Wait()
	// Aucune assertion d'état final (courses légitimes) : le sujet est
	// l'absence de data race et de panic — détectées par -race.
}

// --- Helpers d'assertion ----------------------------------------------------

// candidateActions reconstruit la table hash → action de tous les records
// que les tests peuvent avoir produits (boîte blanche : même format que le
// package — la mutation du format casse AUSSI
// TestLeavesAreHashOnlyExactRecords, qui reconstruit les records à la
// main). Ce helper vérifie l'ORDRE et le NOMBRE des actions tracées.
func candidateActions(r *rig) map[[32]byte]byte {
	c := make(map[[32]byte]byte)
	add := func(record []byte, action byte) {
		c[registry.HashPayload(rigSalt, record)] = action
	}
	r.probe.mu.Lock()
	history := append([]string{}, r.probe.history...)
	r.probe.mu.Unlock()
	for _, detail := range history {
		add(recordDown(detail), recordActionDown)
	}
	add([]byte{'T', 'B', 'T', 'D', '1', recordActionRecovered}, recordActionRecovered)
	for _, sys := range []System{criticalSys, standardSys} {
		for _, jti := range [][16]byte{nlInput.JTI, stInput.JTI} {
			add(recordRequest(recordActionNLRejected, jti, sys.ID), recordActionNLRejected)
			add(recordRequest(recordActionEscalated, jti, sys.ID), recordActionEscalated)
			add(recordRequest(recordActionDefaultDeny, jti, sys.ID), recordActionDefaultDeny)
		}
	}
	return c
}

func leafActions(t *testing.T, r *rig) []byte {
	t.Helper()
	candidates := candidateActions(r)
	leaves := r.leaves.snapshot()
	actions := make([]byte, 0, len(leaves))
	for _, leaf := range leaves {
		action, ok := candidates[leaf.PayloadHash]
		if !ok {
			t.Fatalf("feuille non identifiée (hash %x) — record inattendu", leaf.PayloadHash)
		}
		actions = append(actions, action)
	}
	return actions
}

func assertLeafActions(t *testing.T, r *rig, want ...byte) {
	t.Helper()
	got := leafActions(t, r)
	if len(got) != len(want) {
		t.Fatalf("actions tracées %v, attendu %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("actions tracées %v, attendu %v", got, want)
		}
	}
}

func assertAlarms(t *testing.T, r *rig, want ...string) {
	t.Helper()
	got := r.alarm.snapshot()
	if len(got) != len(want) {
		t.Fatalf("alarmes %v, attendu %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("alarmes %v, attendu %v", got, want)
		}
	}
}
