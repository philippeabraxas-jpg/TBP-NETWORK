// console_test.go — T34c (issue #60, D81/D82) : console lecture seule
// PAR CONSTRUCTION. Le garde-fou de la mutation M13 : toute méthode
// autre que GET sur une route existante ⇒ 405 du mux, chemin inconnu ⇒
// 404 — pas parce qu'un handler refuse, mais parce que la route
// n'existe pas. Si une route mutante est un jour enregistrée, ces tests
// tombent immédiatement.
package supervision

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// stubEpochs / stubStats sont les coutures T29/T17 figées pour tests.
type stubEpochs struct{ st cluster.TrackerStatus }

func (s stubEpochs) Status() cluster.TrackerStatus { return s.st }

type stubStats struct{ st broker.BrokerStats }

func (s stubStats) Stats() broker.BrokerStats { return s.st }

// consoleFixture assemble une console sur un vrai moniteur (fixture
// supervision), un vrai store de contrats (feuilles sur le log de la
// cellule) et des sources époque/stats figées.
type consoleFixture struct {
	mf        *monitorFixture
	contracts *pep.ContractStore
	opPriv    ed25519.PrivateKey
	epochs    *stubEpochs
	stats     *stubStats
	console   *Console
}

func newConsoleFixture(t *testing.T) *consoleFixture {
	t.Helper()
	mf := newMonitorFixture(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	contracts, err := pep.NewContractStore(pep.ContractOptions{
		CellID:       mf.cell.cellID,
		PolicyID:     [32]byte{0xA1, 0xB2},
		OperatorKeys: []ed25519.PublicKey{pub},
		Salt:         []byte("t34c-console-salt-0123456789"),
		Leaves:       mf.cell.log,
		Now:          mf.clk.now,
	})
	if err != nil {
		t.Fatalf("NewContractStore: %v", err)
	}
	cfx := &consoleFixture{
		mf:        mf,
		contracts: contracts,
		opPriv:    priv,
		epochs: &stubEpochs{st: cluster.TrackerStatus{
			Epoch:             7,
			Authority:         "authority-epoch-7",
			NotBefore:         mf.clk.t.Add(-time.Hour),
			ExpiresAt:         mf.clk.t.Add(time.Hour),
			Quarantined:       []string{"cell-zeta-09", "cell-alpha-02"}, // volontairement non trié
			AutoFailoversHour: 1,
		}},
		stats: &stubStats{st: broker.BrokerStats{Requests: 10, Allows: 6, Denies: 4, PlanDenies: 3}},
	}
	c, err := NewConsole(ConsoleOptions{
		Monitor:   mf.monitor,
		Contracts: contracts,
		Epochs:    cfx.epochs,
		Stats:     cfx.stats,
	})
	if err != nil {
		t.Fatalf("NewConsole: %v", err)
	}
	cfx.console = c
	return cfx
}

// submitPlan soumet un plan de n étapes au store de la fixture.
func (cfx *consoleFixture) submitPlan(t *testing.T, n int) [32]byte {
	t.Helper()
	steps := make([]pep.PlanStep, n)
	for i := range steps {
		steps[i] = pep.PlanStep{Action: "db.write", Resource: "users", ParamsHash: pep.HashParams([]byte{byte(i), byte(n)})}
	}
	h, err := cfx.contracts.Submit(testCtx, steps)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return h
}

// approvePlan approuve le plan avec l'opérateur de la fixture (30 min).
func (cfx *consoleFixture) approvePlan(t *testing.T, h [32]byte) {
	t.Helper()
	expiry := cfx.mf.clk.now().Add(30 * time.Minute)
	sig := ed25519.Sign(cfx.opPriv, pep.ApprovalMessage(h, expiry))
	if err := cfx.contracts.Approve(testCtx, h, expiry, sig); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

func consoleGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestConsoleFailClosedConfig : les quatre sources sont requises — une
// console à moitié branchée afficherait une demi-vérité.
func TestConsoleFailClosedConfig(t *testing.T) {
	cfx := newConsoleFixture(t)
	ok := ConsoleOptions{Monitor: cfx.mf.monitor, Contracts: cfx.contracts, Epochs: cfx.epochs, Stats: cfx.stats}
	cases := map[string]func(*ConsoleOptions){
		"monitor nil":   func(o *ConsoleOptions) { o.Monitor = nil },
		"contracts nil": func(o *ConsoleOptions) { o.Contracts = nil },
		"epochs nil":    func(o *ConsoleOptions) { o.Epochs = nil },
		"stats nil":     func(o *ConsoleOptions) { o.Stats = nil },
	}
	for name, mut := range cases {
		opts := ok
		mut(&opts)
		if _, err := NewConsole(opts); err == nil {
			t.Fatalf("%s : NewConsole accepté — fail-closed attendu", name)
		}
	}
	if _, err := NewConsole(ok); err != nil {
		t.Fatalf("config complète refusée : %v", err)
	}
}

// TestConsoleReadOnlyByConstruction est le garde-fou M13 (D81) : la
// console n'a AUCUNE route mutante. POST/PUT/DELETE/PATCH sur chaque
// route existante ⇒ 405 du mux (Allow: GET), chemins tentants mais
// inexistants ⇒ 404. Si quelqu'un enregistre un jour une route mutante,
// ce test échoue au premier POST qui répond 200.
func TestConsoleReadOnlyByConstruction(t *testing.T) {
	cfx := newConsoleFixture(t)
	h := cfx.console.Handler()

	routes := []string{"/v1/arbitration", "/v1/epoch", "/v1/indicators"}
	for _, r := range routes {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(m, r, strings.NewReader(`{"approve":true}`)))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s %s : %d — attendu 405 (aucune route mutante, D81)", m, r, rec.Code)
			}
			if !strings.Contains(rec.Header().Get("Allow"), http.MethodGet) {
				t.Fatalf("%s %s : Allow=%q — GET attendu", m, r, rec.Header().Get("Allow"))
			}
		}
		// La route existe bel et bien en GET.
		if rec := consoleGet(t, h, r); rec.Code != http.StatusOK {
			t.Fatalf("GET %s : %d — attendu 200", r, rec.Code)
		}
	}
	// Les chemins qu'un attaquant (ou un opérateur pressé) tenterait.
	for _, p := range []string{
		"/v1/arbitration/approve",
		"/v1/plans/abc123/approve",
		"/v1/epoch/quarantine",
		"/v1/failover",
		"/v1/shutdown",
		"/admin",
	} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(m, p, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s : %d — attendu 404 (chemin inexistant)", m, p, rec.Code)
			}
		}
	}
	// La lecture elle-même n'a produit ni feuille ni alerte : le log de
	// supervision n'a pas bougé pendant tout ce trafic.
	if _, size, err := cfx.mf.sup.log.Head(testCtx); err != nil || size != 1 {
		t.Fatalf("log de supervision : taille %d err=%v — attendu 1 (boot) : lire ne feuille jamais (D81)", size, err)
	}
}

// TestConsoleArbitrationQueue : la file d'arbitrage montre les plans en
// attente — hash scellé, bornes temporelles, nombre d'étapes — triés par
// arrivée ; un plan approuvé disparaît ; les étapes ne fuient jamais.
func TestConsoleArbitrationQueue(t *testing.T) {
	cfx := newConsoleFixture(t)
	h := cfx.console.Handler()

	// File vide : pending présent et vide (jamais null côté JSON).
	rec := consoleGet(t, h, "/v1/arbitration")
	var empty arbitrationView
	if err := json.Unmarshal(rec.Body.Bytes(), &empty); err != nil {
		t.Fatalf("décodage : %v", err)
	}
	if empty.Pending == nil || len(empty.Pending) != 0 {
		t.Fatalf("file vide attendue, got %+v", empty.Pending)
	}
	wantPolicy := hex.EncodeToString(append([]byte{0xA1, 0xB2}, make([]byte, 30)...))
	if empty.PolicyID != wantPolicy {
		t.Fatalf("policy_id %q — attendu %q", empty.PolicyID, wantPolicy)
	}

	h1 := cfx.submitPlan(t, 2)
	submitted1 := cfx.mf.clk.now()
	cfx.mf.clk.advance(time.Minute)
	h2 := cfx.submitPlan(t, 1)
	submitted2 := cfx.mf.clk.now()

	rec = consoleGet(t, h, "/v1/arbitration")
	var view arbitrationView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("décodage : %v", err)
	}
	if len(view.Pending) != 2 {
		t.Fatalf("pending : %d plans — attendu 2", len(view.Pending))
	}
	if view.Pending[0].Hash != hex.EncodeToString(h1[:]) || view.Pending[1].Hash != hex.EncodeToString(h2[:]) {
		t.Fatalf("ordre de file : [%s %s] — attendu h1 puis h2 (ordre d'arbitrage)",
			view.Pending[0].Hash[:8], view.Pending[1].Hash[:8])
	}
	if view.Pending[0].Steps != 2 || view.Pending[1].Steps != 1 {
		t.Fatalf("étapes : %d et %d — attendu 2 et 1", view.Pending[0].Steps, view.Pending[1].Steps)
	}
	if !view.Pending[0].SubmittedAt.Equal(submitted1) || !view.Pending[1].SubmittedAt.Equal(submitted2) {
		t.Fatalf("submitted_at : %v / %v", view.Pending[0].SubmittedAt, view.Pending[1].SubmittedAt)
	}
	if !view.Pending[0].ExpiresAt.Equal(submitted1.Add(pep.DefaultPendingTTL)) {
		t.Fatalf("expires_at : %v — attendu submitted + %v", view.Pending[0].ExpiresAt, pep.DefaultPendingTTL)
	}
	// Le plan en clair ne fuit pas : ni étapes, ni paramètres, ni actions
	// dans le corps (hash-only, §6.2).
	if strings.Contains(rec.Body.String(), "db.write") || strings.Contains(rec.Body.String(), "users") {
		t.Fatalf("le corps contient le plan en clair — hash-only violé : %s", rec.Body.String())
	}

	// Un plan approuvé sort de la file (la décision reste une signature
	// opérateur ailleurs — la console constate, elle ne décide pas).
	cfx.approvePlan(t, h1)
	rec = consoleGet(t, h, "/v1/arbitration")
	view = arbitrationView{}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("décodage : %v", err)
	}
	if len(view.Pending) != 1 || view.Pending[0].Hash != hex.EncodeToString(h2[:]) {
		t.Fatalf("pending après approbation : %+v — attendu [h2]", view.Pending)
	}
}

// TestConsoleEpoch : état d'époque rendu tel quel, quarantaine triée
// (sortie déterministe malgré l'itération de map du tracker).
func TestConsoleEpoch(t *testing.T) {
	cfx := newConsoleFixture(t)
	rec := consoleGet(t, cfx.console.Handler(), "/v1/epoch")
	var view epochView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("décodage : %v", err)
	}
	want := cfx.epochs.st
	if view.Epoch != 7 || view.Authority != want.Authority || view.AutoFailoversHour != 1 {
		t.Fatalf("époque : %+v", view)
	}
	if !view.NotBefore.Equal(want.NotBefore) || !view.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("bornes d'époque : %v → %v", view.NotBefore, view.ExpiresAt)
	}
	if len(view.Quarantined) != 2 || view.Quarantined[0] != "cell-alpha-02" || view.Quarantined[1] != "cell-zeta-09" {
		t.Fatalf("quarantaine non triée : %v", view.Quarantined)
	}
}

// TestConsoleIndicators : indicateurs §9.1 — taux d'arbitrage, latence
// ajoutée 0 (par construction), et par cellule la fraîcheur d'ancrage,
// la taille de chaîne vérifiée et l'état de chute.
func TestConsoleIndicators(t *testing.T) {
	cfx := newConsoleFixture(t)
	h := cfx.console.Handler()

	read := func() indicatorsView {
		rec := consoleGet(t, h, "/v1/indicators")
		var view indicatorsView
		if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
			t.Fatalf("décodage : %v", err)
		}
		return view
	}

	// État initial : jamais ancré ⇒ stale (faute §6.2), lag −1.
	view := read()
	if view.Tier1SupervisionLatencyNs != 0 {
		t.Fatalf("latence tier1 ajoutée : %d ns — 0 par construction", view.Tier1SupervisionLatencyNs)
	}
	if view.Arbitration.Requests != 10 || view.Arbitration.PlanDenies != 3 {
		t.Fatalf("compteurs arbitrage : %+v", view.Arbitration)
	}
	if view.Arbitration.ArbitrationRate != 0.3 {
		t.Fatalf("taux d'arbitrage : %v — attendu 0.3 (3/10)", view.Arbitration.ArbitrationRate)
	}
	if view.Arbitration.PendingPlans != 0 {
		t.Fatalf("pending_plans : %d — attendu 0", view.Arbitration.PendingPlans)
	}
	if len(view.Cells) != 1 || view.Cells[0].CellID != "cell-alpha-01" {
		t.Fatalf("cellules : %+v", view.Cells)
	}
	cell := view.Cells[0]
	if cell.ChainSize != 3 {
		t.Fatalf("chain_size : %d — attendu 3 (décision + genèse + transition)", cell.ChainSize)
	}
	if cell.AnchorLagNs != -1 || !cell.AnchorStale {
		t.Fatalf("ancrage jamais observé : lag=%d stale=%v — attendu −1/true", cell.AnchorLagNs, cell.AnchorStale)
	}
	if cell.FallEpisode {
		t.Fatalf("fall_episode true à froid — aucune chute n'a été détectée")
	}
	if view.Failover.MaxTriggers != 2 || view.Failover.FallDelayNs != int64(DefaultFallDelay) || view.Failover.TriggersHour != 0 {
		t.Fatalf("failover : %+v", view.Failover)
	}

	// Après ancrage à l'instant présent : lag 0, stale false.
	cfx.mf.anchorAt(t, cfx.mf.clk.now())
	cfx.mf.check(t)
	cell = read().Cells[0]
	if cell.AnchorLagNs != 0 || cell.AnchorStale {
		t.Fatalf("ancrage frais : lag=%d stale=%v — attendu 0/false", cell.AnchorLagNs, cell.AnchorStale)
	}
	if cell.LastAnchor.IsZero() {
		t.Fatalf("last_anchor omis alors qu'un ancrage existe")
	}

	// Un plan en attente est compté dans l'indicateur d'arbitrage.
	cfx.submitPlan(t, 1)
	if got := read().Arbitration.PendingPlans; got != 1 {
		t.Fatalf("pending_plans : %d — attendu 1", got)
	}
}

// TestConsoleUnixSocketEndToEnd : la console sert réellement sur le
// socket Unix de cellule (broker.ListenUnix), répond, puis s'arrête
// proprement à l'annulation du contexte — pas de coupure en vol.
func TestConsoleUnixSocketEndToEnd(t *testing.T) {
	cfx := newConsoleFixture(t)
	sockPath := t.TempDir() + "/console.sock"
	lis, err := broker.ListenUnix(sockPath)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- cfx.console.Serve(ctx, lis) }()

	client := &http.Client{Transport: &http.Transport{DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(dctx, "unix", sockPath)
	}}}
	resp, err := client.Get("http://console/v1/indicators")
	if err != nil {
		t.Fatalf("GET via socket unix : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d — attendu 200", resp.StatusCode)
	}
	var view indicatorsView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("décodage : %v", err)
	}
	if len(view.Cells) != 1 {
		t.Fatalf("cellules : %+v", view.Cells)
	}
	// Le socket est restreint au propriétaire/groupe (0660 — l'accès au
	// socket EST le contrôle d'accès, doctrine v1).
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket : %v", err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("permissions du socket : %o — attendu 660 (l'accès au socket EST le contrôle d'accès)", fi.Mode().Perm())
	}

	cancel()
	if err := <-serveErr; err != nil {
		t.Fatalf("Serve : %v — arrêt propre attendu", err)
	}
}

// TestConsoleConcurrentWithCheckOnce : la console lit pendant que le
// moniteur vérifie — le verrou de Monitor garantit l'absence de course
// (test utile sous -race) et un instantané jamais à moitié reconstruit.
func TestConsoleConcurrentWithCheckOnce(t *testing.T) {
	cfx := newConsoleFixture(t)
	h := cfx.console.Handler()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/indicators", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("GET /v1/indicators pendant CheckOnce : %d", rec.Code)
				return
			}
		}
	}()
	for i := 0; i < 5; i++ {
		cfx.mf.clk.advance(30 * time.Second)
		cfx.mf.anchorAt(t, cfx.mf.clk.now())
		cfx.mf.check(t)
	}
	close(stop)
	<-done
}
