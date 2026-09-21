// console.go — T34c (issue #60, D81/D82) : la console de supervision,
// lecture seule PAR CONSTRUCTION.
//
// « Le superviseur voit tout, ne touche à rien. » La console expose trois
// routes GET — /v1/arbitration (file d'arbitrage : les plans en attente,
// hash scellé et bornes temporelles, jamais les étapes ni les paramètres),
// /v1/epoch (état du suivi d'époque T29), /v1/indicators (indicateurs
// §9.1) — et AUCUNE route mutante : une requête POST/PUT/DELETE reçoit
// 405 du mux (méthode non enregistrée), un chemin inconnu 404. Le refus
// n'est pas un code de garde dans un handler qui pourrait être oublié ou
// contourné : c'est l'absence de la route elle-même (D81, mutation M13).
//
// La décision humaine n'est PAS ici : l'arbitrage reste une signature
// Ed25519 d'opérateur sur le canal dédié (T30, §4.2 : « l'arbitrage est
// une signature, pas une lecture »). La console montre la file ; elle ne
// peut ni approuver, ni révoquer, ni clore un plan — et ses lectures ne
// produisent ni feuille ni alarme (lire ne change rien).
//
// Transport : socket Unix de cellule (doctrine v1 — pas d'exposition
// réseau, pas d'authentification à inventer ; l'accès au socket EST le
// contrôle d'accès, permissions 0660 via broker.ListenUnix). L'exposition
// réseau, si elle vient, est une autre issue (T35) avec son propre plan.
//
// Latence ajoutée au chemin chaud : 0, mesurée par construction — la
// console lit l'état du moniteur (chaînes-ombre), les compteurs du
// broker et la file du store de contrats ; rien de tout cela n'est sur
// le chemin d'une requête d'action (§9.1, indicateur tier1).
package supervision

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// consoleReadHeaderTimeout borne l'attente des en-têtes (même doctrine
// que le broker — un client qui n'envoie rien ne retient pas une
// goroutine indéfiniment).
const consoleReadHeaderTimeout = 5 * time.Second

// EpochStatusSource est la couture vers le suivi d'époque (T29) : lue,
// jamais pilotée (la quarantaine, la rotation et la révocation restent
// des actes signés ailleurs). *cluster.Tracker l'implémente.
//
// L'ERREUR fait partie du contrat (T37, D110 élargi après revue de plan) :
// une implémentation peut être un adaptateur réseau (cmd/supervisord lit
// l'état sur le brokerd de la cellule), dont la lecture peut échouer.
// Les handlers traduisent TOUTE erreur en 503 — jamais en zero-value :
// une zero-value rendue serait exactement la demi-vérité interdite (§1).
// Les lectures locales infaillibles rendent nil.
type EpochStatusSource interface {
	Status() (cluster.TrackerStatus, error)
}

// BrokerStatsSource est la couture vers les compteurs du broker (T17) :
// compteurs monotones lus pour les indicateurs §9.1, jamais remis à
// zéro ni altérés. *broker.Broker l'implémente. Même contrat d'erreur
// qu'EpochStatusSource : toute erreur de lecture devient 503 dans le
// handler, jamais une zero-value (§1).
type BrokerStatsSource interface {
	Stats() (broker.BrokerStats, error)
}

// ArbitrationSource est la couture vers la file d'arbitrage (T30) : la
// file des plans en attente (hash scellé et bornes temporelles — jamais
// les étapes ni les paramètres) et le hash du bundle de règles auquel ils
// se rattachent. Lecture seule : aucune méthode mutante. *pep.ContractStore
// l'implémente (via SnapshotWithPolicy) ; l'extraction d'interface (T37,
// D110 — plomberie, pas de logique métier) permet à la console d'être
// servie par un process qui ne détient pas le store (adaptateur de
// lecture, cmd/supervisord) sans en dupliquer l'état — une copie serait
// une demi-vérité.
//
// SnapshotWithPolicy rend la file ET la policy dans LE MÊME appel — pas
// deux méthodes séparées (Snapshot puis PolicyID). Une version antérieure
// de ce contrat les séparait avec la garantie documentée « la policy du
// dernier Snapshot réussi, lue seulement après un Snapshot du même
// appelant » ; pour un adaptateur réseau qui garde la policy dans un
// champ partagé entre les deux appels, cette garantie est FAUSSE dès que
// deux requêtes console concurrentes s'exécutent : le Snapshot réussi
// d'une deuxième requête écrase la policy en cache avant que la première
// ne la lise, qui associe alors SA PROPRE liste pending à LA POLICY DE
// L'AUTRE — exactement la demi-vérité que ce contrat existe pour
// interdire (trouvé et prouvé empiriquement en revue de PR T37, #77).
// Une seule méthode qui rend les deux valeurs ensemble, sans état
// intermédiaire partagé entre deux appels, rend cette classe de bug
// structurellement impossible plutôt que dépendante d'une convention
// d'appel. Même contrat d'erreur qu'EpochStatusSource : toute erreur
// devient 503 dans le handler, jamais une zero-value (§1).
type ArbitrationSource interface {
	SnapshotWithPolicy() ([]pep.PendingPlan, [32]byte, error)
}

// ConsoleOptions paramètre la console. Fail-closed dès la configuration :
// les quatre sources sont requises — une console à moitié branchée
// afficherait une demi-vérité, ce qui est pire que pas de console.
type ConsoleOptions struct {
	// Monitor est la source des vues cellules/ancrage/chute (View()).
	Monitor *Monitor
	// Contracts est la source de la file d'arbitrage (SnapshotWithPolicy())
	// — *pep.ContractStore in-process, ou tout adaptateur de lecture
	// satisfaisant ArbitrationSource (T37, D110).
	Contracts ArbitrationSource
	// Epochs est la source de l'état d'époque (T29).
	Epochs EpochStatusSource
	// Stats est la source des compteurs broker (T17).
	Stats BrokerStatsSource
}

// Console est le serveur HTTP de supervision. Lecture seule PAR
// CONSTRUCTION : seuls des patterns « GET … » sont enregistrés sur le
// mux — il n'existe matériellement pas de route mutante à appeler.
type Console struct {
	monitor   *Monitor
	contracts ArbitrationSource
	epochs    EpochStatusSource
	stats     BrokerStatsSource
	mux       *http.ServeMux
}

// NewConsole construit la console et enregistre les trois routes GET.
func NewConsole(opts ConsoleOptions) (*Console, error) {
	if opts.Monitor == nil {
		return nil, errors.New("supervision: moniteur requis (la console est sa vue, pas une source)")
	}
	if opts.Contracts == nil {
		return nil, errors.New("supervision: store de contrats requis (file d'arbitrage — §4.2)")
	}
	if opts.Epochs == nil {
		return nil, errors.New("supervision: source d'époque requise (T29)")
	}
	if opts.Stats == nil {
		return nil, errors.New("supervision: source de compteurs broker requise (§9.1)")
	}
	c := &Console{
		monitor:   opts.Monitor,
		contracts: opts.Contracts,
		epochs:    opts.Epochs,
		stats:     opts.Stats,
	}
	mux := http.NewServeMux()
	// Patterns de méthode Go 1.22 : une méthode autre que GET sur ces
	// chemins reçoit 405 (avec Allow: GET) DU MUX — aucune ligne de code
	// à nous n'est exécutée, il n'y a rien à oublier ni à contourner.
	mux.HandleFunc("GET /v1/arbitration", c.handleArbitration)
	mux.HandleFunc("GET /v1/epoch", c.handleEpoch)
	mux.HandleFunc("GET /v1/indicators", c.handleIndicators)
	c.mux = mux
	return c, nil
}

// Handler rend le handler HTTP (tests httptest, embedder).
func (c *Console) Handler() http.Handler { return c.mux }

// Serve sert la console sur le listener jusqu'à annulation du contexte,
// puis arrêt propre : Shutdown, pas de coupure de requête en vol — une
// lecture console tient en quelques millisecondes, le budget est large.
func (c *Console) Serve(ctx context.Context, lis net.Listener) error {
	srv := &http.Server{
		Handler:           c.mux,
		ReadHeaderTimeout: consoleReadHeaderTimeout,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(lis)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// — Vues JSON (contrat stable, snake_case ; les types internes ne sont
// pas sérialisés directement pour que leur évolution ne casse pas
// l'API de la console) —

type pendingPlanView struct {
	Hash        string    `json:"hash"` // sceau du plan, hex
	SubmittedAt time.Time `json:"submitted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Steps       int       `json:"steps"`
}

type arbitrationView struct {
	PolicyID string            `json:"policy_id"` // hash du bundle de règles (claim −1), hex
	Pending  []pendingPlanView `json:"pending"`
}

type epochView struct {
	Epoch             int       `json:"epoch"` // −1 : aucune époque vérifiée
	Authority         string    `json:"authority"`
	NotBefore         time.Time `json:"not_before"`
	ExpiresAt         time.Time `json:"expires_at"`
	Quarantined       []string  `json:"quarantined"`
	AutoFailoversHour int       `json:"auto_failovers_hour"`
}

type arbitrationIndicators struct {
	Requests        uint64  `json:"requests"`
	PlanDenies      uint64  `json:"plan_denies"`
	ArbitrationRate float64 `json:"arbitration_rate"` // plan_denies / requests ; 0 si aucune requête
	PendingPlans    int     `json:"pending_plans"`
}

type cellIndicators struct {
	CellID       string    `json:"cell_id"`
	ChainSize    uint64    `json:"chain_size"`
	LastAnchor   time.Time `json:"last_anchor,omitempty"` // omis si jamais ancré
	AnchorLagNs  int64     `json:"anchor_lag_ns"`         // −1 si jamais ancré
	AnchorStale  bool      `json:"anchor_stale"`          // dérivé : lag > borne §6.2 ou jamais ancré
	LastProgress time.Time `json:"last_progress"`
	FallEpisode  bool      `json:"fall_episode"` // épisode de chute traité, en attente de reprise
}

type failoverIndicators struct {
	FallDelayNs  int64 `json:"fall_delay_ns"`
	MaxTriggers  int   `json:"max_triggers"`
	TriggersHour int   `json:"triggers_hour"`
}

type indicatorsView struct {
	Now                       time.Time             `json:"now"`
	Tier1SupervisionLatencyNs int64                 `json:"tier1_supervision_latency_added_ns"` // 0 : mesuré par construction (voir en-tête)
	Arbitration               arbitrationIndicators `json:"arbitration"`
	Cells                     []cellIndicators      `json:"cells"`
	Failover                  failoverIndicators    `json:"failover"`
}

// handleArbitration rend la file d'arbitrage : plans en attente, hash
// scellé et bornes temporelles — JAMAIS les étapes ni les paramètres
// (hash-only : le plan en clair circule sur le canal opérateur, pas ici).
func (c *Console) handleArbitration(w http.ResponseWriter, _ *http.Request) {
	snap, policyID, err := c.contracts.SnapshotWithPolicy()
	if err != nil {
		writeSourceUnavailable(w) // jamais une zero-value (§1)
		return
	}
	// policyID vient du MÊME appel que snap (contrat ArbitrationSource) —
	// jamais d'une lecture séparée qu'une requête concurrente aurait pu
	// écraser entre-temps.
	view := arbitrationView{
		PolicyID: hex.EncodeToString(sliceOf(policyID)),
		Pending:  make([]pendingPlanView, 0, len(snap)),
	}
	for _, p := range snap {
		view.Pending = append(view.Pending, pendingPlanView{
			Hash:        hex.EncodeToString(sliceOf(p.Hash)),
			SubmittedAt: p.SubmittedAt.UTC(),
			ExpiresAt:   p.ExpiresAt.UTC(),
			Steps:       p.Steps,
		})
	}
	writeConsoleJSON(w, http.StatusOK, view)
}

// handleEpoch rend l'état du suivi d'époque (T29) — lisible même pour
// une cellule en quarantaine (la quarantaine gèle le service, pas
// l'inspection).
func (c *Console) handleEpoch(w http.ResponseWriter, _ *http.Request) {
	st, err := c.epochs.Status()
	if err != nil {
		writeSourceUnavailable(w) // jamais une zero-value (§1)
		return
	}
	quar := append([]string(nil), st.Quarantined...)
	sort.Strings(quar) // itération de map côté tracker : tri pour une sortie déterministe
	writeConsoleJSON(w, http.StatusOK, epochView{
		Epoch:             st.Epoch,
		Authority:         st.Authority,
		NotBefore:         st.NotBefore.UTC(),
		ExpiresAt:         st.ExpiresAt.UTC(),
		Quarantined:       quar,
		AutoFailoversHour: st.AutoFailoversHour,
	})
}

// handleIndicators rend les indicateurs §9.1 : latence ajoutée au chemin
// chaud (0 par construction), taux d'arbitrage (refus de contrat de plan
// / requêtes, T30/T17), file d'attente, et par cellule la fraîcheur
// d'ancrage (§6.2), la taille de chaîne vérifiée et l'état de chute
// (T34b) — faits du moniteur, interprétation marquée comme dérivée.
func (c *Console) handleIndicators(w http.ResponseWriter, _ *http.Request) {
	mv := c.monitor.View()
	st, err := c.stats.Stats()
	if err != nil {
		writeSourceUnavailable(w) // jamais une zero-value (§1)
		return
	}
	snap, _, err := c.contracts.SnapshotWithPolicy()
	if err != nil {
		writeSourceUnavailable(w) // jamais une zero-value (§1)
		return
	}
	rate := 0.0
	if st.Requests > 0 {
		rate = float64(st.PlanDenies) / float64(st.Requests)
	}
	view := indicatorsView{
		Now: mv.Now.UTC(),
		// Tier1SupervisionLatencyNs reste 0 : il n'existe pas de code qui
		// puisse ajouter de la latence — la supervision ne touche pas le
		// chemin chaud, l'indicateur EST cette propriété structurelle.
		Tier1SupervisionLatencyNs: 0,
		Arbitration: arbitrationIndicators{
			Requests:        st.Requests,
			PlanDenies:      st.PlanDenies,
			ArbitrationRate: rate,
			PendingPlans:    len(snap),
		},
		Cells: make([]cellIndicators, 0, len(mv.Cells)),
		Failover: failoverIndicators{
			FallDelayNs:  int64(mv.FallDelay),
			MaxTriggers:  mv.MaxTriggers,
			TriggersHour: mv.TriggersHour,
		},
	}
	for _, cv := range mv.Cells {
		ci := cellIndicators{
			CellID:       cv.CellID,
			ChainSize:    cv.ChainSize,
			AnchorLagNs:  int64(cv.AnchorLag),
			LastProgress: cv.LastProgress.UTC(),
			FallEpisode:  cv.EpisodeHandled,
		}
		if cv.AnchorLag < 0 {
			ci.AnchorStale = true // jamais ancré : faute comme « trop vieux » (§6.2)
		} else {
			ci.LastAnchor = cv.LastAnchor.UTC()
			ci.AnchorStale = cv.AnchorLag > mv.MaxAnchorLag
		}
		view.Cells = append(view.Cells, ci)
	}
	writeConsoleJSON(w, http.StatusOK, view)
}

// sliceOf rend la tranche d'un array — les sceaux quittent la console en
// hex, jamais en binaire brut.
func sliceOf(a [32]byte) []byte {
	b := make([]byte, 32)
	copy(b, a[:])
	return b
}

// writeSourceUnavailable rend 503 : la vue dépend d'une source en
// erreur — la console ne rend JAMAIS une demi-vérité (§1). Vérifié par
// handler, pas par middleware global : /v1/epoch ne dépend pas des
// compteurs broker, une panne de la source stats ne doit pas le faire
// taire (granularité par route, revue de plan T37).
func writeSourceUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "source indisponible"})
}

// writeConsoleJSON sérialise la vue. Sortie bornée par construction
// (file et état bornés §4.3) ; pas de corps de requête lu, jamais —
// les handlers ignorent r.Body, ce qui est plus fort qu'une limite.
func writeConsoleJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v) // une vue bornée ne peut pas échouer à sérialiser ; une coupure client n'est pas une faute
}
