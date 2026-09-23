package pep

// Vérification PÉRIODIQUE de la révision de politique servie par OPA
// (revue de sécurité #92, finding A5) : TBP_POLICY_ID est auto-déclaré
// par variable d'environnement — sans ce contrôle, rien ne vérifie
// qu'OPA exécute RÉELLEMENT ce bundle. La révision épinglée au build
// (`opa build --revision <TBP_POLICY_ID hex>`, spec §10.3) est comparée à
// la révision RÉELLEMENT servie, lue via le paramètre standard OPA
// `provenance=true` (REST API Data : la réponse porte alors un champ
// provenance.revision qui reflète le .manifest du bundle chargé — voir
// la doc REST API OPA, endpoint Data). Un écart — ou l'impossibilité de
// vérifier — bascule fail-closed (§1) : pas de preuve de révision, pas de
// confiance.
//
// Hors du chemin chaud de décision : Eval() (T11, EvalTimeout 5 ms §9.1)
// n'est PAS touché par ce fichier. C'est un contrôle périodique, en
// arrière-plan, même patron que ClockWatchdog (T13, clock.go) : Check()
// synchrone et testable, Run(ctx) la boucle de production.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// DefaultOPARevisionCheckInterval borne la fréquence de vérification —
// hors chemin chaud, un intervalle de quelques secondes suffit à détecter
// un bundle substitué sans charge notable sur OPA.
const DefaultOPARevisionCheckInterval = 10 * time.Second

// defaultOPARevisionCheckTimeout borne CHAQUE vérification — généreux
// comparé à EvalTimeout car hors chemin chaud, mais toujours strict :
// une vérification qui ne répond jamais ne doit jamais bloquer
// indéfiniment le contrôle suivant.
const defaultOPARevisionCheckTimeout = 2 * time.Second

// Raisons des feuilles/alarmes de révision. opa-revision-mismatch est la
// détection directe de l'attaque #92.A5 (bundle substitué) ;
// opa-revision-unverifiable couvre tout ce qui empêche de conclure
// (réseau, statut, corps illisible, champ provenance absent) — les deux
// sont fail-closed (§1 : pas de preuve, pas de confiance), la distinction
// n'existe que pour le forensique.
const (
	ReasonOPARevisionMismatch     = "opa-revision-mismatch"
	ReasonOPARevisionUnverifiable = "opa-revision-unverifiable"
	ReasonOPARevisionOK           = "opa-revision-ok"
)

// Priorités des feuilles d'alarme de révision (même échelle que clock.go).
const (
	OPARevisionPriorityInfo byte = 0 // retour à la révision attendue
	OPARevisionPriorityHigh byte = 1 // écart ou vérification impossible
)

// opaProvenanceResponse ne décode QUE le champ nécessaire — le reste de
// la réponse OPA (result, decision_id…) est ignoré ici, Eval() s'en
// charge sur le chemin chaud.
type opaProvenanceResponse struct {
	Provenance *struct {
		Revision string `json:"revision"`
	} `json:"provenance"`
}

// OPARevisionMode est l'état du portillon de révision.
type OPARevisionMode int

const (
	OPARevisionModeOK OPARevisionMode = iota
	OPARevisionModeMismatch
)

func (m OPARevisionMode) String() string {
	if m == OPARevisionModeMismatch {
		return "mismatch"
	}
	return "ok"
}

// OPARevisionWatcherOptions paramètre le watcher. Fail-closed dès la
// configuration.
type OPARevisionWatcherOptions struct {
	// Endpoint est le MÊME endpoint de décision qu'OPAClient (p.ex.
	// http://127.0.0.1:8181/v1/data/tbp/allow) — provenance=true y est
	// ajouté en paramètre de requête. Requis.
	Endpoint string
	// Expected est la révision attendue : TBP_POLICY_ID épinglé (hex),
	// exactement la chaîne passée à `opa build --revision` (spec §10.3).
	// Requis.
	Expected string
	// HTTPClient permet d'injecter un transport (tests, socket Unix
	// #92.A3…). Nil ⇒ http.Client par défaut.
	HTTPClient *http.Client
	// Interval est la période de Run. 0 ⇒ DefaultOPARevisionCheckInterval.
	// Négatif ⇒ erreur.
	Interval time.Duration
	// Timeout borne CHAQUE vérification. 0 ⇒
	// defaultOPARevisionCheckTimeout. Négatif ⇒ erreur.
	Timeout time.Duration
	// CellID identifie la cellule dans les feuilles d'alarme. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2), ≥ 16 octets. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : chaque transition est tracée.
	// Requis (une dérive de révision non tracée serait une dérive
	// silencieuse).
	Leaves LeafSink
	// OnTrip est la couture d'alarme vers T14 (fail-closed unique) : tout
	// écart ou vérification impossible y est signalé. Nil ⇒ pas d'alarme
	// (le déni fail-closed T14 existant ne se déclenche alors pas pour
	// CE contrôle, mais le mode reste observable via Mode()/Degraded()).
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2) pour les feuilles.
	// Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// OPARevisionWatcher vérifie périodiquement que la révision servie par
// OPA correspond à TBP_POLICY_ID épinglé. Sûr pour un usage concurrent.
type OPARevisionWatcher struct {
	endpoint string
	expected string
	hc       *http.Client
	interval time.Duration
	timeout  time.Duration
	cellID   string
	salt     []byte
	leaves   LeafSink
	onTrip   func(reason string)
	now      func() time.Time

	mu     sync.Mutex
	mode   OPARevisionMode
	reason string
}

// NewOPARevisionWatcher construit le watcher. Fail-closed : endpoint,
// révision attendue, cellID, sel ≥ 16 o et couture feuilles requis ;
// intervalle et timeout négatifs rejetés.
func NewOPARevisionWatcher(opts OPARevisionWatcherOptions) (*OPARevisionWatcher, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("pep: endpoint OPA requis (révision §92.A5)")
	}
	if opts.Expected == "" {
		return nil, errors.New("pep: révision attendue requise (TBP_POLICY_ID épinglé, §92.A5)")
	}
	if opts.CellID == "" {
		return nil, errors.New("pep: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: couture feuilles requise (§92.A5 : toute dérive tracée)")
	}
	if opts.Interval < 0 {
		return nil, errors.New("pep: intervalle de vérification négatif refusé")
	}
	if opts.Timeout < 0 {
		return nil, errors.New("pep: timeout de vérification négatif refusé")
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultOPARevisionCheckInterval
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultOPARevisionCheckTimeout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &OPARevisionWatcher{
		endpoint: opts.Endpoint,
		expected: opts.Expected,
		hc:       hc,
		interval: interval,
		timeout:  timeout,
		cellID:   opts.CellID,
		salt:     salt,
		leaves:   opts.Leaves,
		onTrip:   opts.OnTrip,
		now:      now,
	}, nil
}

// Interval rapporte la période de vérification effective.
func (w *OPARevisionWatcher) Interval() time.Duration { return w.interval }

// Check effectue une vérification UNIQUE — point d'entrée synchrone
// (tests, premier contrôle au démarrage avant Run).
func (w *OPARevisionWatcher) Check(ctx context.Context) {
	revision, err := w.fetchRevision(ctx)

	w.mu.Lock()
	defer w.mu.Unlock()

	switch {
	case err != nil:
		w.enterLocked(ReasonOPARevisionUnverifiable)
	case revision != w.expected:
		w.enterLocked(ReasonOPARevisionMismatch)
	default:
		w.exitLocked()
	}
}

// fetchRevision interroge OPA avec provenance=true et rend la révision
// annoncée — ou une erreur si quoi que ce soit empêche de la lire
// (réseau, statut, corps, champ absent). Aucune de ces fautes n'est
// distinguée plus finement : toutes bascule fail-closed identiquement.
func (w *OPARevisionWatcher) fetchRevision(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	u, err := url.Parse(w.endpoint)
	if err != nil {
		return "", fmt.Errorf("endpoint OPA illisible: %w", err)
	}
	q := u.Query()
	q.Set("provenance", "true")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := w.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxOPAResponse))
		return "", fmt.Errorf("statut %d", resp.StatusCode)
	}
	var decoded opaProvenanceResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOPAResponse)).Decode(&decoded); err != nil {
		return "", err
	}
	if decoded.Provenance == nil || decoded.Provenance.Revision == "" {
		return "", errors.New("réponse OPA sans provenance.revision (bundle non versionné ? — --revision requis au build, spec §10.3)")
	}
	return decoded.Provenance.Revision, nil
}

// Run vérifie immédiatement puis boucle jusqu'à annulation du contexte —
// la boucle de production ; Check reste le point d'entrée synchrone.
func (w *OPARevisionWatcher) Run(ctx context.Context) {
	w.Check(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Check(ctx)
		}
	}
}

// enterLocked bascule en écart EXPLICITE et tracé. Sans effet si déjà
// dans cet état précis (pas de feuille en double).
func (w *OPARevisionWatcher) enterLocked(reason string) {
	if w.onTrip != nil {
		w.onTrip(reason) // T14 possède le latch — alarmé à CHAQUE détection
	}
	if w.mode == OPARevisionModeMismatch && w.reason == reason {
		return
	}
	w.mode, w.reason = OPARevisionModeMismatch, reason
	w.writeLeafLocked(reason, OPARevisionPriorityHigh)
}

// exitLocked revient à la révision attendue — tracé (le retour aussi est
// prouvé, même doctrine que clock.go). Sans effet si déjà OK.
func (w *OPARevisionWatcher) exitLocked() {
	if w.mode == OPARevisionModeOK {
		return
	}
	w.mode, w.reason = OPARevisionModeOK, ""
	w.writeLeafLocked(ReasonOPARevisionOK, OPARevisionPriorityInfo)
}

// writeLeafLocked inscrit la feuille (KindTelemetry : une alarme n'est
// pas une décision). Hash-only : le registre ne voit que l'engagement.
func (w *OPARevisionWatcher) writeLeafLocked(reason string, priority byte) {
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      w.cellID,
		PayloadHash: registry.HashPayload(w.salt, opaRevisionAlarmRecord(reason, priority)),
		Timestamp:   w.now().UnixNano(),
	}
	if _, err := w.leaves.Append(context.Background(), leaf); err != nil && w.onTrip != nil {
		w.onTrip(ReasonLeafWriteFailed)
	}
}

// opaRevisionAlarmRecord sérialise le record d'alarme de révision :
// "TBPR1" ‖ u8 len(reason) ‖ reason ‖ priority(1).
func opaRevisionAlarmRecord(reason string, priority byte) []byte {
	record := make([]byte, 0, 5+1+len(reason)+1)
	record = append(record, "TBPR1"...)
	record = append(record, byte(len(reason)))
	record = append(record, reason...)
	record = append(record, priority)
	return record
}

// Mode rapporte l'état courant du portillon de révision.
func (w *OPARevisionWatcher) Mode() OPARevisionMode {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mode
}

// Reason rapporte la raison de l'écart courant ("" si OK) — couture
// forensique pour l'observabilité.
func (w *OPARevisionWatcher) Reason() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reason
}

// Mismatch rapporte si le portillon est en écart.
func (w *OPARevisionWatcher) Mismatch() bool { return w.Mode() == OPARevisionModeMismatch }
