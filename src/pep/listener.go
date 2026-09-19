package pep

// Listener HTTP du PEP (T15, §4.1 + §5.3 + §9.1) — le process en écoute
// sur le port local que suppose la redirection nftables
// (config/nftables/pep-redirect.nft, PEP_PORT=8443).
//
// Boucle de décision (pseudo-code de l'issue) :
//
//	gate (T14, étape 0 interne au validateur) → validate (T9) →
//	[passeport ouvert (T12)] → [arbitrage OPA (T11)] → verdict →
//	feuille (§4.1, par le validateur) → posture monitor/closed (T15).
//
// Doctrine §5.3 — MONITOR d'abord : chaque verdict est journalisé
// (feuille de décision, monitor comme closed) mais RIEN n'est bloqué ;
// Forwarded vaut alors true même sur deny (compté en WouldDeny). En
// closed, le verdict s'applique. La bascule de posture passe par
// l'endpoint /v1/mode, gouverné par quorum (ModeController).
//
// Latence §9.1 : chaque évaluation est chronométrée (horloge réelle —
// la mesure n'est pas une donnée de décision) et agrégée dans Stats,
// exposée sur /healthz dès ce premier prototype.
//
// Note d'honnêteté d'intégration : le listener rend des VERDICTS sur
// flux présentés (API HTTP) ; la plomberie de paquets (redirection NAT,
// re-injection) est l'affaire du lab containerlab (T19) — ici, pas de
// promesse de proxy transparent.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"
)

// ListenerOptions paramètre le listener. Fail-closed dès la configuration.
type ListenerOptions struct {
	// Validator est la chaîne de décision T9 — il porte déjà la couture
	// Gate (T14, étape 0). Requis.
	Validator *Validator
	// Mode est le contrôleur de posture monitor/closed (T15). Requis :
	// un listener sans posture explicite est interdit (doctrine §5.3).
	Mode *ModeController
	// Ledger (T12), si non nil, ouvre le passeport de tout jeton allow
	// portant un vecteur quota, et sert l'endpoint /v1/passport/consume.
	Ledger *QuotaLedger
	// OPA (T11), si non nil, est consulté APRÈS validation : son verdict
	// l'emporte sur l'allow du jeton.
	OPA *OPAClient
}

// ListenerStats agrège les mesures du listener (§9.1).
type ListenerStats struct {
	Evaluations    uint64 `json:"evaluations"`
	Forwarded      uint64 `json:"forwarded"`
	Denied         uint64 `json:"denied"`     // bloqués (closed)
	WouldDeny      uint64 `json:"would_deny"` // deny journalisés, non appliqués (monitor)
	MaxElapsedUs   int64  `json:"max_elapsed_us"`
	TotalElapsedUs int64  `json:"total_elapsed_us"`
}

// Listener est le serveur de décision du PEP. Sûr pour un usage
// concurrent.
type Listener struct {
	validator *Validator
	mode      *ModeController
	ledger    *QuotaLedger
	opa       *OPAClient

	evaluations    atomic.Uint64
	forwarded      atomic.Uint64
	denied         atomic.Uint64
	wouldDeny      atomic.Uint64
	maxElapsedUs   atomic.Int64
	totalElapsedUs atomic.Int64
}

// NewListener construit le listener. Fail-closed : validateur et
// contrôleur de mode requis.
func NewListener(opts ListenerOptions) (*Listener, error) {
	if opts.Validator == nil {
		return nil, errors.New("pep: validateur requis (T9 — la chaîne de décision)")
	}
	if opts.Mode == nil {
		return nil, errors.New("pep: contrôleur de mode requis (§5.3 : posture explicite)")
	}
	return &Listener{
		validator: opts.Validator,
		mode:      opts.Mode,
		ledger:    opts.Ledger,
		opa:       opts.OPA,
	}, nil
}

// Stats rapporte les compteurs courants (observabilité §9.1).
func (l *Listener) Stats() ListenerStats {
	return ListenerStats{
		Evaluations:    l.evaluations.Load(),
		Forwarded:      l.forwarded.Load(),
		Denied:         l.denied.Load(),
		WouldDeny:      l.wouldDeny.Load(),
		MaxElapsedUs:   l.maxElapsedUs.Load(),
		TotalElapsedUs: l.totalElapsedUs.Load(),
	}
}

// Handler monte les routes du listener.
func (l *Listener) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evaluate", l.handleEvaluate)
	mux.HandleFunc("/v1/passport/consume", l.handleConsume)
	mux.HandleFunc("/v1/mode", l.handleMode)
	mux.HandleFunc("/healthz", l.handleHealthz)
	return mux
}

// EvaluateRequest est un flux présenté au PEP.
type EvaluateRequest struct {
	Token      string `json:"token"`                 // CWT/COSE_Sign1, base64
	Action     string `json:"action"`                // portée demandée (§4.5)
	Resource   string `json:"resource"`              // portée demandée
	Epoch      uint64 `json:"epoch"`                 // époque courante (§7.2)
	ObjectSeal string `json:"object_seal,omitempty"` // sceau §4.4(2), hex (64), si requis
}

// EvaluateResponse est le verdict rendu — et ce que la posture en fait.
type EvaluateResponse struct {
	Allow          bool   `json:"allow"`
	Reason         string `json:"reason"`
	Mode           string `json:"mode"`
	Forwarded      bool   `json:"forwarded"` // monitor : toujours true (log only)
	LeafWritten    bool   `json:"leaf_written"`
	PassportOpened bool   `json:"passport_opened,omitempty"`
	ElapsedUs      int64  `json:"elapsed_us"`
}

// ConsumeRequest décrémente un passeport à l'exécution (§4.1-bis).
type ConsumeRequest struct {
	JTI string `json:"jti"` // hex (32)
	N   uint64 `json:"n"`
}

// ConsumeResponse rend l'état du compteur après décrément — ou la
// coupure nette (propre, tracée par T12).
type ConsumeResponse struct {
	OK        bool   `json:"ok"`
	Err       string `json:"error,omitempty"`
	Remaining uint64 `json:"remaining"`
	Closed    bool   `json:"closed"`
}

// ModeResponse rapporte la posture courante.
type ModeResponse struct {
	Mode string `json:"mode"`
}

// ModeChangeRequest demande une bascule de posture (gouvernée, §5.3).
type ModeChangeRequest struct {
	Mode    string   `json:"mode"`
	Signers []string `json:"signers"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func methodGuard(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "méthode " + method + " requise"})
		return false
	}
	return true
}

// handleEvaluate : la boucle de décision — gate (T14, étape 0 du
// validateur) → validate (T9) → passeport (T12) → OPA (T11) → posture.
func (l *Listener) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if !methodGuard(w, r, http.MethodPost) {
		return
	}
	var in EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "corps JSON illisible"})
		return
	}
	wire, err := base64.StdEncoding.DecodeString(in.Token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token base64 illisible"})
		return
	}
	req := Request{Action: in.Action, Resource: in.Resource, Epoch: in.Epoch}
	if in.ObjectSeal != "" {
		seal, err := hex.DecodeString(in.ObjectSeal)
		if err != nil || len(seal) != 32 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sceau hex(32) illisible"})
			return
		}
		var s [32]byte
		copy(s[:], seal)
		req.ObjectSeal = &s
	}

	start := time.Now() // §9.1 : mesure réelle — pas une donnée de décision

	// Gate (T14) puis chaîne T9 : le portillon est l'étape 0 INTERNE du
	// validateur — un seul chemin de refus, avant toute mutation.
	d := l.validator.Validate(r.Context(), wire, req)

	// Passeport de quota (§4.1-bis) : ouvert à l'allow — « chaque porte
	// ouverte naît avec son compteur ».
	passportOpened := false
	if d.Allow && d.Token != nil && d.Token.Quota != nil && l.ledger != nil {
		if _, err := l.ledger.Open(d.Token); err != nil {
			// Registre saturé / vecteur invalide : fail-closed, la porte
			// ne s'ouvre pas sans son compteur.
			d.Allow = false
			d.Reason = TripReasonQuotaSaturated
		} else {
			passportOpened = true
		}
	}

	// Arbitrage politique (T11) APRÈS validation : OPA a le dernier mot.
	if d.Allow && l.opa != nil {
		od := l.opa.Eval(r.Context(), OPAInput{
			JTI:      d.JTI,
			Subject:  d.Token.Sub,
			Action:   req.Action,
			Resource: req.Resource,
			Class:    d.Token.Class,
			Epoch:    d.Token.Epoch,
		})
		if !od.Allow {
			d.Allow = false
			d.Reason = od.Reason
		}
	}

	// Posture (§5.3) : monitor = log only ; closed = verdict appliqué.
	forwarded := l.mode.Allows(d)
	elapsed := time.Since(start)

	l.evaluations.Add(1)
	if forwarded {
		l.forwarded.Add(1)
	}
	switch {
	case d.Allow:
	case forwarded:
		l.wouldDeny.Add(1) // deny journalisé, non appliqué (monitor)
	default:
		l.denied.Add(1) // bloqué (closed)
	}
	l.totalElapsedUs.Add(elapsed.Microseconds())
	for {
		cur := l.maxElapsedUs.Load()
		if elapsed.Microseconds() <= cur || l.maxElapsedUs.CompareAndSwap(cur, elapsed.Microseconds()) {
			break
		}
	}

	writeJSON(w, http.StatusOK, EvaluateResponse{
		Allow:          d.Allow,
		Reason:         d.Reason,
		Mode:           l.mode.Mode().String(),
		Forwarded:      forwarded,
		LeafWritten:    d.LeafWritten,
		PassportOpened: passportOpened,
		ElapsedUs:      elapsed.Microseconds(),
	})
}

// handleConsume : décrément d'un passeport à l'exécution (§4.1-bis) —
// compteur à l'exécution, dépassement ⇒ coupure propre + refus + feuille
// (T12), jamais de décrément partiel.
func (l *Listener) handleConsume(w http.ResponseWriter, r *http.Request) {
	if !methodGuard(w, r, http.MethodPost) {
		return
	}
	if l.ledger == nil {
		writeJSON(w, http.StatusOK, ConsumeResponse{OK: false, Err: "pas de registre de quotas sur ce listener"})
		return
	}
	var in ConsumeRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "corps JSON illisible"})
		return
	}
	jtiBytes, err := hex.DecodeString(in.JTI)
	if err != nil || len(jtiBytes) != 16 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "jti hex(16) illisible"})
		return
	}
	var jti [16]byte
	copy(jti[:], jtiBytes)
	counter, ok := l.ledger.Counter(jti)
	if !ok {
		writeJSON(w, http.StatusOK, ConsumeResponse{OK: false, Err: "passeport inconnu"})
		return
	}
	if err := counter.Consume(in.N); err != nil {
		writeJSON(w, http.StatusOK, ConsumeResponse{
			OK:        false,
			Err:       consumeErrReason(err),
			Remaining: counter.Remaining(),
			Closed:    counter.Closed(),
		})
		return
	}
	writeJSON(w, http.StatusOK, ConsumeResponse{OK: true, Remaining: counter.Remaining(), Closed: counter.Closed()})
}

// consumeErrReason mappe les erreurs T12 sur les codes machine stables.
func consumeErrReason(err error) string {
	switch {
	case errors.Is(err, ErrQuotaExceeded):
		return ReasonQuotaExceeded
	case errors.Is(err, ErrPassportExpired):
		return ReasonPassportExpired
	case errors.Is(err, ErrPassportClosed):
		return "passport-closed"
	}
	return "consume-error"
}

// handleMode : GET rapporte la posture ; POST demande une bascule
// GOUVERNÉE (quorum §5.3) — 403 si la preuve est rejetée.
func (l *Listener) handleMode(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, ModeResponse{Mode: l.mode.Mode().String()})
	case http.MethodPost:
		var in ModeChangeRequest
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "corps JSON illisible"})
			return
		}
		m, err := ParsePEPMode(in.Mode)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		proof := QuorumProof{Signers: make([][]byte, 0, len(in.Signers))}
		for _, s := range in.Signers {
			proof.Signers = append(proof.Signers, []byte(s))
		}
		if err := l.mode.SetMode(m, proof); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ModeResponse{Mode: l.mode.Mode().String()})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "méthode GET|POST requise"})
	}
}

// handleHealthz : état du listener + statistiques de latence (§9.1).
func (l *Listener) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if !methodGuard(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Status string        `json:"status"`
		Mode   string        `json:"mode"`
		Stats  ListenerStats `json:"stats"`
	}{
		Status: "ok",
		Mode:   l.mode.Mode().String(),
		Stats:  l.Stats(),
	})
}
