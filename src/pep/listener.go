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
	"context"
	"crypto/ed25519"
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
	// DryRun (T36, §4.4(1)), si non nil, exécute le dry-run des actions
	// F/I/W AVANT l'ouverture du passeport et soumet le diff à OPA. Sans
	// porte configurée, une action F/I/W est soumise à OPA avec
	// dry_run.available=false : la politique tranche (résidu §10.5). Hors
	// classes F/I/W, ce champ n'a AUCUN effet (D105 : coût nul).
	DryRun *DryRunGate
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
	dryRun    *DryRunGate

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
		dryRun:    opts.DryRun,
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
//
// PAS de champ Epoch (retiré — revue de sécurité #90, point 2) : un champ
// que le demandeur pourrait remplir n'aurait plus AUCUN effet (le
// validateur consulte EpochSource, jamais la requête) — le garder aurait
// été un champ malhonnête, qui semble agir sans agir.
type EvaluateRequest struct {
	Token      string `json:"token"`                 // CWT/COSE_Sign1, base64
	Action     string `json:"action"`                // portée demandée (§4.5)
	Resource   string `json:"resource"`              // portée demandée
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
//
// Token (CWT/COSE_Sign1, base64) REMPLACE l'ancien champ JTI nu (revue de
// sécurité #90, point 3) : un jti seul n'authentifie RIEN — quiconque
// l'observe ou le devine (16 octets, mais un canal indirect — journal,
// erreur, timing — peut en fuiter un) pouvait décrémenter, donc épuiser,
// le passeport de QUELQU'UN D'AUTRE (déni de service coopératif). Le jti
// est maintenant EXTRAIT du jeton signé après vérification de possession
// (Validator.VerifyPossession) — jamais déclaré par l'appelant.
type ConsumeRequest struct {
	Token string `json:"token"`
	N     uint64 `json:"n"`
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

// ModeChangeRequest demande une bascule de posture (gouvernée, §5.3) : la
// preuve de quorum est k signatures Ed25519 DISTINCTES (trousseau de
// contrôleurs épinglé §12) sur QuorumMessage("mode-"+mode, Expiry) — pas
// une liste de noms déclarés (revue de sécurité #89).
type ModeChangeRequest struct {
	Mode       string                `json:"mode"`
	Expiry     int64                 `json:"expiry"` // secondes Unix, signé (QuorumMessage)
	Signatures []QuorumSignatureWire `json:"signatures"`
}

// QuorumSignatureWire est la forme hexadécimale sur le fil d'une
// QuorumSignature : kid 16 octets, signature Ed25519 64 octets.
type QuorumSignatureWire struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// decodeQuorumProof décode la preuve de quorum sur le fil (hex) vers sa
// forme binaire. Fail-closed sur tout format illisible : un kid ou une
// signature mal formés ne « dégradent » jamais en preuve vide acceptée
// plus loin — ils font échouer le décodage, donc la requête (400), avant
// même d'atteindre le vérifieur (revue de sécurité #89).
func decodeQuorumProof(in ModeChangeRequest) (QuorumProof, error) {
	sigs := make([]QuorumSignature, 0, len(in.Signatures))
	for _, s := range in.Signatures {
		kid, err := hex.DecodeString(s.KeyID)
		if err != nil || len(kid) != 16 {
			return QuorumProof{}, errors.New("preuve de quorum: key_id illisible (hex 16 octets)")
		}
		sig, err := hex.DecodeString(s.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return QuorumProof{}, errors.New("preuve de quorum: signature illisible (hex 64 octets Ed25519)")
		}
		var kidArr [16]byte
		copy(kidArr[:], kid)
		sigs = append(sigs, QuorumSignature{KeyID: kidArr, Signature: sig})
	}
	return QuorumProof{Expiry: time.Unix(in.Expiry, 0), Signatures: sigs}, nil
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

// evalOutcome est le résultat interne de la chaîne de décision — partagé
// par l'API JSON (handleEvaluate) ET le proxy bloquant (BlockingProxy,
// revue de sécurité #94) : les DEUX appliquent EXACTEMENT le même
// enchaînement gate → validate → dry-run → passeport → OPA → posture.
// Ne JAMAIS dupliquer cette chaîne ailleurs — une copie plus fine
// sauterait silencieusement OPA ou le quota et serait une RÉGRESSION par
// rapport à /v1/evaluate, pas un équivalent.
type evalOutcome struct {
	Decision       Decision
	Forwarded      bool
	PassportOpened bool
	Elapsed        time.Duration
}

// evaluate exécute la chaîne de décision complète — gate (T14, étape 0
// du validateur) → validate (T9) → dry-run (T36) → passeport (T12) →
// OPA (T11) → posture (§5.3). Chronomètre et met à jour les compteurs
// exactement comme avant l'extraction (§9.1).
func (l *Listener) evaluate(ctx context.Context, wire []byte, req Request) evalOutcome {
	start := time.Now() // §9.1 : mesure réelle — pas une donnée de décision

	// Gate (T14) puis chaîne T9 : le portillon est l'étape 0 INTERNE du
	// validateur — un seul chemin de refus, avant toute mutation.
	d := l.validator.Validate(ctx, wire, req)

	// Dry-run (T36, §4.4(1), D104) : classes F/I/W SEULEMENT, AVANT
	// l'ouverture du passeport (revue #62 : un refus dry-run n'ouvre
	// jamais de compteur pour une action qui ne se fera pas), et seulement
	// si OPA est consulté (le diff n'a pas d'autre destinataire). Échec
	// ou timeout = deny fail-closed, tracé par la porte elle-même.
	var dryInput *DryRunInput
	if d.Allow && d.Token != nil && d.Token.Class != ClassOut && l.opa != nil {
		if l.dryRun != nil {
			in, reason := l.dryRun.Execute(ctx, d.JTI, req.Action, req.Resource)
			if reason != "" {
				d.Allow = false
				d.Reason = reason
			} else {
				dryInput = in
			}
		} else {
			// Pas de porte sur ce chemin : la politique est informée que
			// le composant ne fournit pas de dry-run — elle tranche
			// (résidu déclaré §4.4/§10.5 si elle laisse passer).
			dryInput = &DryRunInput{Available: false}
		}
	}

	// Passeport de quota (§4.1-bis) : ouvert à l'allow — « chaque porte
	// ouverte naît avec son compteur ».
	passportOpened := false
	if d.Allow && d.Token != nil && d.Token.Quota != nil && l.ledger != nil {
		if _, err := l.ledger.Open(d.Token); err != nil {
			// Registre saturé / vecteur invalide : fail-closed, la porte
			// ne s'ouvre pas sans son compteur. Le validateur (T9) a déjà
			// écrit SA feuille allow avant que cet échec ne soit connu —
			// sans une feuille supplémentaire ici, le registre ne
			// porterait AUCUNE trace du refus réellement rendu à
			// l'appelant (contrairement au veto OPA ci-dessous, qui trace
			// sa propre feuille dans Eval()). §4.1 : chaque décision doit
			// porter une feuille correspondant au verdict réel.
			d.Allow = false
			d.Reason = TripReasonQuotaSaturated
			l.ledger.writeCutLeaf(d.JTI, d.Reason)
		} else {
			passportOpened = true
		}
	}

	// Arbitrage politique (T11) APRÈS validation : OPA a le dernier mot.
	if d.Allow && l.opa != nil {
		od := l.opa.Eval(ctx, OPAInput{
			JTI:      d.JTI,
			Subject:  d.Token.Sub,
			Action:   req.Action,
			Resource: req.Resource,
			Class:    d.Token.Class,
			Epoch:    d.Token.Epoch,
			DryRun:   dryInput,
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

	return evalOutcome{Decision: d, Forwarded: forwarded, PassportOpened: passportOpened, Elapsed: elapsed}
}

// handleEvaluate : l'API de verdicts JSON — décode {token, action,
// resource[, sceau]} AUTO-DÉCLARÉS par l'appelant et rend le verdict en
// JSON, sans rien transmettre elle-même (voir la note d'honnêteté
// d'intégration en tête de fichier, et BlockingProxy pour l'alternative
// qui transmet réellement, revue de sécurité #94).
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
	req := Request{Action: in.Action, Resource: in.Resource}
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

	out := l.evaluate(r.Context(), wire, req)

	writeJSON(w, http.StatusOK, EvaluateResponse{
		Allow:          out.Decision.Allow,
		Reason:         out.Decision.Reason,
		Mode:           l.mode.Mode().String(),
		Forwarded:      out.Forwarded,
		LeafWritten:    out.Decision.LeafWritten,
		PassportOpened: out.PassportOpened,
		ElapsedUs:      out.Elapsed.Microseconds(),
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
	wire, err := base64.StdEncoding.DecodeString(in.Token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token base64 illisible"})
		return
	}
	// Preuve de possession (§4.1-bis, revue de sécurité #90 point 3) : le
	// jti vient du jeton signé vérifié ici, JAMAIS d'un champ déclaré par
	// l'appelant — sans quoi n'importe qui reachable sur ce port pourrait
	// décrémenter le passeport de quelqu'un d'autre.
	tok, err := l.validator.VerifyPossession(wire)
	if err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "preuve de possession refusée"})
		return
	}
	counter, ok := l.ledger.Counter(tok.JTI)
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
		proof, err := decodeQuorumProof(in)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
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
