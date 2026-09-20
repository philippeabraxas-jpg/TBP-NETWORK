package broker

// Enveloppe d'émission §4.1-bis (T33) : « per-entity, per-epoch aggregate
// quota evaluated by OPA at issuance — closes aggregation of legitimate
// passports ».
//
// Deux moitiés, deux responsabilités DISTINCTES (§1 : le broker applique
// les règles, il n'en écrit pas) :
//
//   - EnvelopeLedger : l'ÉTAT — l'agrégat des volumes de passeports émis
//     par (entité, époque), borné en mémoire (§4.3). Il compte, il ne
//     décide jamais.
//   - EnvelopeEvaluator : la DÉCISION — la règle d'enveloppe vit dans OPA
//     (bundle signé), évaluée à chaque émission de passeport avec
//     l'agrégat en entrée. Aucun seuil n'est codé en dur ici.
//
// Doctrine fail-closed (§1) : OPA injoignable, timeout, réponse
// indécodable ou saturation du ledger ⇒ refus à l'émission, avec feuille
// — l'agrégation de passeports légitimes ne se ferme que si l'enveloppe
// est réellement évaluée. AVERTISSEMENT D'HONNÊTETÉ (même doctrine que
// T11) : le « circuit-breaker » du timeout N'EST PAS un mécanisme natif
// d'OPA — c'est une propriété implémentée ICI, côté appelant : deadline
// stricte sur l'appel, deny fail-closed si dépassée.
//
// Réservation pessimiste : le ledger réserve le volume AVANT l'appel OPA
// et le total renvoyé inclut les demandes en vol — deux requêtes
// concurrentes ne peuvent jamais SUR-émettre (sens fail-closed : elles
// peuvent se voir refusées à tort en cas de course, jamais l'inverse).
// Un refus OPA ou un échec de signature aval libère la réservation.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// EnvelopeEvalTimeout est le budget strict d'un appel d'enveloppe, calé
// sur la latence tier 1 (§9.1) — même chiffre que le circuit-breaker de
// T11, implémenté ici côté appelant (cf. en-tête).
const EnvelopeEvalTimeout = 5 * time.Millisecond

// Raisons de décision de l'enveloppe. envelope-timeout, envelope-unreachable,
// envelope-error et envelope-bad-response sont des FAUTES (alarme OnTrip,
// couture T14) ; envelope-deny et envelope-undefined sont des verdicts
// d'un OPA sain (pas d'alarme) — même distinction que T11.
const (
	ReasonEnvelopeDeny        = "envelope-deny"
	ReasonEnvelopeUndefined   = "envelope-undefined"
	ReasonEnvelopeTimeout     = "envelope-timeout"
	ReasonEnvelopeUnreachable = "envelope-unreachable"
	ReasonEnvelopeError       = "envelope-error"
	ReasonEnvelopeBadResponse = "envelope-bad-response"
)

// TripReasonEnvelopeSaturated est la raison d'alarme OnTrip quand le
// ledger d'enveloppe est plein (couture T14, latchée une seule fois).
const TripReasonEnvelopeSaturated = "envelope-ledger-saturated"

// ErrEnvelopeSaturated refuse toute entité nouvelle quand le ledger est
// plein (§4.3 : borné, jamais d'éviction d'une entité vivante).
var ErrEnvelopeSaturated = errors.New("broker: ledger d'enveloppe saturé (§4.3 : borné en mémoire — refus fail-closed)")

// ErrEnvelopeOverflow refuse un agrégat qui déborderait uint64 — fail-closed,
// le refus vaut refus d'enveloppe (jamais de bouclage arithmétique).
var ErrEnvelopeOverflow = errors.New("broker: agrégat d'enveloppe en débordement uint64 — refus fail-closed")

// maxEnvelopeResponse borne le corps de réponse lu (64 Kio — une décision
// booléenne tient en quelques centaines d'octets, comme T11).
const maxEnvelopeResponse = 64 << 10

// EnvelopeInput est l'entrée d'évaluation de la règle d'enveloppe : les
// faits de l'émission demandée, rien de plus.
type EnvelopeInput struct {
	Subject   string // entité gouvernée (claim 2 du jeton)
	Epoch     uint64 // époque d'émission (§7.2)
	Resource  string // ressource du passeport (quota.1)
	Operation string // opération du passeport (quota.2)
	Requested uint64 // volume_max demandé (quota.3)
	Issued    uint64 // agrégat (entité, époque) APRÈS réservation — inclut
	// cette demande et toutes les demandes en vol (pessimiste, fail-closed)
}

// EnvelopeDecision est le verdict fail-closed d'une évaluation d'enveloppe.
// Err porte la faute technique éventuelle ; Elapsed mesure l'appel réel.
type EnvelopeDecision struct {
	Allow   bool
	Reason  string
	Err     error
	Elapsed time.Duration
}

// EnvelopeEvaluator est la couture de décision d'enveloppe (OPA en
// production). Le ledger compte, l'évaluateur décide (§1).
type EnvelopeEvaluator interface {
	EvalEnvelope(ctx context.Context, in EnvelopeInput) EnvelopeDecision
}

// envelopeKey est la clé d'agrégation : par entité ET par époque (§4.1-bis).
// La révocation d'époque (§7.3) emporte naturellement les agrégats de
// l'ancienne époque (purgeLocked).
type envelopeKey struct {
	subject string
	epoch   uint64
}

// EnvelopeLedger est l'état borné des agrégats d'émission par
// (entité, époque). Sûr pour un usage concurrent. Il ne décide rien :
// il compte pour OPA.
type EnvelopeLedger struct {
	max int
	agg map[envelopeKey]uint64

	onTrip func(reason string)

	mu      sync.Mutex
	tripped bool // latch saturation (T14), même pattern que T10/T12
}

// NewEnvelopeLedger construit le ledger. Fail-closed : capacité > 0 requise
// (§4.3 : dimensionnée au nombre max d'entités servies par époque).
func NewEnvelopeLedger(maxEntities int, onTrip func(reason string)) (*EnvelopeLedger, error) {
	if maxEntities <= 0 {
		return nil, errors.New("broker: capacité du ledger d'enveloppe > 0 requise (§4.3 : borné en mémoire)")
	}
	return &EnvelopeLedger{
		max:    maxEntities,
		agg:    make(map[envelopeKey]uint64, maxEntities),
		onTrip: onTrip,
	}, nil
}

// Reserve ajoute volume à l'agrégat (subject, epoch) et renvoie le total
// APRÈS réservation — incluant cette demande et les demandes en vol.
// L'appel OPA d'enveloppe DOIT utiliser ce total (input Issued) : la
// réservation précède la décision, jamais l'inverse (course concurrente =
// sur-émission sinon). Refus fail-closed : ledger plein (entité nouvelle)
// ou débordement arithmétique.
func (l *EnvelopeLedger) Reserve(subject string, epoch, volume uint64) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.purgeLocked(epoch)

	k := envelopeKey{subject, epoch}
	if _, ok := l.agg[k]; !ok && len(l.agg) == l.max {
		l.tripLocked()
		return 0, ErrEnvelopeSaturated
	}
	if l.agg[k] > ^uint64(0)-volume { // débordement ⇒ refus, jamais de bouclage
		return 0, ErrEnvelopeOverflow
	}
	l.agg[k] += volume
	return l.agg[k], nil
}

// Release défait une réservation (refus OPA, échec de signature aval).
// Relever plus que le réservé est impossible par construction (borne basse
// à zéro) — l'appelant ne peut pas « créer » de volume en libérant.
func (l *EnvelopeLedger) Release(subject string, epoch, volume uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	k := envelopeKey{subject, epoch}
	cur, ok := l.agg[k]
	if !ok {
		return
	}
	if cur <= volume {
		delete(l.agg, k)
		return
	}
	l.agg[k] = cur - volume
}

// Aggregate rapporte l'agrégat courant d'un couple (entité, époque) —
// lecture d'audit et de test.
func (l *EnvelopeLedger) Aggregate(subject string, epoch uint64) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.agg[envelopeKey{subject, epoch}]
}

// Len rapporte le nombre de couples (entité, époque) suivis.
func (l *EnvelopeLedger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.agg)
}

// purgeLocked supprime les agrégats des époques RÉVOLUES (epoch <
// courante) : une époque passée ne sert plus (§7.2/§7.3), ses compteurs
// sont morts avec elle. Les époques futures (config fautive) sont
// conservées — elles comptent dans le plafond, sens fail-closed.
func (l *EnvelopeLedger) purgeLocked(currentEpoch uint64) {
	for k := range l.agg {
		if k.epoch < currentEpoch {
			delete(l.agg, k)
		}
	}
}

// tripLocked enclenche l'alarme de saturation — latchée (T14) : une fois.
func (l *EnvelopeLedger) tripLocked() {
	if l.tripped {
		return
	}
	l.tripped = true
	if l.onTrip != nil {
		l.onTrip(TripReasonEnvelopeSaturated)
	}
}

// HTTPEnvelopeOptions paramètre l'évaluateur HTTP. Fail-closed dès la
// configuration.
type HTTPEnvelopeOptions struct {
	// Endpoint est l'URL complète de la règle d'enveloppe, p.ex.
	// http://127.0.0.1:8181/v1/data/tbp/envelope. Requis.
	Endpoint string
	// Timeout borne l'appel (aller-retour + lecture du corps).
	// 0 ⇒ EnvelopeEvalTimeout (5 ms, §9.1). Négatif ⇒ erreur.
	Timeout time.Duration
	// HTTPClient permet d'injecter un transport (tests, sidecar unix
	// socket…). Nil ⇒ http.Client par défaut.
	HTTPClient *http.Client
	// OnTrip est la couture d'alarme vers T14 : appelé à chaque FAUTE
	// d'enveloppe (timeout, injoignable, statut, corps) — jamais sur un
	// deny métier d'un OPA sain. Nil ⇒ pas d'alarme (le deny reste
	// fail-closed).
	OnTrip func(reason string)
}

// HTTPEnvelopeEvaluator évalue la règle d'enveloppe contre un sidecar OPA
// en boucle locale — même doctrine de transport que T11 (src/pep/
// opa_client.go, dont ce fichier est le pendant pour une entrée de forme
// différente : l'agrégat d'émission au lieu des faits du jeton). Sûr pour
// un usage concurrent ; sans état mutable après construction.
type HTTPEnvelopeEvaluator struct {
	endpoint string
	timeout  time.Duration
	hc       *http.Client
	onTrip   func(reason string)
}

// compile-time : *HTTPEnvelopeEvaluator satisfait la couture.
var _ EnvelopeEvaluator = (*HTTPEnvelopeEvaluator)(nil)

// NewHTTPEnvelopeEvaluator construit l'évaluateur. Fail-closed : endpoint
// requis, timeout négatif rejeté.
func NewHTTPEnvelopeEvaluator(opts HTTPEnvelopeOptions) (*HTTPEnvelopeEvaluator, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("broker: endpoint d'enveloppe requis (circuit-breaker §12 : côté appelant)")
	}
	if opts.Timeout < 0 {
		return nil, errors.New("broker: timeout d'enveloppe négatif refusé")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = EnvelopeEvalTimeout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	return &HTTPEnvelopeEvaluator{
		endpoint: opts.Endpoint,
		timeout:  timeout,
		hc:       hc,
		onTrip:   opts.OnTrip,
	}, nil
}

// Timeout rapporte le budget strict appliqué à chaque appel (§9.1).
func (e *HTTPEnvelopeEvaluator) Timeout() time.Duration { return e.timeout }

// envelopeRequest est le corps POST /v1/data/... : {"input": {...}}.
type envelopeRequest struct {
	Input struct {
		Subject   string `json:"subject"`
		Epoch     uint64 `json:"epoch"`
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
		Requested uint64 `json:"requested"`
		Issued    uint64 `json:"issued"`
	} `json:"input"`
}

// envelopeResponse est la réponse attendue : {"result": {"allow": bool}}.
// Allow est un pointeur : un result sans allow rompt le contrat
// (≠ deny métier, ≠ règle indéfinie) — même contrat que T11.
type envelopeResponse struct {
	Result *struct {
		Allow *bool `json:"allow"`
	} `json:"result"`
}

// EvalEnvelope évalue la règle d'enveloppe et rend TOUJOURS une décision
// tranchée : la moindre faute (timeout, transport, statut, corps) bascule
// en deny avec alarme — fail-closed §4.1, jamais de passeport émis sur
// une enveloppe non évaluée.
func (e *HTTPEnvelopeEvaluator) EvalEnvelope(ctx context.Context, in EnvelopeInput) EnvelopeDecision {
	start := time.Now()

	// Circuit-breaker §12 : deadline STRICTE, implémentée ici côté appelant.
	ectx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	var reqBody envelopeRequest
	reqBody.Input.Subject = in.Subject
	reqBody.Input.Epoch = in.Epoch
	reqBody.Input.Resource = in.Resource
	reqBody.Input.Operation = in.Operation
	reqBody.Input.Requested = in.Requested
	reqBody.Input.Issued = in.Issued
	raw, err := json.Marshal(reqBody)
	if err != nil { // inatteignable (types fixes) — fail-closed quand même
		return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeBadResponse, Err: err}, start)
	}

	req, err := http.NewRequestWithContext(ectx, http.MethodPost, e.endpoint, bytes.NewReader(raw))
	if err != nil { // endpoint invalide : faute de config détectée à l'appel
		return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeUnreachable, Err: err}, start)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			// Le contexte de l'appelant s'est terminé pour une raison qui
			// lui est propre : fail-closed, sans accuser OPA à tort (même
			// honnêteté que classifyContextFault de T11).
			return e.finishNoTrip(EnvelopeDecision{Reason: ReasonEnvelopeUnreachable, Err: ctx.Err()}, start)
		}
		if ectx.Err() == context.DeadlineExceeded {
			return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeTimeout, Err: context.DeadlineExceeded}, start)
		}
		return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeUnreachable, Err: err}, start)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxEnvelopeResponse))
		err := fmt.Errorf("broker: OPA enveloppe statut %d", resp.StatusCode)
		return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeError, Err: err}, start)
	}

	var decoded envelopeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxEnvelopeResponse)).Decode(&decoded); err != nil {
		if ectx.Err() == context.DeadlineExceeded {
			return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeTimeout, Err: context.DeadlineExceeded}, start)
		}
		return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeBadResponse, Err: err}, start)
	}

	switch {
	case decoded.Result == nil:
		// Règle indéfinie : OPA est sain — default-deny §1, pas d'alarme.
		return e.finishNoTrip(EnvelopeDecision{Reason: ReasonEnvelopeUndefined}, start)
	case decoded.Result.Allow == nil:
		err := errors.New("broker: réponse d'enveloppe sans allow (contrat rompu)")
		return e.finish(EnvelopeDecision{Reason: ReasonEnvelopeBadResponse, Err: err}, start)
	case !*decoded.Result.Allow:
		// Deny métier : l'enveloppe est pleine — OPA sain, pas d'alarme.
		return e.finishNoTrip(EnvelopeDecision{Reason: ReasonEnvelopeDeny}, start)
	default:
		return e.finishNoTrip(EnvelopeDecision{Allow: true, Reason: "ok"}, start)
	}
}

// finish épilogue une FAUTE : mesure + alarme T14.
func (e *HTTPEnvelopeEvaluator) finish(d EnvelopeDecision, start time.Time) EnvelopeDecision {
	d.Elapsed = time.Since(start)
	if e.onTrip != nil {
		e.onTrip(d.Reason) // couture T14 — le latch unique est chez T14
	}
	return d
}

// finishNoTrip épilogue un verdict d'OPA sain : mesure, pas d'alarme.
func (e *HTTPEnvelopeEvaluator) finishNoTrip(d EnvelopeDecision, start time.Time) EnvelopeDecision {
	d.Elapsed = time.Since(start)
	return d
}
