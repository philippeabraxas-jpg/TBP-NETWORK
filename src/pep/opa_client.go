package pep

// Client OPA avec circuit-breaker 5 ms fail-closed (T11, §12 + §9.1 + §4.1).
//
// AVERTISSEMENT D'HONNÊTETÉ (même doctrine que policies/README) : le
// « circuit-breaker OPA » de la checklist §12 N'EST PAS un mécanisme natif
// d'OPA — rien dans le moteur Rego ne coupe une évaluation à 5 ms. C'est
// une propriété implémentée ICI, côté appelant (le PEP) : timeout strict
// sur l'appel, deny fail-closed si dépassé. Ne jamais présenter ce
// mécanisme comme une garantie fournie par OPA, ni en doc ni en code.
//
// Choix de transport : HTTP contre un sidecar OPA en boucle locale
// (net/http + deadline de contexte, stdlib uniquement). L'évaluation
// embarquée (lib OPA Go) supprimerait le réseau du chemin chaud mais
// changerait le modèle de déploiement (Rego embarqué à recharger dans
// chaque PEP) ; le cas « OPA arrêté » de la checklist §12 suppose un
// service joignable. Le circuit-breaker reste côté appelant dans les deux
// cas — le transport est isolé derrière OPAOptions.HTTPClient.
//
// Doctrine fail-closed (§4.1) : timeout, OPA injoignable, statut non 200
// ou réponse indécodable ⇒ deny + alarme OnTrip (couture T14 — le latch
// « fail-closed unique » est l'affaire de T14, ce client signale chaque
// faute). Règle indéfinie ou deny métier ⇒ deny SANS alarme : OPA est
// sain, c'est le default-deny §1 qui parle. Chaque décision laisse une
// feuille hash-only (§4.1/§6.2, sel chez le producteur) ; un allow sans
// preuve redevient deny (pas de preuve, pas d'accès — comme T9).

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// EvalTimeout est le budget strict d'un appel OPA, calé sur la latence
// tier 1 du §9.1 : au-delà, deny fail-closed (circuit-breaker §12).
const EvalTimeout = 5 * time.Millisecond

// Raisons de décision propres au client OPA. opa-timeout, opa-unreachable,
// opa-error et opa-bad-response déclenchent l'alarme T14 ; opa-deny et
// opa-undefined sont des verdicts d'un OPA sain (pas d'alarme) ;
// opa-caller-cancelled est un refus fail-closed SANS alarme T14 : le
// contexte de l'appelant s'est annulé ou a expiré pour une raison qui lui
// est propre (rien à voir avec OPA ni avec le budget de 5 ms) — l'honnêteté
// doctrinale de ce fichier (cf. en-tête) interdirait justement de
// l'étiqueter opa-timeout et d'en accuser OPA à tort.
const (
	ReasonOPADeny            = "opa-deny"
	ReasonOPAUndefined       = "opa-undefined"
	ReasonOPATimeout         = "opa-timeout"
	ReasonOPAUnreachable     = "opa-unreachable"
	ReasonOPAError           = "opa-error"
	ReasonOPABadResponse     = "opa-bad-response"
	ReasonOPACallerCancelled = "opa-caller-cancelled"
)

// maxOPAResponse borne le corps de réponse lu (64 Kio — une décision
// booléenne tient en quelques centaines d'octets).
const maxOPAResponse = 64 << 10

// OPAInput est l'entrée d'évaluation : les faits du jeton, rien de plus
// (le PEP n'invente rien — honnêteté de schéma). DryRun est l'entrée
// supplémentaire §4.4(1) (T36, D104) : nil hors classes F/I/W ou sans
// porte configurée sur ce chemin — omitempty côté JSON, les politiques
// écrites avant T36 sont inchangées.
type OPAInput struct {
	JTI      [16]byte
	Subject  string
	Action   string
	Resource string
	Class    Class
	Epoch    uint64
	DryRun   *DryRunInput
}

// opaRequest est le corps POST /v1/data/... : {"input": {...}}.
type opaRequest struct {
	Input struct {
		JTI      string       `json:"jti"` // hex
		Subject  string       `json:"subject"`
		Action   string       `json:"action"`
		Resource string       `json:"resource"`
		Class    int          `json:"class"`
		Epoch    uint64       `json:"epoch"`
		DryRun   *DryRunInput `json:"dry_run,omitempty"` // §4.4(1), T36
	} `json:"input"`
}

// opaResponse est la réponse attendue : {"result": {"allow": bool}}.
// Allow est un pointeur : un result sans allow rompt le contrat
// (≠ deny métier, ≠ règle indéfinie).
type opaResponse struct {
	Result *struct {
		Allow *bool `json:"allow"`
	} `json:"result"`
}

// OPADecision est le verdict fail-closed d'un Eval. Err porte la faute
// technique éventuelle (context.DeadlineExceeded sur timeout, erreur
// transport sur unreachable, …). Elapsed mesure l'appel réel.
type OPADecision struct {
	Allow       bool
	Reason      string
	Err         error
	Elapsed     time.Duration
	LeafWritten bool
	LeafErr     error
}

// OPAOptions paramètre le client. Fail-closed dès la configuration.
type OPAOptions struct {
	// Endpoint est l'URL complète de la décision, p.ex.
	// http://127.0.0.1:8181/v1/data/tbp/allow. Requis.
	Endpoint string
	// Timeout borne l'appel (aller-retour + lecture du corps).
	// 0 ⇒ EvalTimeout (5 ms, §9.1). Négatif ⇒ erreur.
	Timeout time.Duration
	// HTTPClient permet d'injecter un transport (tests, sidecar unix
	// socket…). Nil ⇒ http.Client par défaut.
	HTTPClient *http.Client
	// CellID identifie la cellule dans la feuille. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur, jamais publié. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : chaque décision laisse une
	// feuille. Requis.
	Leaves LeafSink
	// OnTrip est la couture d'alarme vers T14 (fail-closed unique). Appelé
	// à chaque faute OPA (timeout, injoignable, statut, corps) — T14
	// possède le latch. Nil ⇒ pas d'alarme (le deny reste fail-closed).
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2) pour la feuille.
	// Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// OPAClient est le client fail-closed vers OPA. Sûr pour un usage
// concurrent ; sans état mutable après construction.
type OPAClient struct {
	endpoint string
	timeout  time.Duration
	hc       *http.Client
	cellID   string
	salt     []byte
	leaves   LeafSink
	onTrip   func(reason string)
	now      func() time.Time
}

// NewOPAClient construit le client. Fail-closed : endpoint, cellID, sel
// ≥ 16 o et couture feuilles requis ; timeout négatif rejeté.
func NewOPAClient(opts OPAOptions) (*OPAClient, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("pep: endpoint OPA requis (circuit-breaker §12 : côté appelant)")
	}
	if opts.CellID == "" {
		return nil, errors.New("pep: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: couture feuilles requise (§4.1 : chaque décision laisse une feuille)")
	}
	if opts.Timeout < 0 {
		return nil, errors.New("pep: timeout OPA négatif refusé")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = EvalTimeout
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
	return &OPAClient{
		endpoint: opts.Endpoint,
		timeout:  timeout,
		hc:       hc,
		cellID:   opts.CellID,
		salt:     salt,
		leaves:   opts.Leaves,
		onTrip:   opts.OnTrip,
		now:      now,
	}, nil
}

// Timeout rapporte le budget strict appliqué à chaque appel (§9.1).
func (c *OPAClient) Timeout() time.Duration { return c.timeout }

// Eval évalue input auprès d'OPA et rend TOUJOURS une décision tranchée :
// la moindre faute (timeout, transport, statut, corps) bascule en deny —
// fail-closed §4.1, jamais de passage silencieux. Chaque issue laisse une
// feuille ; sur un allow, l'échec d'écriture re-bascule en deny.
func (c *OPAClient) Eval(ctx context.Context, in OPAInput) OPADecision {
	start := time.Now()

	// Circuit-breaker §12 : deadline STRICTE, implémentée ici côté appelant
	// — OPA ne fournit aucune coupure à 5 ms.
	ectx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var reqBody opaRequest
	reqBody.Input.JTI = hex.EncodeToString(in.JTI[:])
	reqBody.Input.Subject = in.Subject
	reqBody.Input.Action = in.Action
	reqBody.Input.Resource = in.Resource
	reqBody.Input.Class = int(in.Class)
	reqBody.Input.Epoch = in.Epoch
	reqBody.Input.DryRun = in.DryRun
	raw, err := json.Marshal(reqBody)
	if err != nil { // inatteignable (types fixes) — fail-closed quand même
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPABadResponse, Err: err}, start)
	}

	req, err := http.NewRequestWithContext(ectx, http.MethodPost, c.endpoint, bytes.NewReader(raw))
	if err != nil { // endpoint invalide : faute de config détectée à l'appel
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPAUnreachable, Err: err}, start)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		if reason, callerErr, ok := classifyContextFault(ctx, ectx); ok {
			return c.finish(ctx, in, OPADecision{Reason: reason, Err: callerErr}, start)
		}
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPAUnreachable, Err: err}, start)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxOPAResponse))
		err := fmt.Errorf("pep: OPA statut %d", resp.StatusCode)
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPAError, Err: err}, start)
	}

	var decoded opaResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOPAResponse)).Decode(&decoded); err != nil {
		// Un corps qui traîne peut consommer la deadline PENDANT la lecture.
		if reason, callerErr, ok := classifyContextFault(ctx, ectx); ok {
			return c.finish(ctx, in, OPADecision{Reason: reason, Err: callerErr}, start)
		}
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPABadResponse, Err: err}, start)
	}

	switch {
	case decoded.Result == nil:
		// Règle indéfinie : OPA est sain — default-deny §1, pas d'alarme.
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPAUndefined}, start)
	case decoded.Result.Allow == nil:
		err := errors.New("pep: réponse OPA sans allow (contrat rompu)")
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPABadResponse, Err: err}, start)
	case !*decoded.Result.Allow:
		// Deny métier : OPA est sain, la politique refuse — pas d'alarme.
		return c.finish(ctx, in, OPADecision{Reason: ReasonOPADeny}, start)
	default:
		return c.finish(ctx, in, OPADecision{Allow: true, Reason: ReasonOK}, start)
	}
}

// classifyContextFault distingue, après une erreur transport/lecture liée au
// contexte, QUI a expiré : notre propre budget (c.timeout, le circuit-
// breaker §12 — ectx) ou le contexte de l'APPELANT (ctx), annulé ou expiré
// pour une raison qui lui est propre. ectx hérite de ctx (WithTimeout) :
// quand ctx est déjà terminé, ectx.Err() reporte exactement la même cause
// (DeadlineExceeded ou Canceled), indiscernable en apparence d'un
// déclenchement du breaker — d'où ce contrôle séparé sur ctx lui-même.
// Étiqueter cela opa-timeout accuserait OPA à tort (l'honnêteté doctrinale
// de ce fichier l'interdit) ; ok=false laisse l'appelant traiter l'erreur
// transport normalement (opa-unreachable).
func classifyContextFault(ctx, ectx context.Context) (reason string, err error, ok bool) {
	if ctx.Err() != nil {
		return ReasonOPACallerCancelled, ctx.Err(), true
	}
	if ectx.Err() == context.DeadlineExceeded {
		return ReasonOPATimeout, context.DeadlineExceeded, true
	}
	return "", nil, false
}

// finish épilogue toute décision : mesure, alarme T14 si faute OPA,
// feuille hash-only — et re-bascule fail-closed un allow sans preuve.
func (c *OPAClient) finish(ctx context.Context, in OPAInput, d OPADecision, start time.Time) OPADecision {
	d.Elapsed = time.Since(start)

	switch d.Reason {
	case ReasonOPATimeout, ReasonOPAUnreachable, ReasonOPAError, ReasonOPABadResponse:
		if c.onTrip != nil {
			c.onTrip(d.Reason) // couture T14 — le latch unique est chez T14
		}
	}

	leaf := registry.Leaf{
		Kind:        registry.KindDecision,
		CellID:      c.cellID,
		PayloadHash: registry.HashPayload(c.salt, decisionLeafRecord(in.JTI, d.Allow, d.Reason)),
		Timestamp:   c.now().UnixNano(),
	}
	if _, err := c.leaves.Append(ctx, leaf); err != nil {
		d.LeafErr = err
		if d.Allow { // pas de preuve, pas d'accès (même doctrine que T9)
			d.Allow = false
			d.Reason = ReasonLeafWriteFailed
		}
		return d
	}
	d.LeafWritten = true
	return d
}

// decisionLeafRecord sérialise le record de décision — même format que le
// validateur (T9) : "TBPD1" ‖ jti(16) ‖ verdict(1) ‖ u8 len(reason) ‖
// reason. La feuille n'en publie que le hash salé (§6.2).
func decisionLeafRecord(jti [16]byte, allow bool, reason string) []byte {
	verdict := byte(0x00)
	if allow {
		verdict = 0x01
	}
	record := make([]byte, 0, 5+16+1+1+len(reason))
	record = append(record, "TBPD1"...)
	record = append(record, jti[:]...)
	record = append(record, verdict, byte(len(reason)))
	record = append(record, reason...)
	return record
}
