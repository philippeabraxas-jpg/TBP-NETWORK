// Package broker implante le broker d'une cellule TBP (T33, §5.1 +
// §4.1-bis) : le point d'entrée unique du flux de décision — « the server
// accepts only the broker ».
//
// Le broker ORCHESTRE sans implémenter (§7.1 : cattle, jamais racine de
// confiance) : chaque demande d'action d'un agent traverse la même chaîne,
// dans l'ordre, sans raccourci :
//
//	bornes d'entrée → jti → époque (§7.2, T29) → traducteur → OPA (T11)
//	→ quorum classe W (§7.5, T29) → enveloppe (§4.1-bis)
//	→ signature (Issuer) → jeton/passeport + feuilles
//
// Doctrine fail-closed (§1) : la moindre faute à n'importe quelle étape —
// traduction, évaluation, enveloppe, signature, écriture de feuille —
// bascule en refus avec feuille ; JAMAIS d'émission partielle. « TBP n'est
// pas un juge, c'est un livre de lois et un greffe » (§1) : le broker est
// le greffe — il applique mécaniquement, sans discrétion. Et « the
// executed action is the translated action » (§4.5) : l'action évaluée et
// émise vient du traducteur, jamais de la déclaration de l'agent.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// maxIntentBytes borne l'intention déclarée par l'agent (le CONTENU métier
// ne transite que par le traducteur ; les feuilles restent hash-only §6.2).
const maxIntentBytes = 4096

// maxQuorumProofBytes borne la preuve de quorum (§7.5) : statement
// canonique + n signatures Ed25519 — quelques centaines d'octets en
// pratique ; la borne écarte les blobs sans lien avec un quorum.
const maxQuorumProofBytes = 4096

// Raisons de décision propres au broker. translation-failed est un verdict
// sain (le traducteur dit « je ne sais pas », §4.5 — pas d'alarme) ;
// issuance-failed et leaf-write-failed sont des FAUTES système (alarme
// OnTrip, couture T14). Les raisons d'enveloppe sont celles d'envelope.go.
const (
	ReasonRequestInvalid     = "request-invalid"
	ReasonEpochUnavailable   = "epoch-unavailable"
	ReasonTranslationFailed  = "translation-failed"
	ReasonQuorumRequired     = "quorum-required"
	ReasonQuorumInsufficient = "quorum-insufficient"
	ReasonEnvelopeUnverified = "envelope-unverified"
	ReasonEnvelopeSaturated  = "envelope-saturated"
	ReasonIssuanceFailed     = "issuance-failed"
)

// Translation est l'action STRUCTURÉE produite par le traducteur (§4.5) —
// jamais la déclaration de l'agent. Le traducteur est un paramètre de
// friction, pas de sécurité : l'action produite sera jugée par les règles
// (OPA) sans exception, default-deny.
type Translation struct {
	Action      string     // action autorisée candidate (claim −2)
	Resource    string     // ressource exacte (claim −3)
	Class       *pep.Class // classe F/I/W explicite — nil ⇒ claim absent ⇒ W (§5.3)
	ObjectSeal  *[32]byte  // sceau objet-capacité (§4.4(2)), si le traducteur le scelle
	Quota       *pep.Quota // demande de passeport (§4.1-bis) — non nil ⇒ chemin lourd
	QuorumProof []byte     // preuve k-of-n classe W (§7.5) — octets opaques, vérifiés par QuorumGate, jamais interprétés ici (no-DPI)
}

// Translator est la couture du traducteur (T24–T26 construisent son
// runtime ; ici l'interface). « I can translate » ou « I cannot » (§4.5) :
// toute erreur est un refus, jamais une faute système — l'escalade humaine
// (§4.5 degraded modes) est une couture ultérieure (T25/T30), documentée
// dans le README, pas implémentée ici.
type Translator interface {
	Translate(ctx context.Context, subject, intent string) (Translation, error)
}

// EpochProvider est la couture d'époque de la cellule (§7.2). Le fencing
// réel est cluster.Tracker (T29, #30) — il rend une erreur dès que la
// cellule n'a pas d'époque valide dont elle est l'autorité : « seul le
// détenteur sert ». En mono-cellule dev, StaticEpoch suffit — MARQUÉ dev,
// comme l'issue #59 le prévoit explicitement.
//
// L'erreur fait partie du contrat (revue #30) : une signature sans erreur
// ne peut pas exprimer « pas d'autorité en ce moment » et pousserait une
// implémentation réelle à renvoyer une époque périmée en silence —
// l'exact inverse du fail-closed (§1).
type EpochProvider interface {
	CurrentEpoch() (uint64, error)
}

// StaticEpoch est un EpochProvider fixe — DEV MONO-CELLULE UNIQUEMENT.
// En déploiement multi-cellule, l'époque vient du fencing (T29) : seule la
// détentrice sert, l'ancienne expire seule.
type StaticEpoch uint64

// CurrentEpoch rapporte l'époque fixe de dev — jamais d'erreur (le dev
// mono-cellule n'a pas de fencing, §7.2 : une cellule seule peut différer).
func (e StaticEpoch) CurrentEpoch() (uint64, error) { return uint64(e), nil }

// QuorumGate est la couture de co-signature k-of-n de la classe W
// (§7.5, T29 — implémentée par cluster.QuorumGate). « A single cell,
// adversarial or captured, cannot authorize the maximal irreversible » :
// optionnelle en configuration (comme Envelope/Ledger), mais fail-closed
// dès qu'elle s'applique — toute demande classée W sans quorum satisfait
// est refusée (quorum-required / quorum-insufficient).
type QuorumGate interface {
	VerifyClassW(ctx context.Context, proof []byte, action, resource string, epoch uint64) error
}

// StructuredTranslator est le traducteur du MODE STRUCTURÉ (§4.5 degraded
// modes : quand le modèle est indisponible, seul le structuré passe — la
// dégradation contrôlée de T25 s'appuiera sur cette brique). Il attend une
// intention JSON {"action","resource","class"?,"object_seal"?,"quota"?} —
// aucun modèle, aucune interprétation ; la validation des bornes reste à
// l'Issuer (fail-closed à l'émission).
type StructuredTranslator struct{}

// structuredIntent est le langage structuré : l'agent déclare l'action
// exacte qu'il veut voir évaluer — le traducteur ne fait que la typer.
type structuredIntent struct {
	Action      string `json:"action"`
	Resource    string `json:"resource"`
	Class       *uint8 `json:"class,omitempty"`
	ObjectSeal  string `json:"object_seal,omitempty"`  // hex, 32 octets
	QuorumProof string `json:"quorum_proof,omitempty"` // hex — preuve k-of-n classe W (§7.5), blob opaque
	Quota       *struct {
		Resource  string `json:"resource"`
		Operation string `json:"operation"`
		VolumeMax uint64 `json:"volume_max"`
		WindowS   uint64 `json:"window_s"`
	} `json:"quota,omitempty"`
}

// Translate parse l'intention structurée. Tout écart de forme est une
// erreur (« je ne sais pas traduire ») — le broker refuse.
func (StructuredTranslator) Translate(_ context.Context, _, intent string) (Translation, error) {
	var s structuredIntent
	if err := json.Unmarshal([]byte(intent), &s); err != nil {
		return Translation{}, fmt.Errorf("broker: intention structurée illisible : %w", err)
	}
	if s.Action == "" || s.Resource == "" {
		return Translation{}, errors.New("broker: intention structurée sans action ou resource")
	}
	tr := Translation{Action: s.Action, Resource: s.Resource}
	if s.Class != nil {
		if *s.Class > uint8(pep.ClassOut) {
			return Translation{}, errors.New("broker: classe hors [0..3] (§5.3)")
		}
		c := pep.Class(*s.Class)
		tr.Class = &c
	}
	if s.ObjectSeal != "" {
		var seal [32]byte
		if err := decodeHex32(s.ObjectSeal, &seal); err != nil {
			return Translation{}, err
		}
		tr.ObjectSeal = &seal
	}
	if s.Quota != nil {
		tr.Quota = &pep.Quota{
			Resource:  s.Quota.Resource,
			Operation: s.Quota.Operation,
			VolumeMax: s.Quota.VolumeMax,
			WindowS:   s.Quota.WindowS,
		}
	}
	if s.QuorumProof != "" {
		// Blob opaque (no-DPI) : décodé de son enveloppe hex, borné, puis
		// remis tel quel au QuorumGate — seul le gate l'interprète (§7.5).
		if len(s.QuorumProof) > 2*maxQuorumProofBytes {
			return Translation{}, errors.New("broker: quorum_proof hors bornes (§7.5)")
		}
		proof, err := hex.DecodeString(s.QuorumProof)
		if err != nil {
			return Translation{}, fmt.Errorf("broker: quorum_proof non hexadécimal : %w", err)
		}
		tr.QuorumProof = proof
	}
	return tr, nil
}

// Result est le résultat d'une orchestration : le verdict, le jeton fil
// (si allow), et les mesures par étape — l'intrant du harnais de friction
// T27 (§9.1) et des métriques de supervision T34.
type Result struct {
	Allow   bool
	Reason  string   // code machine stable ("ok", "translation-failed", "opa-deny", …)
	Token   []byte   // fil CWT/COSE_Sign1, présent si Allow
	JTI     [16]byte // identifiant porté par la feuille et le jeton (§4.3)
	Elapsed time.Duration

	// LeafWritten/LeafErr rendent compte de la feuille écrite par le
	// broker lui-même (refus post-allow : enveloppe, émission). Pour un
	// refus au stade OPA, la feuille est celle du client T11 — voir
	// OPADecision dans OPADecision.
	LeafWritten bool
	LeafErr     error

	// OPADecision est le verdict détaillé de l'étape OPA (T11), si atteinte.
	OPADecision *pep.OPADecision
}

// BrokerOptions paramètre le broker. Fail-closed dès la configuration :
// toute couture manquante = erreur (même pattern que T9/T11/T12/T23).
type BrokerOptions struct {
	// CellID identifie la cellule dans les feuilles propres du broker.
	// Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : chaque décision laisse une
	// feuille (§4.1). Requis.
	Leaves pep.LeafSink
	// OPA est le client d'évaluation T11 (circuit-breaker 5 ms,
	// fail-closed, feuille « TBPD1 » par évaluation). Requis.
	OPA *pep.OPAClient
	// Translator est la couture de traduction (§4.5). Requis.
	Translator Translator
	// Issuer est l'émetteur de jetons (issuer.go). Requis.
	Issuer *Issuer
	// Epochs est la couture d'époque (§7.2) — StaticEpoch en dev
	// mono-cellule, cluster.Tracker (T29) en déploiement. Requis. Une
	// erreur de CurrentEpoch refuse la demande (epoch-unavailable, feuille
	// + alarme) AVANT toute traduction : pas d'autorité, pas de service.
	Epochs EpochProvider
	// Quorum est la couture de co-signature k-of-n de la classe W (§7.5,
	// T29 — cluster.QuorumGate). Optionnelle, mais fail-closed dès
	// qu'elle s'applique : toute demande classée W (claim −4=W OU absent,
	// §5.3) sans quorum satisfait est refusée — même doctrine
	// qu'Envelope/Ledger (la règle sans le contrôle ne ferme rien).
	Quorum QuorumGate
	// Envelope est l'évaluateur d'enveloppe §4.1-bis, avec son Ledger
	// d'état borné. Les deux sont requis ENSEMBLE ou absents ensemble ;
	// absents, toute demande de passeport est refusée (envelope-unverified
	// — même doctrine que quota-unverified de T9).
	Envelope *HTTPEnvelopeEvaluator
	Ledger   *EnvelopeLedger
	// OnTrip est la couture d'alarme vers T14 : fautes système du broker
	// (émission impossible, feuille impossible). Nil ⇒ pas d'alarme (le
	// refus reste fail-closed).
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// Broker est l'orchestrateur du flux de décision d'une cellule. Sans état
// mutable après construction (l'état vit dans les coutures) : sûr pour un
// usage concurrent — la concurrence du serveur HTTP (stdlib) est admise.
type Broker struct {
	cellID     string
	salt       []byte
	leaves     pep.LeafSink
	opa        *pep.OPAClient
	translator Translator
	issuer     *Issuer
	epochs     EpochProvider
	quorum     QuorumGate
	envelope   *HTTPEnvelopeEvaluator
	ledger     *EnvelopeLedger
	onTrip     func(reason string)
	now        func() time.Time

	mu    sync.Mutex
	stats BrokerStats
}

// BrokerStats compte les décisions — exposé à la supervision (T34) et au
// harnais de friction (T27). Compteurs monotones, jamais remis à zéro.
type BrokerStats struct {
	Requests            uint64 // demandes reçues
	Allows              uint64 // jetons/passeports émis
	Denies              uint64 // refus (toutes étapes)
	TranslationFailures uint64 // « je ne sais pas traduire » (§4.5)
	EnvelopeEvals       uint64 // évaluations d'enveloppe (§4.1-bis)
	EnvelopeDenies      uint64 // refus d'enveloppe (agrégat plein)
	QuorumDenies        uint64 // refus de quorum classe W (§7.5)
	IssuanceFailures    uint64 // fautes de signature/émission (alarmées)
	LeafFailures        uint64 // feuilles propres impossibles (alarmées)
}

// NewBroker construit le broker. Fail-closed : toutes les coutures
// requises ; Envelope et Ledger ensemble ou pas du tout.
func NewBroker(opts BrokerOptions) (*Broker, error) {
	if opts.CellID == "" {
		return nil, errors.New("broker: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("broker: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("broker: couture feuilles requise (§4.1 : chaque décision laisse une feuille)")
	}
	if opts.OPA == nil {
		return nil, errors.New("broker: client OPA requis (§4.1 : aucune émission sans décision)")
	}
	if opts.Translator == nil {
		return nil, errors.New("broker: traducteur requis (§4.5 : l'action exécutée est l'action traduite)")
	}
	if opts.Issuer == nil {
		return nil, errors.New("broker: émetteur requis (§4.1 : pas de jeton, pas d'action)")
	}
	if opts.Epochs == nil {
		return nil, errors.New("broker: couture d'époque requise (§7.2 : révocation = nouvelle époque)")
	}
	if (opts.Envelope == nil) != (opts.Ledger == nil) {
		return nil, errors.New("broker: évaluateur et ledger d'enveloppe requis ENSEMBLE (§4.1-bis : l'état sans la règle, ou la règle sans l'état, ne ferment rien)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &Broker{
		cellID:     opts.CellID,
		salt:       salt,
		leaves:     opts.Leaves,
		opa:        opts.OPA,
		translator: opts.Translator,
		issuer:     opts.Issuer,
		epochs:     opts.Epochs,
		quorum:     opts.Quorum,
		envelope:   opts.Envelope,
		ledger:     opts.Ledger,
		onTrip:     opts.OnTrip,
		now:        now,
	}, nil
}

// Stats rapporte un instantané des compteurs (supervision T34, harnais T27).
func (b *Broker) Stats() BrokerStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

// HandleAction orchestre une demande d'action, de la réception à
// l'émission ou au refus. L'ordre est strict et chaque étape est
// fail-closed — voir l'en-tête du package. Aucun chemin ne produit un
// jeton sans décision OPA tracée (§4.1), et aucun passeport sans
// enveloppe évaluée (§4.1-bis). Elapsed mesure l'orchestration réelle
// (horloge locale, comme T11 — l'horloge injectée est l'horloge NTS des
// feuilles et des iat, pas l'instrument de mesure).
func (b *Broker) HandleAction(ctx context.Context, subject, intent string) (res Result) {
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()

	b.mu.Lock()
	b.stats.Requests++
	b.mu.Unlock()

	// Étape 1 — bornes d'entrée : subject et intention bornés. Pas de jti
	// encore : un refus d'entrée trace avec l'identifiant nul, comme le
	// validateur T9 pour un jeton mal formé.
	if subject == "" || len(subject) > maxIssSubActionLen || intent == "" || len(intent) > maxIntentBytes {
		return b.deny(ctx, [16]byte{}, ReasonRequestInvalid, nil)
	}

	// Étape 2 — jti tiré AVANT l'évaluation OPA : la feuille de décision
	// (T11) et le jeton émis portent le même identifiant (§4.3 — chaque
	// feuille d'exécution porte le jti).
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil { // inatteignable — fail-closed
		return b.fault(ctx, jti, ReasonIssuanceFailed, fmt.Errorf("broker: tirage jti : %w", err))
	}

	// Étape 3 — époque (§7.2) : le fencing (T29) rend une erreur dès que
	// cette cellule n'a pas d'époque valide dont elle est l'autorité.
	// FAUTE système (pas d'autorité, pas de service) : refus + feuille +
	// alarme AVANT même d'atteindre le traducteur — jamais d'émission sur
	// une base fausse (revue #30 : une époque périmée servie en silence
	// est l'exact inverse du fail-closed).
	epoch, err := b.epochs.CurrentEpoch()
	if err != nil {
		return b.fault(ctx, jti, ReasonEpochUnavailable, err)
	}

	// Étape 4 — traduction (§4.5) : « je ne sais pas » est un verdict
	// SAIN — refus sans alarme (même distinction qu'opa-deny dans T11).
	tr, err := b.translator.Translate(ctx, subject, intent)
	if err != nil {
		b.mu.Lock()
		b.stats.TranslationFailures++
		b.mu.Unlock()
		return b.deny(ctx, jti, ReasonTranslationFailed, nil)
	}

	// Étape 5 — évaluation OPA via le client T11 : fail-closed,
	// circuit-breaker 5 ms et feuille « TBPD1 » sont hérités — le broker
	// n'y touche pas (D34 : on réutilise, on ne réécrit pas).
	class := pep.DefaultClass // claim −4 absent ⇒ W (§5.3)
	if tr.Class != nil {
		class = *tr.Class
	}
	dec := b.opa.Eval(ctx, pep.OPAInput{
		JTI:      jti,
		Subject:  subject,
		Action:   tr.Action,
		Resource: tr.Resource,
		Class:    class,
		Epoch:    epoch,
	})
	if !dec.Allow {
		b.mu.Lock()
		b.stats.Denies++
		b.mu.Unlock()
		return Result{Allow: false, Reason: dec.Reason, JTI: jti, LeafWritten: dec.LeafWritten, LeafErr: dec.LeafErr, OPADecision: &dec}
	}

	// Étape 6 — quorum classe W (§7.5, T29) : « a single cell, adversarial
	// or captured, cannot authorize the maximal irreversible ». Placé
	// APRÈS l'allow OPA — la preuve lie l'action traduite admise, et les
	// demandes qu'OPA refuse ne consomment aucune vérification de quorum
	// (friction §9.1) — et AVANT toute réservation d'enveloppe ou
	// émission. Sans gate configuré ou sans preuve : quorum-required ;
	// preuve insuffisante : quorum-insufficient. Le gate trace sa propre
	// feuille KindQuorum ; le broker trace le refus final (KindDecision).
	if class == pep.ClassW {
		if b.quorum == nil || len(tr.QuorumProof) == 0 {
			b.mu.Lock()
			b.stats.QuorumDenies++
			b.mu.Unlock()
			return b.deny(ctx, jti, ReasonQuorumRequired, &dec)
		}
		if err := b.quorum.VerifyClassW(ctx, tr.QuorumProof, tr.Action, tr.Resource, epoch); err != nil {
			b.mu.Lock()
			b.stats.QuorumDenies++
			b.mu.Unlock()
			return b.deny(ctx, jti, ReasonQuorumInsufficient, &dec)
		}
	}

	// Étape 7 — enveloppe d'émission (§4.1-bis) : UNIQUEMENT pour les
	// passeports. Réservation pessimiste AVANT l'appel OPA (envelope.go) ;
	// libérée sur tout refus ou échec aval.
	if tr.Quota != nil {
		if b.envelope == nil || b.ledger == nil {
			// Config « actions simples uniquement » : tout passeport est
			// refusé — même doctrine que quota-unverified (T9).
			return b.deny(ctx, jti, ReasonEnvelopeUnverified, &dec)
		}
		b.mu.Lock()
		b.stats.EnvelopeEvals++
		b.mu.Unlock()
		total, err := b.ledger.Reserve(subject, epoch, tr.Quota.VolumeMax)
		if err != nil {
			// Saturé ou débordé : refus fail-closed (l'alarme de saturation
			// est latchée par le ledger lui-même, couture T14).
			return b.deny(ctx, jti, ReasonEnvelopeSaturated, &dec)
		}
		edec := b.envelope.EvalEnvelope(ctx, EnvelopeInput{
			Subject:   subject,
			Epoch:     epoch,
			Resource:  tr.Quota.Resource,
			Operation: tr.Quota.Operation,
			Requested: tr.Quota.VolumeMax,
			Issued:    total,
		})
		if !edec.Allow {
			b.ledger.Release(subject, epoch, tr.Quota.VolumeMax)
			b.mu.Lock()
			b.stats.EnvelopeDenies++
			b.mu.Unlock()
			return b.deny(ctx, jti, edec.Reason, &dec)
		}
		// Réservation CONSERVÉE si l'émission réussit ; libérée en dessous
		// si la signature échoue — jamais de sur-émission.
	}

	// Étape 8 — émission : signature via la couture (HSM en production).
	wire, err := b.issuer.Issue(IssueParams{
		Subject:    subject,
		Action:     tr.Action,
		Resource:   tr.Resource,
		Class:      tr.Class,
		ObjectSeal: tr.ObjectSeal,
		Quota:      tr.Quota,
		JTI:        jti,
		Epoch:      epoch,
		Iat:        b.now().Unix(),
	})
	if err != nil {
		if tr.Quota != nil {
			b.ledger.Release(subject, epoch, tr.Quota.VolumeMax)
		}
		b.mu.Lock()
		b.stats.IssuanceFailures++
		b.mu.Unlock()
		return b.fault(ctx, jti, ReasonIssuanceFailed, err)
	}

	// Étape 9 — feuille propre du broker pour l'ÉMISSION elle-même (§4.1 :
	// chaque décision laisse une feuille). La feuille OPA de l'étape 4 ne
	// prouve que l'évaluation de l'action ; elle ne porte ni l'enveloppe
	// (§4.1-bis, OPAInput ne transporte aucun champ quota) ni le fait qu'un
	// jeton ait réellement été signé et remis. Sans cet appel, un passeport
	// approuvé par l'enveloppe n'a AUCUNE trace de registre portant son
	// volume — même trou que si le validateur T9 rendait un allow sans
	// écrire sa propre feuille. Même doctrine ici : un allow sans preuve
	// redevient un refus (writeLeaf). La réservation d'enveloppe déjà
	// commise N'EST PAS libérée sur cet échec précis : la libérer ouvrirait
	// un canal de sondage (retenter pour regonfler le budget) — le
	// fail-closed va toujours vers PLUS de restriction, jamais moins
	// (même principe que le non-rollback de envelope.go).
	res = Result{Allow: true, Reason: pep.ReasonOK, Token: wire, JTI: jti, OPADecision: &dec}
	b.writeLeaf(ctx, &res)
	if !res.Allow {
		b.mu.Lock()
		b.stats.Denies++
		b.mu.Unlock()
		return res
	}
	b.mu.Lock()
	b.stats.Allows++
	b.mu.Unlock()
	return res
}

// deny épilogue un refus de niveau broker : feuille KindDecision propre
// (la feuille OPA de l'étape 4 existe déjà si atteinte — la feuille du
// broker porte la raison du refus FINAL : enveloppe, entrée, traduction).
func (b *Broker) deny(ctx context.Context, jti [16]byte, reason string, opaDec *pep.OPADecision) Result {
	r := Result{Allow: false, Reason: reason, JTI: jti, OPADecision: opaDec}
	b.writeLeaf(ctx, &r)
	b.mu.Lock()
	b.stats.Denies++
	b.mu.Unlock()
	return r
}

// fault épilogue une FAUTE système de niveau broker (émission impossible) :
// refus + feuille + alarme T14. L'erreur technique reste au journal de
// l'appelant ; la feuille ne porte que la raison (hash-only, §6.2).
func (b *Broker) fault(ctx context.Context, jti [16]byte, reason string, _ error) Result {
	if b.onTrip != nil {
		b.onTrip(reason) // couture T14 — le latch unique est chez T14
	}
	r := Result{Allow: false, Reason: reason, JTI: jti}
	b.writeLeaf(ctx, &r)
	b.mu.Lock()
	b.stats.Denies++
	b.mu.Unlock()
	return r
}

// writeLeaf inscrit la feuille de décision propre du broker — même record
// « TBPD1 » que T9/T11 (jti ‖ verdict ‖ raison), même doctrine : hash-only
// (§6.2, le sel reste chez le producteur), un allow sans preuve re-bascule
// en deny (pas de preuve, pas d'accès).
func (b *Broker) writeLeaf(ctx context.Context, r *Result) {
	verdict := byte(0x00)
	if r.Allow {
		verdict = 0x01
	}
	record := make([]byte, 0, 5+16+1+1+len(r.Reason))
	record = append(record, "TBPD1"...)
	record = append(record, r.JTI[:]...)
	record = append(record, verdict, byte(len(r.Reason)))
	record = append(record, r.Reason...)

	leaf := registry.Leaf{
		Kind:        registry.KindDecision,
		CellID:      b.cellID,
		PayloadHash: registry.HashPayload(b.salt, record),
		Timestamp:   b.now().UnixNano(),
	}
	if _, err := b.leaves.Append(ctx, leaf); err != nil {
		r.LeafErr = err
		if r.Allow { // pas de preuve, pas d'accès (même doctrine que T9/T11)
			r.Allow = false
			r.Reason = pep.ReasonLeafWriteFailed
			r.Token = nil // un refus ne doit jamais porter un jeton exploitable
		}
		b.mu.Lock()
		b.stats.LeafFailures++
		b.mu.Unlock()
		if b.onTrip != nil {
			b.onTrip(pep.ReasonLeafWriteFailed)
		}
		return
	}
	r.LeafWritten = true
}

// decodeHex32 décode un sceau hexadécimal de 32 octets exactement —
// utilisé par le traducteur structuré pour le claim −5 (§4.4(2)).
func decodeHex32(s string, out *[32]byte) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("broker: object_seal non hexadécimal : %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("broker: object_seal de %d octets — 32 attendus (claim −5, §4.4(2))", len(b))
	}
	copy(out[:], b)
	return nil
}
