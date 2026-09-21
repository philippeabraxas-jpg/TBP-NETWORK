// plan_contract.go — T30 (issue #31) : l'arbitrage comme contrat (§4.2).
//
// « Le plan présenté à l'opérateur est généré par l'agent (probabiliste) et
// pourrait mentir (plan abstrait bénin masquant un chemin destructeur).
// Parade : le plan approuvé est un contrat — l'exécution est vérifiée contre
// le hash du plan validé ; déviation = refus. » (§4.2)
//
// Ce fichier est le mécanisme qui rend la discrétion humaine vérifiable
// après coup (§1 : « TBP n'est pas un juge, c'est un livre de lois et un
// greffe ») : un plan à N étapes est soumis, scellé par hash à
// l'approbation — qui est une SIGNATURE Ed25519 de l'opérateur (§4.2 :
// « l'arbitrage est une signature, pas une lecture ») — puis chaque demande
// d'exécution est confrontée au plan scellé par le broker (étape 7 de
// HandleAction, couture ContractGate). Toute déviation — étape différente,
// paramètre différent, ordre différent, rejeu d'étape — est un refus avec
// feuille, MÊME si l'action aurait été autorisée isolément par OPA.
//
// Portée bornée (§4.2 le dit lui-même) : le contrat lie la COHÉRENCE
// exécution ↔ plan montré à l'humain, jamais l'INTENTION (dry-run diff
// §4.4(1) et résidu actions non transactionnelles §4.4/§10.5, pas refermés
// ici). Le transport de soumission/approbation (surface opérateur) est hors
// périmètre : API Go niveau cellule, doctrine socket de cellule — pas
// d'endpoint HTTP (exposition réseau = T35).
//
// Cohérence D7/T16 : l'extension PostgreSQL scelle SHA-256(forme canonique
// du plan requête + relations + paramètres liés) ; ici SHA-256(liste
// ordonnée d'étapes) avec séparation de domaine « TBPC1 ». Même motif
// (sceau SHA-256 sur forme canonique domaine-séparée), deux domaines.
package pep

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Bornes du contrat de plan (D57, D59, D60 — plan posté sur #31).
const (
	// MaxPlanSteps borne le nombre d'étapes d'un plan (§4.3 : état borné).
	MaxPlanSteps = 64
	// MaxPlanParamsBytes borne le blob de paramètres opaque d'une étape
	// (no-DPI — même borne que quorum_proof côté broker).
	MaxPlanParamsBytes = 4096
	// maxPlanActionLen / maxPlanResourceLen reprennent les bornes des
	// claims −2 / −3 du schéma de jeton (schema.cddl) : une étape de plan
	// décrit exactement ce qu'un jeton peut porter.
	maxPlanActionLen   = 255
	maxPlanResourceLen = 1024

	// DefaultMaxPendingPlans / DefaultMaxApprovedPlans bornent l'état du
	// store (§4.3) : saturation = refus + alarme, JAMAIS d'éviction
	// (patron T16/D7 et T5).
	DefaultMaxPendingPlans  = 64
	DefaultMaxApprovedPlans = 64

	// DefaultApprovalTTL borne la fenêtre d'un plan approuvé (défaut 1 h,
	// configurable dans [MinApprovalTTL, MaxApprovalTTL]).
	DefaultApprovalTTL = time.Hour
	MinApprovalTTL     = 60 * time.Second
	MaxApprovalTTL     = 24 * time.Hour
	// DefaultPendingTTL est la durée de vie d'une soumission non approuvée
	// — ensuite purge tracée (feuille event=expire).
	DefaultPendingTTL = 15 * time.Minute

	// DefaultMaxTombstones borne le nombre d'entrées EXPIRÉES OU RÉVOQUÉES
	// retenues pour inspection (§4.3 : état borné). Sans cette borne, les
	// quotas MaxPending/MaxApproved ne bornent que les plans VIVANTS — la
	// carte du store grossirait sans fin sur la durée de vie d'une cellule,
	// un plan expiré ou révoqué de plus à chaque nouvelle soumission.
	DefaultMaxTombstones = 128
)

// Événements de feuille KindContract (D64 — record « TBPL1 »).
const (
	planEventSubmit  byte = 1 // plan soumis, hash scellé, en attente
	planEventApprove byte = 2 // approbation opérateur (signature vérifiée)
	planEventRefuse  byte = 3 // refus d'exécution (déviation, état, forme)
	planEventConsume byte = 4 // étape consommée (jeton émis avec −8)
	planEventExpire  byte = 5 // expiration (soumission ou plan approuvé)
	planEventRevoke  byte = 6 // révocation explicite par l'opérateur
	planStepNA            = 0xFFFF
)

// Erreurs du contrat de plan — codes stables, mappés par le broker en
// raisons machine-readable (plan-binding-invalid, plan-unknown, …).
var (
	ErrPlanSubmissionInvalid     = errors.New("pep: plan invalide (étapes 1..64, action ≤ 255, resource ≤ 1024, params ≤ 4096)")
	ErrPlanBindingInvalid        = errors.New("pep: binding de plan mal formé (« TBPB1 » ‖ hash ‖ params)")
	ErrPlanUnknown               = errors.New("pep: plan inconnu de cette cellule")
	ErrPlanPending               = errors.New("pep: plan soumis, pas encore approuvé par l'opérateur")
	ErrPlanExpired               = errors.New("pep: plan expiré")
	ErrPlanRevoked               = errors.New("pep: plan révoqué par l'opérateur")
	ErrPlanDeviation             = errors.New("pep: déviation du plan approuvé (étape, paramètre, ordre, rejeu)")
	ErrPlanApprovalExpiryInvalid = errors.New("pep: expiry d'approbation hors bornes [60 s, TTL configuré]")
	ErrPlanApprovalSignature     = errors.New("pep: signature d'approbation invalide (trousseau opérateur épinglé)")
	ErrPlanStoreSaturated        = errors.New("pep: store de plans saturé (§4.3 : refus + alarme, jamais d'éviction)")
	ErrPlanStoreFault            = errors.New("pep: faute du store de plans (feuille impossible — pas de preuve, pas de contrat)")
)

// PlanStep est une étape du plan présenté à l'opérateur : l'action et la
// ressource exactes (bornes des claims −2/−3) et le hash des paramètres.
// ParamsHash = HashParams des octets BRUTS que l'agent s'engage à présenter
// à l'exécution — pas de canonisation sémantique : un reformatage, même
// bénin, change le hash et refuse (fail-closed dans la bonne direction,
// D57). L'opérateur, lui, voit les paramètres en clair à l'approbation ;
// le store ne retient que le hash (les feuilles restent hash-only, §6.2).
type PlanStep struct {
	Action     string
	Resource   string
	ParamsHash [32]byte
}

// HashParams calcule le sceau de paramètres d'une étape : SHA-256 des
// octets bruts (D57). params vide = « étape sans paramètres » — lié comme
// toute autre valeur.
func HashParams(params []byte) [32]byte {
	return sha256.Sum256(params)
}

// HashPlan calcule le sceau du plan (D58) — séparation de domaine et forme
// canonique à liste ordonnée (aucune map : déterminisme §11.3 natif) :
//
//	SHA-256("TBPC1" ‖ u8 len(cellID) ‖ cellID ‖ submittedAt(u64 BE, unix s)
//	        ‖ policyID(32) ‖ n(u16 BE)
//	        ‖ par étape : u8 len(action)‖action ‖ u16 BE len(resource)‖resource
//	                      ‖ paramsHash(32))
//
// submittedAt entre dans le sceau : deux soumissions du même plan sont deux
// contrats distincts. Exporté pour l'audit (§6 : vérifiable par un tiers).
func HashPlan(cellID string, submittedAt time.Time, policyID [32]byte, steps []PlanStep) [32]byte {
	h := sha256.New()
	h.Write([]byte("TBPC1"))
	h.Write([]byte{byte(len(cellID))})
	h.Write([]byte(cellID))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(submittedAt.Unix()))
	h.Write(buf[:])
	h.Write(policyID[:])
	binary.BigEndian.PutUint16(buf[:2], uint16(len(steps)))
	h.Write(buf[:2])
	for _, st := range steps {
		h.Write([]byte{byte(len(st.Action))})
		h.Write([]byte(st.Action))
		binary.BigEndian.PutUint16(buf[:2], uint16(len(st.Resource)))
		h.Write(buf[:2])
		h.Write([]byte(st.Resource))
		h.Write(st.ParamsHash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ApprovalMessage est le message que l'opérateur SIGNE pour approuver un
// plan (D59) : "TBPA1" ‖ planHash(32) ‖ expiry(u64 BE, unix s). Ed25519
// (§12), vérifiée contre le trousseau d'opérateurs épinglé de la cellule —
// « jamais par nom, toujours par signature ».
func ApprovalMessage(planHash [32]byte, expiry time.Time) []byte {
	msg := make([]byte, 0, 5+32+8)
	msg = append(msg, "TBPA1"...)
	msg = append(msg, planHash[:]...)
	return binary.BigEndian.AppendUint64(msg, uint64(expiry.Unix()))
}

// BuildBinding construit le blob opaque présenté à l'exécution (D62) :
// "TBPB1" ‖ planHash(32) ‖ paramsLen(u16 BE) ‖ params. Le broker le RELAYE
// au ContractGate sans jamais l'interpréter (no-DPI) — seul le gate parse.
func BuildBinding(planHash [32]byte, params []byte) ([]byte, error) {
	if len(params) > MaxPlanParamsBytes {
		return nil, fmt.Errorf("pep: params de %d octets — borne %d (D57)", len(params), MaxPlanParamsBytes)
	}
	b := make([]byte, 0, 5+32+2+len(params))
	b = append(b, "TBPB1"...)
	b = append(b, planHash[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(params)))
	return append(b, params...), nil
}

// Statuts internes d'un plan.
const (
	planStatusPending byte = iota + 1
	planStatusApproved
	planStatusRevoked
)

// planEntry est l'état borné d'un plan (§4.3).
type planEntry struct {
	steps       []PlanStep
	submittedAt time.Time
	expiresAt   time.Time // pending : soumission + PendingTTL ; approved : expiry signé
	status      byte
	cursor      int  // prochaine étape exigible (consommation à l'émission, D61)
	expired     bool // feuille d'expiration déjà écrite (une seule fois)
}

// ContractOptions paramètre le store. Fail-closed dès la configuration,
// comme partout dans le dépôt.
type ContractOptions struct {
	// CellID identifie la cellule (entre dans le sceau de plan et les
	// feuilles). Requis, ≤ 255 octets.
	CellID string
	// PolicyID est le hash du bundle de règles (claim −1 du jeton) : le
	// sceau de plan l'inclut — un plan approuvé sous P meurt avec P.
	PolicyID [32]byte
	// OperatorKeys est le trousseau d'opérateurs ÉPINGLÉ (Ed25519, §12) :
	// une seule signature valide suffit à approuver. Requis, ≥ 1.
	OperatorKeys []ed25519.PublicKey
	// Salt est le sel des feuilles (§6.2) : ≥ 16 octets, reste chez le
	// producteur. Requis.
	Salt []byte
	// Leaves reçoit la feuille KindContract de chaque événement. Requis —
	// un événement de contrat sans feuille est une faute (pas de preuve,
	// pas de contrat ; même doctrine que T9/T11/T29).
	Leaves LeafSink
	// MaxPending / MaxApproved bornent les plans VIVANTS (pending /
	// approved) — 0 ⇒ 64. Les entrées expirées ou révoquées restent
	// inspectables mais ne comptent plus dans les quotas.
	MaxPending  int
	MaxApproved int
	// MaxTombstones borne le nombre d'entrées EXPIRÉES OU RÉVOQUÉES
	// retenues pour inspection après coup — 0 ⇒ 128. Au-delà, les plus
	// anciennes (par submittedAt) sont purgées ; jamais une entrée VIVANTE
	// (pending/approved), déjà protégée par MaxPending/MaxApproved.
	MaxTombstones int
	// ApprovalTTL borne la fenêtre demandée à l'approbation : expiry − now
	// ∈ [60 s, ApprovalTTL]. 0 ⇒ 1 h ; la valeur configurée doit tenir
	// dans [60 s, 24 h].
	ApprovalTTL time.Duration
	// PendingTTL borne la vie d'une soumission non approuvée. 0 ⇒ 15 min ;
	// borné [60 s, 24 h].
	PendingTTL time.Duration
	// OnTrip est la couture d'alarme vers T14 (saturation, faute de
	// feuille). Nil ⇒ pas d'alarme (le refus reste fail-closed).
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// ContractStore est le greffe des contrats de plan d'une cellule (§4.2).
// État borné et protégé par mutex : la vérification d'étape est le point
// de séquencement synchrone unique (consommation à l'émission, D61 — même
// raison structurelle que l'enveloppe, l'époque et le quorum, TOUS vérifiés
// à l'émission : un curseur réparti entre répliques PEP ouvrirait la
// double-consommation — revue #31).
type ContractStore struct {
	cellID        string
	policyID      [32]byte
	operatorKeys  []ed25519.PublicKey
	salt          []byte
	leaves        LeafSink
	maxPending    int
	maxApproved   int
	maxTombstones int
	approvalTTL   time.Duration
	pendingTTL    time.Duration
	onTrip        func(reason string)
	now           func() time.Time

	mu    sync.Mutex
	plans map[[32]byte]*planEntry
}

// NewContractStore construit le store. Fail-closed : cellID, policyID,
// trousseau opérateur, sel, feuilles requis ; bornes et TTL validés.
func NewContractStore(opts ContractOptions) (*ContractStore, error) {
	if opts.CellID == "" || len(opts.CellID) > maxPlanActionLen {
		return nil, errors.New("pep: cellID requis, ≤ 255 octets (§6.2 : feuilles attribuées)")
	}
	if len(opts.OperatorKeys) == 0 {
		return nil, errors.New("pep: trousseau d'opérateurs épinglé vide (§4.2 : l'arbitrage est une signature)")
	}
	for i, k := range opts.OperatorKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pep: clé opérateur %d de %d octets — Ed25519 en exige %d (§12)", i, len(k), ed25519.PublicKeySize)
		}
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: LeafSink requis (§4.1 : chaque événement de contrat laisse une feuille)")
	}
	maxPending, maxApproved := opts.MaxPending, opts.MaxApproved
	if maxPending == 0 {
		maxPending = DefaultMaxPendingPlans
	}
	if maxApproved == 0 {
		maxApproved = DefaultMaxApprovedPlans
	}
	if maxPending < 0 || maxApproved < 0 {
		return nil, errors.New("pep: quotas de plans négatifs (§4.3 : état borné)")
	}
	maxTombstones := opts.MaxTombstones
	if maxTombstones == 0 {
		maxTombstones = DefaultMaxTombstones
	}
	if maxTombstones < 0 {
		return nil, errors.New("pep: MaxTombstones négatif (§4.3 : état borné)")
	}
	approvalTTL := opts.ApprovalTTL
	if approvalTTL == 0 {
		approvalTTL = DefaultApprovalTTL
	}
	if approvalTTL < MinApprovalTTL || approvalTTL > MaxApprovalTTL {
		return nil, fmt.Errorf("pep: ApprovalTTL %v hors bornes [%v, %v]", approvalTTL, MinApprovalTTL, MaxApprovalTTL)
	}
	pendingTTL := opts.PendingTTL
	if pendingTTL == 0 {
		pendingTTL = DefaultPendingTTL
	}
	if pendingTTL < MinApprovalTTL || pendingTTL > MaxApprovalTTL {
		return nil, fmt.Errorf("pep: PendingTTL %v hors bornes [%v, %v]", pendingTTL, MinApprovalTTL, MaxApprovalTTL)
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	keys := make([]ed25519.PublicKey, len(opts.OperatorKeys))
	copy(keys, opts.OperatorKeys)
	return &ContractStore{
		cellID:        opts.CellID,
		policyID:      opts.PolicyID,
		operatorKeys:  keys,
		salt:          salt,
		leaves:        opts.Leaves,
		maxPending:    maxPending,
		maxApproved:   maxApproved,
		maxTombstones: maxTombstones,
		approvalTTL:   approvalTTL,
		pendingTTL:    pendingTTL,
		onTrip:        opts.OnTrip,
		now:           opts.Now,
		plans:         make(map[[32]byte]*planEntry),
	}, nil
}

func (s *ContractStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Submit scelle un plan soumis par l'agent (D58) et le met en attente
// d'approbation. Renvoie le hash scellé — c'est lui qui est présenté (avec
// le plan en clair) à l'opérateur. Saturation ou feuille impossible =
// refus fail-closed : pas de preuve, pas de contrat.
func (s *ContractStore) Submit(ctx context.Context, steps []PlanStep) ([32]byte, error) {
	if len(steps) < 1 || len(steps) > MaxPlanSteps {
		return [32]byte{}, ErrPlanSubmissionInvalid
	}
	for _, st := range steps {
		if len(st.Action) < 1 || len(st.Action) > maxPlanActionLen ||
			len(st.Resource) < 1 || len(st.Resource) > maxPlanResourceLen {
			return [32]byte{}, ErrPlanSubmissionInvalid
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.expireLocked(ctx, now)
	hash := HashPlan(s.cellID, now, s.policyID, steps)
	// Même cellule, même instant, mêmes étapes = même contrat : la
	// soumission en double est idempotente — tracée (chaque événement de
	// contrat laisse une feuille, §4.1), sans créer de second plan.
	exists := false
	if _, found := s.plans[hash]; found {
		exists = true
	} else if s.countStatusLocked(planStatusPending) >= s.maxPending {
		if s.onTrip != nil {
			s.onTrip("plan-store-saturated")
		}
		return [32]byte{}, ErrPlanStoreSaturated
	}
	if err := s.writeLeafLocked(ctx, planEventSubmit, hash, uint16(len(steps)), 1, "ok", now); err != nil {
		s.tripStoreFault()
		return [32]byte{}, ErrPlanStoreFault
	}
	if exists {
		return hash, nil
	}
	cp := make([]PlanStep, len(steps))
	copy(cp, steps)
	s.plans[hash] = &planEntry{
		steps:       cp,
		submittedAt: now,
		expiresAt:   now.Add(s.pendingTTL),
		status:      planStatusPending,
	}
	return hash, nil
}

// Approve valide la signature de l'opérateur (D59) et active le contrat.
// expiry est choisi par l'outil d'approbation et SIGNÉ (il entre dans
// ApprovalMessage) ; le store borne expiry − now ∈ [60 s, ApprovalTTL].
// Toute tentative invalide laisse une feuille de refus — une approbation
// forgée ou hors bornes est un événement de sécurité, pas du bruit.
func (s *ContractStore) Approve(ctx context.Context, planHash [32]byte, expiry time.Time, sig []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.expireLocked(ctx, now)
	e, ok := s.plans[planHash]
	if !ok {
		return s.refuseApprovalLocked(ctx, planHash, "plan-unknown", ErrPlanUnknown, now)
	}
	if e.expired {
		// Soumission expirée avant approbation : le contrat est mort, il
		// faut re-soumettre — pas d'approbation sur un cadavre (fail-closed).
		return s.refuseApprovalLocked(ctx, planHash, "plan-expired", ErrPlanExpired, now)
	}
	if e.status != planStatusPending {
		return s.refuseApprovalLocked(ctx, planHash, "plan-unknown", ErrPlanUnknown, now)
	}
	ttl := expiry.Sub(now)
	if ttl < MinApprovalTTL || ttl > s.approvalTTL {
		return s.refuseApprovalLocked(ctx, planHash, "plan-approval-expiry-invalid", ErrPlanApprovalExpiryInvalid, now)
	}
	msg := ApprovalMessage(planHash, expiry)
	signed := false
	for _, pub := range s.operatorKeys {
		if ed25519.Verify(pub, msg, sig) {
			signed = true
			break
		}
	}
	if !signed {
		return s.refuseApprovalLocked(ctx, planHash, "plan-approval-signature-invalid", ErrPlanApprovalSignature, now)
	}
	if s.countStatusLocked(planStatusApproved) >= s.maxApproved {
		if s.onTrip != nil {
			s.onTrip("plan-store-saturated")
		}
		return s.refuseApprovalLocked(ctx, planHash, "plan-store-saturated", ErrPlanStoreSaturated, now)
	}
	if err := s.writeLeafLocked(ctx, planEventApprove, planHash, planStepNA, 1, "ok", now); err != nil {
		s.tripStoreFault()
		return ErrPlanStoreFault
	}
	e.status = planStatusApproved
	e.expiresAt = expiry
	e.cursor = 0
	return nil
}

// Revoke retire un plan (soumis ou approuvé) : la discrétion humaine coupe
// dans les deux sens. Quarantaine, pas meurtre (esprit §7.3) : l'entrée
// reste inspectable jusqu'à expiration, les tentatives d'exécution seront
// refusées « plan-revoked », et la révocation laisse sa feuille.
func (s *ContractStore) Revoke(ctx context.Context, planHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.expireLocked(ctx, now)
	e, ok := s.plans[planHash]
	if !ok || e.status == planStatusRevoked || e.expired {
		return s.writeRefusalLocked(ctx, planHash, planStepNA, "plan-unknown", ErrPlanUnknown, now)
	}
	if err := s.writeLeafLocked(ctx, planEventRevoke, planHash, planStepNA, 1, "ok", now); err != nil {
		s.tripStoreFault()
		return ErrPlanStoreFault
	}
	e.status = planStatusRevoked
	return nil
}

// PendingPlan est la vue LECTURE SEULE d'un plan en attente d'arbitrage,
// exposée à la console de supervision (T34c, issue #60, D81) : le hash
// scellé, les bornes temporelles et le nombre d'étapes — JAMAIS les étapes
// elles-mêmes ni les paramètres (hash-only : le plan en clair circule sur
// le canal opérateur ; la console n'est pas un second canal de lecture du
// plan, et la décision humaine reste une signature Approve sur ce canal,
// pas une route HTTP — T30).
type PendingPlan struct {
	Hash        [32]byte
	SubmittedAt time.Time
	ExpiresAt   time.Time
	Steps       int
}

// Snapshot renvoie les plans en attente d'arbitrage (pending, non expirés),
// triés par submittedAt (ordre d'arrivée = ordre d'arbitrage), hash en
// bris d'égalité pour un ordre déterministe sous horloge à pas grossier.
// Lecture seule PAR CONSTRUCTION : aucune mutation, aucune feuille, aucune
// alarme — lire la file ne peut ni la changer ni produire d'événement. Les
// entrées dont expiresAt est passé mais dont la feuille d'expiration n'est
// pas encore écrite (expireLocked n'a pas encore tourné) sont filtrées ici
// sur l'horloge : la console ne montre jamais un plan déjà mort.
//
// Lecture locale infaillible : nil ici — l'erreur existe dans la signature
// parce que la couture ArbitrationSource de la console (T37, D110 élargi
// après revue) peut être un adaptateur réseau, dont la lecture peut
// échouer (une zero-value serait une demi-vérité, §1).
func (s *ContractStore) Snapshot() ([]PendingPlan, error) {
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingPlan, 0, len(s.plans))
	for h, e := range s.plans {
		if e.status != planStatusPending || e.expired || !now.Before(e.expiresAt) {
			continue
		}
		out = append(out, PendingPlan{
			Hash:        h,
			SubmittedAt: e.submittedAt,
			ExpiresAt:   e.expiresAt,
			Steps:       len(e.steps),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].SubmittedAt.Equal(out[j].SubmittedAt) {
			return out[i].SubmittedAt.Before(out[j].SubmittedAt)
		}
		return bytes.Compare(out[i].Hash[:], out[j].Hash[:]) < 0
	})
	return out, nil
}

// PolicyID renvoie le hash du bundle de règles sous lequel les plans sont
// scellés (claim −1) : la console l'affiche pour que l'arbitre vérifie
// qu'il arbitre sous la bonne politique (un plan approuvé sous P meurt
// avec P). Contrat ArbitrationSource (T37) : la policy du DERNIER Snapshot
// réussi — ici la policy est fixée à la construction du store, elle
// satisfait donc le contrat pour tout Snapshot ; les adaptateurs réseau,
// eux, ne la mettent à jour que sur une lecture réussie (supervisord).
func (s *ContractStore) PolicyID() [32]byte { return s.policyID }

// VerifyStep est la couture appelée par le broker (étape 7 de HandleAction,
// D62) : la demande (binding opaque + action/resource traduites) est
// confrontée au plan scellé. Concordance EXACTE avec l'étape exigible
// (curseur strict) ⇒ curseur avancé, feuille de consommation, sceau rendu
// au broker pour le claim −8 du jeton. Tout écart = refus + feuille, même
// si OPA aurait autorisé l'action isolément (critère d'acceptation de #31).
//
// La consommation a lieu À L'ÉMISSION (point synchrone unique) : un jeton
// émis puis jamais exécuté consomme l'étape — le plan se termine en impasse
// et repart par une nouvelle approbation (friction bornée, direction sûre ;
// trade-off documenté D61, validé en revue #31).
func (s *ContractStore) VerifyStep(ctx context.Context, binding []byte, action, resource string) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.expireLocked(ctx, now)

	planHash, params, err := parseBinding(binding)
	if err != nil {
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, planStepNA, "plan-binding-invalid", ErrPlanBindingInvalid, now)
	}
	e, ok := s.plans[planHash]
	if !ok {
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, planStepNA, "plan-unknown", ErrPlanUnknown, now)
	}
	if e.expired {
		// La transition a été tracée par expireLocked (une fois) — chaque
		// tentative d'exécution ultérieure reste un refus tracé (§4.1).
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, planStepNA, "plan-expired", ErrPlanExpired, now)
	}
	step := uint16(planStepNA)
	if e.cursor < len(e.steps) {
		step = uint16(e.cursor)
	}
	switch e.status {
	case planStatusPending:
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, step, "plan-pending", ErrPlanPending, now)
	case planStatusRevoked:
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, step, "plan-revoked", ErrPlanRevoked, now)
	}
	if e.cursor >= len(e.steps) {
		// Plan entièrement consommé : toute étape supplémentaire est une
		// déviation (le curseur strict est le contrat, D61).
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, planStepNA, "plan-deviation", ErrPlanDeviation, now)
	}
	want := e.steps[e.cursor]
	if action != want.Action || resource != want.Resource || HashParams(params) != want.ParamsHash {
		return [32]byte{}, s.writeRefusalLocked(ctx, planHash, step, "plan-deviation", ErrPlanDeviation, now)
	}
	// Concordance exacte : feuille de consommation D'ABORD — pas de preuve,
	// pas de progression (le curseur n'avance que si la feuille existe,
	// même doctrine « allow sans feuille = erreur » que T9/T11/T29).
	if err := s.writeLeafLocked(ctx, planEventConsume, planHash, step, 1, "ok", now); err != nil {
		s.tripStoreFault()
		return [32]byte{}, ErrPlanStoreFault
	}
	e.cursor++
	return planHash, nil
}

// parseBinding décode le blob opaque (seul le gate l'interprète — no-DPI
// côté broker). Le hash extrait est rendu même en cas d'erreur de queue,
// pour que la feuille de refus porte le sceau présenté quand il existe.
func parseBinding(binding []byte) (planHash [32]byte, params []byte, err error) {
	if len(binding) < 5+32+2 || string(binding[:5]) != "TBPB1" {
		return planHash, nil, ErrPlanBindingInvalid
	}
	copy(planHash[:], binding[5:37])
	n := int(binary.BigEndian.Uint16(binding[37:39]))
	if len(binding) != 39+n || n > MaxPlanParamsBytes {
		// n > MaxPlanParamsBytes : BuildBinding ne produit jamais un blob
		// pareil (elle borne côté construction), mais parseBinding est
		// appelée sur tout blob reçu par VerifyStep — un appelant futur qui
		// contournerait BuildBinding (la couture est publique, D62) ne doit
		// pas pouvoir faire porter un blob de paramètres non borné plus
		// loin dans le greffe (no-DPI ≠ non borné, §6.2/§9.1).
		return planHash, nil, ErrPlanBindingInvalid
	}
	return planHash, binding[39:], nil
}

// expireLocked trace la transition d'expiration des plans dont l'instant
// est passé — une seule feuille par plan (garde e.expired) — puis purge
// les tombes (expirées ou révoquées) au-delà de maxTombstones.
//
// Les quotas MaxPending/MaxApproved ne bornent QUE les plans VIVANTS
// (countStatusLocked les exclut dès expiration OU révocation) : sans
// purge séparée, la carte grossirait d'une entrée à chaque plan expiré
// ou révoqué, sans jamais rétrécir — un plan par tentative d'arbitrage
// pendant toute la durée de vie de la cellule (§4.3 violé en pratique,
// pas seulement pour les plans vivants). Trouvé en revue de #66.
func (s *ContractStore) expireLocked(ctx context.Context, now time.Time) {
	for hash, e := range s.plans {
		if e.expired || !now.After(e.expiresAt) {
			continue
		}
		if err := s.writeLeafLocked(ctx, planEventExpire, hash, planStepNA, 1, "ok", now); err != nil {
			// Faute de feuille en purge : on alarme et on réessaiera au
			// prochain toucher — l'entrée reste, fail-closed (elle refuse
			// déjà toute exécution par sa date).
			s.tripStoreFault()
			continue
		}
		e.expired = true
	}
	s.evictTombstonesLocked()
}

// evictTombstonesLocked borne le nombre d'entrées EXPIRÉES OU RÉVOQUÉES
// retenues pour inspection (§4.3) : au-delà de maxTombstones, les plus
// anciennes (par submittedAt) sont retirées de la carte. Une entrée
// purgée ainsi tombante rend « plan-unknown » au lieu de « plan-expired »
// / « plan-revoked » au toucher suivant — perte de précision du message,
// jamais de bascule fail-open (le refus tient dans tous les cas). Ne
// touche JAMAIS une entrée vivante (pending/approved non expirée/révoquée)
// — celles-ci restent protégées par MaxPending/MaxApproved uniquement.
func (s *ContractStore) evictTombstonesLocked() {
	type tomb struct {
		hash        [32]byte
		submittedAt time.Time
	}
	var tombs []tomb
	for hash, e := range s.plans {
		if e.expired || e.status == planStatusRevoked {
			tombs = append(tombs, tomb{hash, e.submittedAt})
		}
	}
	if len(tombs) <= s.maxTombstones {
		return
	}
	sort.Slice(tombs, func(i, j int) bool { return tombs[i].submittedAt.Before(tombs[j].submittedAt) })
	for _, t := range tombs[:len(tombs)-s.maxTombstones] {
		delete(s.plans, t.hash)
	}
}

// countStatusLocked compte les plans VIVANTS d'un statut (les entrées
// expirées ne comptent plus — les quotas bornent la pression réelle).
func (s *ContractStore) countStatusLocked(status byte) int {
	n := 0
	for _, e := range s.plans {
		if e.status == status && !e.expired {
			n++
		}
	}
	return n
}

// refuseApprovalLocked trace une approbation refusée (event=approve,
// verdict 0) puis rend l'erreur. Une faute de feuille sur ce chemin est
// une faute de store (alarmée) : le refus, lui, tient toujours.
func (s *ContractStore) refuseApprovalLocked(ctx context.Context, planHash [32]byte, reason string, err error, now time.Time) error {
	if werr := s.writeLeafLocked(ctx, planEventApprove, planHash, planStepNA, 0, reason, now); werr != nil {
		s.tripStoreFault()
		return ErrPlanStoreFault
	}
	return err
}

// writeRefusalLocked trace un refus d'exécution (event=refuse, verdict 0).
func (s *ContractStore) writeRefusalLocked(ctx context.Context, planHash [32]byte, step uint16, reason string, err error, now time.Time) error {
	if werr := s.writeLeafLocked(ctx, planEventRefuse, planHash, step, 0, reason, now); werr != nil {
		s.tripStoreFault()
		return ErrPlanStoreFault
	}
	return err
}

// writeLeafLocked inscrit la feuille KindContract (D64) — hash-only (§6.2 :
// le sel reste chez le producteur) :
//
//	record = "TBPL1" ‖ event(u8) ‖ planHash(32) ‖ step(u16 BE, 0xFFFF = s/o)
//	         ‖ verdict(u8) ‖ u8 len(reason) ‖ reason
func (s *ContractStore) writeLeafLocked(ctx context.Context, event byte, planHash [32]byte, step uint16, verdict byte, reason string, now time.Time) error {
	record := make([]byte, 0, 5+1+32+2+1+1+len(reason))
	record = append(record, "TBPL1"...)
	record = append(record, event)
	record = append(record, planHash[:]...)
	record = binary.BigEndian.AppendUint16(record, step)
	record = append(record, verdict, byte(len(reason)))
	record = append(record, reason...)
	_, err := s.leaves.Append(ctx, registry.Leaf{
		Kind:        registry.KindContract,
		CellID:      s.cellID,
		PayloadHash: registry.HashPayload(s.salt, record),
		Timestamp:   now.UnixNano(),
	})
	return err
}

func (s *ContractStore) tripStoreFault() {
	if s.onTrip != nil {
		s.onTrip("plan-store-fault")
	}
}
