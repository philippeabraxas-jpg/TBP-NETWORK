// Package arbiter est la file d'arbitrage HUMAIN des demandes dégradées (§4.5, T25, #275 suite).
//
// Quand le traducteur est tombé, un système STANDARD n'est pas refusé d'emblée : si un arbitre humain est
// joignable, sa demande est mise en file (verdict différé — ErrPendingArbitration n'est PAS un refus). Un opérateur
// décide par une SIGNATURE (« l'arbitrage est une signature, pas une lecture », §4.2) ; l'agent REPRÉSENTE la même
// demande, qui est alors admise UNE fois par le chemin de traduction — et jugée ensuite par toute la chaîne
// (OPA, quorum, plan, contrats) SANS exception : l'approbation lève l'admission du traducteur, rien d'autre.
//
// Doctrine :
//   - hash-only (no-DPI) : la file ne retient que SHA-256(sujet ‖ intention), le sujet, l'état et l'échéance — jamais
//     l'intention. L'identifiant rendu à l'agent EST ce hash : l'opérateur, qui connaît ce que l'agent veut faire,
//     le recalcule (IntentID) et signe SON hash — il ne signe pas une lecture de la file.
//   - une décision signée ne vaut que pour UNE mise en file de UNE cellule : le message signé porte l'identité de la
//     cellule et le TICKET (16 octets aléatoires tirés à la mise en file). Consommée, la demande qui revient en file
//     reçoit un autre ticket : la même signature ne la rouvre pas (rejeu), et une cellule B n'accepte ni le
//     battement ni la décision signés pour A (même trousseau d'opérateurs).
//   - joignabilité PROUVÉE : « un arbitre est joignable » = un battement de présence signé par une clé d'opérateur
//     épinglée, frais et strictement croissant ; jamais une déclaration.
//   - persistante sans fichier d'état : au démarrage, Restore reconstruit la file depuis le journal (voir Restore) ;
//   - bornée partout : file pleine ⇒ refus (default-deny, pas de file implicite) ; échéance de chaque entrée ;
//     une approbation est à usage UNIQUE et expire.
//   - chaque événement (mise en file, décision, consommation) laisse une feuille « TBAR1 » dont le clair est
//     journalisé AVANT l'inscription ; sans clair, pas de feuille — et pas d'effet (fail-closed).
package arbiter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	translator "github.com/philippeabraxas-jpg/TBP-NETWORK/src/translator"
)

// Bornes et défauts.
const (
	DefaultPresenceTTL = 60 * time.Second
	MinPresenceTTL     = 10 * time.Second
	MaxPresenceTTL     = 10 * time.Minute

	DefaultEntryTTL = 10 * time.Minute
	MinEntryTTL     = time.Minute
	MaxEntryTTL     = time.Hour

	DefaultMaxEntries = 256
	MaxMaxEntries     = 4096

	// MinDecisionTTL : une décision doit laisser à l'agent le temps de représenter sa demande.
	MinDecisionTTL = 30 * time.Second

	// HeartbeatSkew borne l'écart entre l'horodatage signé d'un battement et l'horloge de la cellule.
	HeartbeatSkew = 30 * time.Second

	maxSubjectLen = 255
)

// Verdict est la décision de l'opérateur.
type Verdict byte

const (
	VerdictRefuse  Verdict = 0
	VerdictApprove Verdict = 1
)

func (v Verdict) String() string {
	if v == VerdictApprove {
		return "approve"
	}
	return "refuse"
}

// Erreurs (codes machine stables côté opérateur).
var (
	ErrFull              = errors.New("arbiter: file d'arbitrage pleine — default-deny")
	ErrUnknownEntry      = errors.New("arbiter: demande inconnue, expirée ou déjà tranchée")
	ErrBadSignature      = errors.New("arbiter: signature d'opérateur invalide")
	ErrRoleDenied        = errors.New("arbiter: cette clé d'opérateur n'a pas le rôle d'arbitrage")
	ErrHeartbeatStale    = errors.New("arbiter: battement hors de la fenêtre de fraîcheur")
	ErrHeartbeatReplayed = errors.New("arbiter: battement non croissant (rejeu)")
	ErrDecisionExpiry    = errors.New("arbiter: échéance de décision hors bornes")
	ErrLeaf              = errors.New("arbiter: feuille impossible — aucun effet")
)

// Message signés (domaines DISTINCTS de l'approbation de plan « TBPA1 » et de la révocation « TBPR1 » : une
// signature ne vaut que pour l'acte pour lequel elle a été donnée). Les deux portent l'identité de la CELLULE
// (longueur u16 BE ‖ octets) : un opérateur dont la clé est épinglée dans plusieurs cellules ne signe pas, par un
// geste, pour toutes.

func appendCell(msg []byte, cellID string) []byte {
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(cellID)))
	return append(msg, cellID...)
}

// PresenceMessage : "TBAH2" ‖ len(cellule) u16 BE ‖ cellule ‖ unix(u64 BE).
func PresenceMessage(cellID string, at time.Time) []byte {
	msg := append(make([]byte, 0, 5+2+len(cellID)+8), "TBAH2"...)
	msg = appendCell(msg, cellID)
	return binary.BigEndian.AppendUint64(msg, uint64(at.Unix()))
}

// Ticket est l'identité d'UNE mise en file : 16 octets aléatoires tirés par Enqueue et lisibles par l'opérateur
// (Snapshot, GET /v1/supervision/degraded). Entre dans le message signé de la décision.
type Ticket [16]byte

// DecisionMessage : "TBAV2" ‖ len(cellule) u16 BE ‖ cellule ‖ verdict(1) ‖ id(32) ‖ ticket(16) ‖ expiry unix(u64 BE).
func DecisionMessage(cellID string, id [32]byte, ticket Ticket, v Verdict, expiry time.Time) []byte {
	msg := append(make([]byte, 0, 5+2+len(cellID)+1+32+16+8), "TBAV2"...)
	msg = appendCell(msg, cellID)
	msg = append(msg, byte(v))
	msg = append(msg, id[:]...)
	msg = append(msg, ticket[:]...)
	return binary.BigEndian.AppendUint64(msg, uint64(expiry.Unix()))
}

// IntentID est l'identifiant d'une demande dégradée : SHA-256("tbp-degraded-intent-v1" ‖ len(sujet) u16 ‖ sujet ‖
// intention). Déterministe sur les octets EXACTS de l'intention : la même demande représentée identiquement a le
// même identifiant ; un octet de différence, un autre.
func IntentID(subject string, intent []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("tbp-degraded-intent-v1"))
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(subject)))
	h.Write(l[:])
	h.Write([]byte(subject))
	h.Write(intent)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Options paramètre la file. Fail-closed dès la configuration.
type Options struct {
	CellID string
	Salt   []byte // ≥ 16 octets, reste chez le producteur (§6.2)
	Leaves translator.LeafSink
	// Journal reçoit le clair de chaque feuille AVANT son inscription (#275). Optionnel (nil = feuille nue).
	Journal *registry.RecordStore
	// OperatorKeys : trousseau d'opérateurs ÉPINGLÉ (le même que le store de contrats). Requis.
	OperatorKeys []ed25519.PublicKey
	// ArbiterKeys : le sous-ensemble du trousseau qui tient le rôle d'arbitrage (présence et décision). Nil ⇒ tout le
	// trousseau (historique). Non nil, il ne peut pas être vide et chaque clé doit être dans OperatorKeys. Une clé du
	// trousseau sans ce rôle est refusée avec ErrRoleDenied, pas confondue avec une signature inconnue.
	ArbiterKeys []ed25519.PublicKey
	// RefuserKeys : qui peut REFUSER une demande dégradée. Refuser restreint (la demande reste bloquée), approuver élargit
	// (elle est admise) : le refus est ouvert à plus de clés que l'approbation. Nil ⇒ les mêmes que ArbiterKeys
	// (historique) ; sinon un sous-ensemble du trousseau OperatorKeys, non vide, qui contient ArbiterKeys. Une clé qui
	// peut refuser sans pouvoir approuver et qui tente d'approuver est refusée avec ErrRoleDenied.
	RefuserKeys []ed25519.PublicKey
	PresenceTTL time.Duration // 0 ⇒ DefaultPresenceTTL
	EntryTTL    time.Duration // 0 ⇒ DefaultEntryTTL
	MaxEntries  int           // 0 ⇒ DefaultMaxEntries
	OnAlarm     func(reason string)
	Now         func() time.Time
}

type status byte

const (
	statusPending status = iota
	statusApproved
	statusRefused
)

type entry struct {
	ticket  Ticket
	subject string
	created time.Time
	expires time.Time // pending : fin de la file ; décidé : fin de la décision
	status  status
	by      [16]byte // kid de l'opérateur décideur
}

// Queue est la file d'arbitrage. Sûre pour un usage concurrent. Implémente translator.Arbitration.
type Queue struct {
	cellID  string
	salt    []byte
	leaves  translator.LeafSink
	journal *registry.RecordStore
	keys    []ed25519.PublicKey // clés ayant le rôle d'arbitrage (présence, approbation, refus)
	refuse  []ed25519.PublicKey // clés qui peuvent REFUSER : les arbitres, et celles que la configuration y ajoute
	allKeys []ed25519.PublicKey // tout le trousseau : sert à nommer un refus de rôle
	presTTL time.Duration
	entTTL  time.Duration
	max     int
	alarm   func(string)
	now     func() time.Time

	mu      sync.Mutex
	entries map[[32]byte]*entry
	lastHB  time.Time // dernier battement accepté (horodatage SIGNÉ)
}

// NewQueue construit la file.
func NewQueue(o Options) (*Queue, error) {
	if o.CellID == "" {
		return nil, errors.New("arbiter: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(o.Salt) < 16 {
		return nil, errors.New("arbiter: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if o.Leaves == nil {
		return nil, errors.New("arbiter: couture feuilles requise (toute décision laisse une feuille)")
	}
	if len(o.OperatorKeys) == 0 {
		return nil, errors.New("arbiter: trousseau d'opérateurs requis (l'arbitrage est une signature)")
	}
	keys := make([]ed25519.PublicKey, len(o.OperatorKeys))
	for i, k := range o.OperatorKeys {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("arbiter: clé d'opérateur %d de %d octets", i, len(k))
		}
		keys[i] = append(ed25519.PublicKey(nil), k...)
	}
	arb := keys
	if o.ArbiterKeys != nil {
		if len(o.ArbiterKeys) == 0 {
			return nil, errors.New("arbiter: aucune clé d'opérateur n'a le rôle d'arbitrage — la file ne pourrait jamais être tranchée")
		}
		known := make(map[[16]byte]bool, len(keys))
		for _, k := range keys {
			known[pep.KeyIDFromPublicKey(k)] = true
		}
		arb = make([]ed25519.PublicKey, len(o.ArbiterKeys))
		for i, k := range o.ArbiterKeys {
			if !known[pep.KeyIDFromPublicKey(k)] {
				return nil, fmt.Errorf("arbiter: la clé %d du rôle d'arbitrage n'est pas dans le trousseau d'opérateurs épinglé", i)
			}
			arb[i] = append(ed25519.PublicKey(nil), k...)
		}
	}
	refusers := arb
	if o.RefuserKeys != nil {
		if len(o.RefuserKeys) == 0 {
			return nil, errors.New("arbiter: RefuserKeys vide — la file ne pourrait jamais être refusée")
		}
		known := make(map[[16]byte]bool, len(keys))
		for _, k := range keys {
			known[pep.KeyIDFromPublicKey(k)] = true
		}
		refusers = make([]ed25519.PublicKey, len(o.RefuserKeys))
		have := make(map[[16]byte]bool, len(o.RefuserKeys))
		for i, k := range o.RefuserKeys {
			kid := pep.KeyIDFromPublicKey(k)
			if !known[kid] {
				return nil, fmt.Errorf("arbiter: la clé %d du rôle de refus n'est pas dans le trousseau d'opérateurs épinglé", i)
			}
			have[kid] = true
			refusers[i] = append(ed25519.PublicKey(nil), k...)
		}
		for _, k := range arb {
			if !have[pep.KeyIDFromPublicKey(k)] {
				return nil, errors.New("arbiter: un arbitre doit pouvoir refuser — RefuserKeys contient ArbiterKeys (refuser restreint, approuver élargit : jamais l'inverse)")
			}
		}
	}
	pt := o.PresenceTTL
	if pt == 0 {
		pt = DefaultPresenceTTL
	}
	if pt < MinPresenceTTL || pt > MaxPresenceTTL {
		return nil, fmt.Errorf("arbiter: présence %s hors [%s, %s]", pt, MinPresenceTTL, MaxPresenceTTL)
	}
	et := o.EntryTTL
	if et == 0 {
		et = DefaultEntryTTL
	}
	if et < MinEntryTTL || et > MaxEntryTTL {
		return nil, fmt.Errorf("arbiter: échéance de file %s hors [%s, %s]", et, MinEntryTTL, MaxEntryTTL)
	}
	mx := o.MaxEntries
	if mx == 0 {
		mx = DefaultMaxEntries
	}
	if mx < 1 || mx > MaxMaxEntries {
		return nil, fmt.Errorf("arbiter: taille de file %d hors [1, %d]", mx, MaxMaxEntries)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	salt := append([]byte(nil), o.Salt...)
	return &Queue{
		cellID: o.CellID, salt: salt, leaves: o.Leaves, journal: o.Journal, keys: arb, refuse: refusers, allKeys: keys,
		presTTL: pt, entTTL: et, max: mx, alarm: o.OnAlarm, now: now,
		entries: make(map[[32]byte]*entry),
	}, nil
}

// kidOf identifie le signataire d'un acte d'arbitrage : sa clé si elle tient le rôle ; ErrRoleDenied si elle est du
// trousseau sans ce rôle ; ErrBadSignature sinon.
func (q *Queue) kidOf(msg, sig []byte) ([16]byte, error) {
	return q.kidOfIn(q.keys, msg, sig)
}

// kidOfIn est kidOf pour un ensemble de clés donné : le refus accepte plus de clés que l'approbation.
func (q *Queue) kidOfIn(keys []ed25519.PublicKey, msg, sig []byte) ([16]byte, error) {
	for _, pub := range keys {
		if ed25519.Verify(pub, msg, sig) {
			return pep.KeyIDFromPublicKey(pub), nil
		}
	}
	for _, pub := range q.allKeys {
		if ed25519.Verify(pub, msg, sig) {
			return [16]byte{}, ErrRoleDenied
		}
	}
	return [16]byte{}, ErrBadSignature
}

// Heartbeat enregistre un battement de présence signé par un opérateur épinglé. L'horodatage signé doit être frais
// (±HeartbeatSkew) et strictement croissant (pas de rejeu).
func (q *Queue) Heartbeat(ctx context.Context, at time.Time, sig []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	if d := now.Sub(at); d > HeartbeatSkew || d < -HeartbeatSkew {
		return ErrHeartbeatStale
	}
	if _, err := q.kidOf(PresenceMessage(q.cellID, at), sig); err != nil {
		return err
	}
	if !at.After(q.lastHB) {
		return ErrHeartbeatReplayed
	}
	q.lastHB = at
	return nil
}

// Reachable : un battement valide date de moins de PresenceTTL (translator.Arbitration).
func (q *Queue) Reachable(context.Context) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return !q.lastHB.IsZero() && q.now().Sub(q.lastHB) <= q.presTTL
}

// Enqueue met la demande en file (translator.Arbitration). item.Payload porte l'intention OPAQUE, jamais retenue :
// seul son hash l'est. Idempotent pour une demande déjà en attente. Échec ⇒ erreur ⇒ le contrôleur refuse.
func (q *Queue) Enqueue(ctx context.Context, item translator.ArbitrationItem) error {
	if len(item.SystemID) > maxSubjectLen {
		return errors.New("arbiter: sujet trop long")
	}
	id := IntentID(item.SystemID, item.Payload)
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	q.pruneLocked(now)
	if e, ok := q.entries[id]; ok && e.status == statusPending {
		return nil
	}
	if len(q.entries) >= q.max {
		if q.alarm != nil {
			q.alarm("arbiter-queue-full")
		}
		return ErrFull
	}
	expires := now.Add(q.entTTL)
	var ticket Ticket
	if _, err := rand.Read(ticket[:]); err != nil {
		return fmt.Errorf("arbiter: ticket de mise en file : %w", err) // pas de ticket, pas d'entrée
	}
	// l'échéance et le ticket de mise en file entrent dans la feuille : c'est ce qui permet de RESTAURER l'entrée (Restore)
	if err := q.leafLocked(ctx, actEnqueue, id, ticket, item.SystemID, [16]byte{}, 0, expires, now); err != nil {
		return err
	}
	q.entries[id] = &entry{ticket: ticket, subject: item.SystemID, created: now, expires: expires, status: statusPending}
	return nil
}

// Decide enregistre la décision signée d'un opérateur épinglé sur une demande EN ATTENTE. expiry borne le temps
// laissé à l'agent pour représenter sa demande, dans [now+MinDecisionTTL, now+EntryTTL].
func (q *Queue) Decide(ctx context.Context, id [32]byte, v Verdict, expiry time.Time, sig []byte) error {
	if v != VerdictApprove && v != VerdictRefuse {
		return ErrUnknownEntry
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	q.pruneLocked(now)
	e, ok := q.entries[id]
	if !ok || e.status != statusPending {
		return ErrUnknownEntry
	}
	if ttl := expiry.Sub(now); ttl < MinDecisionTTL || ttl > q.entTTL {
		return ErrDecisionExpiry
	}
	// Refuser restreint, approuver élargit : le refus est ouvert à plus de clés que l'approbation.
	allowed := q.keys
	if v == VerdictRefuse {
		allowed = q.refuse
	}
	kid, err := q.kidOfIn(allowed, DecisionMessage(q.cellID, id, e.ticket, v, expiry), sig)
	if err != nil {
		return err
	}
	act := actRefuse
	if v == VerdictApprove {
		act = actApprove
	}
	if err := q.leafLocked(ctx, act, id, e.ticket, e.subject, kid, byte(v), expiry, now); err != nil {
		return err
	}
	e.status = statusApproved
	if v == VerdictRefuse {
		e.status = statusRefused
	}
	e.expires, e.by = expiry, kid
	return nil
}

// Outcome est ce que la file dit d'une demande représentée.
type Outcome int

const (
	OutcomeNone     Outcome = iota // inconnue (jamais mise en file, ou expirée) : le contrôleur décide
	OutcomePending                 // en attente d'un opérateur
	OutcomeApproved                // approbation CONSOMMÉE : à admettre UNE fois
	OutcomeRefused                 // refus CONSOMMÉ
)

// Take consulte et consomme. Une approbation ou un refus est à usage UNIQUE : consommé, il disparaît. Si la feuille
// de consommation est impossible, l'entrée est conservée et l'erreur rendue (fail-closed : pas d'admission sans trace).
func (q *Queue) Take(ctx context.Context, subject string, intent []byte) (Outcome, [32]byte, error) {
	id := IntentID(subject, intent)
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	q.pruneLocked(now)
	e, ok := q.entries[id]
	if !ok {
		return OutcomeNone, id, nil
	}
	switch e.status {
	case statusPending:
		return OutcomePending, id, nil
	case statusApproved, statusRefused:
		act, out := actConsumeRefused, OutcomeRefused
		if e.status == statusApproved {
			act, out = actConsume, OutcomeApproved
		}
		if err := q.leafLocked(ctx, act, id, e.ticket, e.subject, e.by, 0, e.expires, now); err != nil {
			return OutcomeNone, id, err
		}
		delete(q.entries, id)
		return out, id, nil
	}
	return OutcomeNone, id, nil
}

func (q *Queue) pruneLocked(now time.Time) {
	for id, e := range q.entries {
		if !now.Before(e.expires) {
			delete(q.entries, id)
		}
	}
}

// Entry est la vue d'une entrée pour l'opérateur : jamais l'intention.
type Entry struct {
	ID        [32]byte
	Ticket    Ticket // à signer avec la décision (DecisionMessage)
	Subject   string
	Status    string // pending | approved | refused
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Snapshot rend la file (hors entrées échues), triée par création puis identifiant.
func (q *Queue) Snapshot() []Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pruneLocked(q.now())
	out := make([]Entry, 0, len(q.entries))
	for id, e := range q.entries {
		st := "pending"
		switch e.status {
		case statusApproved:
			st = "approved"
		case statusRefused:
			st = "refused"
		}
		out = append(out, Entry{ID: id, Ticket: e.ticket, Subject: e.subject, Status: st, CreatedAt: e.created, ExpiresAt: e.expires})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return string(out[i].ID[:]) < string(out[j].ID[:])
	})
	return out
}

// --- Feuille « TBAR1 » (KindTelemetry, hash-only §6.2) ----------------------------------------------------------
//
//	"TBAR2" ‖ action(1) ‖ id(32) ‖ ticket(16) ‖ u8 len(sujet) ‖ sujet ‖ kid(16) ‖ verdict(1) ‖ expiry unix(u64 BE)
//
// action : 1=enqueue 2=approve 3=refuse 4=consume 5=consume-refused. kid/verdict sont nuls hors décision ; expiry est
// l'échéance de la mise en file (enqueue), de la décision (approve/refuse) ou de l'entrée consommée. Un « enqueue » à
// expiry nulle (format antérieur à la restauration) n'est pas restaurable.
const (
	actEnqueue        byte = 1
	actApprove        byte = 2
	actRefuse         byte = 3
	actConsume        byte = 4
	actConsumeRefused byte = 5
)

func (q *Queue) leafLocked(ctx context.Context, act byte, id [32]byte, ticket Ticket, subject string, kid [16]byte, verdict byte, expiry, now time.Time) error {
	if len(subject) > maxSubjectLen {
		subject = subject[:maxSubjectLen]
	}
	rec := make([]byte, 0, 5+1+32+16+1+len(subject)+16+1+8)
	rec = append(rec, "TBAR2"...)
	rec = append(rec, act)
	rec = append(rec, id[:]...)
	rec = append(rec, ticket[:]...)
	rec = append(rec, byte(len(subject)))
	rec = append(rec, subject...)
	rec = append(rec, kid[:]...)
	rec = append(rec, verdict)
	var exp uint64
	if !expiry.IsZero() {
		exp = uint64(expiry.Unix())
	}
	rec = binary.BigEndian.AppendUint64(rec, exp)
	if _, err := registry.AppendLeaf(ctx, q.leaves, q.journal, registry.KindTelemetry, q.cellID, q.salt, rec, now.UnixNano()); err != nil {
		if q.alarm != nil {
			q.alarm("arbiter-leaf-write-failed")
		}
		return fmt.Errorf("%w : %v", ErrLeaf, err)
	}
	return nil
}

var _ translator.Arbitration = (*Queue)(nil)

// RestoreStats rend compte d'une restauration.
type RestoreStats struct {
	Pending, Approved, Refused int // entrées vivantes restaurées
	Skipped                    int // enregistrements TBAR1 ignorés (non vérifiés, périmés, incohérents)
}

// Restore reconstruit la file depuis les enregistrements du journal (déjà déchiffrés par registry.ReadRecords), dans
// l'ordre du journal : mise en file, décision, consommation. Rien n'est lu d'un fichier d'état séparé : l'état est
// DÉRIVÉ des événements déjà audités, authentifiés (AEAD) et ancrés dans le log signé.
//
//   - Ce qui ACCORDE un droit — une approbation — n'est restauré que si inLog(rec) est vrai : la feuille est dans le
//     log signé (registry.VerifyRecordsInLog). Un enregistrement journal forgé avec la clé mais jamais inscrit ne
//     rouvre donc rien.
//   - Ce qui RETIRE ou ne grant rien (refus, consommation, mise en file) s'applique dès que le hash correspond : une
//     consommation dont la feuille n'a pas atteint le checkpoint avant l'arrêt ne doit PAS ressusciter l'approbation.
//   - Les entrées échues sont écartées ; la file reste bornée (MaxEntries).
//
// À appeler au démarrage, avant de servir. Les battements de présence ne sont pas restaurés : un arbitre se
// manifeste de nouveau (joignabilité prouvée, jamais présumée).
func (q *Queue) Restore(recs []registry.SealedRecord, inLog func(registry.SealedRecord) bool) RestoreStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	var st RestoreStats
	for _, r := range recs {
		if r.Leaf.Kind != registry.KindTelemetry || r.Leaf.CellID != q.cellID || !bytes.HasPrefix(r.Record, []byte("TBAR2")) {
			continue
		}
		if !bytes.Equal(r.Salt, q.salt) || r.VerifyHash() != nil {
			st.Skipped++
			continue
		}
		act, id, ticket, subject, kid, _, expiry, ok := parseLeafRecord(r.Record)
		if !ok {
			st.Skipped++
			continue
		}
		switch act {
		case actEnqueue:
			if expiry.IsZero() || len(q.entries) >= q.max {
				st.Skipped++
				continue
			}
			if _, exists := q.entries[id]; !exists {
				q.entries[id] = &entry{ticket: ticket, subject: subject, created: time.Unix(0, r.Leaf.Timestamp), expires: expiry, status: statusPending}
			}
		case actApprove:
			e, exists := q.entries[id]
			// le ticket de la décision est celui de la mise en file VIVANTE : l'approbation d'une mise en file
			// antérieure (déjà consommée) n'approuve pas la suivante
			if !exists || e.status != statusPending || e.ticket != ticket || inLog == nil || !inLog(r) {
				st.Skipped++
				continue
			}
			e.status, e.expires, e.by = statusApproved, expiry, kid
		case actRefuse:
			if e, exists := q.entries[id]; exists && e.status == statusPending && e.ticket == ticket {
				e.status, e.expires, e.by = statusRefused, expiry, kid
			} else {
				st.Skipped++
			}
		case actConsume, actConsumeRefused:
			// une consommation ne retire que la mise en file qu'elle a consommée (même ticket)
			if e, exists := q.entries[id]; exists && e.ticket == ticket {
				delete(q.entries, id)
			}
		default:
			st.Skipped++
		}
	}
	q.pruneLocked(q.now())
	for _, e := range q.entries {
		switch e.status {
		case statusPending:
			st.Pending++
		case statusApproved:
			st.Approved++
		case statusRefused:
			st.Refused++
		}
	}
	return st
}

// parseLeafRecord décode un enregistrement « TBAR1 » (voir leafLocked) ; strict sur la longueur.
func parseLeafRecord(rec []byte) (act byte, id [32]byte, ticket Ticket, subject string, kid [16]byte, verdict byte, expiry time.Time, ok bool) {
	const head = 5 + 1 + 32 + 16 + 1
	if len(rec) < head {
		return
	}
	act = rec[5]
	copy(id[:], rec[6:38])
	copy(ticket[:], rec[38:54])
	sl := int(rec[54])
	if len(rec) != head+sl+16+1+8 {
		return
	}
	subject = string(rec[head : head+sl])
	copy(kid[:], rec[head+sl:])
	verdict = rec[head+sl+16]
	if exp := binary.BigEndian.Uint64(rec[head+sl+17:]); exp != 0 {
		expiry = time.Unix(int64(exp), 0)
	}
	ok = true
	return
}
