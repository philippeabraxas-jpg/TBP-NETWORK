package pep

// Compteur de quota passeport data-plane (T12, §4.1-bis + §5.3).
//
// Toute ouverture de chemin lourd (session, tunnel, règle SDN) naît comme
// PASSEPORT À QUOTA : vecteur (resource, operation, volume_max, window_s)
// signé dans le jeton (T8), TTL = exp du jeton. Ce fichier est le COMPTEUR
// AU MOMENT DE L'EXÉCUTION (côté PEP/terminator) : il décrémente le volume
// consommé à chaque quantum de flux. Doctrine §5.3 : « prevent what is
// cheap, detect what is expensive — chaque porte ouverte naît avec son
// compteur et son instrument ».
//
// Sémantique du vecteur : volume_max PAR fenêtre de window_s secondes (le
// quota est un débit, pas un capital — la fenêtre écoulée recharge le
// volume) ; le TTL du passeport reste l'échéance absolue.
//
// Dépassement ou expiration ⇒ COUPURE PROPRE : le compteur se ferme
// (coupure nette, pas de dégradation, plus aucun quantum ne passe — le
// quantum refusé n'est JAMAIS prélevé partiellement), le terminator est
// notifié (OnCut : la session est terminée proprement), le refus est
// explicite (ErrQuotaExceeded / ErrPassportExpired) et une feuille deny
// portant le jti part au registre de la cellule (§4.1-bis).
//
// État borné en mémoire (§4.3, même pattern que T10) : le registre plafonne
// le nombre de compteurs vivants à MaxPassports — paramètre nommé,
// dimensionné au nombre max de sessions concurrentes × TTL. Saturation =
// refus fail-closed + alarme latchée (couture T14), jamais d'éviction d'un
// compteur vivant.
//
// Hors périmètre (anticipé par l'interface) : l'enveloppe d'égress À
// L'ÉMISSION — quota agrégé par entité/epoch évalué par OPA — est côté
// broker. Le compteur expose Resource/Operation/VolumeMax/WindowS pour
// permettre cette agrégation sans re-lecture du jeton.

import (
	"context"
	"errors"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Verdicts de coupure data-plane (feuilles deny du compteur). Distincts de
// ReasonQuotaExhausted (T9, contrôle à l'admission) : ici c'est l'exécution
// qui coupe.
const (
	ReasonQuotaExceeded   = "quota-exceeded"
	ReasonPassportExpired = "passport-expired"
)

// TripReasonQuotaSaturated est la raison d'alarme OnTrip quand le registre
// de compteurs est plein (couture T14).
const TripReasonQuotaSaturated = "quota-ledger-saturated"

// Erreurs de refus explicites du data-plane et du registre.
var (
	ErrQuotaExceeded      = errors.New("pep: quota du passeport dépassé (§4.1-bis : coupure propre + refus + feuille)")
	ErrPassportExpired    = errors.New("pep: passeport expiré (§4.1-bis : coupure sans décrémenter)")
	ErrPassportClosed     = errors.New("pep: compteur fermé — passeport déjà coupé (aucune fuite après coupure)")
	ErrPassportDuplicate  = errors.New("pep: compteur déjà ouvert pour ce jti (§4.1 : jti unique)")
	ErrLedgerSaturated    = errors.New("pep: registre de compteurs saturé (§4.3 : borné en mémoire — refus fail-closed)")
	ErrQuotaVectorMissing = errors.New("pep: passeport sans vecteur quota (§4.1-bis : quota-unverified)")
	ErrQuotaVectorInvalid = errors.New("pep: vecteur quota invalide (window_s > 0 requis)")
)

// PassportCounter est le compteur d'UN passeport — état data-plane léger,
// borné par le TTL, un terminator par session. Sûr pour un usage
// concurrent ; sans allocation après ouverture.
type PassportCounter struct {
	jti        [16]byte
	resource   string
	operation  string
	volumeMax  uint64
	windowS    uint64
	windowFrom int64 // début de la fenêtre courante (unix s)
	remaining  uint64
	exp        int64 // TTL du passeport (unix s)

	now  func() time.Time
	cut  func(jti [16]byte, reason string) // terminator : coupure de session
	leaf func(jti [16]byte, reason string) // registre : feuille deny

	mu     sync.Mutex
	closed bool
}

// Consume prélève un quantum de flux. Appelé par le terminator sur chaque
// quantum. nil = accepté ; ErrQuotaExceeded / ErrPassportExpired = coupure
// propre + feuille ; ErrPassportClosed = toute consommation après coupure
// (aucune fuite). Un quantum qui dépasse n'est JAMAIS prélevé partiellement.
func (c *PassportCounter) Consume(n uint64) error {
	now := c.now().Unix()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrPassportClosed
	}
	// TTL écoulé : coupure SANS décrémenter (l'expiration n'est pas une
	// consommation).
	if now > c.exp {
		c.cutLocked(ReasonPassportExpired)
		return ErrPassportExpired
	}
	// Fenêtre écoulée : le volume se recharge (quota = débit par fenêtre).
	if now >= c.windowFrom+int64(c.windowS) {
		c.windowFrom = now
		c.remaining = c.volumeMax
	}
	if n > c.remaining {
		// Dépassement : coupure nette — le quantum refusé n'est pas prélevé.
		c.cutLocked(ReasonQuotaExceeded)
		return ErrQuotaExceeded
	}
	c.remaining -= n
	return nil
}

// cutLocked ferme le compteur, trace la feuille deny et notifie le
// terminator. Feuille d'abord : la coupure ne doit jamais précéder sa
// preuve (§4.1).
func (c *PassportCounter) cutLocked(reason string) {
	c.closed = true
	if c.leaf != nil {
		c.leaf(c.jti, reason)
	}
	if c.cut != nil {
		c.cut(c.jti, reason)
	}
}

// JTI rapporte l'identifiant du passeport (clé des feuilles et de la
// couture QuotaChecker T9).
func (c *PassportCounter) JTI() [16]byte { return c.jti }

// Remaining rapporte le volume restant dans la fenêtre courante.
func (c *PassportCounter) Remaining() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remaining
}

// Closed rapporte si le compteur a été coupé (dépassement ou expiration).
func (c *PassportCounter) Closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// Vector expose le vecteur quota signé — l'enveloppe d'égress du broker
// (agrégation par resource/operation, hors périmètre T12) le lit sans
// re-décoder le jeton.
func (c *PassportCounter) Vector() (resource, operation string, volumeMax, windowS uint64) {
	return c.resource, c.operation, c.volumeMax, c.windowS
}

// QuotaLedgerOptions paramètre le registre de compteurs. Fail-closed dès
// la configuration.
type QuotaLedgerOptions struct {
	// MaxPassports borne le nombre de compteurs vivants (§4.3, pattern
	// T10) — dimensionné au nombre max de sessions concurrentes × TTL.
	// Paramètre nommé, jamais de croissance.
	MaxPassports int
	// CellID identifie la cellule dans les feuilles de coupure. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : toute coupure laisse une
	// feuille deny portant le jti. Requis.
	Leaves LeafSink
	// OnCut est le point d'insertion du terminator : appelé à chaque
	// coupure pour terminer la session proprement. Nil ⇒ pas de callback
	// (le refus reste fail-closed).
	OnCut func(jti [16]byte, reason string)
	// OnTrip est la couture d'alarme vers T14 : saturation du registre
	// (latchée, une seule fois) ou feuille impossible. Nil ⇒ pas d'alarme.
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// QuotaLedger est le registre borné des compteurs de passeports vivants.
// Il implémente la couture QuotaChecker du validateur (T9). Sûr pour un
// usage concurrent.
type QuotaLedger struct {
	max      int
	counters map[[16]byte]*PassportCounter

	cellID string
	salt   []byte
	leaves LeafSink
	onCut  func(jti [16]byte, reason string)
	onTrip func(reason string)
	now    func() time.Time

	mu      sync.Mutex
	tripped bool // latch saturation (T14), comme T10
}

// compile-time : *QuotaLedger satisfait la couture QuotaChecker (T9).
var _ QuotaChecker = (*QuotaLedger)(nil)

// NewQuotaLedger construit le registre. Fail-closed : capacité > 0,
// cellID, sel ≥ 16 o et couture feuilles requis.
func NewQuotaLedger(opts QuotaLedgerOptions) (*QuotaLedger, error) {
	if opts.MaxPassports <= 0 {
		return nil, errors.New("pep: capacité du registre de quotas > 0 requise (§4.3 : borné en mémoire)")
	}
	if opts.CellID == "" {
		return nil, errors.New("pep: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: couture feuilles requise (§4.1-bis : coupure tracée)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &QuotaLedger{
		max:      opts.MaxPassports,
		counters: make(map[[16]byte]*PassportCounter, opts.MaxPassports),
		cellID:   opts.CellID,
		salt:     salt,
		leaves:   opts.Leaves,
		onCut:    opts.OnCut,
		onTrip:   opts.OnTrip,
		now:      now,
	}, nil
}

// Open naît le compteur d'un passeport validé (T9) : le jeton doit porter
// un vecteur quota sain. Fail-closed : sans vecteur ⇒ quota-unverified ;
// jti déjà compté ⇒ refus ; registre plein ⇒ refus + alarme latchée.
func (l *QuotaLedger) Open(tok *Token) (*PassportCounter, error) {
	if tok == nil || tok.Quota == nil {
		return nil, ErrQuotaVectorMissing
	}
	q := tok.Quota
	if q.WindowS == 0 {
		return nil, ErrQuotaVectorInvalid
	}
	now := l.now().Unix()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.purgeLocked(now)

	if _, dup := l.counters[tok.JTI]; dup {
		return nil, ErrPassportDuplicate
	}
	if len(l.counters) == l.max {
		l.tripLocked()
		return nil, ErrLedgerSaturated
	}

	c := &PassportCounter{
		jti:        tok.JTI,
		resource:   q.Resource,
		operation:  q.Operation,
		volumeMax:  q.VolumeMax,
		windowS:    q.WindowS,
		windowFrom: now,
		remaining:  q.VolumeMax,
		exp:        tok.Exp,
		now:        l.now,
		cut:        l.onCut,
		leaf:       l.writeCutLeaf,
	}
	l.counters[tok.JTI] = c
	return c, nil
}

// Exhausted répond à la couture QuotaChecker (T9) : true si le passeport a
// été coupé (dépassement ou expiration). Un jti inconnu n'est pas épuisé —
// le contrôle d'admission laisse passer, l'exécution comptera.
func (l *QuotaLedger) Exhausted(jti [16]byte) bool {
	l.mu.Lock()
	c, ok := l.counters[jti]
	l.mu.Unlock()
	if !ok {
		return false
	}
	return c.Closed()
}

// Len rapporte le nombre de compteurs vivants (coupés ou non, non purgés).
func (l *QuotaLedger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.counters)
}

// purgeLocked supprime les compteurs dont le TTL est écoulé — coupés ou
// non : un passeport expiré est mort de toute façon (le validateur refuse
// les jetons périmés en amont).
func (l *QuotaLedger) purgeLocked(now int64) {
	for jti, c := range l.counters {
		if now > c.exp {
			delete(l.counters, jti)
		}
	}
}

// tripLocked enclenche l'alarme de saturation — latchée (T14) : une fois.
func (l *QuotaLedger) tripLocked() {
	if l.tripped {
		return
	}
	l.tripped = true
	if l.onTrip != nil {
		l.onTrip(TripReasonQuotaSaturated)
	}
}

// writeCutLeaf inscrit la feuille deny d'une coupure (§4.1-bis + §6.2 :
// hash-only, le sel reste chez le producteur). L'échec est alarmé (T14) —
// la coupure, elle, a déjà fail-closed.
func (l *QuotaLedger) writeCutLeaf(jti [16]byte, reason string) {
	leaf := registry.Leaf{
		Kind:        registry.KindDecision,
		CellID:      l.cellID,
		PayloadHash: registry.HashPayload(l.salt, decisionLeafRecord(jti, false, reason)),
		Timestamp:   l.now().UnixNano(),
	}
	// Consume ne porte pas de contexte (chemin data-plane) : l'append
	// hérite du contexte d'arrière-plan, comme le fait le terminator.
	if _, err := l.leaves.Append(context.Background(), leaf); err != nil && l.onTrip != nil {
		l.onTrip(ReasonLeafWriteFailed)
	}
}
