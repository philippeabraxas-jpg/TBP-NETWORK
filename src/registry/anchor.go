// src/registry/anchor.go — T6 (issue #6)
//
// Ancrage master chain (§6, §6.2) — chemin « tiède », JAMAIS dans le
// chemin chaud de décision :
//
//   - périodiquement, la tête de la chaîne de cellule est horodatée par
//     un TSA RFC 3161 (≥ 2 via FallbackTSA) puis hash(broker_id, tête,
//     TSA) est inscrit comme feuille KindAnchor dans la master chain ;
//   - master chain injoignable : store-and-forward BORNÉ (MaxBacklog) —
//     le rattrapage reste strictement dans la profondeur du dernier
//     ancrage vérifié, aucune réécriture de fork au-delà n'est possible
//     par construction ;
//   - contrôle de lag : Check() refuse les nouveaux jetons d'époque quand
//     le dernier ancrage vérifié dépasse MaxAnchorLag (défaut 120 s) —
//     l'inondation produit un déni de service alarmé, jamais une fenêtre
//     d'impunité (§6.2).
//
// « Vérifié » = la feuille KindAnchor est intégrée à la master chain
// (checkpoint signé, await Tessera) ET le jeton TSA est lié à la requête
// (empreinte + nonce, voir tsa.go).
//
// Coutures : OnTrip → module fail-closed unique T14 (refus des jetons) ;
// OnAlarm → bus d'alarme class-W §5.3. Le temps vient d'une horloge
// disciplinée NTS (RFC 8915, dérive < 5 ms — §6.2) ; Clock est la couture
// d'injection, T13 contrôle l'état de l'horloge.
package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// MaxAnchorLag est la borne §6.2 : au-delà, tout nouveau jeton
	// d'époque est refusé (fail-closed).
	MaxAnchorLag = 120 * time.Second
	// DefaultAnchorInterval est la cadence d'ancrage par défaut — 4×
	// sous la borne pour absorber les ratés isolés sans friction.
	DefaultAnchorInterval = 30 * time.Second
	// DefaultMaxBacklog borne le store-and-forward : à 30 s d'intervalle,
	// 64 entrées ≈ 32 min d'indisponibilité master avant alarme — très
	// au-delà du lag de 120 s qui refuse déjà les jetons.
	DefaultMaxBacklog = 64
	// maxTSFutureSkew est le futur toléré d'un genTime TSA. Un TSA qui
	// date dans le futur au-delà de la dérive NTS admise (§6.2 : < 5 ms,
	// ici 10 s de marge) est défaillant : le jeton est rejeté — sinon un
	// genTime futur gonflerait artificiellement la fenêtre de fraîcheur.
	maxTSFutureSkew = 10 * time.Second
	// anchorSaltLen : sel des feuilles KindAnchor (reste chez le
	// superviseur, jamais dans la master chain — hash-only §6.2).
	anchorSaltLen = 16
)

var (
	// ErrAnchorStale : le dernier ancrage vérifié dépasse MaxAnchorLag.
	ErrAnchorStale = errors.New("registre : ancrage trop ancien (> borne §6.2) — refus des nouveaux jetons (fail-closed)")
	// ErrAnchorNeverAnchored : aucun ancrage vérifié depuis le démarrage —
	// default-deny §1, aucun jeton avant la première preuve externe.
	ErrAnchorNeverAnchored = errors.New("registre : aucun ancrage vérifié — refus des nouveaux jetons (fail-closed)")
	// ErrAnchorerClosed : ancreur arrêté.
	ErrAnchorerClosed = errors.New("registre : ancreur arrêté")
)

// Raisons d'alarme (champ AnchorAlarm.Reason).
const (
	AnchorReasonNever           = "anchor-never-verified"
	AnchorReasonLag             = "anchor-lag"
	AnchorReasonBacklogOverflow = "anchor-backlog-overflow"
	AnchorReasonTSAFuture       = "anchor-tsa-future"
	AnchorReasonRecovered       = "anchor-recovered"
)

// MasterChain est la couture vers la master chain (Tessera côté
// superviseur — §7.1 : « même mécanique, même doctrine »). *CellLog
// l'implémente.
type MasterChain interface {
	Append(ctx context.Context, leaf Leaf) (uint64, error)
}

// AnchorRecord est le contenu ancré : hash(broker_id, tête, TSA) — §6.
type AnchorRecord struct {
	BrokerID  string    // identité du broker de la cellule
	CellID    string    // cellule ancrée
	HeadRoot  [32]byte  // racine Merkle de la chaîne de cellule
	HeadSize  uint64    // taille du log à l'ancrage
	TSATime   time.Time // genTime du jeton RFC 3161 (temps externe)
	TokenHash [32]byte  // sha256 du ContentInfo CMS — la preuve reste hors chaîne
}

// Marshal sérialise l'enregistrement en forme canonique déterministe
// (§11.3) : magie, chaînes préfixées u16-BE, champs fixes big-endian.
func (r AnchorRecord) Marshal() []byte {
	buf := make([]byte, 0, 5+2+len(r.BrokerID)+2+len(r.CellID)+32+8+8+32)
	buf = append(buf, 'T', 'B', 'P', 'A', '1')
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.BrokerID)))
	buf = append(buf, r.BrokerID...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.CellID)))
	buf = append(buf, r.CellID...)
	buf = append(buf, r.HeadRoot[:]...)
	buf = binary.BigEndian.AppendUint64(buf, r.HeadSize)
	buf = binary.BigEndian.AppendUint64(buf, uint64(r.TSATime.UTC().UnixNano()))
	buf = append(buf, r.TokenHash[:]...)
	return buf
}

// AnchorSnapshot est le dernier ancrage vérifié — ce que le jeton
// d'époque emporte (§7.2 : le jeton porte le hash du dernier ancrage).
type AnchorSnapshot struct {
	Hash        [32]byte  // hash salé de l'enregistrement (= PayloadHash de la feuille maîtresse)
	At          time.Time // genTime TSA de l'ancrage
	MasterIndex uint64    // index de la feuille KindAnchor dans la master chain
}

// AnchorAlarm est l'événement vers les coutures T14 (OnTrip) et class-W
// §5.3 (OnAlarm).
type AnchorAlarm struct {
	Reason  string // AnchorReason*
	CellID  string
	Lag     time.Duration // renseigné pour AnchorReasonLag
	Backlog int           // profondeur du backlog au moment de l'alarme
	At      time.Time
}

// AnchorerOptions paramètre un Anchorer.
type AnchorerOptions struct {
	BrokerID string
	CellID   string
	// Cell est la chaîne de la cellule (source des têtes ancrées).
	Cell *CellLog
	// Master est la master chain (destination des feuilles KindAnchor).
	Master MasterChain
	// TSA est le client d'horodatage — FallbackTSA de ≥ 2 TSA en
	// production (§6.2).
	TSA TSAClient
	// Interval : cadence d'ancrage (défaut 30 s). Doit être < MaxLag.
	Interval time.Duration
	// MaxLag : borne de fraîcheur (défaut 120 s, §6.2).
	MaxLag time.Duration
	// MaxBacklog : borne du store-and-forward (défaut 64).
	MaxBacklog int
	// Clock : horloge NTS (défaut time.Now) — couture de test et de
	// contrôle d'état (T13).
	Clock func() time.Time
	// OnTrip : couture T14 — appelée UNE fois par épisode de franchissement
	// (premier Check() qui détecte le dépassement).
	OnTrip func(AnchorAlarm)
	// OnAlarm : couture bus d'alarme §5.3 — franchissements, débordements
	// de backlog, TSA datant dans le futur, reprises.
	OnAlarm func(AnchorAlarm)
}

// Anchorer inscrit périodiquement les têtes de la cellule dans la master
// chain et contrôle la fraîcheur du dernier ancrage vérifié.
type Anchorer struct {
	brokerID   string
	cellID     string
	cell       *CellLog
	master     MasterChain
	tsa        TSAClient
	interval   time.Duration
	maxLag     time.Duration
	maxBacklog int
	clock      func() time.Time
	onTrip     func(AnchorAlarm)
	onAlarm    func(AnchorAlarm)
	salt       []byte

	last    atomic.Value // AnchorSnapshot
	tripped atomic.Bool
	closed  atomic.Bool

	anchorMu        sync.Mutex // sérialise AnchorOnce (Run + appels externes)
	backlogMu       sync.Mutex
	backlog         []AnchorRecord
	overflowAlarmed bool // alarme de débordement émise pour l'épisode courant
}

// NewAnchorer valide les options et construit l'ancreur.
func NewAnchorer(opts AnchorerOptions) (*Anchorer, error) {
	if opts.BrokerID == "" || opts.CellID == "" {
		return nil, errors.New("ancreur : BrokerID et CellID requis")
	}
	if opts.Cell == nil || opts.Master == nil || opts.TSA == nil {
		return nil, errors.New("ancreur : Cell, Master et TSA requis")
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultAnchorInterval
	}
	maxLag := opts.MaxLag
	if maxLag == 0 {
		maxLag = MaxAnchorLag
	}
	if interval >= maxLag {
		return nil, fmt.Errorf("ancreur : Interval %s ≥ MaxLag %s — un seul raté déclencherait le refus", interval, maxLag)
	}
	maxBacklog := opts.MaxBacklog
	if maxBacklog == 0 {
		maxBacklog = DefaultMaxBacklog
	}
	if maxBacklog < 1 {
		return nil, fmt.Errorf("ancreur : MaxBacklog %d invalide", maxBacklog)
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	salt := make([]byte, anchorSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("ancreur : tirage du sel: %w", err)
	}
	return &Anchorer{
		brokerID:   opts.BrokerID,
		cellID:     opts.CellID,
		cell:       opts.Cell,
		master:     opts.Master,
		tsa:        opts.TSA,
		interval:   interval,
		maxLag:     maxLag,
		maxBacklog: maxBacklog,
		clock:      clock,
		onTrip:     opts.OnTrip,
		onAlarm:    opts.OnAlarm,
		salt:       salt,
	}, nil
}

// Run boucle jusqu'à annulation du contexte : un ancrage par intervalle.
// Les erreurs unitaires (TSA, master) ne tuent pas la boucle — elles se
// traduisent en lag, et le lag en refus : c'est Check() qui tranche.
func (a *Anchorer) Run(ctx context.Context) error {
	if a.closed.Load() {
		return ErrAnchorerClosed
	}
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = a.AnchorOnce(ctx)
		}
	}
}

// Close arrête l'ancreur (idempotent). Le dernier ancrage vérifié reste
// consultable ; Check() continue de refuser quand le lag dépasse la borne.
func (a *Anchorer) Close() { a.closed.Store(true) }

// AnchorOnce exécute un cycle : vidange du backlog (rattrapage borné,
// plus ancien d'abord), puis horodatage TSA de la tête courante et
// inscription dans la master chain. Exposé pour l'ancrage forcé
// (superviseur) et les tests.
func (a *Anchorer) AnchorOnce(ctx context.Context) error {
	if a.closed.Load() {
		return ErrAnchorerClosed
	}
	a.anchorMu.Lock()
	defer a.anchorMu.Unlock()

	// 1. Rattrapage : le backlog porte déjà ses genTime TSA — la
	//    continuité depuis le dernier ancrage vérifié prime sur la
	//    nouveauté.
	a.flushBacklog(ctx)

	// 2. Tête courante de la cellule.
	root, size, err := a.cell.Head(ctx)
	if err != nil {
		return fmt.Errorf("ancreur : lecture de tête: %w", err)
	}

	// 3. Horodatage externe (RFC 3161, fallback entre TSA).
	digest := sha256.Sum256(append(root[:], binary.BigEndian.AppendUint64(nil, size)...))
	stamp, err := a.tsa.Timestamp(ctx, digest)
	if err != nil {
		return fmt.Errorf("ancreur : %w", err)
	}
	// Un genTime trop dans le futur gonflerait la fenêtre de fraîcheur :
	// rejet fail-closed (dérive NTS admise §6.2 ≪ maxTSFutureSkew).
	if stamp.GenTime.After(a.clock().Add(maxTSFutureSkew)) {
		a.fireAlarm(AnchorAlarm{Reason: AnchorReasonTSAFuture, CellID: a.cellID, At: a.clock()})
		return fmt.Errorf("ancreur : genTime TSA %s dans le futur — jeton rejeté", stamp.GenTime)
	}

	rec := AnchorRecord{
		BrokerID:  a.brokerID,
		CellID:    a.cellID,
		HeadRoot:  root,
		HeadSize:  size,
		TSATime:   stamp.GenTime,
		TokenHash: sha256.Sum256(stamp.Token),
	}

	// 4. Inscription master chain ; store-and-forward si injoignable.
	if _, err := a.appendAnchor(ctx, rec); err != nil {
		a.pushBacklog(rec)
		return err
	}
	return nil
}

// appendAnchor inscrit la feuille KindAnchor dans la master chain et, en
// cas de succès, met à jour le dernier ancrage vérifié.
func (a *Anchorer) appendAnchor(ctx context.Context, rec AnchorRecord) (uint64, error) {
	leaf := Leaf{
		Kind:        KindAnchor,
		CellID:      a.cellID,
		PayloadHash: HashPayload(a.salt, rec.Marshal()),
		Timestamp:   rec.TSATime.UnixNano(),
	}
	idx, err := a.master.Append(ctx, leaf)
	if err != nil {
		return 0, fmt.Errorf("ancreur : master chain: %w", err)
	}
	a.updateLast(rec, idx, leaf.PayloadHash)
	return idx, nil
}

// updateLast n'avance que monotone : un ancrage plus ancien que le
// dernier vérifié (rattrapage de backlog) ne fait jamais reculer la
// fraîcheur. La reprise après dépassement est automatique et propre :
// l'ancrage vérifié EST la preuve que la fenêtre est refermée (§6.2).
func (a *Anchorer) updateLast(rec AnchorRecord, idx uint64, hash [32]byte) {
	if prev, ok := a.last.Load().(AnchorSnapshot); ok && !rec.TSATime.After(prev.At) {
		return
	}
	a.last.Store(AnchorSnapshot{Hash: hash, At: rec.TSATime, MasterIndex: idx})
	if a.tripped.CompareAndSwap(true, false) {
		a.fireAlarm(AnchorAlarm{Reason: AnchorReasonRecovered, CellID: a.cellID, At: a.clock()})
	}
}

// pushBacklog empile un enregistrement pour store-and-forward borné. Au-
// delà de MaxBacklog : l'entrée la plus RÉCENTE est sacrifiée (la
// continuité depuis le dernier ancrage vérifié est protégée), l'alarme
// part — inondation = DoS alarmé, jamais silencieux (§6.2).
func (a *Anchorer) pushBacklog(rec AnchorRecord) {
	a.backlogMu.Lock()
	overflow := len(a.backlog) >= a.maxBacklog
	alarm := overflow && !a.overflowAlarmed
	if alarm {
		a.overflowAlarmed = true
	}
	if !overflow {
		a.backlog = append(a.backlog, rec)
	}
	depth := len(a.backlog)
	a.backlogMu.Unlock()
	if alarm {
		// Callback HORS du verrou : un OnAlarm qui rappellerait
		// BacklogDepth() ne doit pas pouvoir se mordre la queue.
		a.fireAlarm(AnchorAlarm{Reason: AnchorReasonBacklogOverflow, CellID: a.cellID, Backlog: depth, At: a.clock()})
	}
}

// flushBacklog rejoue le backlog du plus ancien au plus récent, en
// s'arrêtant au premier échec (l'ordre est la preuve de continuité).
// Le verrou n'est jamais tenu pendant appendAnchor : les callbacks de
// mise à jour (reprise, alarmes) restent libres de rappeler l'ancreur.
func (a *Anchorer) flushBacklog(ctx context.Context) {
	for {
		a.backlogMu.Lock()
		if len(a.backlog) == 0 {
			a.backlogMu.Unlock()
			return
		}
		rec := a.backlog[0]
		a.backlogMu.Unlock()

		if _, err := a.appendAnchor(ctx, rec); err != nil {
			return // la master chain est encore injoignable — on réessaiera
		}

		a.backlogMu.Lock()
		// pushBacklog ne peut pas tourner concurremment (anchorMu
		// sérialise AnchorOnce) : la tête est bien le rec qu'on vient
		// d'inscrire.
		a.backlog = a.backlog[1:]
		if len(a.backlog) < a.maxBacklog {
			a.overflowAlarmed = false
		}
		a.backlogMu.Unlock()
	}
}

// Check est le contrôle de lag §6.2 — appelé à l'émission de chaque jeton
// d'époque (couture T14). O(1), sans I/O, sûr en concurrence. Au-delà de
// MaxLag : trip (une alarme par épisode) + ErrAnchorStale ; avant tout
// ancrage : ErrAnchorNeverAnchored (default-deny §1).
func (a *Anchorer) Check() error {
	snap, ok := a.last.Load().(AnchorSnapshot)
	if !ok {
		a.fireTrip(AnchorAlarm{Reason: AnchorReasonNever, CellID: a.cellID, At: a.clock()})
		return ErrAnchorNeverAnchored
	}
	lag := a.clock().Sub(snap.At)
	if lag < 0 {
		lag = 0 // genTime légèrement en avant (dérive < maxTSFutureSkew admise)
	}
	if lag > a.maxLag {
		a.fireTrip(AnchorAlarm{Reason: AnchorReasonLag, CellID: a.cellID, Lag: lag, At: a.clock()})
		return ErrAnchorStale
	}
	return nil
}

// Snapshot retourne le dernier ancrage vérifié — le hash que le jeton
// d'époque emporte (§7.2).
func (a *Anchorer) Snapshot() (AnchorSnapshot, bool) {
	snap, ok := a.last.Load().(AnchorSnapshot)
	return snap, ok
}

// BacklogDepth expose la profondeur courante du store-and-forward
// (observabilité, tests).
func (a *Anchorer) BacklogDepth() int {
	a.backlogMu.Lock()
	defer a.backlogMu.Unlock()
	return len(a.backlog)
}

// fireTrip n'émet qu'une fois par épisode de dépassement : le refus est
// permanent tant que le lag dépasse, mais l'alarme n'est pas répétée à
// chaque Check (sinon le bus d'alarme devient le vecteur de DoS).
func (a *Anchorer) fireTrip(alarm AnchorAlarm) {
	if a.tripped.CompareAndSwap(false, true) {
		if a.onTrip != nil {
			a.onTrip(alarm)
		}
		a.fireAlarm(alarm)
	}
}

func (a *Anchorer) fireAlarm(alarm AnchorAlarm) {
	if a.onAlarm != nil {
		a.onAlarm(alarm)
	}
}
