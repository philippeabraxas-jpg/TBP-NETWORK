// src/registry/async_writer.go — T38 (issue #71)
//
// Modèle de durabilité « async borné » du chemin de décision chaud — arbitrage
// de l'issue #71 : le chemin synchrone (Append) paie le plancher STRUCTUREL
// du driver POSIX (~100 ms de checkpoint + ~50 ms de poll ≈ 150 ms mesurés
// par le spike T27, 30–50× le budget de friction §9.1) ; un backend tessera
// non-POSIX à checkpoint sub-100 ms n'existe pas dans les dépendances
// actuelles. L'async borné retire l'attente de publication du chemin de
// verdict SANS abandonner la doctrine T9 :
//
//   - le verdict n'est rendu qu'à l'ACCEPTATION de la feuille par le batcher
//     (sérialisée, comptée, en file FIFO — jamais du fire-and-forget) ;
//   - un tracker unique confirme les publications DANS L'ORDRE (tessera
//     intègre en séquence) ;
//   - FENÊTRE D'OPPOSABILITÉ bornée (défaut 1 s) : si la plus vieille feuille
//     non confirmée la dépasse, le writer bascule en COUPURE — Append refuse
//     immédiatement (ErrDurabilityCut) et le validateur T9 transforme tout
//     allow en deny « leaf-write-failed », le chemin de refus existant :
//     pas de preuve à venir, pas d'accès (fail-closed à la coupure) ;
//   - la coupure est ALARMÉE immédiatement (OnTrip — aucune feuille n'est
//     possible tant que la publication est en panne, l'alarme ne peut pas
//     être une feuille) ;
//   - le RATTRAPAGE est TRACÉ : quand la publication reprend et que la file
//     se vide, une feuille KindTelemetry d'épisode (refus comptés, bornes
//     temporelles) est écrite en SYNCHRONE — la preuve arrive à rattrapage,
//     exactement le modèle demandé par l'issue.
//
// Honnêteté du modèle (à lire avant de l'adopter) : en cas de MORT du
// processus pendant la fenêtre, les feuilles acceptées et pas encore
// publiées (≤ fenêtre) sont perdues — les décisions correspondantes ont
// pourtant été rendues. C'est le prix du retrait des ~150 ms du chemin
// chaud ; la fenêtre borne la perte. Le chemin SYNC (CellLog.Append)
// reste disponible pour les écritures administratives (T5, T14, posture,
// quota, horloge) qui paient la preuve avant retour.
//
// Coexistence T5 (backpressure) : le double contrôle Engaged() est repris
// à l'identique, et WaitOutstanding permet au moniteur de drainer les
// feuilles acceptées avant la feuille d'arrêt — KindBackpressure reste
// littéralement la DERNIÈRE feuille du log (testé).
package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/transparency-dev/tessera"
)

// Erreurs du writer async borné — toutes fail-closed : le validateur T9
// les transforme en deny « leaf-write-failed » sur un allow.
var (
	// ErrDurabilityCut : la fenêtre d'opposabilité est dépassée (coupure)
	// — refus immédiat, pas de file d'attente infinie.
	ErrDurabilityCut = errors.New("registre : fenêtre d'opposabilité dépassée — coupure fail-closed")
	// ErrDurabilityBacklog : la file bornée est pleine — refus immédiat.
	ErrDurabilityBacklog = errors.New("registre : file async saturée — écriture refusée (fail-closed)")
	// ErrAsyncClosed : le writer est fermé (arrêt du démon).
	ErrAsyncClosed = errors.New("registre : AsyncWriter fermé")
)

const (
	// DefaultOpposabilityWindow est la fenêtre d'opposabilité par défaut :
	// 1 s = 10× le checkpoint POSIX minimal + poll — absorbe la gigue
	// normale, borne la perte en cas de mort du processus.
	DefaultOpposabilityWindow = time.Second
	// DefaultAsyncQueueCapacity borne la file des feuilles acceptées non
	// confirmées (large : la fenêtre TEMPS est la borne doctrinale, la
	// capacité n'est qu'un garde-fou mémoire).
	DefaultAsyncQueueCapacity = 8192
)

// AsyncOptions paramètre un AsyncWriter. Fail-closed dès la configuration.
type AsyncOptions struct {
	// CellID identifie la cellule dans la feuille de rattrapage. Requis.
	CellID string
	// Salt est le sel de la feuille de rattrapage (§6.2, ≥ 16 octets) —
	// il ne quitte JAMAIS la cellule. Requis.
	Salt []byte
	// Window est la fenêtre d'opposabilité : au-delà, coupure fail-closed.
	// Zéro = DefaultOpposabilityWindow. Plancher : 4× l'intervalle de
	// checkpoint du log sous-jacent (en dessous, la gigue normale de
	// publication déclencherait des coupures parasites — refusé à la
	// construction).
	Window time.Duration
	// QueueCapacity borne la file (garde-fou mémoire). Zéro = défaut.
	QueueCapacity int
	// OnTrip est appelé à la coupure, IMMÉDIATEMENT, avec le diagnostic —
	// la feuille étant impossible (publication en panne), c'est le seul
	// signal en temps réel. Ne doit pas bloquer.
	OnTrip func(detail string)
	// OnClear est appelé après rattrapage complet et écriture de la
	// feuille d'épisode. Optionnel.
	OnClear func()
	// Now est l'horloge (tests). Nil ⇒ time.Now.
	Now func() time.Time
}

// AsyncStats est un instantané des compteurs du writer (observabilité,
// forensique — feuilles d'épisode).
type AsyncStats struct {
	Accepted       uint64 // feuilles acceptées par le batcher
	Confirmed      uint64 // feuilles confirmées publiées par le tracker
	RefusedAtCut   uint64 // refus pendant coupure (ErrDurabilityCut)
	RefusedBacklog uint64 // refus par saturation de file (ErrDurabilityBacklog)
	CutEpisodes    uint64 // épisodes de coupure
	Tripped        bool   // coupure en cours
}

// pendingFuture est une feuille acceptée en attente de confirmation.
type pendingFuture struct {
	future   tessera.IndexFuture
	enqueued time.Time
}

// AsyncWriter est un puits de feuilles async borné pour le chemin chaud.
// Il implémente la même couture que *CellLog (Append) — le validateur T9
// n'a pas à savoir quel modèle de durabilité le sert. Sûr pour un usage
// concurrent.
type AsyncWriter struct {
	log      *CellLog
	cellID   string
	salt     []byte
	window   time.Duration
	capacity int
	onTrip   func(detail string)
	onClear  func()
	now      func() time.Time

	// mu protège la file et l'état de coupure. cond signale le tracker
	// (file non vide) et WaitOutstanding (file vide hors rattrapage).
	mu         sync.Mutex
	cond       sync.Cond // initialisé sur mu dans le constructeur
	queue      []pendingFuture
	head       int // indice de tête — la file est queue[head:]
	tripped    bool
	tripAt     time.Time
	refusedCut uint64 // refus de l'épisode courant
	episodes   uint64
	catchup    bool // feuille de rattrapage en cours d'écriture
	stop       bool // plus aucun Append ; le tracker vide puis sort

	closed       chan struct{} // fermé quand le tracker est sorti
	trackerCtx   context.Context
	trackerStop  context.CancelFunc
	tickerStop   chan struct{}
	accepted     uint64
	confirmed    uint64
	refusedBklog uint64
	closeOnce    sync.Once
}

// NewAsyncWriter enveloppe log (ouvert, vivant) d'un writer async borné.
// Le log DOIT rester ouvert au moins jusqu'à Close du writer.
func NewAsyncWriter(log *CellLog, opts AsyncOptions) (*AsyncWriter, error) {
	if log == nil {
		return nil, fmt.Errorf("AsyncWriter: CellLog nil")
	}
	if opts.CellID == "" {
		return nil, fmt.Errorf("AsyncOptions.CellID requis (feuille de rattrapage attribuée)")
	}
	if len(opts.Salt) < 16 {
		return nil, fmt.Errorf("AsyncOptions.Salt ≥ 16 octets requis (§6.2)")
	}
	window := opts.Window
	if window == 0 {
		window = DefaultOpposabilityWindow
	}
	if window < 0 {
		return nil, fmt.Errorf("AsyncOptions.Window négative")
	}
	// Plancher anti-coupures-parasites : la publication normale coûte
	// cpInterval + poll ; en dessous de 4× cpInterval, la gigue déclenche
	// des coupures sans faute réelle — configuration invalide, refusée.
	if floor := 4 * log.cpInterval; window < floor {
		return nil, fmt.Errorf("AsyncOptions.Window %v sous le plancher (4× checkpoint = %v) : coupures parasites garanties", window, floor)
	}
	capacity := opts.QueueCapacity
	if capacity == 0 {
		capacity = DefaultAsyncQueueCapacity
	}
	if capacity < 1 {
		return nil, fmt.Errorf("AsyncOptions.QueueCapacity < 1")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	ctx, cancel := context.WithCancel(context.Background())
	w := &AsyncWriter{
		log:         log,
		cellID:      opts.CellID,
		salt:        salt,
		window:      window,
		capacity:    capacity,
		onTrip:      opts.OnTrip,
		onClear:     opts.OnClear,
		now:         now,
		closed:      make(chan struct{}),
		trackerCtx:  ctx,
		trackerStop: cancel,
		tickerStop:  make(chan struct{}),
	}
	w.cond.L = &w.mu
	go w.tracker()
	go w.cutWatch()
	return w, nil
}

// Append accepte une feuille pour publication asynchrone bornée. Retour
// immédiat (pas d'attente de checkpoint) : l'index n'est pas encore
// opposable — il vaut 0 par honnêteté (seule la publication le fixe).
// Refus IMMÉDIATS, tous fail-closed : backpressure T5 (double contrôle,
// même doctrine que CellLog.Append), coupure (ErrDurabilityCut), file
// pleine (ErrDurabilityBacklog), writer fermé (ErrAsyncClosed).
//
// Invariant d'ordonnancement : l'Add au batcher a lieu SOUS le verrou,
// APRÈS tous les contrôles — un Append refusé n'a AUCUN effet de bord
// (une feuille ajoutée puis « refusée » serait une écriture perdue :
// l'appelant la croit rejetée, le registre la publierait quand même).
func (w *AsyncWriter) Append(ctx context.Context, leaf Leaf) (uint64, error) {
	if bp := w.log.bp; bp != nil && bp.Engaged() {
		return 0, ErrBackpressure
	}
	data, err := encodeLeaf(leaf)
	if err != nil {
		return 0, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stop {
		return 0, ErrAsyncClosed
	}
	if bp := w.log.bp; bp != nil && bp.Engaged() {
		// Le verrou T5 est tombé pendant l'encodage : on refuse plutôt que
		// d'accepter après le drainage du moniteur (doctrine cell_log.go).
		return 0, ErrBackpressure
	}
	if w.tripped {
		w.refusedCut++
		return 0, ErrDurabilityCut
	}
	if len(w.queue)-w.head >= w.capacity {
		w.refusedBklog++
		return 0, ErrDurabilityBacklog
	}
	future := w.log.appender.Add(ctx, tessera.NewEntry(data))
	w.queue = append(w.queue, pendingFuture{future: future, enqueued: w.now()})
	w.accepted++
	w.cond.Signal()
	return 0, nil
}

// cutWatch surveille la fenêtre d'opposabilité : la plus vieille feuille
// non confirmée au-delà de la fenêtre bascule le writer en coupure. La
// file étant FIFO et le temps monotone, queue[head] est toujours la plus
// vieille.
func (w *AsyncWriter) cutWatch() {
	period := w.window / 8
	if period < 20*time.Millisecond {
		period = 20 * time.Millisecond
	}
	if period > 100*time.Millisecond {
		period = 100 * time.Millisecond
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-w.tickerStop:
			return
		case <-ticker.C:
		}
		w.mu.Lock()
		if w.stop || w.tripped || w.head >= len(w.queue) {
			w.mu.Unlock()
			continue
		}
		oldest := w.queue[w.head].enqueued
		if lag := w.now().Sub(oldest); lag > w.window {
			w.tripped = true
			w.tripAt = w.now()
			w.episodes++
			w.refusedCut = 0
			pending := len(w.queue) - w.head
			w.mu.Unlock()
			if w.onTrip != nil {
				w.onTrip(fmt.Sprintf("publication en retard de %v (fenêtre %v, %d feuilles en attente)", lag.Truncate(time.Millisecond), w.window, pending))
			}
			continue
		}
		w.mu.Unlock()
	}
}

// tracker confirme les feuilles DANS L'ORDRE (tessera intègre en séquence)
// et mène la reprise : file vide après une coupure ⇒ feuille d'épisode
// synchrone (rattrapage tracé) puis OnClear.
func (w *AsyncWriter) tracker() {
	defer close(w.closed)
	for {
		w.mu.Lock()
		for w.head >= len(w.queue) {
			if w.stop {
				w.mu.Unlock()
				return
			}
			w.cond.Wait()
		}
		pf := w.queue[w.head]
		w.mu.Unlock()

		// Await avec le contexte du tracker, JAMAIS celui de l'Appendeur :
		// l'appelant peut annuler après acceptation, la feuille acceptée
		// doit tout de même être suivie jusqu'à publication.
		if _, _, err := w.log.await.Await(w.trackerCtx, pf.future); err != nil {
			// Fermeture (contexte annulé) : les feuilles restantes seront
			// publiées par le shutdown tessera — on sort, la traçabilité
			// d'épisode a déjà été alarmée à la coupure.
			return
		}

		w.mu.Lock()
		w.head++
		if w.head == len(w.queue) {
			w.queue = w.queue[:0]
			w.head = 0
		}
		w.confirmed++
		drained := w.head >= len(w.queue)
		recovering := drained && w.tripped
		if recovering {
			w.catchup = true
		}
		w.cond.Broadcast() // WaitOutstanding
		w.mu.Unlock()

		if recovering {
			w.writeCatchup()
		}
	}
}

// writeCatchup écrit la feuille d'épisode de coupure — SYNCHRONE, car la
// publication a repris (la file vient de se vider) : c'est la preuve à
// rattrapage exigée par le modèle. Appelée par le tracker, jamais en
// concurrence avec un autre rattrapage.
func (w *AsyncWriter) writeCatchup() {
	w.mu.Lock()
	episodes, refused, tripAt := w.episodes, w.refusedCut, w.tripAt
	w.tripped = false
	w.mu.Unlock()

	// Backpressure engagé entre-temps : la feuille d'arrêt T5 doit rester
	// la dernière — l'épisode, déjà alarmé à la coupure, n'est pas feuillé.
	if bp := w.log.bp; bp == nil || !bp.Engaged() {
		lag := w.now().Sub(tripAt)
		payload := fmt.Sprintf(
			`{"record":"TBAD1","episode":%d,"refusedAtCut":%d,"cutAt":%q,"recoveredAt":%q,"lagMs":%d}`,
			episodes, refused,
			tripAt.UTC().Format(time.RFC3339Nano),
			w.now().UTC().Format(time.RFC3339Nano),
			lag.Milliseconds())
		leaf := Leaf{
			Kind:        KindTelemetry,
			CellID:      w.cellID,
			PayloadHash: HashPayload(w.salt, []byte(payload)),
			Timestamp:   w.now().UnixNano(),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		// Échec : l'absence de feuille est elle-même le symptôme (la
		// coupure a été alarmée en temps réel) — jamais de boucle ici.
		_, _ = w.log.appendInternal(ctx, leaf)
		cancel()
	}

	w.mu.Lock()
	w.catchup = false
	w.cond.Broadcast()
	w.mu.Unlock()
	if w.onClear != nil {
		w.onClear()
	}
}

// WaitOutstanding bloque jusqu'à ce que toutes les feuilles acceptées
// soient confirmées (et tout rattrapage terminé) — couture de drainage
// pour le moniteur T5 : appelé entre le verrouillage et la feuille
// d'arrêt, il garantit que KindBackpressure reste la DERNIÈRE feuille.
func (w *AsyncWriter) WaitOutstanding(ctx context.Context) error {
	for {
		w.mu.Lock()
		if w.head >= len(w.queue) && !w.catchup {
			w.mu.Unlock()
			return nil
		}
		w.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// Snapshot rend les compteurs courants (observabilité, forensique).
func (w *AsyncWriter) Snapshot() AsyncStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return AsyncStats{
		Accepted:       w.accepted,
		Confirmed:      w.confirmed,
		RefusedAtCut:   w.refusedCut,
		RefusedBacklog: w.refusedBklog,
		CutEpisodes:    w.episodes,
		Tripped:        w.tripped,
	}
}

// Close arrête d'accepter (Append → ErrAsyncClosed) et laisse le tracker
// vider la file jusqu'à épuisement ou expiration de ctx. Les feuilles non
// confirmées à l'expiration ne sont PAS perdues : le shutdown tessera
// (CellLog.Close, à appeler après) les publie — seul leur suivi cesse.
func (w *AsyncWriter) Close(ctx context.Context) error {
	var err error
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.stop = true
		w.cond.Broadcast()
		w.mu.Unlock()
		select {
		case <-w.closed:
		case <-ctx.Done():
			err = ctx.Err()
		}
		w.trackerStop() // débloque un Await en vol — sortie immédiate du tracker
		<-w.closed
		close(w.tickerStop)
	})
	return err
}
