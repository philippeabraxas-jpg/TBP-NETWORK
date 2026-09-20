// src/telemetry/aggregate.go — T22 (issue #27)
//
// Pipeline d'agrégation entre les records IPFIX (T21) et le registre de
// cellule (T4). La règle de format §4.5 s'applique par analogie :
// AGRÉGATS + HASH — le contenu détaillé n'écrit jamais le registre en
// clair. On n'écrit PAS chaque record brut comme feuille (volume, et
// exposition de métadonnées fines) : on écrit UNE feuille par fenêtre
// agrégée, et le détail brut reste local, soumis à la rétention
// (retention.go, §6.2).
//
// Décisions (voir le commentaire de plan sur l'issue #27) :
//
//	D21 — l'agrégateur implémente RecordSink (la couture D19 de T21) :
//	      il se branche sur l'exporteur sans aucune modification de
//	      celui-ci.
//	D22 — fenêtres tumbling (défaut 60 s) bornées sur l'horloge injectée ;
//	      EXACTEMENT une feuille par fenêtre scellée, y compris vide —
//	      la continuité de la piste est un signal (un trou de fenêtre
//	      est une anomalie détectable en post-traitement, T23) et une
//	      feuille par minute est un volume négligeable.
//	D23 — agrégat hash-only : sérialisation déterministe « TBAG1 »
//	      (§11.3) ; destinations du top-k hachées+salées ; recordsRoot =
//	      racine de Merkle sur les engagements TBTM1 des records — le
//	      MÊME engagement que la feuille record de T21.
//	D26 — fail-closed et borné (§1, §4.3, §5.3) : constructeur exigeant,
//	      aucune goroutine cachée, stats atomiques.
package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	// defaultWindow est la fenêtre d'agrégation du pseudo-code de l'issue.
	defaultWindow = 60 * time.Second
	// defaultTopK est le k du top-k de destinations (pseudo-code : k=10).
	defaultTopK = 10
	// maxTopK borne k : le nombre de destinations tient sur un octet.
	maxTopK = 255
)

var (
	ErrWindowInvalid = errors.New("telemetry: fenêtre d'agrégation invalide (≥ 1 ms requis)")
	ErrTopKInvalid   = errors.New("telemetry: top-k hors [1, 255]")
)

// WindowAggregate est l'agrégat d'UNE fenêtre scellée. Il reste LOCAL
// (dans le lot brut du store de rétention) — le registre ne voit que son
// hash salé (§4.5 par analogie, §6.2).
type WindowAggregate struct {
	CellID      string     // cellule d'origine
	WindowID    int64      // index de fenêtre = Start / fenêtreMs (monotone)
	Start       int64      // début de fenêtre (unix ms, horloge injectée)
	End         int64      // fin de fenêtre (unix ms)
	Flows       uint64     // nombre de records de la fenêtre
	BytesOut    uint64     // somme des OctetDelta
	DstTop      [][32]byte // top-k destinations, HACHÉES+salées (jamais en clair)
	RecordsRoot [32]byte   // racine de Merkle des engagements TBTM1 des records
}

// AggregatorOptions configure l'agrégateur. Fail-closed : CellID, Salt
// (≥ 16 octets) et Leaves requis ; Window et TopK ont des défauts
// documentés ; RetStore est optionnel (rétention des bruts, T22).
type AggregatorOptions struct {
	CellID   string
	Salt     []byte
	Leaves   pep.LeafSink
	Window   time.Duration   // 0 ⇒ 60 s (pseudo-code de l'issue)
	TopK     int             // 0 ⇒ 10 ; borné à 255
	RetStore *RetentionStore // optionnel — rétention locale des bruts (§6.2)
	Now      func() time.Time
	OnTrip   func(reason string) // alarme (nil ⇒ pas d'alarme, §5.3 couture)
}

// AggregatorStats — compteurs atomiques (§5.3 : jamais silencieux).
type AggregatorStats struct {
	WindowsSealed uint64 // fenêtres scellées (= feuilles tentées)
	RecordsIn     uint64 // records reçus via Feed
	LeavesWritten uint64 // feuilles d'agrégat inscrites
	LeafFailures  uint64 // échecs d'Append (propagés à l'appelant)
	StoreFailures uint64 // échecs de rétention du lot brut (alarmés)
	BatchesStored uint64 // lots bruts confiés au store
}

// Aggregator accumule les records de la fenêtre courante et scelle une
// feuille d'agrégat par fenêtre. Implémente RecordSink (D21). Sûr pour
// un usage concurrent ; aucune goroutine : Tick est piloté par l'appelant
// (et appelé en interne par Feed).
type Aggregator struct {
	cellID string
	salt   []byte
	leaves pep.LeafSink
	window time.Duration
	topK   int
	store  *RetentionStore
	now    func() time.Time
	onTrip func(string)

	mu     sync.Mutex
	curID  int64    // fenêtre courante (−1 : pas encore ouverte)
	curRec []Record // records de la fenêtre courante

	stats AggregatorStats
}

// NewAggregator construit l'agrégateur. Fail-closed (§1) : cellID, sel
// ≥ 16 octets et registre requis ; fenêtre et top-k bornés.
func NewAggregator(opts AggregatorOptions) (*Aggregator, error) {
	if opts.CellID == "" {
		return nil, ErrCellIDRequired
	}
	if len(opts.Salt) < 16 {
		return nil, ErrSaltTooShort
	}
	if opts.Leaves == nil {
		return nil, ErrLeavesRequired
	}
	w := opts.Window
	if w == 0 {
		w = defaultWindow
	}
	// windowID() divise par w.Milliseconds() : toute durée positive mais
	// < 1 ms (ex. 500*time.Microsecond, un typo d'unité plausible côté
	// appelant) passerait un simple test "w < 0", pour ensuite paniquer
	// (division par zéro) au premier Feed()/Tick()/Seal() — un refus
	// différé, pas fail-closed à la configuration comme promis (§1, D26).
	if w < time.Millisecond {
		return nil, ErrWindowInvalid
	}
	k := opts.TopK
	if k == 0 {
		k = defaultTopK
	}
	if k < 0 || k > maxTopK {
		return nil, ErrTopKInvalid
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := make([]byte, len(opts.Salt))
	copy(s, opts.Salt)
	return &Aggregator{
		cellID: opts.CellID, salt: s, leaves: opts.Leaves,
		window: w, topK: k, store: opts.RetStore,
		now: now, onTrip: opts.OnTrip,
		curID: -1,
	}, nil
}

// Stats retourne un instantané des compteurs.
func (a *Aggregator) Stats() AggregatorStats {
	return AggregatorStats{
		WindowsSealed: atomic.LoadUint64(&a.stats.WindowsSealed),
		RecordsIn:     atomic.LoadUint64(&a.stats.RecordsIn),
		LeavesWritten: atomic.LoadUint64(&a.stats.LeavesWritten),
		LeafFailures:  atomic.LoadUint64(&a.stats.LeafFailures),
		StoreFailures: atomic.LoadUint64(&a.stats.StoreFailures),
		BatchesStored: atomic.LoadUint64(&a.stats.BatchesStored),
	}
}

// Feed ajoute un record à la fenêtre courante (couture RecordSink, D21).
// Au passage, il scelle les fenêtres écoulées — une erreur de feuille est
// PROPAGÉE (l'exporteur T21 la compte et l'alarme, comme pour tout sink).
func (a *Aggregator) Feed(r Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.tickLocked(a.now()); err != nil {
		return err
	}
	id := a.windowID(a.now())
	if a.curID == -1 {
		a.curID = id
	}
	a.curRec = append(a.curRec, r)
	atomic.AddUint64(&a.stats.RecordsIn, 1)
	return nil
}

// Tick scelle toutes les fenêtre entièrement écoulées jusqu'à maintenant
// — EXACTEMENT une feuille par fenêtre, y compris vide (D22). Idempotent.
// Le runtime l'appelle périodiquement ; Feed l'appelle en interne.
func (a *Aggregator) Tick() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tickLocked(a.now())
}

// Seal force la fermeture de la fenêtre courante (arrêt propre, tests).
// La fenêtre scellée est celle en cours même si elle n'est pas écoulée.
func (a *Aggregator) Seal() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.curID == -1 {
		a.curID = a.windowID(a.now())
	}
	return a.sealLocked(a.curID)
}

// windowID retourne l'index de fenêtre contenant t (§11.3 : déterministe).
func (a *Aggregator) windowID(t time.Time) int64 {
	return t.UnixMilli() / a.window.Milliseconds()
}

// tickLocked scelle [curID .. idCourant[ : chaque fenêtre ÉCOULÉE produit
// sa feuille, y compris les vides entre deux ticks.
func (a *Aggregator) tickLocked(t time.Time) error {
	id := a.windowID(t)
	if a.curID == -1 {
		return nil // rien d'ouvert : le prochain Feed ouvrira la fenêtre courante
	}
	for a.curID < id {
		if err := a.sealLocked(a.curID); err != nil {
			return err
		}
	}
	return nil
}

// sealLocked scelle la fenêtre id : agrégat, feuille, lot brut. Une
// erreur de feuille NE fait PAS avancer la fenêtre — l'appelant verra
// l'erreur et l'alarme ; rien n'est perdu silencieusement (§5.3).
func (a *Aggregator) sealLocked(id int64) error {
	wms := a.window.Milliseconds()
	agg := buildAggregate(a.cellID, id, id*wms, (id+1)*wms, a.curRec, a.salt, a.topK)
	atomic.AddUint64(&a.stats.WindowsSealed, 1)

	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      a.cellID,
		PayloadHash: registry.HashPayload(a.salt, aggregateBytes(agg)),
		Timestamp:   a.now().UnixNano(),
	}
	if _, err := a.leaves.Append(context.Background(), leaf); err != nil {
		atomic.AddUint64(&a.stats.LeafFailures, 1)
		return err
	}
	atomic.AddUint64(&a.stats.LeavesWritten, 1)

	// Rétention locale du brut (§6.2) — le détail reste chez le
	// producteur, soumis au TTL explicite de retention.go. Store plein :
	// alarme (jamais de destruction silencieuse) mais la fenêtre avance —
	// la feuille d'agrégat, elle, EST écrite.
	if a.store != nil && len(a.curRec) > 0 {
		batch := RawBatch{
			WindowID:  id,
			SealedAt:  a.now().UnixMilli(),
			Aggregate: agg,
			Records:   append([]Record(nil), a.curRec...),
			LeafHash:  leaf.PayloadHash,
		}
		if err := a.store.Put(batch); err != nil {
			atomic.AddUint64(&a.stats.StoreFailures, 1)
			if a.onTrip != nil {
				a.onTrip(ReasonStoreFull)
			}
		} else {
			atomic.AddUint64(&a.stats.BatchesStored, 1)
		}
	}

	a.curID = id + 1
	a.curRec = a.curRec[:0]
	return nil
}

// buildAggregate calcule l'agrégat d'une fenêtre depuis ses records bruts
// — fonction pure, déterministe (§11.3) : c'est aussi la fonction que
// rejoue l'auditeur dans RetentionStore.Verify.
func buildAggregate(cellID string, windowID, start, end int64, recs []Record, salt []byte, k int) WindowAggregate {
	agg := WindowAggregate{
		CellID:   cellID,
		WindowID: windowID,
		Start:    start,
		End:      end,
		Flows:    uint64(len(recs)),
	}
	// top-k des destinations (ressource SIGNÉE — autoritaire, D18) par
	// octets ; chaque destination n'apparaît que hachée+salée.
	type dstAcc struct {
		hash  [32]byte
		bytes uint64
	}
	byDst := make(map[string]dstAcc, len(recs))
	commitments := make([][32]byte, 0, len(recs))
	for _, r := range recs {
		agg.BytesOut += r.OctetDelta
		h := hashDestination(salt, r.Resource)
		acc := byDst[r.Resource]
		acc.hash = h
		acc.bytes += r.OctetDelta
		byDst[r.Resource] = acc
		commitments = append(commitments, registry.HashPayload(salt, telemetryRecord(r)))
	}
	agg.RecordsRoot = merkleRoot(commitments)

	ranked := make([]dstAcc, 0, len(byDst))
	for _, acc := range byDst {
		ranked = append(ranked, acc)
	}
	// tri déterministe : octets décroissants, puis hash croissant — deux
	// exécutions sur les mêmes records donnent le même top-k (§11.3).
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].bytes != ranked[j].bytes {
			return ranked[i].bytes > ranked[j].bytes
		}
		for b := 0; b < 32; b++ {
			if ranked[i].hash[b] != ranked[j].hash[b] {
				return ranked[i].hash[b] < ranked[j].hash[b]
			}
		}
		return false
	})
	if len(ranked) > k {
		ranked = ranked[:k]
	}
	agg.DstTop = make([][32]byte, 0, len(ranked))
	for _, acc := range ranked {
		agg.DstTop = append(agg.DstTop, acc.hash)
	}
	return agg
}

// hashDestination : sha256(sel ‖ destination) — la destination en clair
// ne quitte jamais le producteur (§6.2).
func hashDestination(salt []byte, dst string) [32]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(dst))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleRoot : arbre binaire sha256 sur les engagements des records ;
// feuille impaire dupliquée ; arbre vide ⇒ racine nulle (fenêtre vide —
// la feuille d'agrégat existe quand même, D22).
func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			r := level[i]
			var s [32]byte
			if i+1 < len(level) {
				s = level[i+1]
			} else {
				s = r // duplicata de la feuille impaire
			}
			h := sha256.New()
			h.Write(r[:])
			h.Write(s[:])
			var n [32]byte
			copy(n[:], h.Sum(nil))
			next = append(next, n)
		}
		level = next
	}
	return level[0]
}

// aggregateBytes sérialise l'agrégat pour le hash de la feuille — layout
// fixe déterministe (§11.3) :
//
//	"TBAG1" ‖ u8 len(cell) ‖ cell ‖ i64be windowID ‖ i64be start ‖ i64be end
//	‖ u64be flows ‖ u64be bytesOut ‖ u8 len(dstTop) ‖ k×hash(dst)(32)
//	‖ recordsRoot(32)
//
// RIEN EN CLAIR : les destinations ne sont que des hashes salés.
func aggregateBytes(agg WindowAggregate) []byte {
	buf := make([]byte, 0, 5+1+len(agg.CellID)+8*3+8*2+1+32*len(agg.DstTop)+32)
	buf = append(buf, "TBAG1"...)
	buf = append(buf, byte(len(agg.CellID)))
	buf = append(buf, agg.CellID...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(agg.WindowID))
	buf = binary.BigEndian.AppendUint64(buf, uint64(agg.Start))
	buf = binary.BigEndian.AppendUint64(buf, uint64(agg.End))
	buf = binary.BigEndian.AppendUint64(buf, agg.Flows)
	buf = binary.BigEndian.AppendUint64(buf, agg.BytesOut)
	buf = append(buf, byte(len(agg.DstTop)))
	for _, h := range agg.DstTop {
		buf = append(buf, h[:]...)
	}
	buf = append(buf, agg.RecordsRoot[:]...)
	return buf
}
