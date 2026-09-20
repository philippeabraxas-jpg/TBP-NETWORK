// src/telemetry/retention.go — T22 (issue #27)
//
// Politique de rétention EXPLICITE des records bruts de télémétrie
// (§6.2 — GDPR / rétention : un log append-only infini entre en conflit
// avec les obligations de rétention).
//
// Le registre ne porte que des feuilles hash-only ; le détail brut des
// records reste LOCAL au producteur, dans ce store borné à TTL explicite.
// La purge est EFFECTIVE et TRACÉE : chaque lot détruit laisse une
// feuille KindRetentionPurge dont le payload est le hash salé du
// manifeste « TBRP1 » (cell ‖ windowID ‖ nbRecords ‖ recordsRoot ‖
// purgedAt) — la preuve de destruction, jamais le contenu.
//
// Doctrine fail-closed (§1, §9.1) :
//   - le store est BORNÉ (MaxBatches, §4.3) : plein ⇒ ErrStoreFull, à
//     l'appelant d'alarmer — on ne détruit jamais du brut non expiré ;
//   - la feuille de purge est tentée AVANT la suppression : si le
//     registre est en panne, le lot N'EST PAS détruit (destruction non
//     tracée = proscrite) — l'alarme et la borne du store feront le
//     reste (§5.3 : jamais silencieux) ;
//   - après purge, la correspondance agrégat ↔ brut n'est plus
//     re-vérifiable : c'est précisément le sens de la rétention.
package telemetry

import (
	"context"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	// defaultRetentionTTL : les bruts sont conservés 24 h — assez pour un
	// audit de la correspondance agrégat ↔ records, pas indéfiniment (§6.2).
	defaultRetentionTTL = 24 * time.Hour
	// defaultMaxBatches borne le store : 24 h à fenêtres de 60 s (§4.3).
	defaultMaxBatches = 1440
)

// ReasonStoreFull : alarme quand le store de rétention est plein —
// la purge n'a pas tourné ou la borne est sous-dimensionnée (§5.3).
const ReasonStoreFull = "retention-store-full"

var (
	ErrTTLInvalid        = errors.New("telemetry: TTL de rétention invalide (≤ 0)")
	ErrMaxBatchesInvalid = errors.New("telemetry: borne de lots invalide (≤ 0)")
	ErrStoreFull         = errors.New("telemetry: store de rétention plein — purge requise (§4.3)")
	ErrBatchGone         = errors.New("telemetry: lot brut purgé ou inconnu — correspondance non re-vérifiable (§6.2)")
)

// RawBatch est le détail brut d'une fenêtre scellée, conservé localement
// le temps du TTL. LeafHash est le payload de la feuille d'agrégat
// correspondante — le lien audit (D25).
type RawBatch struct {
	WindowID  int64           // fenêtre scellée
	SealedAt  int64           // scellé à (unix ms) — base du TTL
	Aggregate WindowAggregate // agrégat local (le registre n'a que son hash)
	Records   []Record        // records bruts de la fenêtre
	LeafHash  [32]byte        // PayloadHash de la feuille d'agrégat
}

// RetentionOptions configure le store. Fail-closed : CellID, Salt
// (≥ 16 octets) et Leaves requis ; TTL et MaxBatches ont des défauts
// documentés.
type RetentionOptions struct {
	CellID     string
	Salt       []byte
	Leaves     pep.LeafSink
	TTL        time.Duration // 0 ⇒ 24 h
	MaxBatches int           // 0 ⇒ 1440
	Now        func() time.Time
	OnTrip     func(reason string) // alarme (nil ⇒ pas d'alarme, couture §5.3)
}

// RetentionStats — compteurs (§5.3).
type RetentionStats struct {
	BatchesStored uint64 // lots actuellement conservés
	BatchesPurged uint64 // lots détruits (avec feuille de purge)
	PurgeLeaves   uint64 // feuilles KindRetentionPurge inscrites
	PurgeFailures uint64 // échecs d'Append pendant la purge (lot conservé)
}

// RetentionStore conserve les lots bruts à TTL explicite et trace chaque
// purge au registre. Sûr pour un usage concurrent ; aucune goroutine :
// PurgeExpired est piloté par l'appelant.
type RetentionStore struct {
	cellID string
	salt   []byte
	leaves pep.LeafSink
	ttl    time.Duration
	max    int
	now    func() time.Time
	onTrip func(string)

	mu      sync.Mutex
	batches map[int64]RawBatch // indexé par windowID (monotone)
	stats   RetentionStats
}

// NewRetentionStore construit le store. Fail-closed (§1).
func NewRetentionStore(opts RetentionOptions) (*RetentionStore, error) {
	if opts.CellID == "" {
		return nil, ErrCellIDRequired
	}
	if len(opts.Salt) < 16 {
		return nil, ErrSaltTooShort
	}
	if opts.Leaves == nil {
		return nil, ErrLeavesRequired
	}
	ttl := opts.TTL
	if ttl == 0 {
		ttl = defaultRetentionTTL
	}
	if ttl < 0 {
		return nil, ErrTTLInvalid
	}
	max := opts.MaxBatches
	if max == 0 {
		max = defaultMaxBatches
	}
	if max < 0 {
		return nil, ErrMaxBatchesInvalid
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	s := make([]byte, len(opts.Salt))
	copy(s, opts.Salt)
	return &RetentionStore{
		cellID: opts.CellID, salt: s, leaves: opts.Leaves,
		ttl: ttl, max: max, now: now, onTrip: opts.OnTrip,
		batches: make(map[int64]RawBatch),
	}, nil
}

// Stats retourne un instantané des compteurs.
func (s *RetentionStore) Stats() RetentionStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.BatchesStored = uint64(len(s.batches))
	return st
}

// Put conserve un lot brut. Les fenêtres vides ne laissent rien à
// retenir (leur feuille d'agrégat suffit — D22). Plein ⇒ ErrStoreFull :
// l'appelant alarme, rien n'est détruit pour faire de la place.
func (s *RetentionStore) Put(b RawBatch) error {
	if len(b.Records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.batches[b.WindowID]; !dup && len(s.batches) >= s.max {
		return ErrStoreFull
	}
	s.batches[b.WindowID] = b
	return nil
}

// Batch expose un lot brut pour audit local (présent ⇒ vérifiable).
func (s *RetentionStore) Batch(windowID int64) (RawBatch, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.batches[windowID]
	return b, ok
}

// PurgeExpired détruit les lots dont le TTL est écoulé — chaque
// destruction est TRACÉE par une feuille KindRetentionPurge écrite AVANT
// la suppression : registre en panne ⇒ lot conservé, échec compté et
// alarmé (§5.3, §9.1). Retourne le nombre de lots purgés.
func (s *RetentionStore) PurgeExpired() int {
	nowMs := s.now().UnixMilli()

	s.mu.Lock()
	expired := make([]RawBatch, 0)
	for _, b := range s.batches {
		if b.SealedAt+s.ttl.Milliseconds() <= nowMs {
			expired = append(expired, b)
		}
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i].WindowID < expired[j].WindowID })

	purged := 0
	for _, b := range expired {
		leaf := registry.Leaf{
			Kind:        registry.KindRetentionPurge,
			CellID:      s.cellID,
			PayloadHash: registry.HashPayload(s.salt, purgeManifest(s.cellID, b, nowMs)),
			Timestamp:   s.now().UnixNano(),
		}
		if _, err := s.leaves.Append(context.Background(), leaf); err != nil {
			// pas de trace, pas de destruction — le lot reste (§9.1)
			s.stats.PurgeFailures++
			if s.onTrip != nil {
				s.onTrip(pep.ReasonLeafWriteFailed)
			}
			continue
		}
		delete(s.batches, b.WindowID)
		s.stats.BatchesPurged++
		s.stats.PurgeLeaves++
		purged++
	}
	s.mu.Unlock()
	return purged
}

// Verify rejoue l'engagement de la fenêtre depuis les bruts — la preuve
// auditeur (D25) : engagements TBTM1 → racine de Merkle → agrégat TBAG1
// → hash salé, comparé au payload de la feuille. ErrBatchGone si le lot
// a été purgé : la correspondance n'est plus re-vérifiable, et c'est le
// sens de la rétention (§6.2).
func (s *RetentionStore) Verify(windowID int64, leafPayloadHash [32]byte) (bool, error) {
	s.mu.Lock()
	b, ok := s.batches[windowID]
	s.mu.Unlock()
	if !ok {
		return false, ErrBatchGone
	}
	// k = nombre de destinations de l'agrégat scellé : rejouer le top-k à
	// l'identique (si la fenêtre compte moins de destinations que k, le
	// résultat est le même — top-k de n < k = tout, trié).
	k := len(b.Aggregate.DstTop)
	if k == 0 {
		k = 1
	}
	rebuilt := buildAggregate(s.cellID, b.Aggregate.WindowID, b.Aggregate.Start,
		b.Aggregate.End, b.Records, s.salt, k)
	if rebuilt.RecordsRoot != b.Aggregate.RecordsRoot {
		return false, nil // incohérence interne du lot — falsification locale ?
	}
	want := registry.HashPayload(s.salt, aggregateBytes(rebuilt))
	return want == leafPayloadHash, nil
}

// purgeManifest sérialise le manifeste de purge pour le hash de la
// feuille — layout fixe déterministe (§11.3) :
//
//	"TBRP1" ‖ u8 len(cell) ‖ cell ‖ i64be windowID ‖ u64be nbRecords
//	‖ recordsRoot(32) ‖ i64be purgedAtMs
//
// La feuille prouve QUOI a été détruit (fenêtre, volume, racine) sans
// jamais révéler le contenu.
func purgeManifest(cellID string, b RawBatch, purgedAt int64) []byte {
	buf := make([]byte, 0, 5+1+len(cellID)+8+8+32+8)
	buf = append(buf, "TBRP1"...)
	buf = append(buf, byte(len(cellID)))
	buf = append(buf, cellID...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(b.WindowID))
	buf = binary.BigEndian.AppendUint64(buf, uint64(len(b.Records)))
	buf = append(buf, b.Aggregate.RecordsRoot[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(purgedAt))
	return buf
}
