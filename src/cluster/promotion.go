// promotion.go — PromotionController : promotion miroir/canari par preuve
// de réception du bundle ANCRÉ (§7.4, T29).
//
// §7.4 : le hash du bundle est ancré par époque dans la master chain ; la
// fenêtre saine est DÉFINIE ET ANCRÉE dans le master, JAMAIS mesurée par
// le canari lui-même ; la promotion est la preuve de réception du bundle
// ancré. Conséquence structurelle : l'API de ce contrôleur n'accepte
// AUCUNE donnée de santé venant du candidat — sous partition, un canari
// qui clame « je suis sain » n'a aucun canal pour le faire valoir (pas de
// paramètre, pas de champ) ; seules parlent les ancres du master.
//
// Fail-closed : ancre indisponible (partition) ⇒ refus ; hash de bundle ≠
// ancré ⇒ refus ; fenêtre absente ou expirée ⇒ refus ; réception mal
// signée ⇒ refus. Toute décision laisse une feuille KindPromotion (§4.1,
// hash-only §6.2).
package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Erreurs de promotion — codes machine stables.
var (
	ErrPromotionAnchorUnavailable = errors.New("cluster: ancre master indisponible — partition ou master injoignable, promotion refusée (§7.4)")
	ErrPromotionBundleMismatch    = errors.New("cluster: hash du bundle reçu ≠ hash ancré dans le master")
	ErrPromotionWindowUnavailable = errors.New("cluster: fenêtre saine non ancrée dans le master")
	ErrPromotionWindowExpired     = errors.New("cluster: fenêtre saine ancrée expirée — hors fenêtre, pas de promotion")
	ErrPromotionBadReceipt        = errors.New("cluster: réception invalide (signature de cellule)")
	ErrPromotionUnknownCell       = errors.New("cluster: cellule candidate inconnue (pas de clé de réception)")
)

// MasterAnchorSource est la couture de lecture des ancres du master
// (§7.4). L'implémentation réelle lit la master chain (T6) — branchée en
// T31 (manifeste attesté) / T34 (supervision) ; ici l'interface. ok=false
// = ancre absente ou master injoignable : le contrôleur ne distingue PAS
// partition et absence — dans les deux cas, refus (fail-closed).
type MasterAnchorSource interface {
	// BundleAnchor rend le hash du bundle ancré pour une époque.
	BundleAnchor(epoch uint64) ([32]byte, bool)
	// HealthyWindow rend la fenêtre saine [start, end] DÉFINIE ET ANCRÉE
	// dans le master pour une époque — jamais mesurée par le canari.
	HealthyWindow(epoch uint64) (start, end time.Time, ok bool)
}

// Receipt est la preuve de réception signée par la cellule candidate :
// elle atteste avoir reçu LE bundle ancré (hash) pour une époque. Struct
// à champs fixes ⇒ canonique déterministe (§11.3).
type Receipt struct {
	CellID     string `json:"cell_id"`
	Epoch      uint64 `json:"epoch"`
	BundleHash string `json:"bundle_hash"` // hex, 32 octets
	ReceivedAt string `json:"received_at"` // RFC3339 UTC
}

// SignedReceipt = réception + signature Ed25519 de la cellule candidate.
type SignedReceipt struct {
	Receipt Receipt `json:"receipt"`
	Sig     string  `json:"sig"` // hex Ed25519 (64 octets) sur le JSON canonique de Receipt
}

// PromotionConfig paramètre le contrôleur. Fail-closed dès la config.
type PromotionConfig struct {
	// CellID identifie la cellule qui TRANCHE la promotion (l'autorité de
	// l'époque) dans les feuilles KindPromotion. Requis.
	CellID string
	// Salt ≥ 16 octets, reste chez le producteur (§6.2). Requis.
	Salt []byte
	// Leaves : chaque décision de promotion laisse une feuille (§4.1). Requis.
	Leaves LeafSink
	// Source lit les ancres du master (bundle par époque, fenêtre saine).
	// Requis — sans source, aucune promotion n'est possible.
	Source MasterAnchorSource
	// CellKeys : clés publiques Ed25519 des cellules candidates
	// (vérification des réceptions). Requis.
	CellKeys map[string]ed25519.PublicKey
	// Now : horloge NTS (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// PromotionController tranche les promotions miroir/canari. Sans état
// mutable après construction — sûr pour un usage concurrent.
type PromotionController struct {
	cellID string
	salt   []byte
	leaves LeafSink
	src    MasterAnchorSource
	keys   map[string]ed25519.PublicKey
	now    func() time.Time
	mu     sync.Mutex
}

// NewPromotionController construit le contrôleur — config complète exigée.
func NewPromotionController(cfg PromotionConfig) (*PromotionController, error) {
	if cfg.CellID == "" {
		return nil, errors.New("cluster: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(cfg.Salt) < 16 {
		return nil, errors.New("cluster: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if cfg.Leaves == nil {
		return nil, errors.New("cluster: couture feuilles requise (§4.1 : chaque promotion laisse une feuille)")
	}
	if cfg.Source == nil {
		return nil, errors.New("cluster: source d'ancres master requise (§7.4 : promotion = preuve de réception du bundle ancré)")
	}
	if len(cfg.CellKeys) == 0 {
		return nil, errors.New("cluster: clés des cellules candidates requises (§7.4)")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(cfg.Salt))
	copy(salt, cfg.Salt)
	keys := make(map[string]ed25519.PublicKey, len(cfg.CellKeys))
	for id, pub := range cfg.CellKeys {
		if id == "" {
			return nil, errors.New("cluster: cellID candidat vide")
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("cluster: pubkey de %q de %d octets", id, len(pub))
		}
		keys[id] = append(ed25519.PublicKey(nil), pub...)
	}
	return &PromotionController{
		cellID: cfg.CellID, salt: salt, leaves: cfg.Leaves,
		src: cfg.Source, keys: keys, now: now,
	}, nil
}

// Promote tranche une demande de promotion : la réception présentée doit
// prouver que la candidate a reçu le bundle ANCRÉ de l'époque, pendant
// une fenêtre saine ancrée et encore valide. Aucune donnée de santé du
// candidat n'est un paramètre — la fenêtre ne se mesure pas, elle se lit
// dans le master (§7.4).
func (c *PromotionController) Promote(ctx context.Context, receiptJSON []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var sr SignedReceipt
	if err := json.Unmarshal(receiptJSON, &sr); err != nil {
		return c.refuseLocked(ctx, "", 0, [32]byte{}, "malformed-receipt")
	}
	r := sr.Receipt
	if r.CellID == "" || len(r.CellID) > 255 {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, [32]byte{}, "schema-violation")
	}
	pub, ok := c.keys[r.CellID]
	if !ok {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, [32]byte{}, "unknown-candidate-cell")
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, [32]byte{}, "receipt-unserializable")
	}
	sig, err := hex.DecodeString(sr.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, canonical, sig) {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, [32]byte{}, "bad-receipt-signature")
	}
	var bundle [32]byte
	raw, err := hex.DecodeString(r.BundleHash)
	if err != nil || len(raw) != 32 {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, [32]byte{}, "bundle-hash-malformed")
	}
	copy(bundle[:], raw)
	if _, err := time.Parse(time.RFC3339, r.ReceivedAt); err != nil {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, bundle, "received-at-unparseable")
	}

	// 1. L'ancre du bundle pour cette époque doit exister dans le master
	// — sous partition, ok=false : le canari ne peut pas s'auto-promouvoir.
	anchored, ok := c.src.BundleAnchor(r.Epoch)
	if !ok {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, bundle, "promotion-anchor-unavailable")
	}
	// 2. Le bundle reçu doit être EXACTEMENT le bundle ancré.
	if bundle != anchored {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, bundle, "bundle-mismatch")
	}
	// 3. La fenêtre saine — définie et ancrée dans le master, JAMAIS
	// mesurée par le canari — doit exister et couvrir l'instant présent.
	start, end, ok := c.src.HealthyWindow(r.Epoch)
	if !ok {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, bundle, "window-unavailable")
	}
	now := c.now()
	if now.Before(start) || !now.Before(end) {
		return c.refuseLocked(ctx, r.CellID, r.Epoch, bundle, "window-expired")
	}

	return c.leafLocked(ctx, 0x01, r.CellID, r.Epoch, bundle, "ok")
}

// refuseLocked écrit la feuille de refus KindPromotion puis rend l'erreur.
func (c *PromotionController) refuseLocked(ctx context.Context, cell string, epoch uint64, bundle [32]byte, reason string) error {
	if err := c.leafLocked(ctx, 0x00, cell, epoch, bundle, reason); err != nil {
		return fmt.Errorf("cluster: refus promotion %s NON TRACÉ (feuille impossible) : %w", reason, err)
	}
	switch reason {
	case "promotion-anchor-unavailable":
		return ErrPromotionAnchorUnavailable
	case "bundle-mismatch":
		return ErrPromotionBundleMismatch
	case "window-unavailable":
		return ErrPromotionWindowUnavailable
	case "window-expired":
		return ErrPromotionWindowExpired
	case "unknown-candidate-cell":
		return ErrPromotionUnknownCell
	default:
		return fmt.Errorf("%w (%s)", ErrPromotionBadReceipt, reason)
	}
}

// leafLocked inscrit la feuille KindPromotion — record « TBPP1 » :
//
//	"TBPP1" ‖ verdict 1B ‖ cellLen u8 ‖ cellID ‖ epoch u64 BE ‖ bundleHash 32B ‖ reasonLen u8 ‖ reason
//
// hash-only (§6.2 : le sel reste chez le producteur).
func (c *PromotionController) leafLocked(ctx context.Context, verdict byte, cell string, epoch uint64, bundle [32]byte, reason string) error {
	if len(cell) > 255 {
		cell = cell[:255]
	}
	if len(reason) > 255 {
		reason = reason[:255]
	}
	rec := make([]byte, 0, 5+1+1+len(cell)+8+32+1+len(reason))
	rec = append(rec, "TBPP1"...)
	rec = append(rec, verdict, byte(len(cell)))
	rec = append(rec, cell...)
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	rec = append(rec, eb[:]...)
	rec = append(rec, bundle[:]...)
	rec = append(rec, byte(len(reason)))
	rec = append(rec, reason...)
	_, err := c.leaves.Append(ctx, registry.Leaf{
		Kind:        registry.KindPromotion,
		CellID:      c.cellID,
		PayloadHash: registry.HashPayload(c.salt, rec),
		Timestamp:   c.now().UnixNano(),
	})
	return err
}
