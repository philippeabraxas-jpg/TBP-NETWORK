package main

// mirror.go — la cellule miroir (§7.4) devant la garde de dégradation du traducteur (#275 suite).
//
// OPT-IN, et seulement AVEC la garde (TBP_TRANSLATOR_GUARD=1) : sans garde, aucun mode dégradé n'existe.
//
//	TBP_MIRROR_ANCHORS_FILE    fichier d'ancres signé par le quorum des contrôleurs de la genèse : par époque, le
//	                           hash du bundle ancré et la fenêtre saine DÉFINIE là (jamais mesurée par le canari).
//	                           Relu et revérifié à chaque lecture ; NON mesuré par le provisionnement (#192) :
//	                           il change à chaque fenêtre et porte sa propre signature de quorum.
//	TBP_MIRROR_CELL_KEYS_FILE  JSON {"<cell_id>": "<clé publique Ed25519 hex>"} des cellules candidates —
//	                           racine de confiance des reçus ; MESURÉ par le provisionnement (« mirror-cell-keys »).
//
// Les deux sont requis ensemble. Une promotion est un acte d'opérateur sur le plan d'administration : le reçu
// signé de la cellule miroir (« j'ai reçu le bundle ancré de l'époque N ») est déposé sur
// POST /v1/supervision/mirror/promote ; PromotionController le tranche (feuille KindPromotion, journalisée).
// MirrorCell.Available est vrai tant qu'une promotion valide couvre l'ÉPOQUE COURANTE de la cellule et que la
// fenêtre saine ancrée n'est pas échue. Une cellule ne peut pas être son propre miroir.
//
// Ce que le failover change : en mode dégradé, un système CRITIQUE (classes F, I, W) voit son entrée STRUCTURÉE
// admise sur le chemin déterministe — la chaîne complète (OPA, quorum, plan, contrats) s'applique ensuite SANS
// exception ; seule l'admission par le traducteur est levée.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	strictjson "github.com/philippeabraxas-jpg/TBP-NETWORK/src/strictjson"
)

const maxMirrorBodyBytes = 4 << 10

type mirrorConfig struct {
	enabled      bool
	anchorsFile  string
	cellKeysFile string
}

// mirrorFromEnv lit et valide TBP_MIRROR_* — fail-closed.
func mirrorFromEnv(getenv func(string) string, guardEnabled bool) (mirrorConfig, error) {
	cfg := mirrorConfig{anchorsFile: getenv("TBP_MIRROR_ANCHORS_FILE"), cellKeysFile: getenv("TBP_MIRROR_CELL_KEYS_FILE")}
	switch {
	case cfg.anchorsFile == "" && cfg.cellKeysFile == "":
		return cfg, nil
	case cfg.anchorsFile == "" || cfg.cellKeysFile == "":
		return cfg, errors.New("TBP_MIRROR_ANCHORS_FILE et TBP_MIRROR_CELL_KEYS_FILE sont requis ENSEMBLE (§7.4 : sans clés de cellule, aucun reçu ne se vérifie ; sans ancres, aucune fenêtre)")
	case !guardEnabled:
		return cfg, errors.New("TBP_MIRROR_* sans TBP_TRANSLATOR_GUARD=1 — configuration incohérente (le miroir ne sert qu'en mode dégradé)")
	}
	cfg.enabled = true
	return cfg, nil
}

// loadMirrorCellKeys lit {"cell_id": "hex pubkey"} — borné, décodage strict, clés Ed25519 de 32 octets.
func loadMirrorCellKeys(path string) (map[string]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clés des cellules miroir : %w", err)
	}
	if len(data) > 64<<10 {
		return nil, errors.New("clés des cellules miroir : fichier trop volumineux")
	}
	return parseMirrorCellKeys(data)
}

func parseMirrorCellKeys(data []byte) (map[string]ed25519.PublicKey, error) {
	var raw map[string]string
	if err := strictjson.Decode(data, &raw); err != nil {
		return nil, fmt.Errorf("clés des cellules miroir illisibles : %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("clés des cellules miroir : aucune cellule")
	}
	out := make(map[string]ed25519.PublicKey, len(raw))
	for id, h := range raw {
		pub, err := hex.DecodeString(h)
		if id == "" || err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("clés des cellules miroir : clé de %q illisible (Ed25519 hex 32 octets)", id)
		}
		out[id] = ed25519.PublicKey(pub)
	}
	return out, nil
}

// mirrorGate : PromotionController + état de la promotion courante. Satisfait translator.MirrorCell.
type mirrorGate struct {
	self   string
	salt   []byte
	keys   map[string]ed25519.PublicKey
	ctl    *cluster.PromotionController
	src    *cluster.FileAnchorSource
	epochs broker.EpochProvider
	now    func() time.Time

	mu    sync.Mutex
	cell  string
	epoch uint64
	end   time.Time
}

type mirrorStatus struct {
	Available bool   `json:"available"`
	Cell      string `json:"cell,omitempty"`
	Epoch     uint64 `json:"epoch,omitempty"`
	WindowEnd string `json:"window_end,omitempty"`
}

func newMirrorGate(cfg mirrorConfig, self string, salt []byte, leaves cluster.LeafSink, journal *registry.RecordStore,
	controllers map[int]ed25519.PublicKey, quorum int, epochs broker.EpochProvider, now func() time.Time) (*mirrorGate, error) {
	keys, err := loadMirrorCellKeys(cfg.cellKeysFile)
	if err != nil {
		return nil, err
	}
	if _, isSelf := keys[self]; isSelf {
		return nil, fmt.Errorf("clés des cellules miroir : %q est cette cellule — une cellule n'est pas son propre miroir", self)
	}
	src, err := cluster.NewFileAnchorSource(cfg.anchorsFile, controllers, quorum)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	ctl, err := cluster.NewPromotionController(cluster.PromotionConfig{
		CellID: self, Salt: salt, Leaves: leaves, Journal: journal, Source: src, CellKeys: keys, Now: now,
	})
	if err != nil {
		return nil, err
	}
	return &mirrorGate{self: self, salt: append([]byte(nil), salt...), keys: keys, ctl: ctl, src: src, epochs: epochs, now: now}, nil
}

// Promote tranche un reçu (octets bruts du plan d'administration). Succès ⇒ la promotion courante est
// retenue, bornée par la fenêtre ANCRÉE (relue dans le fichier signé), jamais par le reçu.
func (g *mirrorGate) Promote(ctx context.Context, body []byte) (mirrorStatus, error) {
	if err := g.ctl.Promote(ctx, body); err != nil {
		return mirrorStatus{}, err
	}
	var sr cluster.SignedReceipt
	if err := strictjson.Decode(body, &sr); err != nil { // déjà validé par Promote
		return mirrorStatus{}, err
	}
	_, end, ok := g.src.HealthyWindow(sr.Receipt.Epoch)
	if !ok {
		return mirrorStatus{}, errors.New("fenêtre ancrée indisponible après promotion")
	}
	g.mu.Lock()
	g.cell, g.epoch, g.end = sr.Receipt.CellID, sr.Receipt.Epoch, end
	g.mu.Unlock()
	return g.Status(), nil
}

// Available : une promotion valide couvre l'époque COURANTE et la fenêtre ancrée n'est pas échue.
func (g *mirrorGate) Available(context.Context) bool { return g.Status().Available }

func (g *mirrorGate) Status() mirrorStatus {
	g.mu.Lock()
	cell, epoch, end := g.cell, g.epoch, g.end
	g.mu.Unlock()
	if cell == "" {
		return mirrorStatus{}
	}
	st := mirrorStatus{Cell: cell, Epoch: epoch, WindowEnd: end.UTC().Format(time.RFC3339)}
	cur, err := g.epochs.CurrentEpoch()
	st.Available = err == nil && cur == epoch && g.now().Before(end)
	return st
}

// systemClassOf : les classes F, I, W (financier, infrastructure, survie — celles qui exigent plan ou quorum)
// sont les systèmes CRITIQUES du §4.5 ; tout le reste (hors F/I/W, sujet inconnu) est STANDARD.
func systemClassOf(reg broker.AgentRegistry) func(subject string) bool {
	return func(subject string) bool {
		rec, ok := reg.Resolve(subject)
		if !ok {
			return false
		}
		return rec.Class == pep.ClassF || rec.Class == pep.ClassI || rec.Class == pep.ClassW
	}
}

// Restore rétablit, au démarrage, la promotion courante depuis le journal (déjà déchiffré par registry.ReadRecords) :
// la DERNIÈRE décision « promue » de cette cellule (feuille « TBPP1 », verdict 1), comme le fait la porte en
// fonctionnement. Rien n'est lu d'un fichier d'état : l'état est dérivé d'événements audités.
//
// Une promotion ACCORDE un droit : elle n'est restaurée que si (1) sa feuille est dans le log signé (inLog), (2) la
// cellule candidate est toujours dans les clés mesurées, et (3) l'ancre signée d'AUJOURD'HUI donne encore le même
// hash de bundle pour cette époque et une fenêtre saine qui court encore — le journal ne prolonge jamais la fenêtre
// ancrée. Sinon rien n'est restauré : un opérateur redépose un reçu (comportement antérieur).
func (g *mirrorGate) Restore(recs []registry.SealedRecord, inLog func(registry.SealedRecord) bool) bool {
	var cell string
	var epoch uint64
	var bundle [32]byte
	var found *registry.SealedRecord
	for i := range recs {
		r := &recs[i]
		if r.Leaf.Kind != registry.KindPromotion || r.Leaf.CellID != g.self || !bytes.HasPrefix(r.Record, []byte("TBPP1")) ||
			!bytes.Equal(r.Salt, g.salt) || r.VerifyHash() != nil {
			continue
		}
		c, e, b, promoted, ok := parsePromotionRecord(r.Record)
		if !ok || !promoted {
			continue
		}
		cell, epoch, bundle, found = c, e, b, r
	}
	if found == nil || inLog == nil || !inLog(*found) {
		return false
	}
	if _, known := g.keys[cell]; !known || cell == g.self {
		return false
	}
	if anchored, ok := g.src.BundleAnchor(epoch); !ok || anchored != bundle {
		return false
	}
	_, end, ok := g.src.HealthyWindow(epoch)
	if !ok || !g.now().Before(end) {
		return false
	}
	g.mu.Lock()
	g.cell, g.epoch, g.end = cell, epoch, end
	g.mu.Unlock()
	return true
}

// parsePromotionRecord décode « TBPP1 » ‖ verdict ‖ u8 len(cell) ‖ cell ‖ epoch u64 BE ‖ bundle 32 ‖ u8 len(reason) ‖
// reason (cluster.PromotionController.leafLocked). promoted = verdict 1 (« ok »).
func parsePromotionRecord(rec []byte) (cell string, epoch uint64, bundle [32]byte, promoted, ok bool) {
	if len(rec) < 5+1+1 {
		return
	}
	verdict, cl := rec[5], int(rec[6])
	off := 7 + cl
	if len(rec) < off+8+32+1 {
		return
	}
	cell = string(rec[7:off])
	epoch = binary.BigEndian.Uint64(rec[off:])
	copy(bundle[:], rec[off+8:off+8+32])
	rl := int(rec[off+8+32])
	if len(rec) != off+8+32+1+rl {
		return
	}
	return cell, epoch, bundle, verdict == 0x01, true
}
