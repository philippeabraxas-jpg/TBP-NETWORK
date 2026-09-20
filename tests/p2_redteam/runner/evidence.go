// evidence.go — T28 (issue #28) : registre réel de la campagne red-team,
// export vérifié et feuilles d'évidence.
//
// Réplique le motif d'ouverture de registre de pepd / T27
// (tests/p1_friction/harness.go) — volontairement NON importé : ce motif
// vit dans un package main (revue #28, remarque 2). Mêmes ~30 lignes :
// clé de cellule note (cell_log.key privée + cell_log.vkey publique),
// registry.Open, scan ChainWatcher. Les artefacts (clés, sel) restent
// locaux et gitignorés avec out/ (§6.2).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

// leafSinkIface est la signature commune de pep.LeafSink /
// cluster.LeafSink — *registry.CellLog l'implémente nativement.
type leafSinkIface interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// registryOrigin est l'origine (nom de clé note) du log de la campagne.
func registryOrigin(cellID string) string { return "tbp/registry/" + cellID }

// openCellRegistry ouvre (ou crée) le registre tessera de la campagne dans
// outDir/registry. La paire de clés suit le motif pepd : cell_log.key
// (privée, 0600) + cell_log.vkey (publique) — artefacts locaux.
func openCellRegistry(ctx context.Context, outDir, cellID string) (*registry.CellLog, string, error) {
	regDir := filepath.Join(outDir, "registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("registry dir: %w", err)
	}
	origin := registryOrigin(cellID)
	signer, err := registry.LoadSigner(regDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("signer: %w", err)
		}
		skey, vkey, gerr := registry.GenerateCellKey(origin)
		if gerr != nil {
			return nil, "", fmt.Errorf("clé de cellule: %w", gerr)
		}
		if serr := registry.SaveSignerKey(regDir, skey); serr != nil {
			return nil, "", fmt.Errorf("sauvegarde clé: %w", serr)
		}
		if werr := os.WriteFile(filepath.Join(regDir, "cell_log.vkey"), []byte(vkey), 0o644); werr != nil {
			return nil, "", fmt.Errorf("sauvegarde vkey: %w", werr)
		}
		if signer, err = registry.LoadSigner(regDir); err != nil {
			return nil, "", fmt.Errorf("signer: %w", err)
		}
	}
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		return nil, "", fmt.Errorf("clé de vérification: %w", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		return nil, "", fmt.Errorf("verifier: %w", err)
	}
	cellLog, err := registry.Open(ctx, registry.Options{Dir: regDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return nil, "", fmt.Errorf("cell log: %w", err)
	}
	return cellLog, regDir, nil
}

// leafRecord est la vue exportée d'une feuille (scan vérifié) — même
// forme que T27 pour que assert_logged.py lise un format déjà éprouvé.
type leafRecord struct {
	Seq    uint64 `json:"seq"`
	Kind   byte   `json:"kind"`
	TS     int64  `json:"ts"`
	CellID string `json:"cell_id"`
}

// exportLeaves scanne le registre fermé via le ChainWatcher de supervision
// (vérification de chaîne incluse — pas de deuxième lecteur tessera).
func exportLeaves(ctx context.Context, cellID, regDir string) ([]leafRecord, error) {
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		return nil, fmt.Errorf("clé de vérification: %w", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}
	boot, w, err := supervision.NewChainWatcher(ctx, cellID, regDir, registryOrigin(cellID), verifier, 0)
	if err != nil {
		return nil, fmt.Errorf("chain watcher: %w", err)
	}
	more, err := w.Tick(ctx)
	if err != nil {
		return nil, fmt.Errorf("tick: %w", err)
	}
	all := append(boot, more...)
	recs := make([]leafRecord, len(all))
	for i, l := range all {
		recs[i] = leafRecord{Seq: uint64(i), Kind: l.Kind, TS: l.Timestamp, CellID: l.CellID}
	}
	return recs, nil
}

// countingSink enveloppe le registre réel : chaque scénario reçoit le sien
// pour compter ses feuilles par kind et bornes d'index (corrélation D94).
// Les composants sous test écrivent dans le registre RÉEL à travers ce
// compteur — aucune feuille « de théâtre ». Les bornes sont des MIN/MAX
// d'index, pas des premier/dernier complétés : sous concurrence (S5),
// l'ordre de complétion d'Append n'est pas l'ordre des index.
type countingSink struct {
	inner leafSinkIface

	mu     sync.Mutex
	counts map[byte]uint64
	min    int64 // plus petit index écrit (−1 si aucun)
	max    int64 // plus grand index écrit (−1 si aucun)
}

func newCountingSink(inner leafSinkIface) *countingSink {
	return &countingSink{inner: inner, counts: map[byte]uint64{}, min: -1, max: -1}
}

func (c *countingSink) Append(ctx context.Context, leaf registry.Leaf) (uint64, error) {
	idx, err := c.inner.Append(ctx, leaf)
	if err != nil {
		return idx, err
	}
	c.mu.Lock()
	c.counts[leaf.Kind]++
	i := int64(idx)
	if c.min < 0 || i < c.min {
		c.min = i
	}
	if i > c.max {
		c.max = i
	}
	c.mu.Unlock()
	return idx, nil
}

// snapshot rend (comptes par kind, index min, index max).
func (c *countingSink) snapshot() (map[byte]uint64, int64, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[byte]uint64, len(c.counts))
	for k, v := range c.counts {
		out[k] = v
	}
	return out, c.min, c.max
}

func (c *countingSink) total() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n uint64
	for _, v := range c.counts {
		n += v
	}
	return n
}

// ---------------------------------------------------------------------------
// Feuille d'évidence (D93) — les scénarios réseau (S1/S2, exécutés sur le
// lab netns) et le constat S3 inscrivent l'OBSERVATION de l'attaque
// (compteurs du mur, journal NAC, constat USB) : hash salé, sel local.
// ---------------------------------------------------------------------------

// evidenceSalt charge (ou crée) le sel d'évidence du run — ≥ 16 octets,
// conservé local 0600, jamais dans le registre ni le dépôt (§6.2).
func evidenceSalt(outDir string) ([]byte, error) {
	p := filepath.Join(outDir, "evidence_salt.hex")
	if b, err := os.ReadFile(p); err == nil {
		salt, err := hex.DecodeString(string(b))
		if err != nil || len(salt) < 16 {
			return nil, fmt.Errorf("sel d'évidence corrompu (%s)", p)
		}
		return salt, nil
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("sel d'évidence: %w", err)
	}
	if err := os.WriteFile(p, []byte(hex.EncodeToString(salt)), 0o600); err != nil {
		return nil, fmt.Errorf("sel d'évidence: %w", err)
	}
	return salt, nil
}

// evidenceEntry trace la correspondance scénario ↔ feuille d'évidence
// (sidecar local, gitignoré) — assert_logged.py le recoupe au scan.
type evidenceEntry struct {
	Scenario string `json:"scenario"`
	LeafIdx  uint64 `json:"leaf_index"`
	SHA256   string `json:"evidence_sha256"` // hash de l'évidence en clair (locale, jamais leafée)
	At       string `json:"at"`
}

// AppendEvidence inscrit une feuille KindTelemetry portant
// HashPayload(sel, évidence) dans le registre du run, consigne la
// correspondance dans evidence_log.jsonl, puis RE-EXPORTE le scan
// vérifié (leaves_export.json) — le vérificateur transversal doit voir
// la feuille d'évidence, pas un registre figé d'avant le lab. Rend
// l'index de la feuille.
func AppendEvidence(ctx context.Context, outDir, cellID, scenarioID string, evidence []byte) (uint64, error) {
	if scenarioID == "" {
		return 0, fmt.Errorf("évidence sans scénario — une feuille orpheline est un trou")
	}
	if len(evidence) == 0 {
		return 0, fmt.Errorf("évidence vide refusée — rien à attester")
	}
	cellLog, regDir, err := openCellRegistry(ctx, outDir, cellID)
	if err != nil {
		return 0, err
	}
	salt, err := evidenceSalt(outDir)
	if err != nil {
		return 0, err
	}
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      cellID,
		PayloadHash: registry.HashPayload(salt, evidence),
		Timestamp:   time.Now().UTC().UnixNano(),
	}
	idx, err := cellLog.Append(ctx, leaf)
	if err != nil {
		return 0, fmt.Errorf("feuille d'évidence: %w", err)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cellLog.Close(closeCtx); err != nil {
		return 0, fmt.Errorf("fermeture registre: %w", err)
	}
	sum := registry.HashPayload(salt, evidence) // même fonction, traçabilité locale
	entry := evidenceEntry{
		Scenario: scenarioID, LeafIdx: idx,
		SHA256: hex.EncodeToString(sum[:]),
		At:     time.Now().UTC().Format(time.RFC3339),
	}
	f, err := os.OpenFile(filepath.Join(outDir, "evidence_log.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, fmt.Errorf("journal d'évidence: %w", err)
	}
	b, _ := json.Marshal(entry)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return 0, fmt.Errorf("journal d'évidence: %w", err)
	}
	f.Close()
	// Re-export : la feuille d'évidence doit être visible du vérificateur
	// transversal (scan vérifié ChainWatcher, comme le run).
	leaves, err := exportLeaves(ctx, cellID, regDir)
	if err != nil {
		return 0, fmt.Errorf("re-export après évidence: %w", err)
	}
	if err := writeJSONFile(filepath.Join(outDir, "leaves_export.json"), leaves); err != nil {
		return 0, fmt.Errorf("re-export après évidence: %w", err)
	}
	return idx, nil
}
