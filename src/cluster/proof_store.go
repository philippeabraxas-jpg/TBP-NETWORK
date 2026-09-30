// proof_store.go — registre des preuves de quorum classe W CONSOMMÉES
// (issue #206, red team R-19).
//
// Les preuves de posture et de levée fail-closed avancent un plancher
// persistant (pep.QuorumStateStore, #105) : une preuve vaut une fois. Le
// gate de la classe W (quorum.go) vérifiait liaison, fraîcheur et
// signatures mais ne consommait rien : une preuve k-of-n valide pouvait
// être présentée N fois pendant sa fenêtre (≤ 300 s). Le plan_binding
// (#177) empêchait de rejouer l'action À L'IDENTIQUE, mais « une preuve =
// une autorisation » restait une propriété implicite, pas imposée.
//
// Ici l'identité d'une preuve est le hash SHA-256 de son énoncé canonique
// (action, ressource, policy, époque, expiry) — pas de ses signatures : deux
// sous-ensembles de signataires d'un MÊME énoncé sont la même autorisation.
// Pour autoriser une seconde exécution, les contrôleurs signent un nouvel
// énoncé (autre expiry).
//
// Doctrine, alignée sur antireplay.go et #105 :
//   - consommation DURABLE avant de rendre la main (un crash entre la
//     consommation et l'action laisse la preuve brûlée, jamais rejouable) ;
//   - borné : les entrées expirées sont purgées, jamais évincées ; registre
//     plein ⇒ refus (fail-closed), jamais un oubli silencieux ;
//   - illisible ⇒ refus de démarrer, jamais un registre vide en repli.

package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultProofStoreCapacity borne le nombre de preuves consommées encore
// dans leur fenêtre : 300 s de TTL maximal, donc 4096 autorisations W
// distinctes dans ce laps de temps dépassent tout usage réel (friction
// §9.1 : la classe W est rare par construction).
const DefaultProofStoreCapacity = 4096

// Erreurs du registre de preuves.
var (
	ErrQuorumProofReplayed  = errors.New("cluster: preuve de quorum déjà consommée (une preuve vaut une autorisation)")
	ErrProofStoreFull       = errors.New("cluster: registre des preuves consommées plein (fail-closed, aucune éviction)")
	ErrQuorumProofStoreFail = errors.New("cluster: registre des preuves consommées indisponible (fail-closed)")
)

// ProofStore consomme une preuve : ok=true la première fois seulement.
// Consume est ATOMIQUE et DURABLE : si ok=true est rendu, l'identité est
// déjà persistée.
type ProofStore interface {
	Consume(id [32]byte, expiry, now time.Time) (ok bool, err error)
}

// proofID calcule l'identité d'une preuve : SHA-256 de l'énoncé canonique.
func proofID(st QuorumStatement) ([32]byte, error) {
	canonical, err := json.Marshal(st)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// consumedProofs est le cœur partagé mémoire/fichier.
type consumedProofs struct {
	mu       sync.Mutex
	entries  map[string]int64 // id hex → expiry (secondes Unix)
	capacity int
	path     string // "" ⇒ mémoire seule
}

func newConsumedProofs(capacity int, path string) (*consumedProofs, error) {
	if capacity == 0 {
		capacity = DefaultProofStoreCapacity
	}
	if capacity < 1 {
		return nil, errors.New("cluster: capacité du registre de preuves négative")
	}
	c := &consumedProofs{entries: map[string]int64{}, capacity: capacity, path: path}
	if path == "" {
		return c, nil
	}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return c, nil
	case err != nil:
		return nil, fmt.Errorf("cluster: lecture du registre de preuves (%s): %w", path, err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c.entries); err != nil {
			return nil, fmt.Errorf("cluster: registre de preuves illisible (%s): %w — refus de démarrer plutôt que d'oublier les preuves consommées", path, err)
		}
	}
	return c, nil
}

// Consume : voir ProofStore.
func (c *consumedProofs) Consume(id [32]byte, expiry, now time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := hex.EncodeToString(id[:])
	if _, seen := c.entries[key]; seen {
		return false, nil
	}
	// Purge des preuves dont la fenêtre est close : elles ne sont plus
	// rejouables (VerifyClassW refuse toute preuve expirée), donc inutiles
	// à retenir. Jamais d'éviction d'une preuve encore valide.
	purged := map[string]int64{}
	for k, exp := range c.entries {
		if exp <= now.Unix() {
			purged[k] = exp
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.capacity {
		for k, exp := range purged { // état inchangé : on remet ce qu'on a purgé
			c.entries[k] = exp
		}
		return false, ErrProofStoreFull
	}
	c.entries[key] = expiry.Unix()
	if err := c.persistLocked(); err != nil {
		delete(c.entries, key)
		for k, exp := range purged {
			c.entries[k] = exp
		}
		return false, fmt.Errorf("%w: %v", ErrQuorumProofStoreFail, err)
	}
	return true, nil
}

// persistLocked écrit atomiquement (temporaire + fsync + rename + fsync du
// répertoire) — l'identité est durable avant que Consume rende ok=true.
func (c *consumedProofs) persistLocked() error {
	if c.path == "" {
		return nil
	}
	raw, err := json.Marshal(c.entries)
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(c.path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// Len rend le nombre d'identités retenues (observabilité, tests).
func (c *consumedProofs) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// MemoryProofStore est le registre non persistant (tests, dev). En
// production, le gate exige un FileProofStore : un registre en mémoire
// perd ses entrées au redémarrage et rouvre la fenêtre de rejeu.
type MemoryProofStore struct{ *consumedProofs }

// NewMemoryProofStore construit un registre en mémoire. capacity 0 ⇒ défaut.
func NewMemoryProofStore(capacity int) (*MemoryProofStore, error) {
	c, err := newConsumedProofs(capacity, "")
	if err != nil {
		return nil, err
	}
	return &MemoryProofStore{c}, nil
}

// FileProofStore persiste le registre auprès du registre de la cellule
// (même frontière de custody que quorum_state.json).
type FileProofStore struct{ *consumedProofs }

// NewFileProofStore ouvre (ou crée au premier Consume) le registre sur path.
// Un fichier présent mais illisible est une ERREUR : refuser de démarrer
// vaut mieux qu'oublier silencieusement les preuves consommées.
func NewFileProofStore(path string, capacity int) (*FileProofStore, error) {
	if path == "" {
		return nil, errors.New("cluster: chemin du registre de preuves requis")
	}
	c, err := newConsumedProofs(capacity, path)
	if err != nil {
		return nil, err
	}
	return &FileProofStore{c}, nil
}
