package pep

// Antirejeu PERSISTANT de la preuve de quorum (revue de sécurité post-#86,
// issue #105).
//
// QuorumMessage (quorum_verifier.go) lie déjà la CONDITION, l'identité de
// la cellule et une fenêtre de fraîcheur bornée (expiry) — mais rien ne
// gardait trace, d'une requête à l'autre, du dernier expiry déjà
// consommé pour une condition donnée : une preuve valide capturée une
// fois restait rejouable jusqu'à sa propre expiration (jusqu'à 5 min,
// DefaultQuorumProofTTL), y compris APRÈS un redémarrage de pepd — ce qui
// annule le fail-closed du redémarrage (#93, ModeController.StartRefused)
// en rejouant une ANCIENNE preuve « monitor » au lieu d'en exiger une
// nouvelle.
//
// QuorumStateStore ferme ce trou avec un plancher de fraîcheur PERSISTANT
// par condition : une preuve n'est consommée que si son expiry dépasse
// STRICTEMENT le dernier expiry déjà accepté pour cette même condition —
// donc jamais deux fois la même preuve, jamais une preuve plus ancienne
// qu'une déjà consommée. Comme cell_log.key (§12), l'état survit au
// redémarrage : même frontière de custody, même répertoire de registre.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// QuorumStateStore valide et avance ATOMIQUEMENT le plancher de fraîcheur
// d'une condition. Consume(condition, expiryUnix) :
//   - si expiryUnix > plancher actuel de condition : le persiste comme
//     nouveau plancher (durable AVANT de rendre la main — une bascule
//     commise après cet appel qui ne survivrait pas à un crash laisserait
//     la preuve rejouable une fois de plus, donc l'écriture doit précéder
//     tout commit en mémoire chez l'appelant) et rend ok=true ;
//   - sinon (rejeu, ou preuve plus ancienne qu'une déjà consommée) :
//     n'écrit RIEN et rend ok=false — fail-closed, jamais un état à
//     moitié avancé.
type QuorumStateStore interface {
	Consume(condition string, expiryUnix int64) (ok bool, err error)
}

// FileQuorumStateStore persiste le plancher dans un fichier JSON auprès
// du registre de la cellule — écriture atomique (fichier temporaire +
// rename, même motif que loadOrGenerateCellKey) pour ne jamais laisser un
// état à moitié écrit après un crash.
type FileQuorumStateStore struct {
	path string
	mu   sync.Mutex
}

// NewFileQuorumStateStore construit le magasin sur path (typiquement
// <TBP_REGISTRY_DIR>/quorum_state.json — le fichier est créé au premier
// Consume qui avance un plancher, jamais à la construction).
func NewFileQuorumStateStore(path string) *FileQuorumStateStore {
	return &FileQuorumStateStore{path: path}
}

func (s *FileQuorumStateStore) load() (map[string]int64, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]int64{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pep: lecture de l'état de quorum (%s): %w", s.path, err)
	}
	state := map[string]int64{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &state); err != nil {
			return nil, fmt.Errorf("pep: état de quorum illisible (%s): %w", s.path, err)
		}
	}
	return state, nil
}

// Consume implémente QuorumStateStore — voir la doctrine ci-dessus.
func (s *FileQuorumStateStore) Consume(condition string, expiryUnix int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.load()
	if err != nil {
		return false, err
	}
	if prev, ok := state[condition]; ok && expiryUnix <= prev {
		return false, nil // rejeu ou preuve plus ancienne — fail-closed, rien n'est écrit
	}
	state[condition] = expiryUnix
	raw, err := json.Marshal(state)
	if err != nil {
		return false, fmt.Errorf("pep: sérialisation de l'état de quorum: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return false, fmt.Errorf("pep: écriture de l'état de quorum: %w", err)
	}
	if f, openErr := os.Open(tmp); openErr == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return false, fmt.Errorf("pep: engagement de l'état de quorum: %w", err)
	}
	return true, nil
}
