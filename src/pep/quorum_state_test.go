package pep

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFileQuorumStateStoreMonotonic : preuve NON-VACUE directe de la
// doctrine (#105) — un expiry strictement supérieur au plancher avance et
// persiste ; un expiry égal ou inférieur est refusé SANS rien écrire.
func TestFileQuorumStateStoreMonotonic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quorum_state.json")
	s := NewFileQuorumStateStore(path)

	ok, err := s.Consume("mode-monitor", 100)
	if err != nil || !ok {
		t.Fatalf("premier Consume: ok=%v err=%v, veut true/nil (aucun plancher encore)", ok, err)
	}

	// Rejeu exact (même expiry) : refusé, rien écrit.
	ok, err = s.Consume("mode-monitor", 100)
	if err != nil || ok {
		t.Fatalf("rejeu exact: ok=%v err=%v, veut false/nil", ok, err)
	}

	// Preuve plus ancienne que le plancher : refusée aussi.
	ok, err = s.Consume("mode-monitor", 50)
	if err != nil || ok {
		t.Fatalf("expiry plus ancien: ok=%v err=%v, veut false/nil", ok, err)
	}

	// Expiry strictement supérieur : avance le plancher.
	ok, err = s.Consume("mode-monitor", 101)
	if err != nil || !ok {
		t.Fatalf("expiry strictement supérieur: ok=%v err=%v, veut true/nil", ok, err)
	}

	// Le plancher avancé rejette maintenant 100 ET 101 (déjà consommé).
	if ok, err := s.Consume("mode-monitor", 101); err != nil || ok {
		t.Fatalf("rejeu du nouveau plancher: ok=%v err=%v, veut false/nil", ok, err)
	}
}

// TestFileQuorumStateStorePerCondition : le plancher est tenu PAR
// CONDITION — avancer "mode-closed" ne touche pas "mode-monitor" (une
// bascule closed→monitor→closed→monitor répétée doit rester possible,
// chaque condition avec sa propre fraîcheur).
func TestFileQuorumStateStorePerCondition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quorum_state.json")
	s := NewFileQuorumStateStore(path)

	if ok, err := s.Consume("mode-closed", 100); err != nil || !ok {
		t.Fatalf("mode-closed premier: ok=%v err=%v", ok, err)
	}
	// mode-monitor n'a pas encore de plancher : le même expiry 100 y est
	// accepté, aucune contamination croisée entre conditions.
	if ok, err := s.Consume("mode-monitor", 100); err != nil || !ok {
		t.Fatalf("mode-monitor indépendant de mode-closed: ok=%v err=%v", ok, err)
	}
}

// TestFileQuorumStateStorePersistsAcrossInstances : l'état survit à la
// reconstruction du store sur le MÊME fichier — c'est exactement ce qui
// doit survivre à un redémarrage de pepd (#105, #93).
func TestFileQuorumStateStorePersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quorum_state.json")
	first := NewFileQuorumStateStore(path)
	if ok, err := first.Consume("mode-monitor", 100); err != nil || !ok {
		t.Fatalf("premier processus: ok=%v err=%v", ok, err)
	}

	second := NewFileQuorumStateStore(path)
	if ok, err := second.Consume("mode-monitor", 100); err != nil || ok {
		t.Fatalf("second processus (même fichier): ok=%v err=%v, veut false/nil (plancher hérité)", ok, err)
	}
	if ok, err := second.Consume("mode-monitor", 101); err != nil || !ok {
		t.Fatalf("second processus, expiry frais: ok=%v err=%v, veut true/nil", ok, err)
	}
}

// TestFileQuorumStateStoreAbsentFileIsEmptyState : un fichier d'état
// absent (premier démarrage) n'est jamais une erreur — état vide, tout
// premier expiry est accepté (cohérent avec cell_log.key : absent au
// premier déploiement, jamais un défaut fail-open pour autant).
func TestFileQuorumStateStoreAbsentFileIsEmptyState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n-existe-pas", "quorum_state.json")
	// Le répertoire parent n'existe pas non plus : Consume doit échouer
	// PROPREMENT (erreur), jamais accepter silencieusement sans pouvoir
	// persister — mais lire un chemin absent (répertoire présent, fichier
	// absent) doit rendre un état vide, pas une erreur.
	if _, err := os.Stat(filepath.Dir(path)); err == nil {
		t.Fatal("précondition invalide: le répertoire ne devrait pas exister")
	}
	if _, err := NewFileQuorumStateStore(path).Consume("mode-monitor", 100); err == nil {
		t.Fatal("Consume vers un répertoire absent accepté sans erreur — l'état ne peut pas avoir été persisté")
	}

	// Répertoire présent, fichier absent : premier Consume accepté et
	// persiste normalement.
	realPath := filepath.Join(t.TempDir(), "quorum_state.json")
	ok, err := NewFileQuorumStateStore(realPath).Consume("mode-monitor", 100)
	if err != nil || !ok {
		t.Fatalf("premier Consume (fichier absent, répertoire présent): ok=%v err=%v", ok, err)
	}
}
