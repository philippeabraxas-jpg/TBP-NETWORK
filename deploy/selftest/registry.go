// registry.go — T35 (issue #61) : registres tessera réels du selftest.
// Motif répliqué de tests/p2_redteam/runner/evidence.go (T28) — répliqué,
// non importé (package main), conformément à la règle en vigueur. La
// paire de clés suit le motif pepd : cell_log.key (privée, 0600) +
// cell_log.vkey (publique). Le scan est VÉRIFIÉ (ChainWatcher T34 :
// checkpoint signé + cohérence Merkle), jamais une lecture naïve.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

// registryOrigin est le nom de la note tessera d'une cellule — même
// convention que pepd (src/pep/cmd/pepd/main.go : GenerateCellKey(cellID),
// l'origine est le cellID nu).
func registryOrigin(cellID string) string { return cellID }

// openCellRegistry ouvre (ou crée) le registre tessera de la cellule dans
// regDir. Retourne le log (LeafSink natif pour cluster.*) et le chemin.
func openCellRegistry(ctx context.Context, regDir, cellID string) (*registry.CellLog, error) {
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		return nil, fmt.Errorf("registry dir: %w", err)
	}
	signer, err := registry.LoadSigner(regDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("signer: %w", err)
		}
		skey, vkey, gerr := registry.GenerateCellKey(registryOrigin(cellID))
		if gerr != nil {
			return nil, fmt.Errorf("clé de cellule: %w", gerr)
		}
		if serr := registry.SaveSignerKey(regDir, skey); serr != nil {
			return nil, fmt.Errorf("sauvegarde clé: %w", serr)
		}
		if werr := os.WriteFile(filepath.Join(regDir, "cell_log.vkey"), []byte(vkey), 0o644); werr != nil {
			return nil, fmt.Errorf("sauvegarde vkey: %w", werr)
		}
		if signer, err = registry.LoadSigner(regDir); err != nil {
			return nil, fmt.Errorf("signer: %w", err)
		}
	}
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		return nil, fmt.Errorf("clé de vérification: %w", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}
	cellLog, err := registry.Open(ctx, registry.Options{Dir: regDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return nil, fmt.Errorf("cell log: %w", err)
	}
	return cellLog, nil
}

// countKinds scanne le registre (scan vérifié ChainWatcher) et compte les
// feuilles par kind. Utilisable pendant que le log est ouvert en écriture
// par le composant sous test (lecture tessera concurrente — motif T28).
func countKinds(ctx context.Context, cellID, regDir string) (map[byte]int, error) {
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
	counts := map[byte]int{}
	for _, l := range append(boot, more...) {
		counts[l.Kind]++
	}
	return counts, nil
}
