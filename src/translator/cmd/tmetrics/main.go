// main.go — T26 (issue #22) : tmetrics inscrit un rapport measure.py au
// registre de la cellule (feuille de métriques du traducteur, §4.5).
//
// Enchaînement : measure.py (replay de corpus, gate CI) → report.json
// (agrégats + hash de corpus, jamais de contenu) → tmetrics --report
// report.json → feuille KindTelemetry hash-only « TBTM1 » (§6.2).
//
// Fail-closed (§1) :
//   - TBP_CELL_ID, TBP_SALT (hex ≥ 32 car., §6.2) et TBP_REGISTRY_DIR
//     requis — absents ⇒ refus de démarrer ;
//   - les clés du registre (cell_log.key 0600 + cell_log.vkey) DOIVENT
//     déjà exister : l'identité du registre appartient aux services de la
//     cellule (pepd/brokerd) — tmetrics n'en crée JAMAIS une nouvelle (un
//     registre à l'identité fraîche et silencieuse serait une fourche) ;
//   - un rapport mal formé, incohérent ou d'une version inconnue est
//     refusé — une mesure douteuse n'entre pas au registre.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	translator "github.com/philippeabraxas-jpg/TBP-NETWORK/src/translator"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tmetrics: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("tmetrics", flag.ContinueOnError)
	reportPath := fs.String("report", "", "chemin du rapport measure.py (JSON, requis)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *reportPath == "" {
		return errors.New("--report requis (rapport measure.py)")
	}

	cellID := os.Getenv("TBP_CELL_ID")
	if cellID == "" {
		return errors.New("TBP_CELL_ID requis (§6.2 : feuilles attribuées)")
	}
	saltHex := os.Getenv("TBP_SALT")
	salt, err := hex.DecodeString(saltHex)
	if err != nil || len(salt) < 16 {
		return errors.New("TBP_SALT requis (hex, ≥ 32 car. — §6.2 : feuilles hash-only)")
	}
	regDir := os.Getenv("TBP_REGISTRY_DIR")
	if regDir == "" {
		return errors.New("TBP_REGISTRY_DIR requis (registre de la cellule)")
	}

	raw, err := os.ReadFile(*reportPath)
	if err != nil {
		return fmt.Errorf("rapport illisible : %w", err)
	}
	report, err := translator.MetricsReportFromJSON(raw)
	if err != nil {
		return err
	}

	// Clés du registre : REQUISES, jamais générées ici (l'identité du
	// registre appartient aux services de la cellule).
	signer, err := registry.LoadSigner(regDir)
	if err != nil {
		return fmt.Errorf("cell_log.key absent ou illisible — le registre de la cellule doit être initialisé par ses services (pepd/brokerd) : %w", err)
	}
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		return fmt.Errorf("cell_log.vkey absent ou illisible : %w", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		return fmt.Errorf("verifier : %w", err)
	}

	ctx := context.Background()
	log, err := registry.Open(ctx, registry.Options{Dir: regDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return fmt.Errorf("registre : %w", err)
	}
	defer func() { _ = log.Close(context.Background()) }()

	idx, err := translator.AppendMetricsLeaf(ctx, log, cellID, salt, report, time.Now())
	if err != nil {
		return fmt.Errorf("inscription : %w", err)
	}
	fmt.Printf("tmetrics: feuille de métriques inscrite (indice %d, corpus %x, %d classes)\n",
		idx, report.CorpusHash, len(report.Classes))
	return nil
}
