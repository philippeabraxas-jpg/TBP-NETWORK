// main.go — T28 (issue #28) : runner de la campagne red-team P2 « Michel ».
//
//	run           — exécute S4–S9 in-process (composants réels, registre
//	                réel), écrit run_report.json + leaves_export.json.
//	                Exit 1 si un mécanisme exécuté n'a pas tenu.
//	leaf-evidence — inscrit une feuille d'évidence KindTelemetry pour les
//	                scénarios réseau (S1/S2/S3) exécutés par les scripts
//	                netns sur le lab (D93) : hash salé, sel local §6.2.
//
// Le verdict transversal (« feuille présente », trous comptés) appartient
// à assert_logged.py — le runner produit les preuves, il ne s'auto-valide pas.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: runner <run|leaf-evidence> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "leaf-evidence":
		os.Exit(cmdLeafEvidence(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "sous-commande inconnue %q\n", os.Args[1])
		os.Exit(2)
	}
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	out := fs.String("out", "out", "répertoire de sortie (registre, rapports — gitignoré)")
	cell := fs.String("cell", DefaultConfig().CellID, "identifiant de cellule de la campagne")
	floodUp := fs.Int("flood-up", DefaultConfig().FloodUp, "S5 : requêtes concurrentes phase A (OPA sain)")
	floodDown := fs.Int("flood-down", DefaultConfig().FloodDown, "S5 : requêtes phase B (OPA tombé)")
	// Mutations — garde-fous (D95) ; absentes en nominal, exercées par les tests.
	mutDeaf := fs.Bool("mut-detector-deaf", false, "M-S4 : détecteur anti-dribble sourd (seuil muté)")
	mutSilent := fs.Bool("mut-silent-flood", false, "M-S5 : feuilles silencieusement perdues sous submersion")
	mutDev := fs.Bool("mut-accept-deviation", false, "M-S6 : déviations de plan acceptées")
	mutCanary := fs.Bool("mut-canary-self-measured", false, "M-S7 : fenêtre mesurée par le canari (§7.4 violé)")
	mutReplay := fs.Bool("mut-replay-accept", false, "M-S8 : anti-rejeu neutralisé")
	mutQuorum := fs.Bool("mut-skip-quorum", false, "M-S9 : quorum de classe W accepté d'office")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := Config{
		OutDir: *out, CellID: *cell, FloodUp: *floodUp, FloodDown: *floodDown,
		MutDetectorDeaf: *mutDeaf, MutSilentFlood: *mutSilent, MutAcceptDeviation: *mutDev,
		MutCanarySelfMeasured: *mutCanary, MutReplayAccept: *mutReplay, MutSkipQuorum: *mutQuorum,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	report, err := Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "redteam: %v\n", err)
		return 1
	}
	printReport(report, cfg.OutDir)
	for _, s := range report.Scenarios {
		if s.Status == "executed" && s.Held != nil && !*s.Held {
			fmt.Printf("\nredteam: %s (%s) NON TENU — campagne ROUGE\n", s.ID, s.Name)
			return 1
		}
	}
	fmt.Println("\nredteam: mécanismes exécutés tenus — verdict transversal : assert_logged.py")
	return 0
}

func cmdLeafEvidence(args []string) int {
	fs := flag.NewFlagSet("leaf-evidence", flag.ContinueOnError)
	out := fs.String("out", "out", "répertoire de sortie du run (registre existant)")
	cell := fs.String("cell", DefaultConfig().CellID, "identifiant de cellule du run")
	scenario := fs.String("scenario", "", "identifiant du scénario (S1|S2|S3) — requis")
	file := fs.String("evidence", "", "fichier d'évidence (défaut : stdin)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scenario == "" {
		fmt.Fprintln(os.Stderr, "leaf-evidence: -scenario requis — une feuille orpheline est un trou")
		return 2
	}
	var evidence []byte
	var err error
	if *file != "" {
		evidence, err = os.ReadFile(*file)
	} else {
		evidence, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "leaf-evidence: lecture: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	idx, err := AppendEvidence(ctx, *out, *cell, *scenario, evidence)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leaf-evidence: %v\n", err)
		return 1
	}
	fmt.Printf("redteam: évidence %s inscrite en feuille KindTelemetry index %d (hash salé — sel local, §6.2)\n", *scenario, idx)
	return 0
}

// printReport affiche le tableau de la campagne — trous déclarés inclus,
// jamais masqués.
func printReport(r *RunReport, outDir string) {
	fmt.Printf("redteam: run %s (%s)\n", r.RunID, r.GeneratedAt)
	for _, s := range r.Scenarios {
		verdict := "—"
		switch {
		case s.Held != nil && *s.Held:
			verdict = "TENU"
		case s.Held != nil:
			verdict = "NON TENU"
		}
		n := uint64(0)
		for _, c := range s.Leaves {
			n += c
		}
		fmt.Printf("  %-4s %-22s %-13s feuilles=%-4d %s\n", s.ID, s.Name, verdict, n, s.Mechanism)
		if s.Detail != "" {
			fmt.Printf("       %s\n", s.Detail)
		}
	}
	fmt.Println("  trous résiduels DÉCLARÉS (comptés, jamais ignorés) :")
	for _, h := range r.DeclaredHoles {
		fmt.Printf("    - %s : %s\n", h.ID, h.Description)
	}
	fmt.Printf("  artifacts: %s/{run_report.json,leaves_export.json}\n", outDir)
}
