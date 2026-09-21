// main.go — T27 (issue #29) : point d'entrée du harnais de friction.
//
//	go run ./tests/p1_friction run         — mesure + measurements.json + leaves_export.json
//	go run ./tests/p1_friction leaf-report — inscrit friction_report.json comme feuille
//	                                         KindTelemetry (D90 : l'alarme est leafée)
//
// Entre les deux : python3 leading_indicators.py rend le verdict (D89/D91).
// Le workflow prêt-à-copier friction_thresholds.yml chaîne les trois.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "leaf-report":
		err = cmdLeafReport(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "friction: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `harnais de friction T27 — usage :
  go run ./tests/p1_friction run [flags]         mesure + exports (measurements.json, leaves_export.json)
  go run ./tests/p1_friction leaf-report [flags] inscrit friction_report.json en feuille KindTelemetry (D90)
Le verdict de seuil : python3 leading_indicators.py (D89/D91).
`)
}

func runFlags(fs *flag.FlagSet, cfg *Config) {
	fs.IntVar(&cfg.Tier1Samples, "tier1", cfg.Tier1Samples, "échantillons tier1 du bras décision (et baseline)")
	fs.IntVar(&cfg.Tier2Plans, "tier2", cfg.Tier2Plans, "plans du bras décision (submit+approve+verify)")
	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "concurrence d'invocation")
	fs.IntVar(&cfg.DurTier1, "durability-tier1", cfg.DurTier1, "échantillons tier1 du bras durabilité (registre réel)")
	fs.IntVar(&cfg.DurTier2, "durability-tier2", cfg.DurTier2, "plans du bras durabilité (feuilles KindContract réelles)")
	fs.DurationVar(&cfg.InjectLatency, "inject-latency", 0, "M-harness : latence injectée sur le chemin tier1 (mutation)")
	fs.Float64Var(&cfg.InjectDenyRate, "inject-deny-rate", 0.05, "M-arbitrage : fraction de VerifyStep déviant [0,1]")
	fs.Float64Var(&cfg.TTLStretch, "ttl-stretch", 1.0, "M-ttl : multiplicateur des TTL émis (mutation)")
	fs.DurationVar(&cfg.TTLBase, "ttl-base", cfg.TTLBase, "TTL nominal émis (référence ttl_drift)")
	fs.StringVar(&cfg.OutDir, "out", cfg.OutDir, "répertoire des artefacts")
	fs.StringVar(&cfg.CellID, "cell", cfg.CellID, "identité de la cellule de mesure")
}

func cmdRun(args []string) error {
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	runFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx := context.Background()
	m, err := Run(ctx, cfg)
	if err != nil {
		return err
	}
	// Résumé de log — le verdict de seuil est à leading_indicators.py.
	printSummary(m)
	return nil
}

func cmdLeafReport(args []string) error {
	cfg := DefaultConfig()
	fs := flag.NewFlagSet("leaf-report", flag.ContinueOnError)
	fs.StringVar(&cfg.OutDir, "out", cfg.OutDir, "répertoire des artefacts (registre du run)")
	fs.StringVar(&cfg.CellID, "cell", cfg.CellID, "identité de la cellule de mesure")
	report := fs.String("report", "", "chemin de friction_report.json (défaut: <out>/friction_report.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *report == "" {
		*report = cfg.OutDir + "/friction_report.json"
	}
	idx, err := LeafReport(context.Background(), cfg, *report)
	if err != nil {
		return err
	}
	fmt.Printf("friction: rapport inscrit en feuille KindTelemetry index %d (D90 — alarme leafée, vérifiée au scan)\n", idx)
	return nil
}

// printSummary affiche les deux bras CÔTE À CÔTE (condition A de la revue
// #29 : jamais le bras « décision » sans le coût réel de la durabilité —
// borne pire cas sync ; #71 arbitré par T38, prod par défaut async borné).
func printSummary(m *Measurements) {
	byTier := func(tier, op string) []Sample {
		var out []Sample
		for _, s := range m.Samples {
			if s.Tier == tier && (op == "" || s.Op == op) {
				out = append(out, s)
			}
		}
		return out
	}
	fmt.Printf("friction: run %s (%s)\n", m.RunID, m.StartedAt.Format(time.RFC3339))
	for _, t := range []struct{ tier, op, label string }{
		{"tier1_baseline", "noop", "baseline no-op"},
		{"tier1_decision", "evaluate", "tier1 DÉCISION (seuil §9.1 bloquant : p95 ajoutée < 5 ms)"},
		{"tier1_durability", "evaluate", "tier1 DURABILITÉ (registre réel, mode sync = pire cas — T38/#71)"},
		{"tier2_decision", "verify", "tier2 verify DÉCISION (bloquant : p95 ≤ 50 ms)"},
		{"tier2_durability", "verify", "tier2 verify DURABILITÉ (surveillé)"},
	} {
		p50, p95, p99 := summarize(byTier(t.tier, t.op))
		fmt.Printf("  %-62s p50=%-12s p95=%-12s p99=%-12s\n", t.label, p50, p95, p99)
	}
	c := m.Counters
	total := c.Tier2DecVerifyOK + c.Tier2DecVerifyDenied
	rate := 0.0
	if total > 0 {
		rate = float64(c.Tier2DecVerifyDenied) / float64(total) * 100
	}
	fmt.Printf("  arbitrage (refus VerifyStep décision) : %d/%d = %.1f%% (alerte >10%%, danger >20%%)\n",
		c.Tier2DecVerifyDenied, total, rate)
	fmt.Printf("  feuilles attendues : decision=%d contract=%d (corrélation au scan : leading_indicators.py)\n",
		c.LeavesExpectedDecision, c.LeavesExpectedContract)
	fmt.Printf("  artifacts: %s/{measurements.json,leaves_export.json}\n", m.Config.OutDir)
}
