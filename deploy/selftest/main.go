// main.go — T35 (issue #61) : selftest de déploiement.
//
// Ce harness EXÉCUTE les guides de deploy/ au lieu de se contenter de les
// relire : chaque étape documentée dont l'exécution est possible hors lab
// est jouée ici contre les vrais binaires (pepd compilé, OPA réel) et les
// vrais composants (trackers d'époques, QuorumGate, PromotionController
// sur registres tessera réels). Un guide qui dérive du code se voit
// immédiatement : le selftest casse.
//
// Deux phases :
//
//	mono    — une cellule réelle : build pepd, capabilities OPA strippées,
//	          pepd en monitor avec OPA, jetons valides/témoins, bascule
//	          gouvernée monitor→closed (§5.3), scan vérifié du registre.
//	fencing — deux cellules in-process (motif T27/T28, exigé en relecture) :
//	          epoch 0, équivoque, rotation sans fenêtre à deux autorités,
//	          révocation roster (§7.3), QuorumGate (§7.5), promotion (§7.4).
//
// Le rapport JSON (out/selftest-report.json) liste chaque contrôle avec
// son verdict ; le code de sortie est 1 dès qu'un contrôle échoue —
// fail-closed, comme le reste.
//
// Substitution DEV documentée : la genèse réelle exige SoftHSM
// (scripts/genesis, §12 — jamais de clé logicielle en production). Ici,
// faute de HSM dans l'environnement de test, les clés d'émetteur et de
// contrôleurs sont dérivées de seeds fixes en pure Go. C'est une
// SUBSTITUTION DE TEST, pas une genèse : les guides renvoient à
// scripts/genesis pour la vraie cérémonie.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// check est un contrôle unitaire — non-vacuole par construction : chaque
// témoin est une faute précise qui DOIT être prise (mutation).
type check struct {
	Phase  string `json:"phase"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// suite accumule les contrôles et écrit le rapport.
type suite struct {
	mu     sync.Mutex
	checks []check
	failed int
}

func (s *suite) add(phase, name string, ok bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checks = append(s.checks, check{Phase: phase, Name: name, OK: ok, Detail: detail})
	if ok {
		log.Printf("[ ok ] %-7s %s%s", phase, name, suffix(detail))
		return
	}
	s.failed++
	log.Printf("[FAIL] %-7s %s — %s", phase, name, detail)
}

func (s *suite) fail(phase, name string, err error) {
	s.add(phase, name, false, err.Error())
}

func suffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " — " + detail
}

// config porte les paramètres CLI résolus.
type config struct {
	phase  string
	out    string
	repo   string
	goBin  string
	opaBin string
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("selftest: ")

	var cfg config
	flag.StringVar(&cfg.phase, "phase", "all", "phase à exécuter : all | mono | fencing")
	flag.StringVar(&cfg.out, "out", "", "répertoire de sortie (défaut : <repo>/deploy/selftest/out — gitignoré)")
	flag.StringVar(&cfg.repo, "repo", ".", "racine du dépôt (cwd recommandé)")
	flag.StringVar(&cfg.goBin, "go-bin", "go", "binaire go (phase mono)")
	flag.StringVar(&cfg.opaBin, "opa-bin", "opa", "binaire opa (phase mono)")
	flag.Parse()

	repo, err := filepath.Abs(cfg.repo)
	if err != nil {
		log.Fatalf("repo: %v", err)
	}
	cfg.repo = repo
	if cfg.out == "" {
		cfg.out = filepath.Join(repo, "deploy", "selftest", "out")
	}
	if err := os.MkdirAll(cfg.out, 0o755); err != nil {
		log.Fatalf("out: %v", err)
	}

	s := &suite{}
	switch cfg.phase {
	case "all":
		runMono(s, cfg)
		runFencing(s, cfg)
	case "mono":
		runMono(s, cfg)
	case "fencing":
		runFencing(s, cfg)
	default:
		log.Fatalf("phase inconnue: %q (all|mono|fencing)", cfg.phase)
	}

	reportPath := filepath.Join(cfg.out, "selftest-report.json")
	data, err := json.MarshalIndent(struct {
		Checks []check `json:"checks"`
		Failed int     `json:"failed"`
	}{Checks: s.checks, Failed: s.failed}, "", "  ")
	if err != nil {
		log.Fatalf("rapport: %v", err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		log.Fatalf("rapport: %v", err)
	}

	fmt.Printf("selftest: %d contrôles, %d échecs — rapport %s\n", len(s.checks), s.failed, reportPath)
	if s.failed > 0 {
		os.Exit(1)
	}
}
