// tbp-audit — vérification hors-ligne des enregistrements d'audit (#271).
//
// Un auditeur qui détient le journal d'un démon (records.jsonl), sa clé de
// journal et — pour la preuve d'inclusion — le répertoire du log et la clé
// publique du log, vérifie que chaque enregistrement en clair correspond bien
// à une feuille INSCRITE au registre :
//
//	tbp-audit keygen -out records.key
//	tbp-audit verify -records records.jsonl -key records.key \
//	    [-log /var/lib/tbp/registry -vkey-file cell_log.pub | -vkey <clé note>] \
//	    [-index N] [-reveal] [-no-coverage]
//
// Avec -log, la vérification INVERSE (couverture) est faite PAR DÉFAUT : verify relit toutes les feuilles du log
// (checkpoint signé vérifié) et liste celles qui n'ont AUCUNE entrée dans le journal — feuilles inscrites sans clair
// (journal refusé en disque plein : feuille d'arrêt du backpressure, feuille d'épisode de durabilité), antérieures au
// journal, OU dont l'entrée a été EFFACÉE du journal. Sans elle, un enregistrement orphelin est vu, une entrée
// effacée ne l'est pas (revue tierce du 2 octobre, 4.5) : « 0 échec » ne voulait alors pas dire « journal complet ».
// -no-coverage la désactive explicitement (un avertissement le dit) ; -index N, vérification ciblée, ne la fait pas
// non plus sauf -coverage ; -coverage reste accepté (redondant avec -log, seul avec -index il change quelque chose).
//
// Sans -log, seule la correspondance (sel ‖ record) ↔ hash de la feuille est
// contrôlée (« hash »). Avec -log, la feuille doit en plus figurer dans le log
// sous un checkpoint signé, preuve d'inclusion RFC 6962 vérifiée. Le clair
// n'est affiché qu'avec -reveal ; il ne quitte jamais la cellule autrement.
//
// Code de sortie : 0 tout est vérifié, 1 au moins un enregistrement échoue
// (orphelin, clair altéré, preuve rejetée), 2 usage / journal illisible.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return cmdKeygen(args[1:], stdout, stderr)
	case "verify":
		return cmdVerify(args[1:], stdout, stderr)
	}
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage : tbp-audit keygen -out FICHIER | tbp-audit verify -records FICHIER -key FICHIER [-log RÉP (-vkey CLÉ | -vkey-file FICHIER)] [-index N] [-reveal] [-coverage | -no-coverage]")
}

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "fichier de la clé de journal (0600, jamais écrasé)")
	if fs.Parse(args) != nil || *out == "" {
		usage(stderr)
		return 2
	}
	if err := registry.GenerateRecordKey(*out); err != nil {
		fmt.Fprintln(stderr, "keygen :", err)
		return 2
	}
	fmt.Fprintln(stdout, "clé de journal écrite :", *out)
	return 0
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	records := fs.String("records", "", "journal d'enregistrements du démon")
	keyFile := fs.String("key", "", "clé du journal")
	logDir := fs.String("log", "", "répertoire du log de la cellule (preuve d'inclusion)")
	vkey := fs.String("vkey", "", "clé publique du log (format note)")
	vkeyFile := fs.String("vkey-file", "", "fichier contenant la clé publique du log")
	index := fs.Int64("index", -1, "ne vérifier que l'enregistrement dont la feuille est à cet index (exige -log)")
	reveal := fs.Bool("reveal", false, "afficher le clair des enregistrements (base64)")
	coverage := fs.Bool("coverage", false, "couverture explicite (exige -log) ; déjà le défaut avec -log, utile avec -index")
	noCoverage := fs.Bool("no-coverage", false, "ne PAS vérifier la couverture (une entrée effacée du journal ne sera pas vue)")
	if fs.Parse(args) != nil || *records == "" || *keyFile == "" {
		usage(stderr)
		return 2
	}
	if *index >= 0 && *logDir == "" {
		fmt.Fprintln(stderr, "-index exige -log")
		return 2
	}
	if *coverage && *logDir == "" {
		fmt.Fprintln(stderr, "-coverage exige -log")
		return 2
	}
	if *coverage && *noCoverage {
		fmt.Fprintln(stderr, "-coverage et -no-coverage s'excluent")
		return 2
	}
	// Couverture par défaut dès qu'un log est fourni ; -index est une vérification ciblée (sauf -coverage explicite).
	runCoverage := *logDir != "" && !*noCoverage && (*index < 0 || *coverage)
	key, err := registry.LoadRecordKey(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "clé :", err)
		return 2
	}
	recs, err := registry.ReadRecords(*records, key)
	if err != nil {
		fmt.Fprintln(stderr, "journal :", err)
		return 2
	}

	var fetch registry.LogFetcher
	var vk string
	if *logDir != "" {
		vk = *vkey
		if *vkeyFile != "" {
			raw, err := os.ReadFile(*vkeyFile)
			if err != nil {
				fmt.Fprintln(stderr, "vkey-file :", err)
				return 2
			}
			vk = string(raw)
		}
		if strings.TrimSpace(vk) == "" {
			fmt.Fprintln(stderr, "-log exige -vkey ou -vkey-file (un checkpoint non vérifié n'est pas une preuve)")
			return 2
		}
		fetch = client.FileFetcher{Root: *logDir}
	}
	var v note.Verifier
	if fetch != nil {
		v, err = registry.NewVerifier(vk)
		if err != nil {
			fmt.Fprintln(stderr, "vkey :", err)
			return 2
		}
	}

	switch {
	case *logDir == "":
		fmt.Fprintln(stderr, "avertissement : sans -log, seule la correspondance hash est vérifiée — ni l'inclusion dans le log signé ni la couverture (une entrée effacée du journal ne serait pas vue)")
	case !runCoverage:
		fmt.Fprintln(stderr, "avertissement : couverture NON vérifiée (-no-coverage ou -index) — une entrée effacée du journal ne serait pas vue ; « 0 échec » ne dit pas « journal complet »")
	}

	ctx := context.Background()
	failed, shown := 0, 0
	for i, r := range recs {
		status := "hash-ok"
		at := ""
		var verr error
		if fetch != nil {
			idx, e := r.VerifyInLog(ctx, fetch, v)
			verr = e
			if e == nil {
				status = "inclus"
				at = fmt.Sprintf(" index=%d", idx)
				if *index >= 0 && int64(idx) != *index {
					continue
				}
			}
			// Une entrée en échec n'a pas d'index établi : même avec -index,
			// on ne la masque pas.
		} else {
			verr = r.VerifyHash()
		}
		shown++
		if verr != nil {
			failed++
			status = failureCode(verr)
		}
		line := fmt.Sprintf("#%d kind=%d cell=%s ts=%s %s%s", i+1, r.Leaf.Kind, r.Leaf.CellID,
			time.Unix(0, r.Leaf.Timestamp).UTC().Format(time.RFC3339Nano), status, at)
		if verr != nil {
			line += " : " + verr.Error()
		}
		if *reveal && verr == nil {
			line += " record=" + base64.StdEncoding.EncodeToString(r.Record)
		}
		fmt.Fprintln(stdout, line)
	}
	if *index >= 0 && shown == 0 {
		fmt.Fprintf(stderr, "aucun enregistrement vérifié pour l'index %d\n", *index)
		return 1
	}
	fmt.Fprintf(stdout, "%d enregistrement(s) examiné(s), %d échec(s)\n", shown, failed)
	if runCoverage {
		uncovered, total, err := uncoveredLeaves(ctx, *logDir, v, recs)
		if err != nil {
			fmt.Fprintln(stderr, "coverage :", err)
			if failed > 0 { // des enregistrements déjà rejetés : c'est un échec de vérification, pas un usage erroné
				return 1
			}
			return 2
		}
		for _, u := range uncovered {
			fmt.Fprintf(stdout, "feuille index=%d kind=%d cell=%s ts=%s SANS-CLAIR : aucune entrée de journal\n", u.index, u.leaf.Kind, u.leaf.CellID,
				time.Unix(0, u.leaf.Timestamp).UTC().Format(time.RFC3339Nano))
		}
		fmt.Fprintf(stdout, "%d feuille(s) dans le log, %d sans entrée de journal\n", total, len(uncovered))
		if len(uncovered) > 0 {
			failed += len(uncovered)
		}
	}
	if failed > 0 {
		return 1
	}
	return 0
}

type uncoveredLeaf struct {
	index int
	leaf  registry.Leaf
}

// uncoveredLeaves relit TOUTES les feuilles du log sous checkpoint signé (supervision.ChainWatcher :
// re-hash, consistance) et rend celles dont aucune entrée du journal ne porte les mêmes octets.
func uncoveredLeaves(ctx context.Context, logDir string, v note.Verifier, recs []registry.SealedRecord) ([]uncoveredLeaf, int, error) {
	leaves, _, err := supervision.NewChainWatcher(ctx, "tbp-audit", logDir, v.Name(), v, 0)
	if err != nil {
		return nil, 0, err
	}
	journaled := make(map[registry.Leaf]int, len(recs))
	for _, r := range recs {
		journaled[r.Leaf]++
	}
	var out []uncoveredLeaf
	for i, l := range leaves {
		if journaled[l] > 0 {
			journaled[l]--
			continue
		}
		out = append(out, uncoveredLeaf{index: i, leaf: l})
	}
	return out, len(leaves), nil
}

func failureCode(err error) string {
	switch {
	case errors.Is(err, registry.ErrRecordNotInLog):
		return "ORPHELIN"
	case errors.Is(err, registry.ErrRecordHashMismatch):
		return "HASH-DIFFÉRENT"
	}
	return "REJETÉ"
}
