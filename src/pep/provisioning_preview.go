package pep

// provisioning_preview.go — la condition de transition RECALCULÉE hors de la machine qu'on contrôle (#264).
//
// Depuis #236 une preuve de transition porte l'état de départ ET l'état cible :
// « base|from=<hex>|to=<hex> ». Cette condition n'était affichée que par le démon qui REFUSE de
// démarrer : les contrôleurs signaient un condensé fourni par la machine qu'ils sont censés contrôler.
// Chaque démon (pepd, brokerd, anod) sait maintenant la recalculer à la demande :
//
//	<démon> -print-provisioning-condition -cell-vkey cell_log.vkey [-binary FICHIER]
//
// sur le poste du contrôleur, avec SA configuration (le même environnement que le démon), les
// fichiers QU'IL A RELUS et une COPIE du témoin. Le démon n'écrit rien, ne signe rien, n'ouvre pas son
// journal : il mesure avec le même code que le démarrage (registry.PreviewProvisioning) et imprime.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// PrintConditionFlag est l'argument qui déclenche le recalcul dans chaque démon.
const PrintConditionFlag = "-print-provisioning-condition"

// PrintConditionArgs est la ligne de commande du recalcul.
type PrintConditionArgs struct {
	CellVKey string // clé PUBLIQUE de la cellule (cell_log.vkey) : vérifie le témoin copié
	Binary   string // anod : le binaire à mesurer (défaut : l'exécutable courant)
}

// ParsePrintConditionArgs lit les arguments qui suivent PrintConditionFlag.
func ParsePrintConditionArgs(args []string, stderr io.Writer) (PrintConditionArgs, error) {
	var a PrintConditionArgs
	fs := flag.NewFlagSet("print-provisioning-condition", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&a.CellVKey, "cell-vkey", "", "clé publique de la cellule (cell_log.vkey) — vérifie la copie du témoin")
	fs.StringVar(&a.Binary, "binary", "", "binaire à mesurer (anod ; défaut : l'exécutable courant)")
	if err := fs.Parse(args); err != nil {
		return a, err
	}
	if a.CellVKey == "" {
		return a, errors.New("-cell-vkey requis : sans la clé publique de la cellule, le témoin copié ne prouve rien")
	}
	return a, nil
}

// CellVerifierFromFile lit la clé publique de la cellule (format note).
func CellVerifierFromFile(path string) (note.Verifier, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("-cell-vkey : %w", err)
	}
	v, err := registry.NewVerifier(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("-cell-vkey : %w", err)
	}
	return v, nil
}

// WriteProvisioningPreview imprime ce que le contrôleur compare à ce qu'il a relu, puis la
// condition à signer. Forme stable, lisible par un script (« clé=valeur »).
func WriteProvisioningPreview(w io.Writer, base, component string, pv registry.ProvisioningPreview) {
	state := "divergent"
	switch {
	case !pv.WitnessPresent:
		state = "no-witness"
	case pv.Conforming:
		state = "conforming"
	}
	fmt.Fprintf(w, "component=%s\nstate=%s\n", component, state)
	if pv.WitnessPresent {
		fmt.Fprintf(w, "witness_seq=%d\n", pv.Seq)
	}
	fmt.Fprintf(w, "from=%x\nto=%x\n", pv.From, pv.To)
	if pv.Changed != "" {
		fmt.Fprintf(w, "changed=%s\n", pv.Changed)
	}
	for _, f := range pv.Files {
		fmt.Fprintf(w, "file %s sha256=%x\n", f.Name, f.Hash)
	}
	switch state {
	case "conforming":
		fmt.Fprintln(w, "aucune transition à signer : l'état mesuré est celui du témoin")
	case "no-witness":
		fmt.Fprintln(w, "pas de témoin : premier démarrage (aucune preuve) ; pour ré-engager un témoin EFFACÉ, signer la condition ci-dessous (from nul)")
		fmt.Fprintf(w, "condition=%s\n", TransitionCondition(base, pv.From, pv.To))
	default:
		fmt.Fprintf(w, "condition=%s\n", TransitionCondition(base, pv.From, pv.To))
	}
}
