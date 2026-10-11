package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// Issue #265 : pepd ne doit enregistrer que des conditions fail-closed qu'un détecteur de ce dépôt peut
// déclencher. L'opérateur lit la liste (GET /v1/failclosed) ; une condition enregistrée mais jamais déclenchée
// lui laisse croire à un verrou qui n'existe pas. « ancrage en retard » et « disque registre haut » l'étaient.
//
// failClosedDetectors nomme, pour chaque condition enregistrée, la constante Go que son détecteur passe à
// OnTrip. Ajouter une condition à failClosedConditions oblige à l'ajouter ici — donc à désigner son détecteur.
var failClosedDetectors = map[string]string{
	pep.ReasonOPATimeout:              "ReasonOPATimeout",
	pep.ReasonOPAStalled:              "ReasonOPAStalled",
	pep.ReasonOPAUnreachable:          "ReasonOPAUnreachable",
	pep.ReasonOPAError:                "ReasonOPAError",
	pep.ReasonOPABadResponse:          "ReasonOPABadResponse",
	pep.ReasonOPARevisionUnverifiable: "ReasonOPARevisionUnverifiable",
	pep.ReasonOPARevisionMismatch:     "ReasonOPARevisionMismatch",
	pep.ReasonClockSkew:               "ReasonClockSkew",
	pep.TripReasonJTISaturated:        "TripReasonJTISaturated",
	pep.TripReasonQuotaSaturated:      "TripReasonQuotaSaturated",
}

func TestEveryRegisteredFailClosedConditionIsNamedWithItsDetector(t *testing.T) {
	var got, want []string
	for _, c := range failClosedConditions() {
		got = append(got, c.name)
	}
	for name := range failClosedDetectors {
		want = append(want, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("conditions enregistrées = %v, détecteurs nommés = %v — chaque condition enregistrée désigne son détecteur", got, want)
	}
}

func TestReservedConditionsWithoutDetectorAreNotRegistered(t *testing.T) {
	for _, c := range failClosedConditions() {
		if c.name == pep.CondAnchorLag || c.name == pep.CondRegistryDiskHigh {
			t.Errorf("%s enregistrée alors qu'aucun détecteur ne la déclenche (#265)", c.name)
		}
	}
}

// Chaque condition enregistrée est RÉELLEMENT référencée par du code de production autre que sa déclaration et
// que la liste d'enregistrement : sinon le détecteur nommé plus haut n'existe pas.
func TestEveryRegisteredFailClosedConditionHasAProductionDetector(t *testing.T) {
	root := filepath.Join("..", "..", "..") // src/
	var files []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == "main.go" && strings.HasSuffix(filepath.Dir(path), filepath.Join("pep", "cmd", "pepd")) {
			return nil // la liste d'enregistrement n'est pas un détecteur
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("aucun source de production parcouru — le test ne prouverait rien")
	}
	srcs := make(map[string][]string, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		srcs[f] = strings.Split(string(b), "\n")
	}
	for _, c := range failClosedConditions() {
		ident := failClosedDetectors[c.name]
		use := regexp.MustCompile(`\b` + ident + `\b`)
		decl := regexp.MustCompile(`^\s*(const\s+)?` + ident + `\s*=`)
		found := false
		for _, lines := range srcs {
			for _, ln := range lines {
				trim := strings.TrimSpace(ln)
				if strings.HasPrefix(trim, "//") || decl.MatchString(ln) {
					continue
				}
				if use.MatchString(ln) {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("%s (%s) : aucun code de production ne la déclenche — ne pas l'enregistrer (#265)", c.name, ident)
		}
	}
}
