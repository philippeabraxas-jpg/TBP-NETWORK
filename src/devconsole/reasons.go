package devconsole

import (
	_ "embed"
	"strings"
)

// reasons.tsv est la copie embarquée de scripts/devtest/reasons.tsv (le CLI `m1 trace` la lit là) : un test vérifie
// qu'elles sont identiques, pour que les deux affichages expliquent les raisons de la même façon.
//
//go:embed reasons.tsv
var reasonsTSV string

// Why est l'explication d'un code de raison.
type Why struct {
	Where   string `json:"where"`
	Meaning string `json:"meaning"`
}

var catalogue = parseCatalogue(reasonsTSV)

func parseCatalogue(tsv string) map[string]Why {
	out := map[string]Why{}
	for _, line := range strings.Split(tsv, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		out[f[0]] = Why{Where: f[1], Meaning: f[2]}
	}
	return out
}

// Explain rend l'explication d'une raison, si le catalogue la connaît.
func Explain(reason string) (Why, bool) {
	w, ok := catalogue[reason]
	return w, ok
}

// whyText : « raison — où : sens », ou la raison seule si elle n'est pas au catalogue.
func whyText(reason string) string {
	if reason == "" {
		return ""
	}
	if w, ok := catalogue[reason]; ok {
		return reason + " — " + w.Where + ": " + w.Meaning
	}
	return reason
}
