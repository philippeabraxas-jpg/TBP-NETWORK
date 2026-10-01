package ano

// rules.go — règles de détection DÉCLARATIVES d'ano (#178). Fixées au
// déploiement, jamais déclarées par l'agent (même doctrine que le registre
// d'agents, #125) : ce sont elles, et l'éventuel classifieur local, qui
// décident quelles valeurs ne sortent pas de la cellule.
//
// Format JSON :
//
//	{
//	  "keep_paths": ["action", "meta"],
//	  "mask_paths": ["beneficiary", "items.*.iban"],
//	  "patterns":   [{"name": "iban", "regex": "\\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\\b"}]
//	}
//
// Un chemin est une suite de segments séparés par « . » (clés d'objet ou
// index de tableau) ; « * » remplace exactement un segment. Un chemin
// s'applique à tout ce qui se trouve SOUS lui (préfixe) : « beneficiary »
// couvre beneficiary.name, beneficiary.account.number…
//
// Précédence entre keep_paths et mask_paths : la règle au préfixe le plus
// LONG l'emporte ; à longueur égale, le masquage l'emporte (la direction
// sûre — une fuite est pire qu'un champ masqué en trop).
//
// « Garder » dispense la feuille du CLASSIFIEUR (et du masquage par défaut),
// jamais des MOTIFS (#237) : une chaîne sous keep_paths qui contient un IBAN
// voit la plage remplacée par un jeton, le reste de la chaîne passe tel quel.
// Seul mask_paths masque une feuille en entier ; seule une chaîne SANS motif
// sort inchangée d'un chemin gardé.
//
// Les motifs sont des regex RE2 (bibliothèque standard Go : temps linéaire,
// pas de retour arrière catastrophique) appliquées aux CHAÎNES restantes
// (celles qui ne sont pas masquées en entier). Ils ne sont jamais
// désactivables par le classifieur : « l'IA ne peut que renforcer ».

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Bornes des règles (état borné, §4.3).
const (
	maxRulePaths    = 256
	maxRulePatterns = 64
	maxPatternLen   = 512
	maxPathSegments = 16
)

// Erreurs de configuration des règles (fail-closed dès le chargement).
var (
	ErrRules = errors.New("ano: règles invalides")
)

// PatternRule est un motif nommé (JSON).
type PatternRule struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

// RulesConfig est la forme JSON des règles.
type RulesConfig struct {
	KeepPaths []string      `json:"keep_paths"`
	MaskPaths []string      `json:"mask_paths"`
	Patterns  []PatternRule `json:"patterns"`
}

type pathRule []string

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

// Rules est un jeu de règles compilé et validé. Immuable après création :
// sûr pour un usage concurrent.
type Rules struct {
	keep     []pathRule
	mask     []pathRule
	patterns []compiledPattern
}

// ParseRules décode et valide une configuration JSON de règles.
func ParseRules(data []byte) (*Rules, error) {
	var cfg RulesConfig
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: JSON illisible: %v", ErrRules, err)
	}
	return NewRules(cfg)
}

// NewRules valide et compile une configuration.
func NewRules(cfg RulesConfig) (*Rules, error) {
	if len(cfg.KeepPaths) > maxRulePaths || len(cfg.MaskPaths) > maxRulePaths {
		return nil, fmt.Errorf("%w: plus de %d chemins", ErrRules, maxRulePaths)
	}
	if len(cfg.Patterns) > maxRulePatterns {
		return nil, fmt.Errorf("%w: plus de %d motifs", ErrRules, maxRulePatterns)
	}
	r := &Rules{}
	for _, p := range cfg.KeepPaths {
		pr, err := parsePath(p)
		if err != nil {
			return nil, err
		}
		r.keep = append(r.keep, pr)
	}
	for _, p := range cfg.MaskPaths {
		pr, err := parsePath(p)
		if err != nil {
			return nil, err
		}
		r.mask = append(r.mask, pr)
	}
	seen := map[string]bool{}
	for _, p := range cfg.Patterns {
		if !validPatternName(p.Name) {
			return nil, fmt.Errorf("%w: nom de motif %q (1–32 caractères [a-z0-9_-])", ErrRules, p.Name)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("%w: motif %q dupliqué", ErrRules, p.Name)
		}
		seen[p.Name] = true
		if p.Regex == "" || len(p.Regex) > maxPatternLen {
			return nil, fmt.Errorf("%w: motif %q hors bornes (1–%d octets)", ErrRules, p.Name, maxPatternLen)
		}
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("%w: motif %q: %v", ErrRules, p.Name, err)
		}
		// Un motif qui reconnaît la chaîne vide produirait des spans vides :
		// refusé dès le chargement plutôt que géré à chaque évaluation.
		if re.MatchString("") {
			return nil, fmt.Errorf("%w: motif %q reconnaît la chaîne vide", ErrRules, p.Name)
		}
		r.patterns = append(r.patterns, compiledPattern{name: p.Name, re: re})
	}
	return r, nil
}

func validPatternName(n string) bool {
	if len(n) < 1 || len(n) > 32 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func parsePath(p string) (pathRule, error) {
	if p == "" {
		return nil, fmt.Errorf("%w: chemin vide", ErrRules)
	}
	segs := strings.Split(p, ".")
	if len(segs) > maxPathSegments {
		return nil, fmt.Errorf("%w: chemin %q de plus de %d segments", ErrRules, p, maxPathSegments)
	}
	for _, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("%w: chemin %q avec un segment vide", ErrRules, p)
		}
	}
	return pathRule(segs), nil
}

// matchLen rend la longueur du chemin de règle si celui-ci est un préfixe
// (avec jokers) de path, sinon -1.
func (pr pathRule) matchLen(path []string) int {
	if len(pr) > len(path) {
		return -1
	}
	for i, seg := range pr {
		if seg != "*" && seg != path[i] {
			return -1
		}
	}
	return len(pr)
}

type verdict int

const (
	verdictNone verdict = iota
	verdictKeep
	verdictMask
)

// decide applique keep/mask au chemin d'une feuille (précédence : préfixe le
// plus long ; à égalité le masquage l'emporte).
func (r *Rules) decide(path []string) verdict {
	keepLen, maskLen := -1, -1
	for _, pr := range r.keep {
		if l := pr.matchLen(path); l > keepLen {
			keepLen = l
		}
	}
	for _, pr := range r.mask {
		if l := pr.matchLen(path); l > maskLen {
			maskLen = l
		}
	}
	switch {
	case maskLen >= 0 && maskLen >= keepLen:
		return verdictMask
	case keepLen >= 0:
		return verdictKeep
	default:
		return verdictNone
	}
}

// span est une plage d'octets à masquer dans une chaîne.
type span struct {
	start, end int
}

// findSpans rend les plages à masquer dans s : toutes les occurrences de
// tous les motifs, évaluées sur la chaîne d'ORIGINE (jamais l'une sur la
// sortie de l'autre — un motif pourrait sinon reconnaître un jeton déjà
// posé), puis résolues de façon déterministe : début croissant, plage la
// plus longue d'abord, chevauchements écartés.
func (r *Rules) findSpans(s string) []span {
	if len(r.patterns) == 0 || s == "" {
		return nil
	}
	var all []span
	for _, p := range r.patterns {
		for _, m := range p.re.FindAllStringIndex(s, -1) {
			if m[1] > m[0] {
				all = append(all, span{m[0], m[1]})
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	// tri : début croissant, longueur décroissante
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && lessSpan(all[j], all[j-1]); j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}
	out := all[:0:0]
	last := 0
	for _, sp := range all {
		if sp.start >= last {
			out = append(out, sp)
			last = sp.end
		}
	}
	return out
}

func lessSpan(a, b span) bool {
	if a.start != b.start {
		return a.start < b.start
	}
	return (a.end - a.start) > (b.end - b.start)
}
