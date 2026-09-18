// policies/validate_determinism.go — T2 (issue #4)
//
// Validateur du profil de déterminisme du langage de règles contraint
// (spec §11.3, §12) :
//
//	A. stratification — détection de cycles dans le graphe de dépendances
//	   des règles du bundle (§11.3 : monotone, ordre-indépendant,
//	   stratifié ; stratification = détection de cycles) ;
//	B. constructions ordre-dépendantes — agrégations dont le résultat
//	   dépend de l'ordre d'itération (§12 : constructions ordonnées
//	   uniquement — listes, clés triées) ;
//	C. stabilité — K évaluations identiques doivent produire des sorties
//	   identiques (§12 : test CI d'ordre-stabilité).
//
// Une politique qui casse le profil est rejetée en CI : ajuster des règles
// re-dessine les périmètres — c'est un acte de gouvernance (§11.3).
//
// Le validateur s'appuie sur le binaire `opa` déployé (parse --format json
// pour l'AST, eval pour la stabilité) : comme pour capabilities.json (T1),
// c'est la version réellement déployée qui fait foi, pas une réimplémentation.
//
// Usage :
//
//	go run policies/validate_determinism.go \
//	    -rego-dir policies/rego -fixtures policies/testdata/stability
//	go run policies/validate_determinism.go -selftest \
//	    -invalid-dir policies/testdata/invalid
//
// Code de sortie : 0 si le bundle respecte le profil, 1 sinon.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const exitViolation = 1

// finding est une violation du profil de déterminisme, rattachée à la
// section de la spec qui l'interdit.
type finding struct {
	Section string // référence spec (ex. "§11.3")
	Rule    string // règle concernée (node id) ou fichier
	Message string
}

// ---------------------------------------------------------------------------
// AST Rego (opa parse --format json) — structures minimales
// ---------------------------------------------------------------------------

// module est un fichier .rego parsé. On ne type que ce qu'on utilise ;
// le reste est parcouru en map[string]any générique.
type module struct {
	path    string   // chemin du fichier source
	pkgPath []string // ["tbp","example","action"] (sans "data")
	rules   []rule
	raw     map[string]any
}

type rule struct {
	name string
	node string // "data.tbp.example.action.allow"
	raw  map[string]any
}

func main() {
	var (
		regoDir     = flag.String("rego-dir", "policies/rego", "répertoire du bundle de règles à valider")
		fixturesDir = flag.String("fixtures", "policies/testdata/stability", "fixtures de stabilité (*.json)")
		invalidDir  = flag.String("invalid-dir", "policies/testdata/invalid", "fixtures invalides (selftest)")
		opaBin      = flag.String("opa", "opa", "binaire opa de la version déployée")
		k           = flag.Int("k", 10, "nombre d'évaluations pour le test de stabilité (§12)")
		selfTest    = flag.Bool("selftest", false, "valide le validateur contre les fixtures invalides")
	)
	flag.Parse()

	if *selfTest {
		os.Exit(runSelfTest(*opaBin, *invalidDir, *k))
	}

	findings, err := validateBundle(*opaBin, *regoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(exitViolation)
	}

	stabFindings, err := checkStability(*opaBin, *regoDir, *fixturesDir, *k)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(exitViolation)
	}
	findings = append(findings, stabFindings...)

	report(findings)
	if len(findings) > 0 {
		os.Exit(exitViolation)
	}
}

// validateBundle exécute les contrôles statiques (A et B) sur un bundle.
func validateBundle(opaBin, regoDir string) ([]finding, error) {
	modules, err := parseDir(opaBin, regoDir)
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("aucun fichier .rego dans %s", regoDir)
	}

	var findings []finding
	findings = append(findings, checkCycles(modules)...)
	findings = append(findings, checkOrderSensitivity(modules)...)
	return findings, nil
}

// ---------------------------------------------------------------------------
// Parsing via le binaire OPA déployé
// ---------------------------------------------------------------------------

func parseDir(opaBin, dir string) ([]module, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.rego"))
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	var modules []module
	for _, path := range entries {
		m, err := parseFile(opaBin, path)
		if err != nil {
			return nil, err
		}
		modules = append(modules, m)
	}
	return modules, nil
}

func parseFile(opaBin, path string) (module, error) {
	out, err := exec.Command(opaBin, "parse", "--format", "json",
		"--json-include", "-comments", path).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return module{}, fmt.Errorf("opa parse %s: %s", path, ee.Stderr)
		}
		return module{}, fmt.Errorf("opa parse %s: %w", path, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(out, &raw); err != nil {
		return module{}, fmt.Errorf("AST JSON invalide pour %s: %w", path, err)
	}

	m := module{path: path, raw: raw}
	// package.path = [{"var":"data"}, {"string":"tbp"}, ...]
	for _, term := range asList(asMap(raw["package"]), "path") {
		if t, ok := term.(map[string]any); ok && t["type"] == "string" {
			m.pkgPath = append(m.pkgPath, t["value"].(string))
		}
	}
	pkg := "data." + strings.Join(m.pkgPath, ".")
	for _, r := range asList(raw, "rules") {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		name, _ := asMap(rm["head"])["name"].(string)
		m.rules = append(m.rules, rule{name: name, node: pkg + "." + name, raw: rm})
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// A. Stratification — détection de cycles (§11.3)
// ---------------------------------------------------------------------------

// edge est une dépendance inter-règles, marquée si elle passe par une
// négation (négation sur un cycle = non stratifiable).
type edge struct {
	to      string
	negated bool
}

// checkCycles construit le graphe de dépendances inter-règles du bundle et
// y détecte les cycles. Une négation sur un cycle est signalée
// explicitement (négation non stratifiable).
func checkCycles(modules []module) []finding {
	nodes := map[string]bool{}
	for _, m := range modules {
		for _, r := range m.rules {
			nodes[r.node] = true
		}
	}

	adj := map[string][]edge{}

	for _, m := range modules {
		// Noms de règles du package courant — une variable de corps qui
		// porte le nom d'une règle du même package est une référence à
		// cette règle (ex. `not allow`).
		local := map[string]string{}
		for _, r := range m.rules {
			local[r.name] = r.node
		}
		for _, r := range m.rules {
			for _, e := range collectRuleRefs(r.raw, local, nodes) {
				adj[r.node] = append(adj[r.node], e)
			}
		}
	}

	var findings []finding
	visited := map[string]int{} // 0=inconnu, 1=en cours, 2=terminé
	var stack []string

	var dfs func(u string, neg bool) bool
	dfs = func(u string, viaNeg bool) bool {
		visited[u] = 1
		stack = append(stack, u)
		for _, e := range adj[u] {
			if visited[e.to] == 1 {
				// cycle détecté : stack[idx:] + e.to
				idx := 0
				for i, n := range stack {
					if n == e.to {
						idx = i
						break
					}
				}
				cycle := append(append([]string{}, stack[idx:]...), e.to)
				msg := "cycle de dépendances : " + strings.Join(cycle, " → ")
				if viaNeg || e.negated {
					msg += " (négation sur le cycle — non stratifiable)"
				}
				findings = append(findings, finding{Section: "§11.3", Rule: u, Message: msg})
				return true
			}
			if visited[e.to] == 0 && dfs(e.to, e.negated) {
				return true
			}
		}
		stack = stack[:len(stack)-1]
		visited[u] = 2
		return false
	}

	for _, m := range modules {
		for _, r := range m.rules {
			if visited[r.node] == 0 {
				dfs(r.node, false)
			}
		}
	}
	return findings
}

// collectRuleRefs extrait les références à des règles du bundle depuis le
// corps d'une règle (y compris la chaîne else).
func collectRuleRefs(raw map[string]any, local map[string]string, nodes map[string]bool) []edge {
	var out []edge

	var walkTerm func(v any, negated bool)
	var walkExpr func(v any, negated bool)

	walkTerm = func(v any, negated bool) {
		switch t := v.(type) {
		case map[string]any:
			switch t["type"] {
			case "ref":
				elems, _ := t["value"].([]any)
				if len(elems) == 0 {
					return
				}
				head, _ := elems[0].(map[string]any)
				if head["type"] != "var" {
					return
				}
				if head["value"] == "data" {
					var parts []string
					for _, e := range elems[1:] {
						if s, ok := e.(map[string]any); ok && s["type"] == "string" {
							parts = append(parts, s["value"].(string))
						}
					}
					// plus long préfixe correspondant à une règle du bundle
					for n := len(parts); n > 0; n-- {
						cand := "data." + strings.Join(parts[:n], ".")
						if nodes[cand] {
							out = append(out, edge{to: cand, negated: negated})
							break
						}
					}
				} else if len(elems) == 1 {
					if node, ok := local[head["value"].(string)]; ok {
						out = append(out, edge{to: node, negated: negated})
					}
				}
				for _, e := range elems {
					walkTerm(e, negated)
				}
			case "var":
				if node, ok := local[t["value"].(string)]; ok {
					out = append(out, edge{to: node, negated: negated})
				}
			default:
				for _, e := range t {
					walkTerm(e, negated)
				}
			}
		case []any:
			for _, e := range t {
				walkTerm(e, negated)
			}
		}
	}

	walkExpr = func(v any, negated bool) {
		m, ok := v.(map[string]any)
		if !ok {
			walkTerm(v, negated)
			return
		}
		neg := negated
		if b, _ := m["negated"].(bool); b {
			neg = true
		}
		walkTerm(m["terms"], neg)
	}

	// corps + chaîne else
	cur := raw
	for cur != nil {
		for _, e := range asList(cur, "body") {
			walkExpr(e, false)
		}
		if h, ok := cur["head"].(map[string]any); ok {
			walkTerm(h["value"], false)
			walkTerm(h["key"], false)
		}
		next, _ := cur["else"].(map[string]any)
		cur = next
	}
	return out
}

// ---------------------------------------------------------------------------
// B. Constructions ordre-dépendantes (§12)
// ---------------------------------------------------------------------------

// orderSensitiveBuiltins : fonctions dont le résultat dépend de l'ordre
// d'itération quand on leur passe une collection non ordonnée (set/object).
// sum/count/min/max/all/any sont commutatives — non listées.
// Heuristique v1, à affiner avec le calibration set (§11.3).
var orderSensitiveBuiltins = map[string]bool{
	"concat": true, // l'ordre de jointure d'un set n'est pas défini
}

func checkOrderSensitivity(modules []module) []finding {
	var findings []finding
	for _, m := range modules {
		for _, r := range m.rules {
			for _, call := range findCalls(r.raw) {
				op := callOperator(call)
				if !orderSensitiveBuiltins[op] {
					continue
				}
				// concat(sep, collection) — la collection est le 2e argument
				if len(call) < 3 {
					continue
				}
				if !orderSafeCollection(call[2]) {
					findings = append(findings, finding{
						Section: "§12",
						Rule:    r.node,
						Message: fmt.Sprintf("%s() sur une collection non ordonnée — passer une liste triée (sort(...)) ou un littéral de liste", op),
					})
				}
			}
		}
	}
	return findings
}

// findCalls retourne toutes les expressions d'appel de l'AST. Deux formes
// dans la sortie de `opa parse --format json` : un terme {"type":"call",
// "value":[op, args...]} (position de valeur, ex. côté droit d'une
// assignation), et la liste brute [op, args...] (position d'expression de
// corps). Dans les deux cas le premier élément est une référence à
// l'opérateur.
func findCalls(v any) [][]any {
	var calls [][]any
	var rec func(x any)
	rec = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			if t["type"] == "call" {
				if l, ok := t["value"].([]any); ok && isCallList(l) {
					calls = append(calls, l)
					for _, e := range l {
						rec(e) // éléments un par un : la liste elle-même est consommée
					}
					return
				}
			}
			for _, e := range t {
				rec(e)
			}
		case []any:
			if isCallList(t) {
				calls = append(calls, t)
			}
			for _, e := range t {
				rec(e)
			}
		}
	}
	rec(v)
	return calls
}

// isCallList : une liste dont le premier élément est une référence à un
// opérateur (var ou chemin de built-in, ex. internal.member_2).
func isCallList(l []any) bool {
	if len(l) == 0 {
		return false
	}
	m, ok := l[0].(map[string]any)
	return ok && m["type"] == "ref"
}

func callOperator(call []any) string {
	head, _ := call[0].(map[string]any)
	elems, _ := head["value"].([]any)
	if len(elems) == 0 {
		return ""
	}
	last, _ := elems[len(elems)-1].(map[string]any)
	name, _ := last["value"].(string)
	return name
}

// orderSafeCollection : la collection passée à une fonction sensible à
// l'ordre est acceptable si c'est un littéral de liste (ordre explicite,
// §12) ou un appel à sort(...) (ordre trié). Un appel apparaît comme terme
// {"type":"call","value":[...]} ou comme liste brute selon la position.
func orderSafeCollection(term any) bool {
	if m, ok := term.(map[string]any); ok {
		if m["type"] == "array" {
			return true
		}
		if m["type"] == "call" {
			if l, ok := m["value"].([]any); ok && callOperator(l) == "sort" {
				return true
			}
		}
		return false
	}
	if l, ok := term.([]any); ok && callOperator(l) == "sort" {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// C. Stabilité — K évaluations identiques (§12)
// ---------------------------------------------------------------------------

type fixture struct {
	Query string          `json:"query"`
	Input json.RawMessage `json:"input"`
}

func checkStability(opaBin, regoDir, fixturesDir string, k int) ([]finding, error) {
	files, err := filepath.Glob(filepath.Join(fixturesDir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		fmt.Printf("note: aucune fixture de stabilité dans %s — contrôle C sauté\n", fixturesDir)
		return nil, nil
	}
	sort.Strings(files)

	var findings []finding
	for _, f := range files {
		ok, detail := stabilityCheckOne(opaBin, regoDir, f, k)
		if !ok {
			findings = append(findings, finding{Section: "§12", Rule: f, Message: detail})
		}
	}
	return findings, nil
}

func stabilityCheckOne(opaBin, regoDir, fixturePath string, k int) (bool, string) {
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		return false, fmt.Sprintf("lecture fixture: %v", err)
	}
	var fx fixture
	if err := json.Unmarshal(data, &fx); err != nil {
		return false, fmt.Sprintf("fixture JSON invalide: %v", err)
	}

	inputFile, err := os.CreateTemp("", "tbp-input-*.json")
	if err != nil {
		return false, fmt.Sprintf("tmpfile: %v", err)
	}
	defer os.Remove(inputFile.Name())
	if _, err := inputFile.Write(fx.Input); err != nil {
		return false, fmt.Sprintf("écriture input: %v", err)
	}
	inputFile.Close()

	var reference string
	for i := 0; i < k; i++ {
		out, err := exec.Command(opaBin, "eval", "--format", "json",
			"-d", regoDir, "-i", inputFile.Name(), fx.Query).Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return false, fmt.Sprintf("opa eval: %s", ee.Stderr)
			}
			return false, fmt.Sprintf("opa eval: %v", err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(out, &parsed); err != nil {
			return false, fmt.Sprintf("sortie eval non JSON: %v", err)
		}
		// json.Marshal trie les clés des maps — sérialisation canonique
		// suffisante pour comparer des résultats structurels (§12).
		canon, err := json.Marshal(parsed["result"])
		if err != nil {
			return false, fmt.Sprintf("canonicalisation: %v", err)
		}
		if i == 0 {
			reference = string(canon)
			continue
		}
		if string(canon) != reference {
			return false, fmt.Sprintf("évaluation %d/%d diverge de la première pour la requête %q — politique non déterministe", i+1, k, fx.Query)
		}
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// Self-test — le validateur doit rejeter les fixtures invalides
// ---------------------------------------------------------------------------

func runSelfTest(opaBin, invalidDir string, k int) int {
	type expectation struct {
		name    string
		regoDir string // bundle à valider (répertoire d'un seul fichier)
		fixture string // répertoire de fixtures de stabilité, ou ""
		want    string // sous-chaîne attendue dans les findings
	}

	// Chaque fixture invalide vit dans son propre sous-répertoire pour être
	// validée isolément comme un bundle.
	expectations := []expectation{
		{"cycle", filepath.Join(invalidDir, "cyclic"), "", "cycle"},
		{"ordre", filepath.Join(invalidDir, "order"), "", "concat"},
		{"non-déterminisme", filepath.Join(invalidDir, "nondet"),
			filepath.Join(invalidDir, "nondet", "stability"), "diverge"},
	}

	failures := 0
	for _, e := range expectations {
		var findings []finding
		fs, err := validateBundle(opaBin, e.regoDir)
		if err != nil {
			fmt.Printf("selftest %-18s ERREUR %v\n", e.name, err)
			failures++
			continue
		}
		findings = append(findings, fs...)
		if e.fixture != "" {
			fs, err := checkStability(opaBin, e.regoDir, e.fixture, k)
			if err != nil {
				fmt.Printf("selftest %-18s ERREUR %v\n", e.name, err)
				failures++
				continue
			}
			findings = append(findings, fs...)
		}
		matched := false
		for _, f := range findings {
			if strings.Contains(f.Message, e.want) {
				matched = true
				break
			}
		}
		if matched {
			fmt.Printf("selftest %-18s OK (rejeté comme attendu)\n", e.name)
		} else {
			fmt.Printf("selftest %-18s ÉCHEC — la fixture invalide n'a PAS été rejetée\n", e.name)
			failures++
		}
	}

	if failures > 0 {
		fmt.Printf("selftest: %d attente(s) non satisfaite(s)\n", failures)
		return exitViolation
	}
	fmt.Println("selftest: toutes les fixtures invalides ont été rejetées")
	return 0
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func report(findings []finding) {
	if len(findings) == 0 {
		fmt.Println("profil de déterminisme respecté (§11.3, §12) — stratification, ordre, stabilité")
		return
	}
	fmt.Printf("profil de déterminisme NON respecté — %d violation(s) :\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  [%s] %s: %s\n", f.Section, f.Rule, f.Message)
	}
	fmt.Println("une politique hors profil est rejetée en CI — ajuster des règles " +
		"re-dessine les périmètres, c'est un acte de gouvernance (§11.3)")
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asList(m map[string]any, key string) []any {
	l, _ := m[key].([]any)
	return l
}
