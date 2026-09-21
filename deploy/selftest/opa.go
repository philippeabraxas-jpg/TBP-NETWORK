// opa.go — T37 (issue #74) : cycle de vie OPA partagé du selftest.
//
// La recette des capabilities restreintes (§12) était inline dans la phase
// mono (T35) ; la phase daemons en a besoin à l'identique (brokerd exige
// un OPA réel, même doctrine que pepd). Extraction de plomberie, pas de
// logique nouvelle : mêmes contrôles, mêmes noms — seule la phase portée
// au rapport change. La recette reste celle de policies/gen_capabilities.sh
// (jq remplacé par Go) ; un guide qui dérive casse ici, pas chez
// l'opérateur.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// forbiddenBuiltins : même liste que policies/gen_capabilities.sh (§12).
var forbiddenBuiltins = []string{"http.send", "net.lookup_ip_addr", "time.now_ns", "opa.runtime"}

// prepareCapabilities génère le document capabilities restreint dans
// opaDir et prouve sa non-vacuité (les interdits existent AVANT le
// retrait — sinon la liste FORBIDDEN est à revoir — et une règle qui en
// appelle un est refusée au chargement COMME au build de bundle). Rend le
// chemin du fichier restreint ; ok=false si un contrôle a cassé (les
// échecs sont déjà enregistrés dans la suite).
func prepareCapabilities(s *suite, phase string, cfg config, opaDir string) (string, bool) {
	// 'opa capabilities' SANS --current liste des noms de version (texte) ;
	// le document JSON de CETTE version exige --current.
	fullJSON, errB, err := runCmd(cfg.repo, nil, cfg.opaBin, "capabilities", "--current")
	if err != nil {
		s.fail(phase, "opa capabilities --current", fmt.Errorf("%v — %s", err, errB))
		return "", false
	}
	// Le document capabilities a d'autres clés (features — dont rego_v1 —,
	// future_keywords, wasm_abi_versions) : le filtrage ne touche QUE
	// builtins, le reste est préservé tel quel (sinon « illegal
	// capabilities: rego_v1 feature required » au build).
	var caps map[string]any
	if err := json.Unmarshal([]byte(fullJSON), &caps); err != nil {
		s.fail(phase, "opa capabilities --current", fmt.Errorf("document illisible: %w", err))
		return "", false
	}
	builtins, ok := caps["builtins"].([]any)
	if !ok {
		s.fail(phase, "opa capabilities --current", fmt.Errorf("clé builtins absente ou illisible"))
		return "", false
	}
	present := map[string]bool{}
	for _, b := range builtins {
		if m, ok := b.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				present[name] = true
			}
		}
	}
	missingBefore := []string{}
	for _, f := range forbiddenBuiltins {
		if !present[f] {
			missingBefore = append(missingBefore, f)
		}
	}
	if len(missingBefore) > 0 {
		s.fail(phase, "capabilities: interdits présents AVANT retrait (non-vacuité)",
			fmt.Errorf("absents: %s — la version d'OPA a changé, revoir FORBIDDEN", strings.Join(missingBefore, ", ")))
		return "", false
	}
	s.add(phase, "capabilities: interdits présents AVANT retrait (non-vacuité)", true,
		fmt.Sprintf("%d built-ins listés", len(builtins)))

	kept := make([]any, 0, len(builtins))
	for _, b := range builtins {
		m, _ := b.(map[string]any)
		name, _ := m["name"].(string)
		if !containsStr(forbiddenBuiltins, name) {
			kept = append(kept, b)
		}
	}
	caps["builtins"] = kept
	strippedPath := filepath.Join(opaDir, "capabilities.stripped.json")
	strippedJSON, _ := json.Marshal(caps)
	if err := os.WriteFile(strippedPath, strippedJSON, 0o644); err != nil {
		s.fail(phase, "capabilities: écriture du fichier restreint", err)
		return "", false
	}
	// Re-parse du fichier écrit : les interdits ont disparu, le reste du
	// document (features, future_keywords…) est intact.
	var reCaps map[string]any
	reRaw, _ := os.ReadFile(strippedPath)
	if err := json.Unmarshal(reRaw, &reCaps); err != nil {
		s.fail(phase, "capabilities: re-lecture du fichier restreint", err)
		return "", false
	}
	reBuiltins, _ := reCaps["builtins"].([]any)
	leaked := []string{}
	for _, b := range reBuiltins {
		m, _ := b.(map[string]any)
		name, _ := m["name"].(string)
		if containsStr(forbiddenBuiltins, name) {
			leaked = append(leaked, name)
		}
	}
	if len(leaked) > 0 {
		s.fail(phase, "capabilities: interdits absents APRÈS retrait", fmt.Errorf("encore présents: %s", strings.Join(leaked, ", ")))
		return "", false
	}
	s.add(phase, "capabilities: interdits absents APRÈS retrait", true,
		fmt.Sprintf("%d built-ins retenus, features préservées=%v", len(reBuiltins), reCaps["features"] != nil))

	// Vérification négative (même motif que gen_capabilities.sh étape 4) :
	// une règle appelant http.send DOIT être refusée au chargement.
	negRule := filepath.Join(cfg.repo, "policies", "testdata", "rule_http_send.rego")
	if _, _, err := runCmd(cfg.repo, nil, cfg.opaBin, "check", "--capabilities", strippedPath, negRule); err == nil {
		s.fail(phase, "capabilities: règle http.send refusée au chargement",
			fmt.Errorf("opa check a ACCEPTÉ %s — le filtrage ne filtre rien", negRule))
		return "", false
	}
	s.add(phase, "capabilities: règle http.send refusée au chargement", true, negRule)

	// Forme serveur OPA ≥ 1.0 : 'opa run' n'a PLUS de flag --capabilities
	// (retiré ; policies/README.md et le rappel de gen_capabilities.sh
	// datent d'OPA 0.x — trou documenté dans deploy/cellule.md). La voie
	// supportée : compiler un bundle AVEC les capabilities restreintes
	// (rejet à la compilation des built-ins interdits) puis exécuter ce
	// bundle. Témoin : la même règle http.send doit casser le BUILD.
	// Le message d'erreur d'opa build sort sur stdout (pas stderr) : le
	// verdict est le code de sortie, le détail joint les deux flux.
	outB, errB, err := runCmd(cfg.repo, nil, cfg.opaBin, "build", "--capabilities", strippedPath, negRule, "-o", filepath.Join(opaDir, "neg.tar.gz"))
	combined := strings.TrimSpace(outB + " " + errB)
	if err == nil {
		s.fail(phase, "capabilities: règle http.send refusée au BUILD de bundle",
			fmt.Errorf("opa build a ACCEPTÉ %s — le filtrage ne filtre rien", negRule))
		return "", false
	}
	if !strings.Contains(combined, "http.send") {
		s.fail(phase, "capabilities: règle http.send refusée au BUILD de bundle",
			fmt.Errorf("build refusé mais la cause n'est pas http.send : %s", combined))
		return "", false
	}
	s.add(phase, "capabilities: règle http.send refusée au BUILD de bundle", true, "opa build --capabilities")
	return strippedPath, true
}

// buildBundle compile le bundle de règles AVEC les capabilities restreintes
// (OPA ≥ 1.0 : la restriction se fige à la compilation du bundle — voir
// deploy/cellule.md étape 4).
func buildBundle(s *suite, phase string, cfg config, capsPath, regoPath, bundlePath string) bool {
	if _, errB, err := runCmd(cfg.repo, nil, cfg.opaBin, "build", "--capabilities", capsPath, regoPath, "-o", bundlePath); err != nil {
		s.fail(phase, "opa build du bundle (capabilities restreintes)", fmt.Errorf("%v — %s", err, errB))
		return false
	}
	s.add(phase, "opa build du bundle avec capabilities restreintes", true, bundlePath)
	return true
}

// opaServer est le cycle de vie d'un OPA serveur lancé par le selftest.
type opaServer struct {
	cmd  *exec.Cmd
	logF *os.File
	addr string
}

// startOPA lance OPA en serveur sur le bundle compilé et sonde /health.
func startOPA(s *suite, phase string, cfg config, addr, bundlePath, logPath string) (*opaServer, bool) {
	opaLog, err := os.Create(logPath)
	if err != nil {
		s.fail(phase, "opa run", err)
		return nil, false
	}
	opaCmd := exec.Command(cfg.opaBin, "run", "--server", "--addr", addr, bundlePath)
	opaCmd.Stdout, opaCmd.Stderr = opaLog, opaLog
	if err := opaCmd.Start(); err != nil {
		_ = opaLog.Close()
		s.fail(phase, "opa run", err)
		return nil, false
	}
	srv := &opaServer{cmd: opaCmd, logF: opaLog, addr: addr}
	if err := waitHTTP200("http://"+addr+"/health", 15*time.Second); err != nil {
		srv.stop()
		s.fail(phase, "opa run (sonde /health)", err)
		return nil, false
	}
	s.add(phase, "opa run avec capabilities restreintes", true, "http://"+addr)
	return srv, true
}

// stop tue le serveur OPA et ferme son journal.
func (o *opaServer) stop() {
	if o == nil || o.cmd == nil || o.cmd.Process == nil {
		return
	}
	_ = o.cmd.Process.Kill()
	_, _ = o.cmd.Process.Wait()
	_ = o.logF.Close()
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
