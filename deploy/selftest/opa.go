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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

// generateSigningKeypair produit une paire RSA 2048 en PEM (PKCS1 privée,
// PKIX publique — le format que `opa build --signing-key`/`opa run
// --verification-key` acceptent, vérifié contre le binaire opa réel) dans
// opaDir. Revue de sécurité #106 : la révision épinglée (#92, A5) est une
// étiquette auto-déclarée au build — quiconque peut écrire le fichier
// bundle peut y mettre la bonne valeur. Seule une signature vérifiée par
// OPA lui-même AVANT de servir prouve que le contenu n'a pas été altéré
// après la signature. La clé PRIVÉE ne quitte jamais la machine qui
// construit les bundles (même frontière de custody que les clés de
// contrôleurs §12) — ici, le selftest EST cette machine ; en déploiement
// réel, voir deploy/cellule.md étape 4.
func generateSigningKeypair(s *suite, phase string, opaDir string) (privPath, pubPath string, ok bool) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.fail(phase, "génération de la paire de signature de bundle (§106)", err)
		return "", "", false
	}
	privPath = filepath.Join(opaDir, "policy-signing.key")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		s.fail(phase, "écriture de la clé privée de signature", err)
		return "", "", false
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		s.fail(phase, "encodage de la clé publique de vérification", err)
		return "", "", false
	}
	pubPath = filepath.Join(opaDir, "policy-verify.pub")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		s.fail(phase, "écriture de la clé publique de vérification", err)
		return "", "", false
	}
	s.add(phase, "paire de signature de bundle générée (RSA 2048, §106)", true, pubPath)
	return privPath, pubPath, true
}

// buildBundle compile le bundle de règles AVEC les capabilities restreintes
// (OPA ≥ 1.0 : la restriction se fige à la compilation du bundle — voir
// deploy/cellule.md étape 4), la révision épinglée (revue de sécurité #92,
// finding A5) ET une signature (revue de sécurité #106, finding : la
// révision seule est une étiquette auto-déclarée, pas une preuve). -b
// (mode bundle) est REQUIS pour que --signing-key prenne effet — vérifié
// contre le binaire opa réel : opa build refuse silencieusement de signer
// sans lui, même avec un chemin de répertoire positionnel par ailleurs
// valide.
func buildBundle(s *suite, phase string, cfg config, capsPath, regoPath, bundlePath, revision, signingKeyPath string) bool {
	regoDir := filepath.Dir(regoPath)
	if _, errB, err := runCmd(cfg.repo, nil, cfg.opaBin, "build",
		"--capabilities", capsPath, "--revision", revision,
		"--signing-key", signingKeyPath, "--signing-alg", "RS256",
		"-b", regoDir, "-o", bundlePath); err != nil {
		s.fail(phase, "opa build du bundle (capabilities restreintes, signé §106)", fmt.Errorf("%v — %s", err, errB))
		return false
	}
	s.add(phase, "opa build du bundle avec capabilities restreintes et signature", true, bundlePath)
	return true
}

// opaServer est le cycle de vie d'un OPA serveur lancé par le selftest.
type opaServer struct {
	cmd  *exec.Cmd
	logF *os.File
	addr string
}

// startOPA lance OPA en serveur sur le bundle compilé, signature VÉRIFIÉE
// (revue de sécurité #106), et sonde /health. --bundle (pas un chemin
// positionnel nu) est REQUIS pour que la vérification de signature
// s'active — vérifié contre le binaire opa réel : un chemin positionnel
// ignore silencieusement --verification-key, ce qui rendrait la
// signature de buildBundle purement cosmétique.
func startOPA(s *suite, phase string, cfg config, addr, bundlePath, verificationKeyPath, logPath string) (*opaServer, bool) {
	opaLog, err := os.Create(logPath)
	if err != nil {
		s.fail(phase, "opa run", err)
		return nil, false
	}
	opaCmd := exec.Command(cfg.opaBin, "run", "--server", "--addr", addr,
		"--bundle", bundlePath, "--verification-key", verificationKeyPath, "--verification-key-id", "default")
	opaCmd.Stdout, opaCmd.Stderr = opaLog, opaLog
	if err := opaCmd.Start(); err != nil {
		_ = opaLog.Close()
		s.fail(phase, "opa run", err)
		return nil, false
	}
	srv := &opaServer{cmd: opaCmd, logF: opaLog, addr: addr}
	if err := waitHTTP200("http://"+addr+"/health", 15*time.Second); err != nil {
		srv.stop()
		s.fail(phase, "opa run (sonde /health, signature vérifiée)", err)
		return nil, false
	}
	s.add(phase, "opa run avec capabilities restreintes et signature vérifiée (§106)", true, "http://"+addr)
	return srv, true
}

// verifyForgedBundleRefused est le témoin NON-VACUE direct de #106 :
// un bundle produit SANS la clé privée pinglée (même capabilities, même
// révision — tout ce qu'un attaquant qui n'a qu'un accès en écriture au
// fichier bundle peut reproduire) doit être refusé par un OPA qui vérifie
// contre la clé publique de la cellule — jamais juste « une autre erreur
// », précisément l'absence de démarrage (le port ne s'ouvre jamais).
// Avant #106, ce même scénario passait : seule la révision (auto-déclarée)
// était comparée.
func verifyForgedBundleRefused(s *suite, phase string, cfg config, capsPath, regoPath, revision, realVerificationKeyPath, opaDir string) bool {
	forgedDir := filepath.Join(opaDir, "forged")
	if err := os.MkdirAll(forgedDir, 0o700); err != nil {
		s.fail(phase, "témoin bundle forgé (§106): préparation du répertoire", err)
		return false
	}
	forgedPriv, _, ok := generateSigningKeypair(s, phase, forgedDir)
	if !ok {
		return false
	}
	forgedBundle := filepath.Join(forgedDir, "bundle.tar.gz")
	if !buildBundle(s, phase, cfg, capsPath, regoPath, forgedBundle, revision, forgedPriv) {
		return false
	}
	addr := "127.0.0.1:18199"
	opaLog, err := os.Create(filepath.Join(forgedDir, "opa.log"))
	if err != nil {
		s.fail(phase, "témoin bundle forgé (§106): journal", err)
		return false
	}
	defer opaLog.Close()
	opaCmd := exec.Command(cfg.opaBin, "run", "--server", "--addr", addr,
		"--bundle", forgedBundle, "--verification-key", realVerificationKeyPath, "--verification-key-id", "default")
	opaCmd.Stdout, opaCmd.Stderr = opaLog, opaLog
	if err := opaCmd.Start(); err != nil {
		s.fail(phase, "témoin bundle forgé (§106): lancement", err)
		return false
	}
	srv := &opaServer{cmd: opaCmd, logF: opaLog, addr: addr}
	defer srv.stop()
	// Même capabilities, même révision, MAIS signé par une clé différente
	// de celle pinglée sur la cellule — la sonde /health ne doit JAMAIS
	// répondre 200 : le port ne s'ouvre pas du tout (échec de vérification
	// au chargement, avant même que le serveur HTTP démarre).
	probeErr := waitHTTP200("http://"+addr+"/health", 3*time.Second)
	if probeErr == nil {
		s.fail(phase, "témoin bundle forgé (§106): OPA a servi un bundle signé par une AUTRE clé",
			fmt.Errorf("/health a répondu 200 — la vérification de signature ne vérifie rien"))
		return false
	}
	s.add(phase, "témoin §106: bundle forgé (autre clé, même révision) refusé par OPA — jamais servi", true, probeErr.Error())
	return true
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
