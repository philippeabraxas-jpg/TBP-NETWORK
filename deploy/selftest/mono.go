// mono.go — T35 (issue #61) : phase mono-cellule RÉELLE du selftest.
//
// Exécute la séquence documentée dans deploy/cellule.md contre les vrais
// binaires : build de pepd, capabilities OPA générées puis restreintes
// (même recette que policies/gen_capabilities.sh, jq remplacé par Go),
// OPA lancé avec ces capabilities, pepd en monitor, jetons valides et
// témoins, bascule gouvernée monitor→closed (§5.3), scan vérifié du
// registre tessera. Chaque témoin est une faute précise qui DOIT être
// prise — un contrôle qui passerait sans la faute est non-vacuole.
//
// Substitution DEV (documentée dans deploy/cellule.md) : la clé d'émetteur
// est dérivée d'une seed fixe en pure Go, faute de HSM ici. Ce n'est PAS
// une genèse — la vraie cérémonie est scripts/genesis (§12).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	phaseMono     = "mono"
	monoOPAAddr   = "127.0.0.1:18181"
	monoPEPDAddr  = "127.0.0.1:18443"
	monoCellID    = "cell-a"
	// kid de l'émetteur DEV du selftest : 16 octets (32 car. hex) — le
	// keyring pepd rejette toute autre longueur (fail-closed au chargement).
	monoDevKIDHex = "7433352d73656c66746573742d646576" // "t35-selftest-dev"
)

// forbiddenBuiltins : même liste que policies/gen_capabilities.sh (§12).
var forbiddenBuiltins = []string{"http.send", "net.lookup_ip_addr", "time.now_ns", "opa.runtime"}

// evalResponse est la vue locale du verdict du listener.
type evalResponse struct {
	Allow     bool   `json:"allow"`
	Reason    string `json:"reason"`
	Mode      string `json:"mode"`
	Forwarded bool   `json:"forwarded"`
}

// runCmd exécute une commande et capture stdout/stderr séparément.
func runCmd(dir string, env []string, name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	var out, errB strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errB
	err := cmd.Run()
	return out.String(), errB.String(), err
}

// waitHTTP200 attend qu'un endpoint réponde 200 (sonde de démarrage).
func waitHTTP200(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:noctx — sonde locale à timeout borné
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s toujours injoignable après %s", url, timeout)
}

// postJSON POSTe un corps JSON et rend (status, corps).
func postJSON(url string, body any) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// evaluate frappe POST /v1/evaluate et décode le verdict.
func evaluate(pepdURL string, token []byte, action, resource string, epoch uint64) (int, evalResponse, error) {
	status, raw, err := postJSON(pepdURL+"/v1/evaluate", map[string]any{
		"token":    base64.StdEncoding.EncodeToString(token),
		"action":   action,
		"resource": resource,
		"epoch":    epoch,
	})
	var er evalResponse
	if err != nil {
		return status, er, err
	}
	if err := json.Unmarshal(raw, &er); err != nil {
		return status, er, fmt.Errorf("verdict illisible: %w", err)
	}
	return status, er, nil
}

// devKey dérive une clé Ed25519 de test depuis une seed labelisée.
// SUBSTITUTION DEV — jamais une clé de gouvernance (§12).
func devKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("tbp-t35-selftest-dev:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// runMono exécute la phase mono-cellule. Les échecs sont enregistrés dans
// la suite ; la fonction ne rend d'erreur que sur faute d'orchestration.
func runMono(s *suite, cfg config) {
	ctx := context.Background()
	pepdURL := "http://" + monoPEPDAddr
	opaURL := "http://" + monoOPAAddr

	// --- Prérequis : binaires go et opa ------------------------------------
	if _, err := exec.LookPath(cfg.goBin); err != nil {
		s.fail(phaseMono, "prérequis: binaire go", fmt.Errorf("go introuvable (%s) : %w", cfg.goBin, err))
		return
	}
	s.add(phaseMono, "prérequis: binaire go", true, cfg.goBin)
	if _, err := exec.LookPath(cfg.opaBin); err != nil {
		s.fail(phaseMono, "prérequis: binaire opa", fmt.Errorf("opa introuvable (%s) : %w", cfg.opaBin, err))
		return
	}
	s.add(phaseMono, "prérequis: binaire opa", true, cfg.opaBin)

	binDir := filepath.Join(cfg.out, "bin")
	opaDir := filepath.Join(cfg.out, "opa")
	regDir := filepath.Join(cfg.out, "registry", monoCellID)
	for _, d := range []string{binDir, opaDir, regDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			s.fail(phaseMono, "préparation des répertoires", err)
			return
		}
	}

	// --- Étape : build de pepd ---------------------------------------------
	pepdBin := filepath.Join(binDir, "pepd")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", pepdBin, "./src/pep/cmd/pepd"); err != nil {
		s.fail(phaseMono, "build pepd", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(phaseMono, "build pepd (deploy/cellule.md §binaire)", true, pepdBin)

	// --- Témoin : démarrage sans TBP_SALT = refus fail-closed ---------------
	hermetic := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TBP_CELL_ID=" + monoCellID}
	_, errB, err := runCmd(cfg.repo, hermetic, pepdBin)
	if err == nil {
		s.fail(phaseMono, "témoin: pepd sans TBP_SALT refuse de démarrer", fmt.Errorf("pepd a démarré SANS sel — fail-open"))
		return
	}
	s.add(phaseMono, "témoin: pepd sans TBP_SALT refuse de démarrer", true,
		strings.TrimSpace(strings.SplitN(errB, "\n", 2)[0]))

	// --- Étape : capabilities OPA (recette gen_capabilities.sh) -------------
	// 'opa capabilities' SANS --current liste des noms de version (texte) ;
	// le document JSON de CETTE version exige --current.
	fullJSON, errB, err := runCmd(cfg.repo, nil, cfg.opaBin, "capabilities", "--current")
	if err != nil {
		s.fail(phaseMono, "opa capabilities --current", fmt.Errorf("%v — %s", err, errB))
		return
	}
	// Le document capabilities a d'autres clés (features — dont rego_v1 —,
	// future_keywords, wasm_abi_versions) : le filtrage ne touche QUE
	// builtins, le reste est préservé tel quel (sinon « illegal
	// capabilities: rego_v1 feature required » au build).
	var caps map[string]any
	if err := json.Unmarshal([]byte(fullJSON), &caps); err != nil {
		s.fail(phaseMono, "opa capabilities --current", fmt.Errorf("document illisible: %w", err))
		return
	}
	builtins, ok := caps["builtins"].([]any)
	if !ok {
		s.fail(phaseMono, "opa capabilities --current", fmt.Errorf("clé builtins absente ou illisible"))
		return
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
		s.fail(phaseMono, "capabilities: interdits présents AVANT retrait (non-vacuité)",
			fmt.Errorf("absents: %s — la version d'OPA a changé, revoir FORBIDDEN", strings.Join(missingBefore, ", ")))
		return
	}
	s.add(phaseMono, "capabilities: interdits présents AVANT retrait (non-vacuité)", true,
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
		s.fail(phaseMono, "capabilities: écriture du fichier restreint", err)
		return
	}
	// Re-parse du fichier écrit : les interdits ont disparu, le reste du
	// document (features, future_keywords…) est intact.
	var reCaps map[string]any
	reRaw, _ := os.ReadFile(strippedPath)
	if err := json.Unmarshal(reRaw, &reCaps); err != nil {
		s.fail(phaseMono, "capabilities: re-lecture du fichier restreint", err)
		return
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
		s.fail(phaseMono, "capabilities: interdits absents APRÈS retrait", fmt.Errorf("encore présents: %s", strings.Join(leaked, ", ")))
		return
	}
	s.add(phaseMono, "capabilities: interdits absents APRÈS retrait", true,
		fmt.Sprintf("%d built-ins retenus, features préservées=%v", len(reBuiltins), reCaps["features"] != nil))

	// Vérification négative (même motif que gen_capabilities.sh étape 4) :
	// une règle appelant http.send DOIT être refusée au chargement.
	negRule := filepath.Join(cfg.repo, "policies", "testdata", "rule_http_send.rego")
	if _, _, err := runCmd(cfg.repo, nil, cfg.opaBin, "check", "--capabilities", strippedPath, negRule); err == nil {
		s.fail(phaseMono, "capabilities: règle http.send refusée au chargement",
			fmt.Errorf("opa check a ACCEPTÉ %s — le filtrage ne filtre rien", negRule))
		return
	}
	s.add(phaseMono, "capabilities: règle http.send refusée au chargement", true, negRule)

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
		s.fail(phaseMono, "capabilities: règle http.send refusée au BUILD de bundle",
			fmt.Errorf("opa build a ACCEPTÉ %s — le filtrage ne filtre rien", negRule))
		return
	}
	if !strings.Contains(combined, "http.send") {
		s.fail(phaseMono, "capabilities: règle http.send refusée au BUILD de bundle",
			fmt.Errorf("build refusé mais la cause n'est pas http.send : %s", combined))
		return
	}
	s.add(phaseMono, "capabilities: règle http.send refusée au BUILD de bundle", true, "opa build --capabilities")

	// --- Étape : OPA serveur sur le bundle compilé avec capabilities --------
	regoPath := filepath.Join(cfg.repo, "policies", "rego", "action_example.rego")
	bundlePath := filepath.Join(opaDir, "tbp-example.tar.gz")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.opaBin, "build", "--capabilities", strippedPath, regoPath, "-o", bundlePath); err != nil {
		s.fail(phaseMono, "opa build du bundle (capabilities restreintes)", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(phaseMono, "opa build du bundle avec capabilities restreintes", true, bundlePath)

	opaLog, err := os.Create(filepath.Join(opaDir, "opa.log"))
	if err != nil {
		s.fail(phaseMono, "opa run", err)
		return
	}
	defer func() { _ = opaLog.Close() }()
	opaCmd := exec.Command(cfg.opaBin, "run", "--server", "--addr", monoOPAAddr, bundlePath)
	opaCmd.Stdout, opaCmd.Stderr = opaLog, opaLog
	if err := opaCmd.Start(); err != nil {
		s.fail(phaseMono, "opa run", err)
		return
	}
	defer func() { _ = opaCmd.Process.Kill(); _, _ = opaCmd.Process.Wait() }()
	if err := waitHTTP200(opaURL+"/health", 15*time.Second); err != nil {
		s.fail(phaseMono, "opa run (sonde /health)", err)
		return
	}
	s.add(phaseMono, "opa run avec capabilities restreintes", true, opaURL)

	// --- Étape : environnement pepd (SUBSTITUTION DEV documentée) -----------
	issuer := devKey("issuer")
	issuerPub := issuer.Public().(ed25519.PublicKey)
	keyringPath := filepath.Join(cfg.out, "keyring.dev.json")
	keyring, _ := json.Marshal(map[string]string{monoDevKIDHex: hex.EncodeToString(issuerPub)})
	if err := os.WriteFile(keyringPath, keyring, 0o600); err != nil {
		s.fail(phaseMono, "keyring dev", err)
		return
	}
	regoRaw, err := os.ReadFile(regoPath)
	if err != nil {
		s.fail(phaseMono, "policyID (hash du bundle rego)", err)
		return
	}
	policyID := sha256.Sum256(regoRaw)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		s.fail(phaseMono, "sel registre", err)
		return
	}
	pepdEnv := append(os.Environ(),
		"TBP_CELL_ID="+monoCellID,
		"TBP_SALT="+hex.EncodeToString(salt),
		"TBP_KEYRING_FILE="+keyringPath,
		"TBP_POLICY_ID="+hex.EncodeToString(policyID[:]),
		"TBP_REGISTRY_DIR="+regDir,
		"TBP_LISTEN_ADDR="+monoPEPDAddr,
		"TBP_OPA_ENDPOINT="+opaURL+"/v1/data/tbp/example/action",
	)

	// --- Étape : démarrage pepd — TOUJOURS monitor au boot (§5.3) -----------
	pepdLog, err := os.Create(filepath.Join(cfg.out, "pepd.log"))
	if err != nil {
		s.fail(phaseMono, "pepd démarrage", err)
		return
	}
	defer func() { _ = pepdLog.Close() }()
	pepdCmd := exec.Command(pepdBin)
	pepdCmd.Env = pepdEnv
	pepdCmd.Stdout, pepdCmd.Stderr = pepdLog, pepdLog
	if err := pepdCmd.Start(); err != nil {
		s.fail(phaseMono, "pepd démarrage", err)
		return
	}
	defer func() { _ = pepdCmd.Process.Kill(); _, _ = pepdCmd.Process.Wait() }()
	if err := waitHTTP200(pepdURL+"/healthz", 15*time.Second); err != nil {
		s.fail(phaseMono, "pepd démarrage (sonde /healthz)", err)
		return
	}
	s.add(phaseMono, "pepd démarré (OPA branché, registre réel)", true, pepdURL)

	// Posture au démarrage : monitor, jamais closed (§5.3).
	resp, err := http.Get(pepdURL + "/v1/mode") //nolint:noctx
	if err != nil {
		s.fail(phaseMono, "posture initiale = monitor", err)
		return
	}
	var modeView struct {
		Mode string `json:"mode"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&modeView)
	_ = resp.Body.Close()
	s.add(phaseMono, "posture initiale = monitor (§5.3)", modeView.Mode == "monitor", "mode="+modeView.Mode)

	// --- Étape : jeton valide (action « read » → allow OPA) -----------------
	kid, _ := hex.DecodeString(monoDevKIDHex)
	mintOK := func(action string) ([]byte, error) {
		jti := make([]byte, 16)
		_, _ = rand.Read(jti)
		now := time.Now().Unix()
		// TTL du jeton borné à [30, 60] s par le validateur
		// (src/pep/validator.go) : 45 s — hors de cette fenêtre, le refus
		// serait ttl-out-of-range et les témoins ne prouveraient rien.
		return mintToken(issuer, mintClaims{
			iss: "selftest-dev", sub: "agent-1",
			exp: now + 45, iat: now,
			jti: jti, policyID: policyID[:],
			action: action, resource: "doc-1",
			class: 1, epoch: 0, version: 1, kid: kid,
		})
	}
	tokRead, err := mintOK("read")
	if err != nil {
		s.fail(phaseMono, "menthe jeton read", err)
		return
	}
	_, er, err := evaluate(pepdURL, tokRead, "read", "doc-1", 0)
	s.add(phaseMono, "monitor: jeton valide (read) → allow, forwardé (log only)",
		err == nil && er.Allow && er.Forwarded && er.Mode == "monitor",
		fmt.Sprintf("allow=%v forwarded=%v reason=%s", er.Allow, er.Forwarded, er.Reason))

	// --- Témoin : action hors politique (write → deny OPA), monitor ---------
	tokWrite, _ := mintOK("write")
	_, er, err = evaluate(pepdURL, tokWrite, "write", "doc-1", 0)
	// La raison DOIT être le veto OPA (opa_*) : un deny pour une autre cause
	// (signature, TTL…) rendrait ce témoin non-vacuole.
	s.add(phaseMono, "monitor: témoin write → deny OPA, forwardé quand même (§5.3)",
		err == nil && !er.Allow && er.Forwarded && strings.HasPrefix(er.Reason, "opa"),
		fmt.Sprintf("allow=%v forwarded=%v reason=%s", er.Allow, er.Forwarded, er.Reason))

	// --- Témoin : clé inconnue (rogue) → refus validateur -------------------
	rogue := devKey("rogue")
	rogueKID, _ := hex.DecodeString("726f6775652d73656c66746573742d6431") // "rogue-selftest-d1" — absent du keyring
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := time.Now().Unix()
	tokRogue, _ := mintToken(rogue, mintClaims{
		iss: "selftest-dev", sub: "agent-2",
		exp: now + 45, iat: now, // TTL conforme : le refus vient de la CLÉ, rien d'autre
		jti: jti, policyID: policyID[:],
		action: "read", resource: "doc-1",
		class: 1, epoch: 0, version: 1, kid: rogueKID,
	})
	_, er, err = evaluate(pepdURL, tokRogue, "read", "doc-1", 0)
	s.add(phaseMono, "témoin: jeton signé par une clé inconnue → refus",
		err == nil && !er.Allow,
		fmt.Sprintf("allow=%v reason=%s", er.Allow, er.Reason))

	// --- Étape : bascule gouvernée monitor→closed (§5.3) --------------------
	status, _, _ := postJSON(pepdURL+"/v1/mode", map[string]any{"mode": "closed", "signers": []string{"op-1"}})
	s.add(phaseMono, "bascule closed: 1 signataire < quorum → 403", status == http.StatusForbidden,
		fmt.Sprintf("status=%d", status))
	status, _, _ = postJSON(pepdURL+"/v1/mode", map[string]any{"mode": "closed", "signers": []string{"op-1", "op-2"}})
	s.add(phaseMono, "bascule closed: quorum 2/2 → 200", status == http.StatusOK,
		fmt.Sprintf("status=%d", status))
	resp, err = http.Get(pepdURL + "/v1/mode") //nolint:noctx
	if err == nil {
		_ = json.NewDecoder(resp.Body).Decode(&modeView)
		_ = resp.Body.Close()
	}
	s.add(phaseMono, "posture effective = closed après quorum", modeView.Mode == "closed", "mode="+modeView.Mode)

	// --- Post-closed : le verdict s'APPLIQUE --------------------------------
	tokWrite2, _ := mintOK("write")
	_, er, err = evaluate(pepdURL, tokWrite2, "write", "doc-1", 0)
	s.add(phaseMono, "closed: write → deny BLOQUÉ (forwarded=false)",
		err == nil && !er.Allow && !er.Forwarded,
		fmt.Sprintf("allow=%v forwarded=%v", er.Allow, er.Forwarded))
	tokRead2, _ := mintOK("read")
	_, er, err = evaluate(pepdURL, tokRead2, "read", "doc-1", 0)
	s.add(phaseMono, "closed: read → allow forwardé",
		err == nil && er.Allow && er.Forwarded,
		fmt.Sprintf("allow=%v forwarded=%v", er.Allow, er.Forwarded))

	// --- Étape : registre — chaque décision laisse une feuille (§4.1) -------
	// Non-vacuité par DELTA. Une évaluation ALLOW écrit exactement DEUX
	// feuilles KindDecision : le verdict du validateur ET l'ouverture du
	// passeport de quota (§4.1-bis — src/pep/validator.go + src/pep/quota.go).
	before, err := countKinds(ctx, monoCellID, regDir)
	if err != nil {
		s.fail(phaseMono, "registre: scan vérifié", err)
		return
	}
	tokDelta, _ := mintOK("read")
	if _, _, err := evaluate(pepdURL, tokDelta, "read", "doc-1", 0); err != nil {
		s.fail(phaseMono, "registre: évaluation delta", err)
		return
	}
	// tessera intègre de façon asynchrone : borne courte de repli.
	var after map[byte]int
	for i := 0; i < 20; i++ {
		time.Sleep(150 * time.Millisecond)
		after, err = countKinds(ctx, monoCellID, regDir)
		if err == nil && after[registry.KindDecision] > before[registry.KindDecision] {
			break
		}
	}
	if err != nil {
		s.fail(phaseMono, "registre: re-scan", err)
		return
	}
	s.add(phaseMono, "registre: une évaluation allow = verdict + passeport (delta KindDecision +2, §4.1-bis)",
		after[registry.KindDecision] == before[registry.KindDecision]+2,
		fmt.Sprintf("avant=%d après=%d", before[registry.KindDecision], after[registry.KindDecision]))
	s.add(phaseMono, "registre: ≥6 décisions tracées (valides + témoins)",
		after[registry.KindDecision] >= 6, fmt.Sprintf("KindDecision=%d", after[registry.KindDecision]))
	s.add(phaseMono, "registre: bascule de posture tracée (KindTelemetry ≥ 1)",
		after[registry.KindTelemetry] >= 1, fmt.Sprintf("KindTelemetry=%d", after[registry.KindTelemetry]))
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
