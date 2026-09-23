// mono.go — T35 (issue #61) : phase mono-cellule RÉELLE du selftest.
//
// Exécute la séquence documentée dans deploy/cellule.md contre les vrais
// binaires : build de pepd, capabilities OPA générées puis restreintes
// (helpers partagés de opa.go — même recette que
// policies/gen_capabilities.sh, jq remplacé par Go), OPA lancé avec ces
// capabilities, pepd en monitor, jetons valides et
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

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	phaseMono    = "mono"
	monoOPAAddr  = "127.0.0.1:18181"
	monoPEPDAddr = "127.0.0.1:18443"
	monoCellID   = "cell-a"
	// kid de l'émetteur DEV du selftest : 16 octets (32 car. hex) — le
	// keyring pepd rejette toute autre longueur (fail-closed au chargement).
	monoDevKIDHex = "7433352d73656c66746573742d646576" // "t35-selftest-dev"
)

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
//
// PAS de champ epoch dans le corps (retiré — revue de sécurité #90, point
// 2) : l'époque n'est plus une entrée de la requête, elle vient
// exclusivement d'EpochSource côté pepd (TBP_BROKER_SOCKET, ou FixedEpoch(0)
// par défaut) — l'envoyer aurait été un paramètre malhonnête, sans effet.
func evaluate(pepdURL string, token []byte, action, resource string) (int, evalResponse, error) {
	status, raw, err := postJSON(pepdURL+"/v1/evaluate", map[string]any{
		"token":    base64.StdEncoding.EncodeToString(token),
		"action":   action,
		"resource": resource,
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
	adminSock := filepath.Join(cfg.out, "pepd-admin.sock")
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
	// Contrôles détaillés dans opa.go (partagés avec la phase daemons, T37).
	strippedPath, ok := prepareCapabilities(s, phaseMono, cfg, opaDir)
	if !ok {
		return
	}

	// --- Étape : OPA serveur sur le bundle compilé avec capabilities --------
	// policyID est calculé AVANT le build (hash des sources rego, pas de
	// l'artefact compilé) : c'est ce qui permet de l'épingler comme
	// révision du bundle SANS circularité (revue de sécurité #92, A5).
	regoPath := filepath.Join(cfg.repo, "policies", "rego", "action_example.rego")
	regoRaw, err := os.ReadFile(regoPath)
	if err != nil {
		s.fail(phaseMono, "policyID (hash du bundle rego)", err)
		return
	}
	policyID := sha256.Sum256(regoRaw)
	bundlePath := filepath.Join(opaDir, "tbp-example.tar.gz")
	// Signature de bundle (revue de sécurité #106) : la révision seule
	// (juste au-dessus) est une étiquette auto-déclarée — seule une
	// signature vérifiée par OPA au chargement prouve que le contenu n'a
	// pas été altéré après coup.
	signingKeyPath, verificationKeyPath, ok := generateSigningKeypair(s, phaseMono, opaDir)
	if !ok {
		return
	}
	if !buildBundle(s, phaseMono, cfg, strippedPath, regoPath, bundlePath, hex.EncodeToString(policyID[:]), signingKeyPath) {
		return
	}
	// Témoin NON-VACUE de #106 : un bundle produit avec la MÊME révision
	// et les MÊMES capabilities mais signé par une AUTRE clé (tout ce
	// qu'un simple accès en écriture au fichier bundle permettrait de
	// reproduire) doit être refusé par un OPA qui vérifie contre la clé
	// pinglée de la cellule.
	if !verifyForgedBundleRefused(s, phaseMono, cfg, strippedPath, regoPath, hex.EncodeToString(policyID[:]), verificationKeyPath, opaDir) {
		return
	}
	opa, ok := startOPA(s, phaseMono, cfg, monoOPAAddr, bundlePath, verificationKeyPath, filepath.Join(opaDir, "opa.log"))
	if !ok {
		return
	}
	defer opa.stop()

	// --- Étape : environnement pepd (SUBSTITUTION DEV documentée) -----------
	issuer := devKey("issuer")
	issuerPub := issuer.Public().(ed25519.PublicKey)
	keyringPath := filepath.Join(cfg.out, "keyring.dev.json")
	keyring, _ := json.Marshal(map[string]string{monoDevKIDHex: hex.EncodeToString(issuerPub)})
	if err := os.WriteFile(keyringPath, keyring, 0o600); err != nil {
		s.fail(phaseMono, "keyring dev", err)
		return
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		s.fail(phaseMono, "sel registre", err)
		return
	}

	// Trousseau de contrôleurs pour la preuve de quorum de /v1/mode (§5.3,
	// revue de sécurité #89) : k=2 signatures Ed25519 DISTINCTES, jamais
	// une liste d'identités déclarées.
	ctrl1, ctrl2 := devKey("quorum-ctrl-1"), devKey("quorum-ctrl-2")
	ctrl1KID, ctrl2KID := [16]byte{0x11}, [16]byte{0x22}
	quorumKeyring, _ := json.Marshal(map[string]string{
		hex.EncodeToString(ctrl1KID[:]): hex.EncodeToString(ctrl1.Public().(ed25519.PublicKey)),
		hex.EncodeToString(ctrl2KID[:]): hex.EncodeToString(ctrl2.Public().(ed25519.PublicKey)),
	})
	quorumKeyringPath := filepath.Join(cfg.out, "quorum-keyring.dev.json")
	if err := os.WriteFile(quorumKeyringPath, quorumKeyring, 0o600); err != nil {
		s.fail(phaseMono, "trousseau de quorum dev", err)
		return
	}

	pepdEnv := append(os.Environ(),
		"TBP_CELL_ID="+monoCellID,
		"TBP_SALT="+hex.EncodeToString(salt),
		"TBP_KEYRING_FILE="+keyringPath,
		"TBP_POLICY_ID="+hex.EncodeToString(policyID[:]),
		"TBP_REGISTRY_DIR="+regDir,
		"TBP_LISTEN_ADDR="+monoPEPDAddr,
		// Plan d'ADMINISTRATION dédié (revue de sécurité #95, finding A10) :
		// /healthz et /v1/mode ne sont plus servis sur le plan de données
		// (TBP_LISTEN_ADDR) — un test qui les sonderait encore là échouerait
		// désormais systématiquement (revue #86 : le selftest doit rester
		// exécutable, pas seulement le code).
		"TBP_ADMIN_SOCKET="+adminSock,
		"TBP_OPA_ENDPOINT="+opaURL+"/v1/data/tbp/example/action",
		// OPA reste en TCP loopback ici (selftest local, pas de socket
		// Unix propre à cette machine partagée) — dev/lab EXPLICITE,
		// revue de sécurité #92, finding A3.
		"TBP_OPA_INSECURE_TCP_DEV=1",
		"TBP_QUORUM_KEYRING_FILE="+quorumKeyringPath,
		// T38/#71 : explicite même si async-bounded est le défaut — le
		// selftest éping le modèle de durabilité qu'il exerce.
		"TBP_DURABILITY=async-bounded",
		"TBP_DURABILITY_WINDOW_MS=1000",
		// Measured boot est désormais actif PAR DÉFAUT (revue #112) ; le
		// câblage réel (genèse, CheckBoot, transition sous preuve de
		// quorum) est déjà couvert par measured_boot_test.go en isolation.
		// Le désactiver ici EXPLICITEMENT est dev/lab uniquement, jamais en
		// production — même doctrine que TBP_OPA_INSECURE_TCP_DEV ci-dessus.
		"TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1",
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
	adminHC := unixClient(adminSock)
	if err := waitUnix200(adminHC, "http://pepd-admin/healthz", 15*time.Second); err != nil {
		s.fail(phaseMono, "pepd démarrage (sonde /healthz, plan d'administration)", err)
		return
	}
	s.add(phaseMono, "pepd démarré (OPA branché, registre réel)", true, pepdURL)

	// Posture au démarrage : monitor, jamais closed (§5.3).
	var modeView struct {
		Mode string `json:"mode"`
	}
	_, raw, err := getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err != nil {
		s.fail(phaseMono, "posture initiale = monitor", err)
		return
	}
	_ = json.Unmarshal(raw, &modeView)
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
	_, er, err := evaluate(pepdURL, tokRead, "read", "doc-1")
	s.add(phaseMono, "monitor: jeton valide (read) → allow, forwardé (log only)",
		err == nil && er.Allow && er.Forwarded && er.Mode == "monitor",
		fmt.Sprintf("allow=%v forwarded=%v reason=%s", er.Allow, er.Forwarded, er.Reason))

	// --- Témoin : action hors politique (write → deny OPA), monitor ---------
	tokWrite, _ := mintOK("write")
	_, er, err = evaluate(pepdURL, tokWrite, "write", "doc-1")
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
	_, er, err = evaluate(pepdURL, tokRogue, "read", "doc-1")
	s.add(phaseMono, "témoin: jeton signé par une clé inconnue → refus",
		err == nil && !er.Allow,
		fmt.Sprintf("allow=%v reason=%s", er.Allow, er.Reason))

	// --- Étape : bascule gouvernée monitor→closed (§5.3) --------------------
	// Preuve de quorum RÉELLE (revue de sécurité #89) : k signatures Ed25519
	// distinctes sur pep.QuorumMessage("mode-closed", cellID, expiry) — un
	// ancien appelant qui se contenterait de déclarer des noms ("signers")
	// est witnessé séparément juste après (attaque #89 exacte, refusée).
	// cellID lié dans le message signé (revue #105) — jamais un champ de
	// la requête.
	expiry := time.Now().Add(1 * time.Minute)
	signCtrl := func(priv ed25519.PrivateKey, kid [16]byte) map[string]string {
		sig := ed25519.Sign(priv, pep.QuorumMessage("mode-closed", monoCellID, expiry))
		return map[string]string{"key_id": hex.EncodeToString(kid[:]), "signature": hex.EncodeToString(sig)}
	}

	legacy, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{"mode": "closed", "signers": []string{"op-1", "op-1"}})
	s.add(phaseMono, "témoin #89: attaque historique (signers déclarés, sans signature) → refusée",
		legacy == http.StatusForbidden, fmt.Sprintf("status=%d", legacy))

	status, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
		"mode": "closed", "expiry": expiry.Unix(),
		"signatures": []map[string]string{signCtrl(ctrl1, ctrl1KID)},
	})
	s.add(phaseMono, "bascule closed: 1 signature valide < quorum 2 → 403", status == http.StatusForbidden,
		fmt.Sprintf("status=%d", status))
	status, _, _ = postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
		"mode": "closed", "expiry": expiry.Unix(),
		"signatures": []map[string]string{signCtrl(ctrl1, ctrl1KID), signCtrl(ctrl2, ctrl2KID)},
	})
	s.add(phaseMono, "bascule closed: quorum 2/2 signatures valides → 200", status == http.StatusOK,
		fmt.Sprintf("status=%d", status))
	_, raw, err = getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err == nil {
		_ = json.Unmarshal(raw, &modeView)
	}
	s.add(phaseMono, "posture effective = closed après quorum", modeView.Mode == "closed", "mode="+modeView.Mode)

	// --- Post-closed : le verdict s'APPLIQUE --------------------------------
	tokWrite2, _ := mintOK("write")
	_, er, err = evaluate(pepdURL, tokWrite2, "write", "doc-1")
	s.add(phaseMono, "closed: write → deny BLOQUÉ (forwarded=false)",
		err == nil && !er.Allow && !er.Forwarded,
		fmt.Sprintf("allow=%v forwarded=%v", er.Allow, er.Forwarded))
	tokRead2, _ := mintOK("read")
	_, er, err = evaluate(pepdURL, tokRead2, "read", "doc-1")
	s.add(phaseMono, "closed: read → allow forwardé",
		err == nil && er.Allow && er.Forwarded,
		fmt.Sprintf("allow=%v forwarded=%v", er.Allow, er.Forwarded))

	// --- Étape #93 : redémarrage = refus total jusqu'à reconfirmation ------
	// Vérification prioritaire suggérée par l'issue elle-même : pepd en
	// closed (bascule quorée ci-dessus), puis kill + redémarrage — la
	// posture ne doit JAMAIS repartir en monitor SANS signature (attaque
	// par rétrogradation, revue de sécurité #93, option la plus stricte
	// actée par le mainteneur).
	_ = pepdCmd.Process.Kill()
	_, _ = pepdCmd.Process.Wait()

	pepdLog2, err := os.Create(filepath.Join(cfg.out, "pepd-restart.log"))
	if err != nil {
		s.fail(phaseMono, "pepd redémarrage (§93)", err)
		return
	}
	pepdCmd = exec.Command(pepdBin)
	pepdCmd.Env = pepdEnv // MÊME registre : cell_log.key existe déjà
	pepdCmd.Stdout, pepdCmd.Stderr = pepdLog2, pepdLog2
	if err := pepdCmd.Start(); err != nil {
		_ = pepdLog2.Close()
		s.fail(phaseMono, "pepd redémarrage (§93)", err)
		return
	}
	if err := waitUnix200(adminHC, "http://pepd-admin/healthz", 15*time.Second); err != nil {
		s.fail(phaseMono, "pepd redémarrage (§93, sonde /healthz)", err)
		return
	}

	_, raw, err = getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err == nil {
		_ = json.Unmarshal(raw, &modeView)
	}
	s.add(phaseMono, "témoin #93: redémarrage → posture refused (PAS monitor silencieux)",
		modeView.Mode == "refused", "mode="+modeView.Mode)

	// Refus TOTAL : même un jeton par ailleurs valide (allow) est bloqué.
	tokReadRestart, _ := mintOK("read")
	_, er, err = evaluate(pepdURL, tokReadRestart, "read", "doc-1")
	s.add(phaseMono, "témoin #93: refused bloque même un allow",
		err == nil && !er.Forwarded && er.Mode == "refused",
		fmt.Sprintf("allow=%v forwarded=%v mode=%s", er.Allow, er.Forwarded, er.Mode))

	// Seule sortie : quorum reconfirmant EXPLICITEMENT une posture — ici
	// monitor, comme tout acte gouverné (aller ou retour).
	expiry93 := time.Now().Add(1 * time.Minute)
	signCtrlMonitor := func(priv ed25519.PrivateKey, kid [16]byte) map[string]string {
		sig := ed25519.Sign(priv, pep.QuorumMessage("mode-monitor", monoCellID, expiry93))
		return map[string]string{"key_id": hex.EncodeToString(kid[:]), "signature": hex.EncodeToString(sig)}
	}
	status93, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
		"mode": "monitor", "expiry": expiry93.Unix(),
		"signatures": []map[string]string{signCtrlMonitor(ctrl1, ctrl1KID), signCtrlMonitor(ctrl2, ctrl2KID)},
	})
	s.add(phaseMono, "témoin #93: reconfirmation quorée de monitor après redémarrage → 200",
		status93 == http.StatusOK, fmt.Sprintf("status=%d", status93))
	_, raw, err = getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err == nil {
		_ = json.Unmarshal(raw, &modeView)
	}
	s.add(phaseMono, "témoin #93: posture = monitor après reconfirmation", modeView.Mode == "monitor", "mode="+modeView.Mode)

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
	if _, _, err := evaluate(pepdURL, tokDelta, "read", "doc-1"); err != nil {
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
