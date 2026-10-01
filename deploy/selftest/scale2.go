// scale2.go — phase scale2 (issue #86) : le guide deploy/scale-2.md EXÉCUTÉ contre les vrais binaires.
//
// Échelle 2 = une petite structure : quelques machines derrière UN brokerd, un seul registre, un quorum
// k-sur-n avec une clé de rechange. Cette phase joue les commandes DU GUIDE — quorumproof keygen pour les
// contrôleurs, le manifeste de genèse construit à partir de leurs clés publiques, brokerd réel en topologie
// mono, l'approbation de plan et les preuves de classe W fabriquées par quorumproof — et vérifie ce que
// l'échelle 2 promet : le quorum de 2-sur-3 est exigé de bout en bout, l'échelle (k, topologie) est ATTESTÉE
// et ne se change que par le quorum attesté (#224), et le redémarrage reste vert.
//
// Ce qu'elle n'exerce pas, dit dans le guide : le plan mTLS réseau (couvert par les tests de brokerd,
// net_tls_test.go) et les pepd des serveurs applicatifs (couverts par les phases mono et scale1).
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	phaseScale2   = "scale2"
	scale2OPAAddr = "127.0.0.1:18382"
	scale2CellID  = "cell-s2"
)

func runScale2(s *suite, cfg config) {
	ph := phaseScale2

	if _, err := exec.LookPath(cfg.goBin); err != nil {
		s.fail(ph, "prérequis: binaire go", err)
		return
	}
	s.add(ph, "prérequis: binaire go", true, cfg.goBin)
	if _, err := exec.LookPath(cfg.opaBin); err != nil {
		s.fail(ph, "prérequis: binaire opa", err)
		return
	}
	s.add(ph, "prérequis: binaire opa", true, cfg.opaBin)

	base := filepath.Join(cfg.out, "scale2")
	_ = os.RemoveAll(base) // un témoin ou un registre d'une exécution précédente ferait un faux échec (#93)
	binDir := filepath.Join(base, "bin")
	opaDir := filepath.Join(base, "opa")
	genesisDir := filepath.Join(base, "genesis")
	keysDir := filepath.Join(base, "keys")
	regDir := filepath.Join(base, "registry", scale2CellID)
	for _, d := range []string{binDir, opaDir, genesisDir, keysDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			s.fail(ph, "préparation des répertoires", err)
			return
		}
	}

	// --- Étape 1 du guide : les binaires -------------------------------------------------------
	brokerdBin := filepath.Join(binDir, "brokerd")
	qpBin := filepath.Join(binDir, "quorumproof")
	for _, b := range []struct{ out, pkg string }{{brokerdBin, "./src/broker/cmd/brokerd"}, {qpBin, "./src/pep/cmd/quorumproof"}} {
		if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", b.out, b.pkg); err != nil {
			s.fail(ph, "build "+filepath.Base(b.out), fmt.Errorf("%v — %s", err, errB))
			return
		}
	}
	s.add(ph, "build brokerd et quorumproof (deploy/scale-2.md étape 1)", true, binDir)

	capsPath, ok := prepareCapabilities(s, ph, cfg, opaDir)
	if !ok {
		return
	}
	regoPath := filepath.Join(cfg.repo, "policies", "rego", "action_example.rego")
	regoRaw, err := os.ReadFile(regoPath)
	if err != nil {
		s.fail(ph, "policyID (hash du bundle rego)", err)
		return
	}
	policyID := sha256.Sum256(regoRaw)
	policyHex := hex.EncodeToString(policyID[:])
	bundlePath := filepath.Join(opaDir, "tbp-scale2.tar.gz")
	signingKey, verificationKey, ok := generateSigningKeypair(s, ph, opaDir)
	if !ok {
		return
	}
	if !buildBundle(s, ph, cfg, capsPath, regoPath, bundlePath, policyHex, signingKey) {
		return
	}
	opa, ok := startOPA(s, ph, cfg, scale2OPAAddr, bundlePath, verificationKey, filepath.Join(opaDir, "opa.log"))
	if !ok {
		return
	}
	defer opa.stop()

	// --- Étape 2 : trois contrôleurs, k = 2 (une clé de rechange : n = k + 1) --------------------
	keyring := filepath.Join(keysDir, "quorum-keyring.json")
	var ctlKeys, ctlPubs []string
	for i := 1; i <= 3; i++ {
		kf := filepath.Join(keysDir, fmt.Sprintf("controller-%d.key", i))
		out, errB, err := runCmd(cfg.repo, nil, qpBin, "keygen", "-key", kf, "-keyring", keyring)
		pub := ""
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			for _, f := range strings.Fields(sc.Text()) {
				if strings.HasPrefix(f, "public=") {
					pub = strings.TrimPrefix(f, "public=")
				}
			}
		}
		if err != nil || len(pub) != 64 {
			s.fail(ph, "quorumproof keygen (contrôleur)", fmt.Errorf("err=%v pub=%q stderr=%s", err, pub, errB))
			return
		}
		ctlKeys, ctlPubs = append(ctlKeys, kf), append(ctlPubs, pub)
	}
	manifestJSON, _ := json.Marshal(map[string][]string{"pubkeys": ctlPubs})
	manifestPath := filepath.Join(genesisDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		s.fail(ph, "manifeste de genèse", err)
		return
	}
	s.add(ph, "3 contrôleurs créés (quorumproof keygen), manifeste de genèse 2-sur-3 (deploy/scale-2.md étape 2)", true, manifestPath)

	// --- Étape 3 : registres de la cellule + démarrage de brokerd -------------------------------
	cellSalt := make([]byte, 16)
	_, _ = rand.Read(cellSalt)
	issuerSeed := sha256.Sum256([]byte("tbp-scale2-selftest-dev:issuer"))
	issuerSeedPath := filepath.Join(base, "issuer.seed")
	// la clé d'OPÉRATEUR (celle qui approuve les plans) est créée par la même commande que les contrôleurs
	opKeyPath := filepath.Join(keysDir, "operator.key")
	opOut, opErr, err := runCmd(cfg.repo, nil, qpBin, "keygen", "-key", opKeyPath, "-keyring", filepath.Join(keysDir, "operator-ring.json"))
	opPub := ""
	for _, f := range strings.Fields(opOut) {
		if strings.HasPrefix(f, "public=") {
			opPub = strings.TrimPrefix(f, "public=")
		}
	}
	if err != nil || len(opPub) != 64 {
		s.fail(ph, "quorumproof keygen (opérateur)", fmt.Errorf("err=%v pub=%q stderr=%s", err, opPub, opErr))
		return
	}
	opKeysPath := filepath.Join(base, "operators.json")
	opKeysJSON, _ := json.Marshal([]string{opPub})
	agentsPath := filepath.Join(base, "agents.json")
	agentsJSON, _ := json.Marshal(map[string]map[string]any{"agent-w": {"class": 2}})
	for _, f := range []struct {
		path string
		data []byte
	}{
		{issuerSeedPath, []byte(hex.EncodeToString(issuerSeed[:]))},
		{opKeysPath, opKeysJSON},
		{agentsPath, agentsJSON},
	} {
		if err := os.WriteFile(f.path, f.data, 0o600); err != nil {
			s.fail(ph, "fichiers de la cellule", err)
			return
		}
	}
	brokerSock := filepath.Join(base, "broker.sock")
	adminSock := filepath.Join(base, "broker-admin.sock")
	witness := filepath.Join(base, "brokerd-provisioning-witness.json")
	brokerEnv := func(k string) []string {
		return append(os.Environ(),
			"TBP_CELL_ID="+scale2CellID,
			"TBP_SALT="+hex.EncodeToString(cellSalt),
			"TBP_POLICY_ID="+policyHex,
			"TBP_REGISTRY_DIR="+regDir,
			"TBP_OPA_ENDPOINT=http://"+scale2OPAAddr+"/v1/data/tbp/example/action",
			"TBP_OPA_INSECURE_TCP_DEV=1",
			"TBP_TRANSLATOR=structured",
			"TBP_ISSUER_SEED_FILE="+issuerSeedPath,
			"TBP_GENESIS_DIR="+genesisDir,
			"TBP_QUORUM_MIN="+k,
			"TBP_TOPOLOGY=mono",                 // une cellule : pas de bail d'époque (#97)
			"TBP_CLUSTER_MEMBERS="+scale2CellID, // mono : la cellule est son seul membre (#128)
			"TBP_OPERATOR_KEYS_FILE="+opKeysPath,
			"TBP_AGENT_REGISTRY_FILE="+agentsPath,
			"TBP_PROVISIONING_WITNESS_FILE="+witness,
			"TBP_BROKER_SOCKET="+brokerSock,
			"TBP_BROKER_ADMIN_SOCKET="+adminSock,
		)
	}
	brokerHC, adminHC := unixClient(brokerSock), unixClient(adminSock)
	logPath := filepath.Join(base, "brokerd.log")
	start := func(env []string, log string) (*daemonProc, error) {
		_ = os.Remove(brokerSock)
		_ = os.Remove(adminSock)
		return startDaemon(brokerdBin, env, log)
	}
	brokerd, err := start(brokerEnv("2"), logPath)
	if err != nil {
		s.fail(ph, "brokerd démarrage", err)
		return
	}
	defer func() { brokerd.stop() }()
	if err := waitUnix200(adminHC, "http://brokerd/v1/supervision/stats", 20*time.Second); err != nil {
		s.fail(ph, "brokerd démarrage (sonde /v1/supervision/stats)", err)
		return
	}
	s.add(ph, "brokerd démarré en topologie mono, k = 2 (deploy/scale-2.md étape 3)", true, brokerSock)
	logBytes, _ := os.ReadFile(logPath)
	s.add(ph, "k = 2 avec une clé de rechange : AUCUN avertissement de quorum fragile (#199)",
		!strings.Contains(string(logBytes), "AVERTISSEMENT quorum"), "")

	// --- Étape 4 : une action de classe W exige 2 contrôleurs ----------------------------------
	// Un plan sans destinataire, ou pour un agent hors registre, n'existe pas (#235).
	for name, subj := range map[string]string{"sans sujet": "", "sujet hors registre": "agent-inconnu"} {
		st, _, _ := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/submit", map[string]any{
			"subject": subj,
			"steps":   []map[string]string{{"action": "read", "resource": "doc-1", "params_hex": ""}},
		})
		s.add(ph, "plan "+name+" refusé à la soumission (#235)", st == http.StatusBadRequest, fmt.Sprintf("status=%d", st))
	}
	submitStatus, raw, err := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/submit", map[string]any{
		"subject": "agent-w",
		"steps":   []map[string]string{{"action": "read", "resource": "doc-1", "params_hex": ""}},
	})
	var planSub daemonPlanSubmitResponse
	if submitStatus == http.StatusOK {
		err = json.Unmarshal(raw, &planSub)
	}
	if submitStatus != http.StatusOK || err != nil || planSub.PlanHash == "" {
		s.fail(ph, "plan soumis (canal opérateur)", fmt.Errorf("status=%d err=%v", submitStatus, err))
		return
	}
	approvalFile := filepath.Join(base, "approval.json")
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "planapprove", "-plan-hash", planSub.PlanHash, "-key", opKeyPath, "-out", approvalFile); err != nil {
		s.fail(ph, "quorumproof planapprove", fmt.Errorf("%v — %s", err, errB))
		return
	}
	approvalRaw, _ := os.ReadFile(approvalFile)
	var approvalBody map[string]any
	_ = json.Unmarshal(approvalRaw, &approvalBody)
	approveStatus, _, _ := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/approve", approvalBody)
	s.add(ph, "plan soumis, approuvé par l'opérateur (quorumproof planapprove, deploy/scale-2.md étape 4)", approveStatus == http.StatusOK, fmt.Sprintf("status=%d", approveStatus))
	bindOut, errB, err := runCmd(cfg.repo, nil, qpBin, "planbind", "-plan-hash", planSub.PlanHash)
	binding := strings.TrimSpace(bindOut)
	if err != nil || binding == "" {
		s.fail(ph, "quorumproof planbind", fmt.Errorf("%v — %s", err, errB))
		return
	}
	wproof := func(name string, keys ...string) string {
		out := filepath.Join(base, name)
		args := []string{"wproof", "-manifest", manifestPath, "-action", "read", "-resource", "doc-1", "-policy", policyHex, "-out", out}
		for _, k := range keys {
			args = append(args, "-key", k)
		}
		if _, errB, err := runCmd(cfg.repo, nil, qpBin, args...); err != nil {
			s.fail(ph, "quorumproof wproof", fmt.Errorf("%v — %s", err, errB))
			return ""
		}
		b, _ := os.ReadFile(out)
		return hex.EncodeToString(b)
	}
	act := func(proofHex string) daemonActionResponse {
		intent := fmt.Sprintf(`{"action":"read","resource":"doc-1","plan_binding":"%s"`, binding)
		if proofHex != "" {
			intent += fmt.Sprintf(`,"quorum_proof":"%s"`, proofHex)
		}
		intent += "}"
		_, raw, err := postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{"subject": "agent-w", "intent": intent})
		var r daemonActionResponse
		if err == nil {
			_ = json.Unmarshal(raw, &r)
		}
		return r
	}
	none := act("")
	s.add(ph, "classe W sans preuve de quorum → refusé", !none.Allow, "reason="+none.Reason)
	oneP := wproof("proof-1sig.json", ctlKeys[0])
	one := act(oneP)
	s.add(ph, "classe W avec UN contrôleur sur 2 requis → refusé", oneP != "" && !one.Allow, "reason="+one.Reason)
	twoP := wproof("proof-2sig.json", ctlKeys[0], ctlKeys[2]) // les contrôleurs 1 et 3 : le 2 est « perdu »
	two := act(twoP)
	s.add(ph, "classe W avec DEUX contrôleurs (le 2e est indisponible : n = k + 1) → autorisé, jeton émis",
		twoP != "" && two.Allow && two.Token != "", fmt.Sprintf("allow=%v reason=%s", two.Allow, two.Reason))

	// --- Étape 5 : l'échelle est attestée (#224) ----------------------------------------------
	brokerd.stop()
	refused := func(env []string, log string) (bool, string) {
		d, err := start(env, log)
		if err != nil {
			return false, err.Error()
		}
		exited := make(chan error, 1)
		go func() { exited <- d.cmd.Wait() }()
		bad := false
		select {
		case werr := <-exited:
			bad = werr != nil
		case <-time.After(20 * time.Second):
			d.stop()
		}
		b, _ := os.ReadFile(log)
		return bad, string(b)
	}
	low, lowLog := refused(brokerEnv("1"), filepath.Join(base, "brokerd-k1.log"))
	s.add(ph, "#224 : TBP_QUORUM_MIN abaissé à 1 dans l'environnement ⇒ brokerd REFUSE de démarrer, en nommant le réglage",
		low && strings.Contains(lowLog, "quorum-settings"), fmt.Sprintf("refusé=%v", low))
	// une seule signature (suffisante pour k = 1) ne légitime pas l'abaissement : le quorum ATTESTÉ est 2
	proofFile := filepath.Join(base, "provisioning-proof-1sig.json")
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "sign", "-condition", "provisioning-transition-brokerd", "-cell", scale2CellID, "-key", ctlKeys[0], "-out", proofFile); err != nil {
		s.fail(ph, "quorumproof sign (preuve de transition à 1 signature)", fmt.Errorf("%v — %s", err, errB))
		return
	}
	lowProof, _ := refused(append(brokerEnv("1"), "TBP_PROVISIONING_TRANSITION_PROOF_FILE="+proofFile), filepath.Join(base, "brokerd-k1-proof.log"))
	s.add(ph, "#224 : une seule signature ne légitime pas l'abaissement de k (le k ATTESTÉ est 2)", lowProof, "")

	// --- Étape 6 : redémarrage inchangé → conforme au témoin -----------------------------------
	brokerd, err = start(brokerEnv("2"), filepath.Join(base, "brokerd-restart.log"))
	if err != nil {
		s.fail(ph, "brokerd (redémarrage)", err)
		return
	}
	restarted := waitUnix200(adminHC, "http://brokerd/v1/supervision/stats", 20*time.Second) == nil
	s.add(ph, "redémarrage à l'identique ⇒ brokerd repart (témoin de provisionnement conforme, échelle inchangée)", restarted, "")

	// --- Cas voisin : l'abaissement légitime, signé par le quorum ATTESTÉ (2 contrôleurs) ----------
	brokerd.stop()
	proof2 := filepath.Join(base, "provisioning-proof-2sig.json")
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "sign", "-condition", "provisioning-transition-brokerd", "-cell", scale2CellID, "-key", ctlKeys[0], "-key", ctlKeys[1], "-out", proof2); err != nil {
		s.fail(ph, "quorumproof sign (preuve de transition à 2 signatures)", fmt.Errorf("%v — %s", err, errB))
		return
	}
	k1Log := filepath.Join(base, "brokerd-k1-accepted.log")
	brokerd, err = start(append(brokerEnv("1"), "TBP_PROVISIONING_TRANSITION_PROOF_FILE="+proof2), k1Log)
	if err != nil {
		s.fail(ph, "brokerd (abaissement signé par 2 contrôleurs)", err)
		return
	}
	accepted := waitUnix200(adminHC, "http://brokerd/v1/supervision/stats", 20*time.Second) == nil
	k1Bytes, _ := os.ReadFile(k1Log)
	s.add(ph, "#224 : le même abaissement signé par les 2 contrôleurs ATTESTÉS est accepté — et brokerd avertit que k = 1",
		accepted && strings.Contains(string(k1Bytes), "AVERTISSEMENT quorum k=1"), fmt.Sprintf("accepté=%v", accepted))
}
