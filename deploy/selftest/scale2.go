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

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
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
	opaConfigPath := filepath.Join(opaDir, "opa-launch.conf")
	if err := writeOPAConfig(opaConfigPath, scale2OPAAddr, bundlePath, verificationKey); err != nil {
		s.fail(ph, "configuration de l'OPA (mesurée par brokerd, #313)", err)
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
	// les clés d'OPÉRATEUR (celles qui approuvent les plans) sont créées par la même commande que les contrôleurs.
	// #196 : à k = 2, un plan de classe W exige DEUX opérateurs distincts — le trousseau en porte deux.
	var opKeyPaths, opPubs []string
	// Le troisième est l'astreinte de nuit : elle peut COUPER (révoquer un plan, trancher une demande dégradée), pas
	// approuver — approuver élargit ce que la cellule autorise, couper le restreint.
	for i := 1; i <= 3; i++ {
		kp := filepath.Join(keysDir, fmt.Sprintf("operator-%d.key", i))
		opOut, opErr, err := runCmd(cfg.repo, nil, qpBin, "keygen", "-key", kp, "-keyring", filepath.Join(keysDir, fmt.Sprintf("operator-%d-ring.json", i)))
		pub := ""
		for _, f := range strings.Fields(opOut) {
			if strings.HasPrefix(f, "public=") {
				pub = strings.TrimPrefix(f, "public=")
			}
		}
		if err != nil || len(pub) != 64 {
			s.fail(ph, "quorumproof keygen (opérateur)", fmt.Errorf("err=%v pub=%q stderr=%s", err, pub, opErr))
			return
		}
		opKeyPaths, opPubs = append(opKeyPaths, kp), append(opPubs, pub)
	}
	opKeysPath := filepath.Join(base, "operators.json")
	opKeysJSON, _ := json.Marshal([]map[string]any{
		{"key": opPubs[0], "roles": []string{"approve"}},
		{"key": opPubs[1], "roles": []string{"approve"}},
		{"key": opPubs[2], "roles": []string{"revoke", "arbitrate"}},
	})
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
	// Journal d'audit de brokerd (#275) : REQUIS (base est neuf à chaque exécution).
	auditKeyPath := filepath.Join(base, "brokerd-audit.key")
	auditJournalPath := filepath.Join(base, "brokerd-audit-records.jsonl")
	if err := registry.GenerateRecordKey(auditKeyPath); err != nil {
		s.fail(ph, "clé du journal d'audit de brokerd", err)
		return
	}
	brokerSock := filepath.Join(base, "broker.sock")
	adminSock := filepath.Join(base, "broker-admin.sock")
	witness := filepath.Join(base, "brokerd-provisioning-witness.json")
	brokerEnv := func(k string) []string {
		return append(os.Environ(),
			"TBP_AUDIT_RECORDS="+auditJournalPath,
			"TBP_AUDIT_RECORDS_KEY_FILE="+auditKeyPath,
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
			// Les règles servies (issue #313) : l'OPA de la machine de brokerd n'est gardé par aucun pepd mesuré.
			"TBP_PROVISIONING_POLICY_BUNDLE="+bundlePath,
			"TBP_PROVISIONING_OPA_CONFIG="+opaConfigPath,
			"TBP_PROVISIONING_EXTRA_FILES=opa-verification-key="+verificationKey,
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
	// #273 : l'opérateur RECALCULE le hash du plan en clair avant de signer (quorumproof
	// planhash) : le submitted_at vient de la vue d'arbitrage du broker, le reste du plan
	// reçu et de la configuration de la cellule — pas du hash que le broker annonce.
	planFile := filepath.Join(base, "plan.json")
	planBody := `{"subject":"agent-w","steps":[{"action":"read","resource":"doc-1","params_hex":""}]}`
	forgedFile := filepath.Join(base, "plan-forged.json")
	forgedBody := `{"subject":"agent-w","steps":[{"action":"read","resource":"doc-9","params_hex":""}]}`
	if err := os.WriteFile(planFile, []byte(planBody), 0o600); err != nil {
		s.fail(ph, "plan en clair", err)
		return
	}
	if err := os.WriteFile(forgedFile, []byte(forgedBody), 0o600); err != nil {
		s.fail(ph, "plan falsifié", err)
		return
	}
	_, arbRaw, _ := getUnix(adminHC, "http://brokerd/v1/supervision/arbitration")
	var arb struct {
		Pending []struct {
			Hash        string `json:"hash"`
			SubmittedAt string `json:"submitted_at"`
		} `json:"pending"`
	}
	_ = json.Unmarshal(arbRaw, &arb)
	submittedAt := ""
	for _, p := range arb.Pending {
		if p.Hash == planSub.PlanHash {
			submittedAt = p.SubmittedAt
		}
	}
	if submittedAt == "" {
		s.fail(ph, "vue d'arbitrage : plan en attente introuvable", fmt.Errorf("%s", arbRaw))
		return
	}
	planArgs := func(file string) []string {
		return []string{"planhash", "-cell", scale2CellID, "-policy-id", policyHex, "-submitted-at", submittedAt, "-plan", file, "-expect", planSub.PlanHash}
	}
	_, errP, err := runCmd(cfg.repo, nil, qpBin, planArgs(planFile)...)
	s.add(ph, "#273 : quorumproof planhash recalcule le hash que le broker a scellé (plan en clair + submitted_at de la vue d'arbitrage)", err == nil, strings.TrimSpace(errP))
	_, _, err = runCmd(cfg.repo, nil, qpBin, planArgs(forgedFile)...)
	s.add(ph, "#273 : témoin — un plan en clair différent de celui scellé est refusé par -expect (ne signez pas)", err != nil, "")

	// #196 : le plan est de classe W, k = 2. Une seule signature d'opérateur est refusée ; deux opérateurs
	// distincts qui signent chacun chez eux la MÊME échéance, puis `planassemble`, l'approuvent.
	postApproval := func(file string) int {
		raw, _ := os.ReadFile(file)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		st, _, _ := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/approve", body)
		return st
	}
	oneFile := filepath.Join(base, "approval-1.json")
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "planapprove", "-plan-hash", planSub.PlanHash, "-key", opKeyPaths[0], "-out", oneFile); err != nil {
		s.fail(ph, "quorumproof planapprove (opérateur 1)", fmt.Errorf("%v — %s", err, errB))
		return
	}
	oneStatus := postApproval(oneFile)
	s.add(ph, "#196 : une seule signature d'opérateur ne suffit pas pour un plan de classe W à k = 2 — refusé, le plan reste en attente",
		oneStatus == http.StatusBadRequest, fmt.Sprintf("status=%d", oneStatus))
	// rôles : la clé de nuit ne complète pas un quorum d'approbation (le plan reste en attente)
	nightFile := filepath.Join(base, "approval-night.json")
	nightExpiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "planapprove", "-plan-hash", planSub.PlanHash, "-expires-at", nightExpiry, "-key", opKeyPaths[2], "-out", nightFile); err != nil {
		s.fail(ph, "quorumproof planapprove (clé de nuit)", fmt.Errorf("%v — %s", err, errB))
		return
	}
	nightRaw, _ := os.ReadFile(nightFile)
	var nightBody map[string]any
	_ = json.Unmarshal(nightRaw, &nightBody)
	nightStatus, nightOut, _ := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/approve", nightBody)
	s.add(ph, "rôles : une clé qui ne tient pas le rôle d'approbation (l'astreinte de nuit) est refusée, avec un refus nommé — approuver élargit, couper restreint",
		nightStatus == http.StatusBadRequest && strings.Contains(string(nightOut), "rôle d'approbation"), fmt.Sprintf("status=%d %s", nightStatus, strings.TrimSpace(string(nightOut))))
	sameExpiry := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	var perOperator []string
	for i, kp := range opKeyPaths[:2] {
		f := filepath.Join(base, fmt.Sprintf("approval-op%d.json", i+1))
		if _, errB, err := runCmd(cfg.repo, nil, qpBin, "planapprove", "-plan-hash", planSub.PlanHash, "-expires-at", sameExpiry, "-key", kp, "-out", f); err != nil {
			s.fail(ph, "quorumproof planapprove (échéance commune)", fmt.Errorf("%v — %s", err, errB))
			return
		}
		perOperator = append(perOperator, f)
	}
	approvalFile := filepath.Join(base, "approval.json")
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "planassemble", "-in", perOperator[0], "-in", perOperator[1], "-out", approvalFile); err != nil {
		s.fail(ph, "quorumproof planassemble", fmt.Errorf("%v — %s", err, errB))
		return
	}
	approveStatus := postApproval(approvalFile)
	s.add(ph, "plan soumis, approuvé par deux opérateurs distincts (quorumproof planapprove + planassemble, deploy/scale-2.md étape 4, #196)", approveStatus == http.StatusOK, fmt.Sprintf("status=%d", approveStatus))
	// rôles : sur un second plan, un approbateur ne révoque pas ; l'astreinte de nuit, si.
	revStatus, revRaw, _ := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/submit", map[string]any{
		"subject": "agent-w",
		"steps":   []map[string]string{{"action": "read", "resource": "doc-2", "params_hex": ""}},
	})
	var revPlan daemonPlanSubmitResponse
	_ = json.Unmarshal(revRaw, &revPlan)
	if revStatus != http.StatusOK || revPlan.PlanHash == "" {
		s.fail(ph, "second plan (rôles de révocation)", fmt.Errorf("status=%d %s", revStatus, revRaw))
		return
	}
	postRevocation := func(keyPath string) (int, string) {
		f := filepath.Join(base, "revocation.json")
		if _, errB, err := runCmd(cfg.repo, nil, qpBin, "planrevoke", "-plan-hash", revPlan.PlanHash, "-key", keyPath, "-out", f); err != nil {
			return 0, fmt.Sprintf("%v — %s", err, errB)
		}
		raw, _ := os.ReadFile(f)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		st, out, _ := postUnixJSON(adminHC, "http://brokerd/v1/supervision/plan/revoke", body)
		return st, string(out)
	}
	st1, out1 := postRevocation(opKeyPaths[0])
	s.add(ph, "rôles : un approbateur qui ne tient pas le rôle de révocation ne révoque pas (refus nommé)",
		st1 == http.StatusBadRequest && strings.Contains(out1, "rôle de révocation"), fmt.Sprintf("status=%d %s", st1, strings.TrimSpace(out1)))
	st2, out2 := postRevocation(opKeyPaths[2])
	s.add(ph, "rôles : l'astreinte de nuit révoque un plan — couper est ouvert à qui tient ce rôle", st2 == http.StatusOK, fmt.Sprintf("status=%d %s", st2, strings.TrimSpace(out2)))
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
	// #275 : le clair des décisions, du quorum et des plans de brokerd est vérifiable.
	verifyAuditJournal(s, ph, "brokerd", regDir, auditJournalPath, auditKeyPath, 2)

	// --- Étape 4 bis : les règles servies sont attestées (#313) --------------------------------------
	// L'OPA de cette machine n'est gardé par aucun pepd mesuré : changer sa configuration ou le bundle est une
	// transition autorisée par le quorum ATTESTÉ (k = 2), comme un changement du registre d'agents.
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
	for _, item := range []struct {
		name, path string
		edit       func(orig []byte) []byte
	}{
		// le mutant de l'issue : le lancement cesse de vérifier la signature du bundle, sous la même révision
		{"opa-config", opaConfigPath, func(orig []byte) []byte {
			return []byte(strings.ReplaceAll(string(orig), "--verification-key\n"+verificationKey+"\n--verification-key-id\ndefault\n", ""))
		}},
		{"policy-bundle", bundlePath, func(orig []byte) []byte { return append(append([]byte{}, orig...), 0) }},
	} {
		orig, err := os.ReadFile(item.path)
		if err != nil {
			s.fail(ph, "#313 lecture de "+item.name, err)
			return
		}
		edited := item.edit(orig)
		if string(edited) == string(orig) {
			s.fail(ph, "#313 édition de "+item.name, fmt.Errorf("l'édition n'a rien changé"))
			return
		}
		if err := os.WriteFile(item.path, edited, 0o600); err != nil {
			s.fail(ph, "#313 édition de "+item.name, err)
			return
		}
		bad, badLog := refused(brokerEnv("2"), filepath.Join(base, "brokerd-"+item.name+"-edited.log"))
		s.add(ph, "#313 : "+item.name+" modifié sans preuve ⇒ brokerd REFUSE de démarrer, en nommant l'élément",
			bad && strings.Contains(badLog, "modifié(s) : "+item.name), fmt.Sprintf("refusé=%v", bad))
		ruleCond, ok := conditionToSign(badLog)
		if !ok {
			s.fail(ph, "#313 condition à signer annoncée pour "+item.name, fmt.Errorf("absente du refus"))
			return
		}
		oneSig := filepath.Join(base, "rules-proof-"+item.name+"-1sig.json")
		if _, errB, err := runCmd(cfg.repo, nil, qpBin, "sign", "-condition", ruleCond, "-cell", scale2CellID, "-key", ctlKeys[0], "-out", oneSig); err != nil {
			s.fail(ph, "quorumproof sign (1 signature, "+item.name+")", fmt.Errorf("%v — %s", err, errB))
			return
		}
		oneBad, _ := refused(append(brokerEnv("2"), "TBP_PROVISIONING_TRANSITION_PROOF_FILE="+oneSig), filepath.Join(base, "brokerd-"+item.name+"-1sig.log"))
		s.add(ph, "#313 : une seule signature ne légitime pas le changement de "+item.name+" (k = 2)", oneBad, "")
		twoSig := filepath.Join(base, "rules-proof-"+item.name+"-2sig.json")
		if _, errB, err := runCmd(cfg.repo, nil, qpBin, "sign", "-condition", ruleCond, "-cell", scale2CellID, "-key", ctlKeys[0], "-key", ctlKeys[1], "-out", twoSig); err != nil {
			s.fail(ph, "quorumproof sign (2 signatures, "+item.name+")", fmt.Errorf("%v — %s", err, errB))
			return
		}
		brokerd, err = start(append(brokerEnv("2"), "TBP_PROVISIONING_TRANSITION_PROOF_FILE="+twoSig), filepath.Join(base, "brokerd-"+item.name+"-2sig.log"))
		if err != nil {
			s.fail(ph, "brokerd ("+item.name+" signé par 2 contrôleurs)", err)
			return
		}
		up := waitUnix200(adminHC, "http://brokerd/v1/supervision/stats", 20*time.Second) == nil
		s.add(ph, "#313 : le changement de "+item.name+" signé par 2 contrôleurs est accepté — et brokerd repart", up, "")
		brokerd.stop()
	}

	// --- Étape 5 : l'échelle est attestée (#224) ----------------------------------------------
	brokerd.stop()
	low, lowLog := refused(brokerEnv("1"), filepath.Join(base, "brokerd-k1.log"))
	s.add(ph, "#224 : TBP_QUORUM_MIN abaissé à 1 dans l'environnement ⇒ brokerd REFUSE de démarrer, en nommant le réglage",
		low && strings.Contains(lowLog, "quorum-settings"), fmt.Sprintf("refusé=%v", low))
	// Le refus annonce la condition à signer (état de départ attesté + état cible, #236) : c'est
	// elle que les contrôleurs signent, pas une condition générique.
	cond, haveCond := conditionToSign(lowLog)
	s.add(ph, "#236 : le refus annonce la condition à signer (condition|from=attesté|to=cible)", haveCond, cond)
	if !haveCond {
		return
	}
	// une seule signature (suffisante pour k = 1) ne légitime pas l'abaissement : le quorum ATTESTÉ est 2
	proofFile := filepath.Join(base, "provisioning-proof-1sig.json")
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "sign", "-condition", cond, "-cell", scale2CellID, "-key", ctlKeys[0], "-out", proofFile); err != nil {
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
	if _, errB, err := runCmd(cfg.repo, nil, qpBin, "sign", "-condition", cond, "-cell", scale2CellID, "-key", ctlKeys[0], "-key", ctlKeys[1], "-out", proof2); err != nil {
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
