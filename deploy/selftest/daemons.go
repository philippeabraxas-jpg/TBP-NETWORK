// daemons.go — T37 (issue #74) : phase « daemons » du selftest.
//
// Exécute les séquences brokerd de deploy/cellule.md et supervisord de
// deploy/superviseur.md contre les VRAIS binaires, comme la phase mono le
// fait pour pepd : build des deux démons, témoins fail-closed au
// démarrage, OPA réel à capabilities restreintes (helpers partagés de
// opa.go — mêmes contrôles qu'en phase mono), genèse DEV, brokerd assemblé
// (registre propre + tracker + quorum classe W + store de contrats +
// émetteur DEV) sur socket Unix, action réelle de bout en bout, puis
// supervisord (moniteur + console) lisant les vues D109 de brokerd en
// LIVE — y compris le témoin d'honnêteté : brokerd arrêté ⇒ 503
// « source indisponible » par route, jamais une zero-value ni une valeur
// figée (§1).
//
// Substitutions DEV (documentées dans les guides) : clés de contrôleurs,
// d'émetteur et d'opérateur dérivées de seeds fixes, faute de HSM ici —
// la vraie cérémonie est scripts/genesis (§12). L'ancre §6.2 de la cellule
// est publiée dans la master chain par le selftest lui-même, cadencée
// comme en déploiement réel (l'ancrage est cadencé par le TEMPS).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	phaseDaemons     = "daemons"
	daemonsOPAAddr   = "127.0.0.1:18381"
	daemonsCellID    = "cell-a"
	daemonsMonitorID = "monitor-01"
	daemonsMasterID  = "master"
	// epoch0TTL borne la fenêtre de validité de l'époque 0 DEV : le tracker
	// assemblé par brokerd applique les bornes par défaut [10 s, 300 s] —
	// 240 s laisse une marge large à la phase (la fenêtre brokerd réelle
	// tient en quelques secondes) sans jamais frôler l'expiration.
	epoch0TTL = 240
)

// daemonProc est le cycle de vie d'un démon lancé par le selftest.
type daemonProc struct {
	cmd  *exec.Cmd
	logF *os.File
}

// startDaemon lance un binaire avec son environnement, stdout/stderr vers
// un journal — même motif que pepd en phase mono.
func startDaemon(bin string, env []string, logPath string) (*daemonProc, error) {
	logF, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = logF, logF
	if err := cmd.Start(); err != nil {
		_ = logF.Close()
		return nil, err
	}
	return &daemonProc{cmd: cmd, logF: logF}, nil
}

// stop tue le démon et ferme son journal.
func (p *daemonProc) stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
	_ = p.logF.Close()
}

// unixClient rend un client HTTP qui dialogue sur un socket Unix de
// cellule (doctrine v1 — même motif que les adaptateurs de supervisord).
func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// getUnix GET sur le socket et rend (status, corps borné).
func getUnix(hc *http.Client, url string) (int, []byte, error) {
	resp, err := hc.Get(url) //nolint:noctx — client à timeout borné
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// postUnixJSON POSTe un corps JSON sur le socket et rend (status, corps).
func postUnixJSON(hc *http.Client, url string, body any) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	resp, err := hc.Post(url, "application/json", strings.NewReader(string(data))) //nolint:noctx
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// waitUnix200 attend qu'un endpoint du socket réponde 200 (sonde de
// démarrage — même motif que waitHTTP200).
func waitUnix200(hc *http.Client, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, _, err := getUnix(hc, url)
		if err == nil && status == http.StatusOK {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s toujours injoignable après %s", url, timeout)
}

// waitCheckpointFile attend que le checkpoint PUBLIÉ d'un registre couvre
// size (tessera publie de façon asynchrone — motif waitCheckpoint des
// tests supervision, sans testing.T).
func waitCheckpointFile(dir string, verifier note.Verifier, size uint64) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
		if err == nil {
			if cp, perr := registry.ParseCheckpoint(raw, verifier); perr == nil && cp.Size >= size {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("checkpoint de %s jamais publié à taille ≥ %d", dir, size)
}

// — Vues JSON des démons (contrats stables snake_case, D109/T34c) —

type daemonStatsView struct {
	Requests uint64 `json:"requests"`
	Allows   uint64 `json:"allows"`
	Denies   uint64 `json:"denies"`
}

type daemonEpochView struct {
	Epoch     int    `json:"epoch"`
	Authority string `json:"authority"`
}

type daemonArbitrationView struct {
	PolicyID string `json:"policy_id"`
	Pending  []struct {
		Hash string `json:"hash"`
	} `json:"pending"`
}

type daemonIndicatorsView struct {
	Arbitration struct {
		Requests uint64 `json:"requests"`
	} `json:"arbitration"`
	Cells []struct {
		CellID      string `json:"cell_id"`
		ChainSize   uint64 `json:"chain_size"`
		AnchorStale bool   `json:"anchor_stale"`
		FallEpisode bool   `json:"fall_episode"`
	} `json:"cells"`
}

type daemonActionResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Token  string `json:"token,omitempty"`
}

// runDaemons exécute la phase daemons. Les échecs sont enregistrés dans
// la suite ; la fonction ne rend d'erreur que sur faute d'orchestration.
func runDaemons(s *suite, cfg config) {
	ctx := context.Background()

	// --- Prérequis : binaires go et opa ------------------------------------
	if _, err := exec.LookPath(cfg.goBin); err != nil {
		s.fail(phaseDaemons, "prérequis: binaire go", fmt.Errorf("go introuvable (%s) : %w", cfg.goBin, err))
		return
	}
	s.add(phaseDaemons, "prérequis: binaire go", true, cfg.goBin)
	if _, err := exec.LookPath(cfg.opaBin); err != nil {
		s.fail(phaseDaemons, "prérequis: binaire opa", fmt.Errorf("opa introuvable (%s) : %w", cfg.opaBin, err))
		return
	}
	s.add(phaseDaemons, "prérequis: binaire opa", true, cfg.opaBin)

	base := filepath.Join(cfg.out, "daemons")
	binDir := filepath.Join(base, "bin")
	opaDir := filepath.Join(base, "opa")
	genesisDir := filepath.Join(base, "genesis")
	brokerRegDir := filepath.Join(base, "registry", daemonsCellID)
	manifestDir := filepath.Join(base, "manifests", daemonsCellID)
	masterDir := filepath.Join(base, "registry", daemonsMasterID)
	monitorDir := filepath.Join(base, "registry", daemonsMonitorID)
	brokerSock := filepath.Join(base, "broker.sock")
	consoleSock := filepath.Join(base, "supervision.sock")
	for _, d := range []string{binDir, opaDir, genesisDir, manifestDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			s.fail(phaseDaemons, "préparation des répertoires", err)
			return
		}
	}

	// --- Étape : build des deux démons (deploy/cellule.md, superviseur.md) --
	brokerdBin := filepath.Join(binDir, "brokerd")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", brokerdBin, "./src/broker/cmd/brokerd"); err != nil {
		s.fail(phaseDaemons, "build brokerd", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(phaseDaemons, "build brokerd (deploy/cellule.md étape 7)", true, brokerdBin)
	supervisordBin := filepath.Join(binDir, "supervisord")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", supervisordBin, "./src/supervision/cmd/supervisord"); err != nil {
		s.fail(phaseDaemons, "build supervisord", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(phaseDaemons, "build supervisord (deploy/superviseur.md étape 3)", true, supervisordBin)

	// --- Témoins : démarrage sans environnement = refus fail-closed --------
	hermetic := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	_, errB, err := runCmd(cfg.repo, hermetic, brokerdBin)
	if err == nil || !strings.Contains(errB, "TBP_CELL_ID requis") {
		s.fail(phaseDaemons, "témoin: brokerd sans environnement refuse de démarrer",
			fmt.Errorf("err=%v stderr=%s — un brokerd qui démarre à moitié configuré est fail-open (§1)", err, strings.TrimSpace(errB)))
		return
	}
	s.add(phaseDaemons, "témoin: brokerd sans environnement refuse de démarrer", true,
		strings.TrimSpace(strings.SplitN(errB, "\n", 2)[0]))
	_, errB, err = runCmd(cfg.repo, hermetic, supervisordBin)
	if err == nil || !strings.Contains(errB, "TBP_MONITOR_CELL_ID requis") {
		s.fail(phaseDaemons, "témoin: supervisord sans environnement refuse de démarrer",
			fmt.Errorf("err=%v stderr=%s — fail-open (§1)", err, strings.TrimSpace(errB)))
		return
	}
	s.add(phaseDaemons, "témoin: supervisord sans environnement refuse de démarrer", true,
		strings.TrimSpace(strings.SplitN(errB, "\n", 2)[0]))

	// --- Étape : OPA réel à capabilities restreintes (helpers opa.go) -------
	capsPath, ok := prepareCapabilities(s, phaseDaemons, cfg, opaDir)
	if !ok {
		return
	}
	// policyID est calculé AVANT le build (hash des sources rego, pas de
	// l'artefact compilé) : c'est ce qui permet de l'épingler comme
	// révision du bundle SANS circularité (revue de sécurité #92, A5).
	regoPath := filepath.Join(cfg.repo, "policies", "rego", "action_example.rego")
	regoRaw, err := os.ReadFile(regoPath)
	if err != nil {
		s.fail(phaseDaemons, "policyID (hash du bundle rego)", err)
		return
	}
	policyID := sha256.Sum256(regoRaw)
	bundlePath := filepath.Join(opaDir, "tbp-daemons.tar.gz")
	if !buildBundle(s, phaseDaemons, cfg, capsPath, regoPath, bundlePath, hex.EncodeToString(policyID[:])) {
		return
	}
	opa, ok := startOPA(s, phaseDaemons, cfg, daemonsOPAAddr, bundlePath, filepath.Join(opaDir, "opa.log"))
	if !ok {
		return
	}
	defer opa.stop()

	// --- Matériel cryptographique DEV (substitution documentée, §12) -------
	cellSalt := make([]byte, 16)
	monitorSalt := make([]byte, 16)
	masterSalt := make([]byte, 16)
	for _, salt := range [][]byte{cellSalt, monitorSalt, masterSalt} {
		if _, err := rand.Read(salt); err != nil {
			s.fail(phaseDaemons, "sels des chaînes", err)
			return
		}
	}
	pubs, privs := devControllers()

	// --- Étape : registre de cell-a + manifeste de genèse (T31, §6.3) ------
	// Le manifeste est signé par la clé de LA cellule et feuillé dans SA
	// chaîne AVANT que brokerd ne la rouvre (un seul écrivain à la fois).
	cellLog, err := openCellRegistry(ctx, brokerRegDir, daemonsCellID)
	if err != nil {
		s.fail(phaseDaemons, "registre cell-a", err)
		return
	}
	cellVkeyB, err := os.ReadFile(filepath.Join(brokerRegDir, "cell_log.vkey"))
	if err != nil {
		s.fail(phaseDaemons, "vkey cell-a", err)
		return
	}
	cellVerifier, err := registry.NewVerifier(string(cellVkeyB))
	if err != nil {
		s.fail(phaseDaemons, "verifier cell-a", err)
		return
	}
	cellSigner, err := registry.LoadSigner(brokerRegDir)
	if err != nil {
		s.fail(phaseDaemons, "signer cell-a", err)
		return
	}
	manifester, err := registry.NewManifester(registry.ManifestOptions{
		CellID: daemonsCellID, Signer: cellSigner, Verifier: cellVerifier,
		Leaves: cellLog, Salt: cellSalt,
	})
	if err != nil {
		s.fail(phaseDaemons, "manifester cell-a", err)
		return
	}
	var mstate registry.ManifestState
	mstate.PolicyID = policyID
	head, _, err := cellLog.Head(ctx)
	if err != nil {
		s.fail(phaseDaemons, "head cell-a", err)
		return
	}
	mstate.ChainHead = head
	genesisManifest, err := manifester.Genesis(ctx, 0, mstate)
	if err != nil {
		s.fail(phaseDaemons, "manifeste de genèse cell-a", err)
		return
	}
	manifestRaw, err := registry.MarshalSignedManifest(genesisManifest)
	if err != nil {
		s.fail(phaseDaemons, "sérialisation du manifeste", err)
		return
	}
	if err := os.WriteFile(filepath.Join(manifestDir, "000-genesis.json"), manifestRaw, 0o644); err != nil {
		s.fail(phaseDaemons, "publication du manifeste", err)
		return
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = cellLog.Close(closeCtx)
	cancel()
	if err := waitCheckpointFile(brokerRegDir, cellVerifier, 1); err != nil {
		s.fail(phaseDaemons, "checkpoint cell-a après manifeste", err)
		return
	}
	s.add(phaseDaemons, "cellule cell-a : registre et manifeste de genèse publiés (T31, §6.3)", true, manifestDir)

	// --- Étape : master chain + ancre §6.2 cadencée -------------------------
	// L'ancrage est cadencé par le TEMPS (§6.2) : le selftest publie la
	// première ancre de cell-a puis la rafraîchit toutes les 30 s (borne
	// par défaut 120 s) — comme le ferait le déploiement réel.
	masterLog, err := openCellRegistry(ctx, masterDir, daemonsMasterID)
	if err != nil {
		s.fail(phaseDaemons, "master chain", err)
		return
	}
	defer func() {
		c, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelClose()
		_ = masterLog.Close(c)
	}()
	anchorLeaf := func() error {
		_, err := masterLog.Append(ctx, registry.Leaf{
			Kind:        registry.KindAnchor,
			CellID:      daemonsCellID,
			PayloadHash: registry.HashPayload(masterSalt, []byte("anchor:"+daemonsCellID+":epoch0")),
			Timestamp:   time.Now().UnixNano(),
		})
		return err
	}
	if err := anchorLeaf(); err != nil {
		s.fail(phaseDaemons, "ancre initiale", err)
		return
	}
	masterVkeyB, err := os.ReadFile(filepath.Join(masterDir, "cell_log.vkey"))
	if err != nil {
		s.fail(phaseDaemons, "vkey master", err)
		return
	}
	masterVerifier, err := registry.NewVerifier(string(masterVkeyB))
	if err != nil {
		s.fail(phaseDaemons, "verifier master", err)
		return
	}
	if err := waitCheckpointFile(masterDir, masterVerifier, 1); err != nil {
		s.fail(phaseDaemons, "checkpoint master après ancre", err)
		return
	}
	anchorStop := make(chan struct{})
	defer close(anchorStop)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-anchorStop:
				return
			case <-ticker.C:
				_ = anchorLeaf()
			}
		}
	}()
	s.add(phaseDaemons, "master chain : ancre §6.2 de cell-a publiée et cadencée (30 s)", true, masterDir)

	// --- Étape : genèse DEV (manifest contrôleurs + epoch0) -----------------
	manifestJSON, _ := json.Marshal(map[string][]string{"pubkeys": {
		hex.EncodeToString(pubs[1]), hex.EncodeToString(pubs[2]), hex.EncodeToString(pubs[3]),
	}})
	if err := os.WriteFile(filepath.Join(genesisDir, "manifest.json"), manifestJSON, 0o644); err != nil {
		s.fail(phaseDaemons, "manifest de genèse", err)
		return
	}
	writeEpoch0 := func() error {
		epoch0, err := mintEpoch(privs, cluster.EpochPayload{
			N: 0, Authority: daemonsCellID,
			IssuedAt: time.Now().UTC().Format(time.RFC3339), TTLSeconds: epoch0TTL,
		}, 1, 2)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(genesisDir, "epoch0.json"), epoch0, 0o644)
	}
	if err := writeEpoch0(); err != nil {
		s.fail(phaseDaemons, "menthe epoch 0", err)
		return
	}
	s.add(phaseDaemons, "genèse DEV écrite (manifest 2-of-3 + epoch0 — substitution, §12)", true, genesisDir)

	// --- Étape : clés DEV (émetteur 0600, opérateurs, cells.json) -----------
	issuerSeed := sha256.Sum256([]byte("tbp-t35-selftest-dev:issuer"))
	issuerSeedPath := filepath.Join(base, "issuer.seed")
	if err := os.WriteFile(issuerSeedPath, []byte(hex.EncodeToString(issuerSeed[:])), 0o600); err != nil {
		s.fail(phaseDaemons, "seed émetteur DEV", err)
		return
	}
	opPub := devKey("operator-1").Public().(ed25519.PublicKey)
	opKeysPath := filepath.Join(base, "operators.json")
	opKeysJSON, _ := json.Marshal([]string{hex.EncodeToString(opPub)})
	if err := os.WriteFile(opKeysPath, opKeysJSON, 0o600); err != nil {
		s.fail(phaseDaemons, "clés d'opérateurs", err)
		return
	}
	cellsPath := filepath.Join(base, "cells.json")
	cellsJSON, _ := json.Marshal(map[string]any{
		"cells": []map[string]string{{
			"cell_id": daemonsCellID, "log_dir": brokerRegDir, "origin": daemonsCellID,
			"vkey_file": filepath.Join(brokerRegDir, "cell_log.vkey"), "manifest_dir": manifestDir,
		}},
		"master": map[string]string{
			"cell_id": daemonsMasterID, "log_dir": masterDir, "origin": daemonsMasterID,
			"vkey_file": filepath.Join(masterDir, "cell_log.vkey"),
		},
	})
	if err := os.WriteFile(cellsPath, cellsJSON, 0o644); err != nil {
		s.fail(phaseDaemons, "cells.json", err)
		return
	}
	s.add(phaseDaemons, "clés DEV émises (émetteur 0600, opérateurs, cells.json — custody D97)", true, "")

	brokerEnv := append(os.Environ(),
		"TBP_CELL_ID="+daemonsCellID,
		"TBP_SALT="+hex.EncodeToString(cellSalt),
		"TBP_POLICY_ID="+hex.EncodeToString(policyID[:]),
		"TBP_REGISTRY_DIR="+brokerRegDir,
		"TBP_OPA_ENDPOINT=http://"+daemonsOPAAddr+"/v1/data/tbp/example/action",
		// OPA reste en TCP loopback ici (selftest local) — dev/lab
		// EXPLICITE, revue de sécurité #92, finding A3.
		"TBP_OPA_INSECURE_TCP_DEV=1",
		"TBP_TRANSLATOR=structured",
		"TBP_ISSUER_SEED_FILE="+issuerSeedPath,
		"TBP_GENESIS_DIR="+genesisDir,
		"TBP_QUORUM_MIN=2",
		"TBP_CLUSTER_MEMBERS="+daemonsCellID+",cell-b",
		"TBP_OPERATOR_KEYS_FILE="+opKeysPath,
		"TBP_BROKER_SOCKET="+brokerSock,
	)
	supervisorEnv := append(os.Environ(),
		"TBP_MONITOR_CELL_ID="+daemonsMonitorID,
		"TBP_SALT="+hex.EncodeToString(monitorSalt),
		"TBP_REGISTRY_DIR="+monitorDir,
		"TBP_CELLS_FILE="+cellsPath,
		"TBP_CELL_BROKER_SOCKET="+brokerSock,
		"TBP_TICK_MS=1000",
		"TBP_CONSOLE_SOCKET="+consoleSock,
	)
	brokerHC := unixClient(brokerSock)
	consoleHC := unixClient(consoleSock)

	// --- Témoin : pas de console dont les sources sont mortes à la naissance
	// brokerd n'est PAS encore lancé : la sonde de démarrage de supervisord
	// doit être fatale (fail-closed §1), avec la cause dans le message.
	_, errB, err = runCmd(cfg.repo, supervisorEnv, supervisordBin)
	if err == nil || !strings.Contains(errB, "injoignables au démarrage") {
		s.fail(phaseDaemons, "témoin: supervisord refuse de démarrer sans brokerd joignable (sonde fail-closed)",
			fmt.Errorf("err=%v stderr=%s — une console aux sources mortes ne doit pas naître (§1)", err, strings.TrimSpace(errB)))
		return
	}
	s.add(phaseDaemons, "témoin: supervisord refuse de démarrer sans brokerd joignable (sonde fail-closed)", true,
		strings.TrimSpace(strings.SplitN(errB, "\n", 2)[0]))

	// --- Étape : démarrage brokerd (deploy/cellule.md étape 7) --------------
	brokerd, err := startDaemon(brokerdBin, brokerEnv, filepath.Join(base, "brokerd.log"))
	if err != nil {
		s.fail(phaseDaemons, "brokerd démarrage", err)
		return
	}
	defer brokerd.stop()
	if err := waitUnix200(brokerHC, "http://brokerd/v1/supervision/stats", 15*time.Second); err != nil {
		s.fail(phaseDaemons, "brokerd démarrage (sonde unix /v1/supervision/stats)", err)
		return
	}
	s.add(phaseDaemons, "brokerd démarré (registre rouvert, epoch0 accepté, socket unix)", true, brokerSock)

	// --- Vues de supervision D109 -------------------------------------------
	status, raw, err := getUnix(brokerHC, "http://brokerd/v1/supervision/epoch")
	var epochV daemonEpochView
	if err == nil {
		err = json.Unmarshal(raw, &epochV)
	}
	s.add(phaseDaemons, "brokerd: vue époque — époque 0 servie par l'autorité cell-a",
		err == nil && status == http.StatusOK && epochV.Epoch == 0 && epochV.Authority == daemonsCellID,
		fmt.Sprintf("status=%d epoch=%d authority=%s", status, epochV.Epoch, epochV.Authority))

	status, raw, err = getUnix(brokerHC, "http://brokerd/v1/supervision/arbitration")
	var arbV daemonArbitrationView
	if err == nil {
		err = json.Unmarshal(raw, &arbV)
	}
	s.add(phaseDaemons, "brokerd: vue arbitrage — policy_id = hash du bundle, file vide",
		err == nil && status == http.StatusOK && arbV.PolicyID == hex.EncodeToString(policyID[:]) && len(arbV.Pending) == 0,
		fmt.Sprintf("status=%d policy_id=%s pending=%d", status, arbV.PolicyID, len(arbV.Pending)))

	status, raw, err = getUnix(brokerHC, "http://brokerd/v1/supervision/stats")
	var statsV daemonStatsView
	if err == nil {
		err = json.Unmarshal(raw, &statsV)
	}
	s.add(phaseDaemons, "brokerd: compteurs à zéro au démarrage",
		err == nil && status == http.StatusOK && statsV.Requests == 0 && statsV.Allows == 0 && statsV.Denies == 0,
		fmt.Sprintf("status=%d requests=%d allows=%d denies=%d", status, statsV.Requests, statsV.Allows, statsV.Denies))

	// Doctrine GET-only : une méthode autre que GET reçoit 405 DU MUX.
	status, _, _ = postUnixJSON(brokerHC, "http://brokerd/v1/supervision/stats", map[string]string{"x": "y"})
	s.add(phaseDaemons, "brokerd: doctrine GET-only — POST sur une vue de supervision → 405",
		status == http.StatusMethodNotAllowed, fmt.Sprintf("status=%d", status))

	// --- Action réelle de bout en bout (chaîne §5.1 complète) ----------------
	proof, err := mintProof(privs, "read", "doc-1", policyID, 0, time.Now().Add(2*time.Minute), 1, 2)
	if err != nil {
		s.fail(phaseDaemons, "menthe preuve de quorum", err)
		return
	}
	intent := fmt.Sprintf(`{"action":"read","resource":"doc-1","class":2,"quorum_proof":"%s"}`,
		hex.EncodeToString(proof))
	status, raw, err = postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{
		"subject": "agent-1", "intent": intent,
	})
	var actV daemonActionResponse
	if err == nil {
		err = json.Unmarshal(raw, &actV)
	}
	s.add(phaseDaemons, "action de bout en bout: read → allow + jeton (OPA réel, époque 0, quorum 2-of-3)",
		err == nil && status == http.StatusOK && actV.Allow && actV.Token != "",
		fmt.Sprintf("status=%d allow=%v reason=%s token=%d octets", status, actV.Allow, actV.Reason, len(actV.Token)))

	status, raw, err = getUnix(brokerHC, "http://brokerd/v1/supervision/stats")
	statsV = daemonStatsView{}
	if err == nil {
		_ = json.Unmarshal(raw, &statsV)
	}
	s.add(phaseDaemons, "brokerd: compteurs non-vacuoles — requests=1, allows=1 après l'action",
		err == nil && statsV.Requests == 1 && statsV.Allows == 1,
		fmt.Sprintf("requests=%d allows=%d denies=%d", statsV.Requests, statsV.Allows, statsV.Denies))

	// --- Témoin : action hors politique → deny OPA, tracé --------------------
	denyIntent := `{"action":"write","resource":"doc-1","class":1}`
	status, raw, err = postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{
		"subject": "agent-1", "intent": denyIntent,
	})
	actV = daemonActionResponse{}
	if err == nil {
		_ = json.Unmarshal(raw, &actV)
	}
	status2, raw2, _ := getUnix(brokerHC, "http://brokerd/v1/supervision/stats")
	statsV2 := daemonStatsView{}
	if status2 == http.StatusOK {
		_ = json.Unmarshal(raw2, &statsV2)
	}
	s.add(phaseDaemons, "témoin: write → deny OPA tracé (requests=2, denies=1, allows inchangé)",
		err == nil && status == http.StatusOK && !actV.Allow && statsV2.Requests == 2 && statsV2.Denies == 1 && statsV2.Allows == 1,
		fmt.Sprintf("allow=%v reason=%s requests=%d denies=%d", actV.Allow, actV.Reason, statsV2.Requests, statsV2.Denies))

	// --- Étape : démarrage supervisord (deploy/superviseur.md étape 3) -------
	supervisord, err := startDaemon(supervisordBin, supervisorEnv, filepath.Join(base, "supervisord.log"))
	if err != nil {
		s.fail(phaseDaemons, "supervisord démarrage", err)
		return
	}
	defer supervisord.stop()
	if err := waitUnix200(consoleHC, "http://console/v1/epoch", 15*time.Second); err != nil {
		s.fail(phaseDaemons, "supervisord démarrage (sonde console /v1/epoch)", err)
		return
	}
	s.add(phaseDaemons, "supervisord démarré (moniteur cadencé 1 s, console sur socket unix)", true, consoleSock)

	// --- Console : lectures LIVE via les adaptateurs (D110 élargi) -----------
	status, raw, err = getUnix(consoleHC, "http://console/v1/epoch")
	epochV = daemonEpochView{}
	if err == nil {
		_ = json.Unmarshal(raw, &epochV)
	}
	s.add(phaseDaemons, "console: /v1/epoch live == brokerd (époque 0, autorité cell-a)",
		err == nil && status == http.StatusOK && epochV.Epoch == 0 && epochV.Authority == daemonsCellID,
		fmt.Sprintf("status=%d epoch=%d authority=%s", status, epochV.Epoch, epochV.Authority))

	status, raw, err = getUnix(consoleHC, "http://console/v1/arbitration")
	arbV = daemonArbitrationView{}
	if err == nil {
		_ = json.Unmarshal(raw, &arbV)
	}
	s.add(phaseDaemons, "console: /v1/arbitration — policy_id conforme, file vide",
		err == nil && status == http.StatusOK && arbV.PolicyID == hex.EncodeToString(policyID[:]) && len(arbV.Pending) == 0,
		fmt.Sprintf("status=%d policy_id=%s pending=%d", status, arbV.PolicyID, len(arbV.Pending)))

	// Le moniteur a besoin d'au moins un tick (1 s) pour peupler ses vues
	// cellules : borne courte de repli, même motif que le delta tessera.
	var indV daemonIndicatorsView
	healthy := false
	for i := 0; i < 20 && !healthy; i++ {
		time.Sleep(300 * time.Millisecond)
		status, raw, err = getUnix(consoleHC, "http://console/v1/indicators")
		if err != nil || status != http.StatusOK {
			continue
		}
		if json.Unmarshal(raw, &indV) != nil {
			continue
		}
		for _, c := range indV.Cells {
			if c.CellID == daemonsCellID && c.ChainSize >= 1 && !c.AnchorStale && !c.FallEpisode {
				healthy = true
			}
		}
	}
	s.add(phaseDaemons, "console: /v1/indicators — compteurs broker live et cell-a saine (ancrée, sans chute)",
		healthy && indV.Arbitration.Requests >= 2,
		fmt.Sprintf("requests=%d cells=%+v", indV.Arbitration.Requests, indV.Cells))

	// --- Témoins d'honnêteté : brokerd arrêté ⇒ 503 PAR ROUTE (§1) ----------
	brokerd.stop()
	witness503 := func(route string) (int, []byte) {
		st, body, _ := getUnix(consoleHC, "http://console"+route)
		return st, body
	}
	status, raw = witness503("/v1/epoch")
	s.add(phaseDaemons, "témoin: brokerd arrêté ⇒ console /v1/epoch 503 « source indisponible » (honnêteté §1)",
		status == http.StatusServiceUnavailable && strings.Contains(string(raw), "source indisponible"),
		fmt.Sprintf("status=%d body=%s", status, strings.TrimSpace(string(raw))))
	status, raw = witness503("/v1/arbitration")
	s.add(phaseDaemons, "témoin: /v1/arbitration 503 aussi (erreur par route, pas de middleware global)",
		status == http.StatusServiceUnavailable && strings.Contains(string(raw), "source indisponible"),
		fmt.Sprintf("status=%d", status))
	status, raw = witness503("/v1/indicators")
	s.add(phaseDaemons, "témoin: /v1/indicators 503 aussi (sources stats et arbitrage mortes)",
		status == http.StatusServiceUnavailable && strings.Contains(string(raw), "source indisponible"),
		fmt.Sprintf("status=%d", status))

	// --- Reprise : lecture LIVE, jamais de valeur figée -----------------------
	// epoch0 réémis (TTL borné à 240 s par le tracker) : la reprise prouve
	// aussi que le démon relit sa genèse à chaque démarrage.
	if err := writeEpoch0(); err != nil {
		s.fail(phaseDaemons, "re-menthe epoch 0 (reprise)", err)
		return
	}
	brokerd2, err := startDaemon(brokerdBin, brokerEnv, filepath.Join(base, "brokerd-reprise.log"))
	if err != nil {
		s.fail(phaseDaemons, "brokerd reprise", err)
		return
	}
	defer brokerd2.stop()
	recovered := false
	for i := 0; i < 50 && !recovered; i++ {
		time.Sleep(200 * time.Millisecond)
		status, raw, err = getUnix(consoleHC, "http://console/v1/epoch")
		if err == nil && status == http.StatusOK {
			epochV = daemonEpochView{}
			if json.Unmarshal(raw, &epochV) == nil && epochV.Epoch == 0 && epochV.Authority == daemonsCellID {
				recovered = true
			}
		}
	}
	s.add(phaseDaemons, "reprise: brokerd relancé ⇒ console 200 à nouveau (lecture live, pas de cache figé)",
		recovered, fmt.Sprintf("status=%d epoch=%d authority=%s", status, epochV.Epoch, epochV.Authority))
}
