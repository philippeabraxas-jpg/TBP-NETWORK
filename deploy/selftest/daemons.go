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
	"bytes"
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
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	devmode "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devmode"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
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
	Requests     uint64 `json:"requests"`
	Allows       uint64 `json:"allows"`
	Denies       uint64 `json:"denies"`
	QuorumDenies uint64 `json:"quorum_denies"`
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

// daemonPlanSubmitResponse est la réponse de POST
// /v1/supervision/plan/submit (#177) — canal d'opérateur du contrat de
// plan, socket admin.
type daemonPlanSubmitResponse struct {
	PlanHash string `json:"plan_hash"`
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
	brokerAdminSock := filepath.Join(base, "broker-admin.sock")
	consoleSock := filepath.Join(base, "supervision.sock")
	// Un témoin de provisionnement ou un registre d'une exécution précédente ferait un faux échec
	// (brokerd repartirait « conforme » au lieu d'exiger l'adoption) — même précaution que scale2.
	_ = os.RemoveAll(base)
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
	opawatchdogBin := filepath.Join(binDir, "opawatchdog")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", opawatchdogBin, "./src/supervision/cmd/opawatchdog"); err != nil {
		s.fail(phaseDaemons, "build opawatchdog", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(phaseDaemons, "build opawatchdog (deploy/cellule.md, « OPA sous attaque »)", true, opawatchdogBin)

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
	// Signature de bundle (revue de sécurité #106) — témoin de rejeu déjà
	// exercé une fois par la phase mono ; ici seule la recette réelle
	// (signer au build, vérifier au run) est exercée.
	signingKeyPath, verificationKeyPath, ok := generateSigningKeypair(s, phaseDaemons, opaDir)
	if !ok {
		return
	}
	if !buildBundle(s, phaseDaemons, cfg, capsPath, regoPath, bundlePath, hex.EncodeToString(policyID[:]), signingKeyPath) {
		return
	}
	opa, ok := startOPA(s, phaseDaemons, cfg, daemonsOPAAddr, bundlePath, verificationKeyPath, filepath.Join(opaDir, "opa.log"))
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
	// Journal d'audit de brokerd (#275) : REQUIS. Neuf à chaque exécution (base est vidée au début de la
	// phase). Créé AVANT la genèse simulée : la feuille que le harnais écrit dans le registre de brokerd
	// (une cellule déjà déployée) porte son clair dans CE journal, comme celles du démon — la vérification
	// de couverture (`tbp-audit verify -coverage`) ne doit trouver aucune feuille sans clair.
	auditKeyPath := filepath.Join(base, "brokerd-audit.key")
	auditJournalPath := filepath.Join(base, "brokerd-audit-records.jsonl")
	if err := registry.GenerateRecordKey(auditKeyPath); err != nil {
		s.fail(phaseDaemons, "clé du journal d'audit de brokerd", err)
		return
	}
	harnessJournal, err := registry.OpenRecordStoreFiles(auditJournalPath, auditKeyPath)
	if err != nil {
		s.fail(phaseDaemons, "journal d'audit de brokerd (harnais)", err)
		return
	}
	defer harnessJournal.Close()
	manifester, err := registry.NewManifester(registry.ManifestOptions{
		CellID: daemonsCellID, Signer: cellSigner, Verifier: cellVerifier,
		Leaves: cellLog, Journal: harnessJournal, Salt: cellSalt,
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
	// Registre d'agents (revue #125) : "agent-1" résolu classe W — même
	// classe que l'intention de l'action de bout en bout déclarait déjà
	// (class 2) avant #125 ; le registre la porte désormais de façon
	// AUTORITAIRE, la déclaration de l'intention n'étant plus qu'une
	// forme de compatibilité de schéma, jamais la source de la décision.
	agentsPath := filepath.Join(base, "agents.json")
	agentsJSON, _ := json.Marshal(map[string]map[string]any{
		"agent-1":   {"class": 2},
		"agent-std": {"class": 3}, // système STANDARD : escalade humaine en mode dégradé (§4.5)
	})
	if err := os.WriteFile(agentsPath, agentsJSON, 0o600); err != nil {
		s.fail(phaseDaemons, "registre d'agents", err)
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

	// Dégradation contrôlée du traducteur (T25, §4.5) : brokerd sonde ce faux service de santé (loopback).
	translatorHealth, err := startHealthStub()
	if err != nil {
		s.fail(phaseDaemons, "service de santé du traducteur (harnais)", err)
		return
	}
	defer translatorHealth.stop()
	mirrorFx, err := newMirrorFixture(base, policyID, 0, privs)
	if err != nil {
		s.fail(phaseDaemons, "fixture de la cellule miroir (harnais)", err)
		return
	}

	brokerEnv := append(os.Environ(),
		"TBP_TRANSLATOR_GUARD=1",
		"TBP_TRANSLATOR_PROBE_URL="+translatorHealth.URL,
		"TBP_TRANSLATOR_PROBE_INTERVAL_MS=500",
		"TBP_ARBITRATION=1",
		"TBP_MIRROR_ANCHORS_FILE="+mirrorFx.AnchorsFile,
		"TBP_MIRROR_CELL_KEYS_FILE="+mirrorFx.CellKeysFile,
		"TBP_AUDIT_RECORDS="+auditJournalPath,
		"TBP_AUDIT_RECORDS_KEY_FILE="+auditKeyPath,
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
		"TBP_TOPOLOGY=multi", // 2 membres déclarés ci-dessous — cohérence vérifiée fail-closed (issue #128)
		"TBP_CLUSTER_MEMBERS="+daemonsCellID+",cell-b",
		"TBP_OPERATOR_KEYS_FILE="+opKeysPath,
		"TBP_AGENT_REGISTRY_FILE="+agentsPath,
		// Mesure des fichiers de confiance (issue #192) : témoin hors du registre.
		"TBP_PROVISIONING_WITNESS_FILE="+filepath.Join(base, "brokerd-provisioning-witness.json"),
		"TBP_BROKER_SOCKET="+brokerSock,
		// Plan d'ADMINISTRATION dédié (revue de sécurité #95, finding A10) :
		// GET /v1/supervision/* n'est plus servi sur le plan de données
		// (TBP_BROKER_SOCKET) — un test qui les sonderait encore là échouerait
		// désormais systématiquement (revue #86 : le selftest doit rester
		// exécutable, pas seulement le code).
		"TBP_BROKER_ADMIN_SOCKET="+brokerAdminSock,
	)

	// Adoption de #192 sur un registre qui a DÉJÀ vécu (ici : le harness y a écrit des
	// feuilles avant le premier démarrage de brokerd, comme le ferait une cellule déployée
	// avant cette brique) : sans témoin, brokerd refuse — un fichier édité serait sinon
	// ré-engagé comme « premier démarrage » (§111). Le SEUL geste d'adoption est une preuve
	// de quorum. Geste de l'opérateur (issue #236) : brokerd REFUSE sans preuve et annonce la
	// condition à signer (état de départ — aucun témoin — et état cible) ; les contrôleurs
	// signent exactement celle-ci. Le démon est borné : un démon qui ne refuse pas (il sert)
	// est arrêté et l'adoption est signalée en échec.
	provProof := filepath.Join(base, "provisioning-proof.json")
	{
		probe, err := startDaemon(brokerdBin, brokerEnv, filepath.Join(base, "brokerd-adoption-refus.log"))
		if err != nil {
			s.fail(phaseDaemons, "brokerd: démarrage sans preuve (adoption)", err)
			return
		}
		exited := make(chan error, 1)
		go func() { exited <- probe.cmd.Wait() }()
		var rerr error
		select {
		case rerr = <-exited:
		case <-time.After(20 * time.Second):
			probe.stop()
			rerr = nil
		}
		refusal, _ := os.ReadFile(filepath.Join(base, "brokerd-adoption-refus.log"))
		cond, ok := conditionToSign(string(refusal))
		s.add(phaseDaemons, "brokerd: refus sans preuve, et la condition à signer (départ, cible) est annoncée (#236)",
			rerr != nil && ok, strings.TrimSpace(cond))
		if !ok || rerr == nil {
			return
		}
		expiry := time.Now().Add(4 * time.Minute)
		msg := pep.QuorumMessage(cond, daemonsCellID, expiry)
		type sigWire struct {
			KeyID     string `json:"key_id"`
			Signature string `json:"signature"`
		}
		var sigs []sigWire
		for _, id := range []int{1, 2} { // k = TBP_QUORUM_MIN = 2
			kid := pep.KeyIDFromPublicKey(pubs[id])
			sigs = append(sigs, sigWire{KeyID: hex.EncodeToString(kid[:]), Signature: hex.EncodeToString(ed25519.Sign(privs[id], msg))})
		}
		proofJSON, _ := json.Marshal(map[string]any{"expiry": expiry.Unix(), "signatures": sigs})
		if err := os.WriteFile(provProof, proofJSON, 0o600); err != nil {
			s.fail(phaseDaemons, "preuve d'adoption du provisionnement", err)
			return
		}
	}
	brokerEnvFirst := append(append([]string{}, brokerEnv...), "TBP_PROVISIONING_TRANSITION_PROOF_FILE="+provProof)

	// Journal d'enregistrements de supervisord (#275) : requis, comme celui de brokerd.
	monitorAuditKey := filepath.Join(base, "supervisord-audit.key")
	monitorAuditJournal := filepath.Join(base, "supervisord-audit-records.jsonl")
	if err := registry.GenerateRecordKey(monitorAuditKey); err != nil {
		s.fail(phaseDaemons, "clé du journal d'audit de supervisord", err)
		return
	}
	supervisorEnv := append(os.Environ(),
		"TBP_MONITOR_CELL_ID="+daemonsMonitorID,
		"TBP_SALT="+hex.EncodeToString(monitorSalt),
		"TBP_REGISTRY_DIR="+monitorDir,
		"TBP_AUDIT_RECORDS="+monitorAuditJournal,
		"TBP_AUDIT_RECORDS_KEY_FILE="+monitorAuditKey,
		"TBP_CELLS_FILE="+cellsPath,
		// Plan ADMIN (§95) : supervisord ne lit que GET /v1/supervision/*,
		// jamais POST /v1/actions — brokerSock (plan de données) ne sert
		// pas ces routes.
		"TBP_CELL_BROKER_SOCKET="+brokerAdminSock,
		"TBP_TICK_MS=1000",
		"TBP_CONSOLE_SOCKET="+consoleSock,
	)
	brokerHC := unixClient(brokerSock)
	brokerAdminHC := unixClient(brokerAdminSock)
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
	brokerd, err := startDaemon(brokerdBin, brokerEnvFirst, filepath.Join(base, "brokerd.log"))
	if err != nil {
		s.fail(phaseDaemons, "brokerd démarrage", err)
		return
	}
	defer brokerd.stop()
	if err := waitUnix200(brokerAdminHC, "http://brokerd/v1/supervision/stats", 15*time.Second); err != nil {
		s.fail(phaseDaemons, "brokerd démarrage (sonde unix /v1/supervision/stats)", err)
		return
	}
	s.add(phaseDaemons, "brokerd démarré (registre rouvert, epoch0 accepté, socket unix)", true, brokerSock)

	// --- Vues de supervision D109 -------------------------------------------
	status, raw, err := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/epoch")
	var epochV daemonEpochView
	if err == nil {
		err = json.Unmarshal(raw, &epochV)
	}
	s.add(phaseDaemons, "brokerd: vue époque — époque 0 servie par l'autorité cell-a",
		err == nil && status == http.StatusOK && epochV.Epoch == 0 && epochV.Authority == daemonsCellID,
		fmt.Sprintf("status=%d epoch=%d authority=%s", status, epochV.Epoch, epochV.Authority))

	status, raw, err = getUnix(brokerAdminHC, "http://brokerd/v1/supervision/arbitration")
	var arbV daemonArbitrationView
	if err == nil {
		err = json.Unmarshal(raw, &arbV)
	}
	s.add(phaseDaemons, "brokerd: vue arbitrage — policy_id = hash du bundle, file vide",
		err == nil && status == http.StatusOK && arbV.PolicyID == hex.EncodeToString(policyID[:]) && len(arbV.Pending) == 0,
		fmt.Sprintf("status=%d policy_id=%s pending=%d", status, arbV.PolicyID, len(arbV.Pending)))

	status, raw, err = getUnix(brokerAdminHC, "http://brokerd/v1/supervision/stats")
	var statsV daemonStatsView
	if err == nil {
		err = json.Unmarshal(raw, &statsV)
	}
	s.add(phaseDaemons, "brokerd: compteurs à zéro au démarrage",
		err == nil && status == http.StatusOK && statsV.Requests == 0 && statsV.Allows == 0 && statsV.Denies == 0,
		fmt.Sprintf("status=%d requests=%d allows=%d denies=%d", status, statsV.Requests, statsV.Allows, statsV.Denies))

	// Doctrine GET-only : une méthode autre que GET reçoit 405 DU MUX.
	status, _, _ = postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/stats", map[string]string{"x": "y"})
	s.add(phaseDaemons, "brokerd: doctrine GET-only — POST sur une vue de supervision → 405",
		status == http.StatusMethodNotAllowed, fmt.Sprintf("status=%d", status))

	// --- Contrat de plan (#177) : plan_binding désormais obligatoire pour
	// toute action de classe I/W (§5.3) — "agent-1" est résolu classe W
	// par le registre (agents.json ci-dessus). Le canal d'opérateur ouvert
	// par #177 (socket admin, POST /v1/supervision/plan/{submit,approve})
	// est exercé ici pour de vrai contre le brokerd réellement lancé —
	// pas un raccourci de fixture : c'est exactement le canal qu'un
	// opérateur emprunterait avant d'autoriser "agent-1" à exécuter
	// "read"/"doc-1".
	submitStatus, raw, err := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/plan/submit", map[string]any{
		"subject": "agent-1",
		"steps":   []map[string]string{{"action": "read", "resource": "doc-1", "params_hex": ""}},
	})
	var planSub daemonPlanSubmitResponse
	if submitStatus == http.StatusOK {
		err = json.Unmarshal(raw, &planSub)
	}
	s.add(phaseDaemons, "brokerd: plan soumis (canal opérateur, socket admin — #177)",
		submitStatus == http.StatusOK && err == nil && planSub.PlanHash != "",
		fmt.Sprintf("status=%d plan_hash=%s", submitStatus, planSub.PlanHash))

	planHashBytes, err := hex.DecodeString(planSub.PlanHash)
	if err != nil || len(planHashBytes) != 32 {
		s.fail(phaseDaemons, "plan_hash reçu illisible", fmt.Errorf("hash=%q err=%v", planSub.PlanHash, err))
		return
	}
	var planHash [32]byte
	copy(planHash[:], planHashBytes)
	approvalExpiry := time.Now().Add(5 * time.Minute)
	approvalSig := ed25519.Sign(devKey("operator-1"), pep.ApprovalMessage(planHash, approvalExpiry))
	approveStatus, _, err := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/plan/approve", map[string]any{
		"plan_hash":  planSub.PlanHash,
		"expires_at": approvalExpiry.UTC().Format(time.RFC3339),
		"signature":  hex.EncodeToString(approvalSig),
	})
	s.add(phaseDaemons, "brokerd: plan approuvé (signature opérateur Ed25519 — #177)",
		approveStatus == http.StatusOK, fmt.Sprintf("status=%d", approveStatus))

	// --- #244 : la révocation d'un plan est un acte d'opérateur signé -------------
	// Un SECOND plan, approuvé puis révoqué, sans toucher au plan de l'action de bout en bout
	// (les compteurs de requêtes plus bas restent exacts). Une révocation sans signature valide
	// (ici : la signature d'APPROBATION, domaine distinct) est refusée ; la signée coupe le plan ;
	// la rejouer est refusée (déjà révoqué).
	{
		st2, raw2, _ := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/plan/submit", map[string]any{
			"subject": "agent-1",
			"steps":   []map[string]string{{"action": "read", "resource": "doc-revoke", "params_hex": ""}},
		})
		var sub2 daemonPlanSubmitResponse
		if st2 == http.StatusOK {
			_ = json.Unmarshal(raw2, &sub2)
		}
		hb2, derr := hex.DecodeString(sub2.PlanHash)
		if st2 != http.StatusOK || derr != nil || len(hb2) != 32 {
			s.fail(phaseDaemons, "brokerd: second plan soumis (révocation, #244)", fmt.Errorf("status=%d err=%v", st2, derr))
			return
		}
		var h2 [32]byte
		copy(h2[:], hb2)
		exp2 := time.Now().Add(5 * time.Minute)
		apSt, _, _ := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/plan/approve", map[string]any{
			"plan_hash":  sub2.PlanHash,
			"expires_at": exp2.UTC().Format(time.RFC3339),
			"signature":  hex.EncodeToString(ed25519.Sign(devKey("operator-1"), pep.ApprovalMessage(h2, exp2))),
		})
		revoke := func(sig []byte) int {
			st, _, _ := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/plan/revoke", map[string]any{
				"plan_hash":  sub2.PlanHash,
				"expires_at": exp2.UTC().Format(time.RFC3339),
				"signature":  hex.EncodeToString(sig),
			})
			return st
		}
		badSt := revoke(ed25519.Sign(devKey("operator-1"), pep.ApprovalMessage(h2, exp2)))
		okSt := revoke(ed25519.Sign(devKey("operator-1"), pep.RevocationMessage(h2, exp2)))
		replaySt := revoke(ed25519.Sign(devKey("operator-1"), pep.RevocationMessage(h2, exp2)))
		s.add(phaseDaemons, "brokerd: plan approuvé puis révoqué par l'opérateur (signature de révocation distincte de l'approbation — #244)",
			apSt == http.StatusOK && badSt == http.StatusBadRequest && okSt == http.StatusOK && replaySt == http.StatusBadRequest,
			fmt.Sprintf("approbation=%d révocation(sig d'approbation)=%d révocation signée=%d rejeu=%d", apSt, badSt, okSt, replaySt))
	}

	planBinding, err := pep.BuildBinding(planHash, nil)
	if err != nil {
		s.fail(phaseDaemons, "construction du plan_binding", err)
		return
	}

	// --- Action réelle de bout en bout (chaîne §5.1 complète) ----------------
	// TTL de 4 min (plafond 5 min) : la même preuve est représentée plus bas,
	// après un redémarrage de brokerd (issue #206) — elle ne doit pas avoir
	// expiré d'ici là, sinon le refus ne prouverait rien.
	proofMintedAt := time.Now()
	proof, err := mintProof(privs, "read", "doc-1", policyID, 0, proofMintedAt.Add(4*time.Minute), 1, 2)
	if err != nil {
		s.fail(phaseDaemons, "menthe preuve de quorum", err)
		return
	}
	intent := fmt.Sprintf(`{"action":"read","resource":"doc-1","class":2,"quorum_proof":"%s","plan_binding":"%s"}`,
		hex.EncodeToString(proof), hex.EncodeToString(planBinding))
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

	status, raw, err = getUnix(brokerAdminHC, "http://brokerd/v1/supervision/stats")
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
	status2, raw2, _ := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/stats")
	statsV2 := daemonStatsView{}
	if status2 == http.StatusOK {
		_ = json.Unmarshal(raw2, &statsV2)
	}
	s.add(phaseDaemons, "témoin: write → deny OPA tracé (requests=2, denies=1, allows inchangé)",
		err == nil && status == http.StatusOK && !actV.Allow && statsV2.Requests == 2 && statsV2.Denies == 1 && statsV2.Allows == 1,
		fmt.Sprintf("allow=%v reason=%s requests=%d denies=%d", actV.Allow, actV.Reason, statsV2.Requests, statsV2.Denies))

	// --- Témoin : le paquet de durcissement refuse pour de vrai ---------------
	// Même action « read » que l'action de bout en bout autorisée plus haut :
	// seule la RESSOURCE change (un magasin d'identifiants). Le refus vient donc
	// bien du paquet policies/rego/pack_agent_hardening.rego, chargé dans le
	// bundle réel sous capacités restreintes — pas d'une règle d'action absente.
	credIntent := `{"action":"read","resource":"workspace/.env","class":2}`
	status, raw, err = postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{
		"subject": "agent-1", "intent": credIntent,
	})
	actV = daemonActionResponse{}
	if err == nil {
		_ = json.Unmarshal(raw, &actV)
	}
	status3, raw3, _ := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/stats")
	statsV3 := daemonStatsView{}
	if status3 == http.StatusOK {
		_ = json.Unmarshal(raw3, &statsV3)
	}
	s.add(phaseDaemons, "témoin: read d'un magasin d'identifiants (.env) → deny OPA par le paquet de durcissement",
		err == nil && status == http.StatusOK && !actV.Allow && actV.Reason == "opa-deny" &&
			statsV3.Requests == 3 && statsV3.Denies == 2 && statsV3.Allows == 1,
		fmt.Sprintf("allow=%v reason=%s requests=%d denies=%d allows=%d", actV.Allow, actV.Reason, statsV3.Requests, statsV3.Denies, statsV3.Allows))

	// --- Issue #208 (R-13) : les échappatoires dev actives de brokerd ---------
	// laissent une feuille (TBP_OPA_INSECURE_TCP_DEV et TBP_ISSUER_SEED_FILE).
	devLeaf := registry.HashPayload(cellSalt, devmode.ActiveRecord([]string{"TBP_OPA_INSECURE_TCP_DEV", "TBP_ISSUER_SEED_FILE"}))
	foundDev, derr := waitPayloadHash(ctx, daemonsCellID, brokerRegDir, devLeaf, 5*time.Second)
	s.add(phaseDaemons, "#208 : les échappatoires dev actives de brokerd sont consignées en feuille KindTelemetry (recalculable par re-hash)",
		derr == nil && foundDev, fmt.Sprintf("trouvée=%v err=%v", foundDev, derr))

	// --- Dégradation contrôlée du traducteur (T25, §4.5, #275) ----------------
	// Le service de santé tombe : brokerd REFUSE (refus sain « translation-failed », jamais une
	// admission) ; il revient : le chemin se rouvre sans redémarrage (la demande atteint OPA).
	translatorHealth.set(false)
	closedOK := false
	var closedReason string
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		st, rw, e := postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{"subject": "agent-1", "intent": denyIntent})
		var av daemonActionResponse
		if e == nil && st == http.StatusOK && json.Unmarshal(rw, &av) == nil {
			closedReason = av.Reason
			if !av.Allow && av.Reason == "translation-failed" && av.Token == "" {
				closedOK = true
				break
			}
		}
	}
	s.add(phaseDaemons, "T25 : traducteur dégradé (sonde rouge) ⇒ brokerd refuse (translation-failed), jamais d'admission",
		closedOK, "dernière raison="+closedReason)
	translatorHealth.set(true)
	reopenedOK := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		st, rw, e := postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{"subject": "agent-1", "intent": denyIntent})
		var av daemonActionResponse
		if e == nil && st == http.StatusOK && json.Unmarshal(rw, &av) == nil {
			closedReason = av.Reason
			if av.Reason == "opa-deny" { // la demande a franchi le traducteur et atteint OPA
				reopenedOK = true
				break
			}
		}
	}
	s.add(phaseDaemons, "T25 : sonde verte ⇒ le chemin se rouvre sans redémarrage (la demande atteint OPA)",
		reopenedOK, "dernière raison="+closedReason)
	brokerLog, _ := os.ReadFile(filepath.Join(base, "brokerd.log"))
	tbtdRecovered := registry.HashPayload(cellSalt, []byte{'T', 'B', 'T', 'D', '1', 2})
	foundRec, rerr := waitPayloadHash(ctx, daemonsCellID, brokerRegDir, tbtdRecovered, 10*time.Second)
	s.add(phaseDaemons, "T25 : bascules et refus alarmés (log) et la reprise laisse une feuille TBTD1 recalculable",
		strings.Contains(string(brokerLog), "ALARME: translator-down") &&
			strings.Contains(string(brokerLog), "ALARME: translator-default-deny") && rerr == nil && foundRec,
		fmt.Sprintf("feuille reprise trouvée=%v err=%v", foundRec, rerr))

	// --- Issue #207 (R-14) : un jeton d'époque au bail échu ne remplace pas ---
	// l'époque vivante. Le jeton est AUTHENTIQUE (signé 2-of-3 par les
	// contrôleurs) : seul son bail, déjà échu à la réception, le disqualifie.
	staleTok, err := mintEpoch(privs, cluster.EpochPayload{
		N: 1, Authority: daemonsCellID,
		IssuedAt: time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339), TTLSeconds: 60,
	}, 1, 2)
	if err != nil {
		s.fail(phaseDaemons, "menthe jeton d'époque échu (#207)", err)
		return
	}
	renewReq, _ := http.NewRequest(http.MethodPost, "http://brokerd/v1/epoch/renew", bytes.NewReader(staleTok))
	renewResp, renewErr := brokerAdminHC.Do(renewReq)
	renewStatus, renewBody := 0, []byte(nil)
	if renewErr == nil {
		renewStatus = renewResp.StatusCode
		renewBody, _ = io.ReadAll(io.LimitReader(renewResp.Body, 1<<16))
		_ = renewResp.Body.Close()
	}
	_, rawE, _ := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/epoch")
	epochAfter := daemonEpochView{}
	_ = json.Unmarshal(rawE, &epochAfter)
	s.add(phaseDaemons, "#207 : jeton d'époque authentique mais au bail échu → refusé, l'époque vivante (0) est intacte",
		renewErr == nil && renewStatus == http.StatusBadRequest && strings.Contains(string(renewBody), "epoch-token-expired") && epochAfter.Epoch == 0,
		fmt.Sprintf("status=%d epoch=%d corps=%s", renewStatus, epochAfter.Epoch, strings.TrimSpace(string(renewBody))))

	// --- Issue #206 (R-19) : une preuve W vaut UNE autorisation ---------------
	// La MÊME intention, avec la MÊME preuve de quorum, est représentée : le
	// refus doit venir du quorum (quorum_denies=1), pas d'un autre garde-fou
	// — le quorum est évalué avant le plan_binding, donc avant la
	// consommation de l'étape du plan.
	status, raw, err = postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{
		"subject": "agent-1", "intent": intent,
	})
	actV = daemonActionResponse{}
	if err == nil {
		_ = json.Unmarshal(raw, &actV)
	}
	_, rawR, _ := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/stats")
	statsR := daemonStatsView{}
	_ = json.Unmarshal(rawR, &statsR)
	s.add(phaseDaemons, "#206 : la même preuve de quorum W présentée une seconde fois → refus au quorum",
		err == nil && status == http.StatusOK && !actV.Allow && statsR.QuorumDenies == 1,
		fmt.Sprintf("allow=%v reason=%s quorum_denies=%d", actV.Allow, actV.Reason, statsR.QuorumDenies))
	// #275 : le clair des décisions, du quorum et des plans de brokerd est vérifiable.
	verifyAuditJournal(s, phaseDaemons, "brokerd", brokerRegDir, auditJournalPath, auditKeyPath, 3)

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

	// #275 : le journal du moniteur se lit, se déchiffre et chacun de ses enregistrements (aucun alerte
	// attendue : cell-a est saine) est vérifié dans la chaîne du moniteur.
	verifyAuditJournal(s, phaseDaemons, "supervisord", monitorDir, monitorAuditJournal, monitorAuditKey, 0)

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

	// --- Issue #192 : un fichier de confiance édité hors-bande refuse le démarrage ---
	// Même binaire, même environnement, mêmes fichiers — sauf agents.json, dont la
	// classe d'agent-1 (W, quorum + plan) passe à 3 (ni l'un ni l'autre). Avant #192
	// cette édition passait sans alarme ; le témoin signé la détecte.
	brokerd2.stop()
	origAgents, err := os.ReadFile(agentsPath)
	if err != nil {
		s.fail(phaseDaemons, "lecture agents.json (issue #192)", err)
		return
	}
	editedAgents, _ := json.Marshal(map[string]map[string]any{"agent-1": {"class": 3}})
	if err := os.WriteFile(agentsPath, editedAgents, 0o600); err != nil {
		s.fail(phaseDaemons, "édition agents.json (issue #192)", err)
		return
	}
	if err := writeEpoch0(); err != nil {
		s.fail(phaseDaemons, "epoch 0 (issue #192)", err)
		return
	}
	refusedLog := filepath.Join(base, "brokerd-provisioning-refus.log")
	refused, err := startDaemon(brokerdBin, brokerEnv, refusedLog)
	if err != nil {
		s.fail(phaseDaemons, "brokerd (agents.json édité)", err)
		return
	}
	exited := make(chan error, 1)
	go func() { exited <- refused.cmd.Wait() }()
	refusedOK := false
	select {
	case werr := <-exited:
		refusedOK = werr != nil // sortie NON nulle : le démarrage est refusé
	case <-time.After(15 * time.Second):
		refused.stop()
	}
	logBytes, _ := os.ReadFile(refusedLog)
	s.add(phaseDaemons, "issue #192 : agents.json édité hors-bande ⇒ brokerd REFUSE de démarrer, en nommant le fichier",
		refusedOK && strings.Contains(string(logBytes), "agent-registry") && strings.Contains(string(logBytes), "divergents"),
		fmt.Sprintf("sortie non nulle=%v journal=%s", refusedOK, strings.TrimSpace(string(logBytes))))

	// Cas voisin : l'état d'origine restauré, brokerd repart.
	if err := os.WriteFile(agentsPath, origAgents, 0o600); err != nil {
		s.fail(phaseDaemons, "restauration agents.json (issue #192)", err)
		return
	}
	if err := writeEpoch0(); err != nil {
		s.fail(phaseDaemons, "epoch 0 (issue #192)", err)
		return
	}
	brokerd3, err := startDaemon(brokerdBin, brokerEnv, filepath.Join(base, "brokerd-provisioning-restaure.log"))
	if err != nil {
		s.fail(phaseDaemons, "brokerd (agents.json restauré)", err)
		return
	}
	defer brokerd3.stop()
	restarted := false
	for i := 0; i < 50 && !restarted; i++ {
		time.Sleep(200 * time.Millisecond)
		st, _, gerr := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/epoch")
		restarted = gerr == nil && st == http.StatusOK
	}
	s.add(phaseDaemons, "issue #192 : état d'origine restauré ⇒ brokerd repart (le refus ne visait que la divergence)",
		restarted, "")

	// Issue #206 : la consommation survit au redémarrage — la preuve d'avant
	// le redémarrage est encore dans sa fenêtre, et encore refusée au quorum.
	if restarted {
		status, raw, err = postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{
			"subject": "agent-1", "intent": intent,
		})
		actV = daemonActionResponse{}
		if err == nil {
			_ = json.Unmarshal(raw, &actV)
		}
		_, rawA, _ := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/stats")
		statsA := daemonStatsView{}
		_ = json.Unmarshal(rawA, &statsA)
		age := time.Since(proofMintedAt)
		s.add(phaseDaemons, "#206 : la preuve déjà consommée reste refusée APRÈS un redémarrage de brokerd (registre durable)",
			err == nil && status == http.StatusOK && !actV.Allow && statsA.QuorumDenies == 1 && age < 4*time.Minute,
			fmt.Sprintf("allow=%v reason=%s quorum_denies=%d âge_preuve=%s", actV.Allow, actV.Reason, statsA.QuorumDenies, age.Round(time.Second)))

		// --- Cellule miroir (§7.4, #275) : le failover d'un système CRITIQUE ---------------------
		// agent-1 est de classe W (critique). Traducteur tombé : refus (translation-failed). Le reçu signé de
		// la cellule miroir est déposé sur le plan d'administration : agent-1 franchit alors l'admission
		// (il est jugé plus loin par la chaîne — OPA, quorum… — donc la raison n'est PLUS translation-failed).
		translatorHealth.set(false)
		reason := func() string {
			st, rw, e := postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{"subject": "agent-1", "intent": denyIntent})
			var av daemonActionResponse
			if e != nil || st != http.StatusOK || json.Unmarshal(rw, &av) != nil || av.Allow {
				return "erreur-ou-admis"
			}
			return av.Reason
		}
		mirrorClosed := ""
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
			if mirrorClosed = reason(); mirrorClosed == "translation-failed" {
				break
			}
		}
		s.add(phaseDaemons, "miroir : traducteur tombé, sans promotion ⇒ même un système critique est refusé (translation-failed)",
			mirrorClosed == "translation-failed", "raison="+mirrorClosed)
		stP, rawP, errP := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/mirror/promote", json.RawMessage(mirrorFx.receipt(0)))
		s.add(phaseDaemons, "miroir : le reçu signé de la cellule miroir (bundle ancré, fenêtre ancrée) est promu",
			errP == nil && stP == http.StatusOK && strings.Contains(string(rawP), `"available":true`), fmt.Sprintf("status=%d %s", stP, strings.TrimSpace(string(rawP))))
		mirrorOpen := reason()
		s.add(phaseDaemons, "miroir : un système critique franchit l'admission (jugé plus loin par la chaîne), plus translation-failed",
			mirrorOpen != "translation-failed" && mirrorOpen != "erreur-ou-admis", "raison="+mirrorOpen)
		badReceipt := mirrorFx.receipt(7) // époque non ancrée
		stB, _, errB := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/mirror/promote", json.RawMessage(badReceipt))
		s.add(phaseDaemons, "miroir : un reçu d'une époque non ancrée est refusé (400)", errB == nil && stB == http.StatusBadRequest, fmt.Sprintf("status=%d", stB))

		// --- Arbitrage humain (§4.5, #275) : un système STANDARD dégradé ---------------------------
		// agent-std (classe hors F/I/W) n'a pas de miroir : sans arbitre joignable, refus simple ; un opérateur
		// signe sa présence puis sa décision ; la même demande représentée est admise UNE fois (puis jugée par la
		// chaîne : OPA refuse « write » ici, preuve que l'approbation ne contourne rien).
		opKey := devKey("operator-1")
		stdAction := func() (daemonActionResponse, string) {
			st, rw, e := postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{"subject": "agent-std", "intent": denyIntent})
			var av daemonActionResponse
			var extra struct {
				ArbitrationID string `json:"arbitration_id"`
			}
			if e != nil || st != http.StatusOK || json.Unmarshal(rw, &av) != nil {
				return daemonActionResponse{Reason: "erreur"}, ""
			}
			_ = json.Unmarshal(rw, &extra)
			return av, extra.ArbitrationID
		}
		noArb, _ := stdAction()
		s.add(phaseDaemons, "arbitrage : sans arbitre joignable, un système standard dégradé est refusé (translation-failed), rien en file",
			!noArb.Allow && noArb.Reason == "translation-failed", "raison="+noArb.Reason)
		// le ticket de la mise en file vivante d'une demande : ce que l'opérateur lit dans GET /v1/supervision/degraded
		ticketOf := func(hexID string) arbiter.Ticket {
			var tk arbiter.Ticket
			st, rw, e := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/degraded")
			var view struct {
				Pending []struct {
					ID     string `json:"id"`
					Ticket string `json:"ticket"`
				} `json:"pending"`
			}
			if e != nil || st != http.StatusOK || json.Unmarshal(rw, &view) != nil {
				return tk
			}
			for _, p := range view.Pending {
				if p.ID == hexID {
					if b, err := hex.DecodeString(p.Ticket); err == nil && len(b) == len(tk) {
						copy(tk[:], b)
					}
				}
			}
			return tk
		}
		at := time.Now().UTC().Truncate(time.Second)
		// liaison à la cellule (revue tierce) : un battement signé pour une AUTRE cellule du même trousseau est refusé
		stF, _, errF := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/degraded/presence", map[string]string{
			"at": at.Format(time.RFC3339), "signature": hex.EncodeToString(ed25519.Sign(opKey, arbiter.PresenceMessage("cell-b", at))),
		})
		s.add(phaseDaemons, "arbitrage : un battement signé pour une AUTRE cellule (même trousseau) est refusé (400)", errF == nil && stF == http.StatusBadRequest, fmt.Sprintf("status=%d", stF))
		stH, _, errH := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/degraded/presence", map[string]string{
			"at": at.Format(time.RFC3339), "signature": hex.EncodeToString(ed25519.Sign(opKey, arbiter.PresenceMessage(daemonsCellID, at))),
		})
		s.add(phaseDaemons, "arbitrage : la présence signée d'un opérateur épinglé est acceptée", errH == nil && stH == http.StatusOK, fmt.Sprintf("status=%d", stH))
		pend, pendID := stdAction()
		wantID := arbiter.IntentID("agent-std", []byte(denyIntent))
		s.add(phaseDaemons, "arbitrage : arbitre joignable ⇒ verdict DIFFÉRÉ (arbitration-pending) avec l'identifiant de la demande",
			!pend.Allow && pend.Reason == "arbitration-pending" && pendID == hex.EncodeToString(wantID[:]), fmt.Sprintf("raison=%s id=%.16s…", pend.Reason, pendID))
		decExp := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
		wantHex := hex.EncodeToString(wantID[:])
		decBody := map[string]string{
			"id": wantHex, "verdict": "approve", "expires_at": decExp.Format(time.RFC3339),
			"signature": hex.EncodeToString(ed25519.Sign(opKey, arbiter.DecisionMessage(daemonsCellID, wantID, ticketOf(wantHex), arbiter.VerdictApprove, decExp))),
		}
		stD, _, errD := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/degraded/decide", decBody)
		s.add(phaseDaemons, "arbitrage : l'approbation signée de l'opérateur est acceptée", errD == nil && stD == http.StatusOK, fmt.Sprintf("status=%d", stD))
		appr, _ := stdAction()
		s.add(phaseDaemons, "arbitrage : la demande approuvée franchit l'admission, puis la chaîne la juge (OPA refuse : l'approbation ne contourne rien)",
			!appr.Allow && appr.Reason == "opa-deny", "raison="+appr.Reason)
		again, _ := stdAction()
		s.add(phaseDaemons, "arbitrage : l'approbation est à usage unique — la représentation suivante repart en file",
			again.Reason == "arbitration-pending", "raison="+again.Reason)
		// REJEU (revue tierce) : la même décision signée, rejouée sur la demande remise en file, est refusée
		stR, _, errR := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/degraded/decide", decBody)
		stillPend, _ := stdAction()
		s.add(phaseDaemons, "arbitrage : la même décision signée, rejouée après consommation, est refusée (400) et la demande reste en file",
			errR == nil && stR == http.StatusBadRequest && stillPend.Reason == "arbitration-pending", fmt.Sprintf("status=%d raison=%s", stR, stillPend.Reason))

		// --- Persistance (#275) : l'état survit à un redémarrage BRUTAL (kill), sans fichier d'état ---------------
		// Une demande approuvée et non consommée, une demande en attente et la promotion du miroir sont retrouvées
		// depuis le journal, ancrées dans le log signé. brokerd redémarre ici avec le traducteur TOUJOURS tombé et
		// sans nouveau battement d'arbitre ni nouveau reçu.
		stdPendingIntent := `{"action":"read","resource":"doc-9","class":3}`
		pendBody := func(subject, intent string) (daemonActionResponse, string) {
			st, rw, e := postUnixJSON(brokerHC, "http://brokerd/v1/actions", map[string]string{"subject": subject, "intent": intent})
			var av daemonActionResponse
			var extra struct {
				ArbitrationID string `json:"arbitration_id"`
			}
			if e != nil || st != http.StatusOK || json.Unmarshal(rw, &av) != nil {
				return daemonActionResponse{Reason: "erreur"}, ""
			}
			_ = json.Unmarshal(rw, &extra)
			return av, extra.ArbitrationID
		}
		_, _ = pendBody("agent-std", stdPendingIntent) // mise en file (arbitre joignable : battement frais)
		decExp2 := time.Now().Add(8 * time.Minute).UTC().Truncate(time.Second)
		stD2, _, errD2 := postUnixJSON(brokerAdminHC, "http://brokerd/v1/supervision/degraded/decide", map[string]string{
			"id": hex.EncodeToString(wantID[:]), "verdict": "approve", "expires_at": decExp2.Format(time.RFC3339),
			"signature": hex.EncodeToString(ed25519.Sign(opKey, arbiter.DecisionMessage(daemonsCellID, wantID, ticketOf(wantHex), arbiter.VerdictApprove, decExp2))),
		})
		s.add(phaseDaemons, "persistance : une seconde approbation signée (avant le redémarrage) est acceptée", errD2 == nil && stD2 == http.StatusOK, fmt.Sprintf("status=%d", stD2))
		brokerd3.stop() // SIGKILL : aucun arrêt propre
		if err := writeEpoch0(); err != nil {
			s.fail(phaseDaemons, "epoch 0 (persistance)", err)
			return
		}
		brokerd4, err := startDaemon(brokerdBin, brokerEnv, filepath.Join(base, "brokerd-persistance.log"))
		if err != nil {
			s.fail(phaseDaemons, "brokerd (persistance)", err)
			return
		}
		defer brokerd4.stop()
		back := false
		for i := 0; i < 75 && !back; i++ {
			time.Sleep(200 * time.Millisecond)
			st, _, gerr := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/epoch")
			back = gerr == nil && st == http.StatusOK
		}
		s.add(phaseDaemons, "persistance : brokerd redémarre (kill -9) sur le même journal et le même registre", back, "")
		if back {
			stM, rawM, _ := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/mirror")
			s.add(phaseDaemons, "persistance : la promotion du miroir est retrouvée SANS redéposer de reçu",
				stM == http.StatusOK && strings.Contains(string(rawM), `"available":true`), strings.TrimSpace(string(rawM)))
			critAfter, _ := pendBody("agent-1", denyIntent)
			s.add(phaseDaemons, "persistance : le système critique franchit l'admission après le redémarrage (miroir restauré)",
				critAfter.Reason != "translation-failed" && critAfter.Reason != "erreur", "raison="+critAfter.Reason)
			stillPend, _ := pendBody("agent-std", stdPendingIntent)
			s.add(phaseDaemons, "persistance : la demande en attente est retrouvée en attente (sans arbitre joignable)",
				stillPend.Reason == "arbitration-pending", "raison="+stillPend.Reason)
			apprAfter, _ := pendBody("agent-std", denyIntent)
			s.add(phaseDaemons, "persistance : l'approbation restaurée admet la demande (puis OPA la juge), UNE fois",
				apprAfter.Reason == "opa-deny", "raison="+apprAfter.Reason)
			againAfter, _ := pendBody("agent-std", denyIntent)
			s.add(phaseDaemons, "persistance : l'approbation restaurée n'est pas rejouable (consommée)",
				againAfter.Reason == "translation-failed" || againAfter.Reason == "arbitration-pending", "raison="+againAfter.Reason)
		}
		translatorHealth.set(true)
		// Les feuilles de l'arbitrage (TBAR2) et de la dégradation (TBTD1) ont leur clair dans le journal, et
		// aucune feuille du registre n'est restée sans clair (couverture log → journal).
		verifyAuditJournal(s, phaseDaemons, "brokerd (après arbitrage)", brokerRegDir, auditJournalPath, auditKeyPath, 3)

		// --- OPA bloqué (#275) : le PEP signale, le chien de garde redémarre --------------------------------
		// Dernière étape : le verrou T14 de brokerd reste posé après elle. OPA est GELÉ (SIGSTOP : vivant mais
		// muet — exactement le cas qu'un « est-il en vie ? » ne voit pas). Le « systemctl » est un script de test
		// qui consigne ses arguments et dégèle OPA : on prouve la décision et la commande exacte, pas systemd.
		runOPAWatchdogStage(s, cfg, base, opawatchdogBin, brokerAdminSock, brokerAdminHC, opa, func(subject, intent string) string {
			av, _ := pendBody(subject, intent)
			return av.Reason
		})

		// --- #218 et #272 : le fichier d'autorité édité avec ses propres clés, et anod mesuré ---------------
		// Dernière étape : elle réécrit la genèse de la cellule (l'attaquant y ajoute ses clés).
		brokerd4.stop()
		runProvisioningTransitionStage(s, cfg, base, brokerdBin, brokerEnv, genesisDir, brokerAdminHC, writeEpoch0, privs)
	}
}

// runOPAWatchdogStage vérifie la boucle « OPA muet → statut stalled → redémarrage demandé » avec le vrai OPA, le vrai
// brokerd et le vrai chien de garde.
func runOPAWatchdogStage(s *suite, cfg config, base, wdBin, brokerAdminSock string, brokerAdminHC *http.Client, opa *opaServer, send func(subject, intent string) string) {
	state := func() string {
		st, raw, err := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/opa")
		var v struct {
			State string `json:"state"`
		}
		if err != nil || st != http.StatusOK || json.Unmarshal(raw, &v) != nil {
			return "illisible"
		}
		return v.State
	}
	s.add(phaseDaemons, "#275 : brokerd sert GET /v1/supervision/opa — OPA sain au départ", state() == "healthy", "état="+state())

	marker := filepath.Join(base, "opawd-systemctl.out")
	fakeCtl := filepath.Join(base, "fake-systemctl.sh")
	script := fmt.Sprintf("#!/bin/sh\necho \"$@\" > %s\nkill -CONT %d\n", marker, opa.cmd.Process.Pid)
	if err := os.WriteFile(fakeCtl, []byte(script), 0o755); err != nil {
		s.fail(phaseDaemons, "#275 : faux systemctl", err)
		return
	}
	// chaîne PROPRE du chien de garde (§7.1) et son journal d'audit : chaque redémarrage y est feuillé AVANT d'être exécuté
	wdRegDir := filepath.Join(base, "opawd-registry")
	wdAuditKey := filepath.Join(base, "opawd-audit.key")
	wdAuditJournal := filepath.Join(base, "opawd-audit-records.jsonl")
	if err := registry.GenerateRecordKey(wdAuditKey); err != nil {
		s.fail(phaseDaemons, "#275 : clé du journal d'audit du chien de garde", err)
		return
	}
	wd, err := startDaemon(wdBin, append(os.Environ(),
		"TBP_OPAWD_CELL_ID="+daemonsCellID,
		"TBP_OPAWD_LOG_ID=opawd-"+daemonsCellID,
		"TBP_OPAWD_REGISTRY_DIR="+wdRegDir,
		"TBP_OPAWD_AUDIT_RECORDS="+wdAuditJournal,
		"TBP_OPAWD_AUDIT_RECORDS_KEY_FILE="+wdAuditKey,
		"TBP_OPAWD_SOURCES=brokerd="+brokerAdminSock,
		"TBP_OPAWD_SYSTEMCTL="+fakeCtl,
		"TBP_OPAWD_POLL_MS=250", "TBP_OPAWD_CONFIRM=2", "TBP_OPAWD_COOLDOWN_S=5",
	), filepath.Join(base, "opawatchdog.log"))
	if err != nil {
		s.fail(phaseDaemons, "#275 : opawatchdog", err)
		return
	}
	defer wd.stop()

	time.Sleep(1500 * time.Millisecond)
	_, errM := os.Stat(marker)
	s.add(phaseDaemons, "#275 : OPA sain ⇒ le chien de garde ne redémarre rien", os.IsNotExist(errM), "")

	// OPA gelé : des demandes restent sans réponse (3 suffisent), puis le silence dépasse la fenêtre (3 s).
	if err := opa.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		s.fail(phaseDaemons, "#275 : gel d'OPA (SIGSTOP)", err)
		return
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = opa.cmd.Process.Signal(syscall.SIGCONT)
		}
	}()
	for i := 0; i < 4; i++ {
		send("agent-1", `{"action":"write","resource":"doc-1","class":1}`)
	}
	stalled := false
	for i := 0; i < 60 && !stalled; i++ {
		time.Sleep(250 * time.Millisecond)
		stalled = state() == "stalled"
	}
	s.add(phaseDaemons, "#275 : OPA gelé ⇒ le PEP (brokerd) se dit « stalled », sans toucher à OPA", stalled, "état="+state())

	var got []byte
	for i := 0; i < 80 && len(got) == 0; i++ {
		time.Sleep(250 * time.Millisecond)
		got, _ = os.ReadFile(marker)
	}
	s.add(phaseDaemons, "#275 : le chien de garde demande exactement « systemctl --no-ask-password restart tbp-opa.service »",
		strings.TrimSpace(string(got)) == "--no-ask-password restart tbp-opa.service", strings.TrimSpace(string(got)))
	resumed = true
	s.add(phaseDaemons, "#275 : OPA, relancé par le redémarreur, répond de nouveau",
		waitHTTP200("http://"+daemonsOPAAddr+"/health", 10*time.Second) == nil, "")
	// la décision est feuillée dans la chaîne du chien de garde, vérifiable comme `tbp-audit verify` (hash + inclusion
	// dans le log signé) — et le plain du record dit bien « redémarrage demandé » pour la cellule.
	verifyAuditJournal(s, phaseDaemons, "opawatchdog (redémarrage d'OPA)", wdRegDir, wdAuditJournal, wdAuditKey, 0)
	if key, err := registry.LoadRecordKey(wdAuditKey); err == nil {
		recs, err := registry.ReadRecords(wdAuditJournal, key)
		ok := err == nil && len(recs) >= 1
		detail := fmt.Sprintf("%d enregistrement(s)", len(recs))
		if ok {
			ar, perr := supervision.ParseAlertRecord(recs[0].Record)
			ok = perr == nil && recs[0].Leaf.Kind == registry.KindSupervision && ar.Event == supervision.AlertEventOPARestart &&
				ar.CellID == daemonsCellID && ar.Reason == "opa-restart-requested"
			detail = fmt.Sprintf("%+v", ar)
		}
		s.add(phaseDaemons, "#275 : le redémarrage est feuillé dans la chaîne du chien de garde (record TBPS1 « opa-restart-requested », cellule cell-a)", ok, detail)
	}
}

// conditionToSign extrait de la sortie d'un démon la condition annoncée par son refus
// (« condition à signer : base|from=…|to=… », issue #236) — ce que l'opérateur copie
// dans « quorumproof sign -condition ».
func conditionToSign(out string) (string, bool) {
	const marker = "condition à signer : "
	i := strings.Index(out, marker)
	if i < 0 {
		return "", false
	}
	f := strings.Fields(out[i+len(marker):])
	if len(f) == 0 || !strings.Contains(f[0], "|from=") || !strings.Contains(f[0], "|to=") {
		return "", false
	}
	return f[0], true
}
