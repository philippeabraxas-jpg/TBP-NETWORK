// Tests du démon supervisord (T37, issue #74).
//
// Doctrine : assemblage seul — les tests vérifient la validation de
// configuration (fail-closed §1), le chargement des chaînes surveillées
// (vkeys relues ICI), et le câblage de bout en bout avec des chaînes
// RÉELLES (driver POSIX Tessera, checkpoints Ed25519) et un faux brokerd
// sur socket Unix : la console rend l'état réel, et une source morte
// donne 503 — jamais une demi-vérité.
//
// Non-vacuité (mutations qui DOIVENT faire échouer un test nommé) :
//   - accepter une config sans TBP_CELLS_FILE/TBP_CELL_BROKER_SOCKET/… →
//     TestLoadConfigFailClosed ;
//   - accepter TBP_TICK_MS hors [1000, 60000] → TestLoadConfigFailClosed/
//     tick_sous_la_borne, tick_au_dessus_de_la_borne ;
//   - accepter une vkey illisible ou une liste de cellules vide →
//     TestLoadCellsFailClosed ;
//   - servir la console quand le brokerd est mort AU DÉMARRAGE →
//     TestSupervisordStartupBrokerInjoignable ;
//   - servir une valeur figée quand le brokerd MEURT en cours de route
//     (cache dans un adaptateur, ou handler qui ignore l'erreur de sa
//     source) → TestSupervisordEndToEnd (témoin 503) ;
//   - rendre l'arbitrage sans relire la source → TestSupervisordEndToEnd
//     (le hash du plan vient du faux brokerd, pas d'une constante).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// mapGetenv adapte une table à la couture getenv du démon.
func mapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func validConfigEnv() map[string]string {
	return map[string]string{
		"TBP_MONITOR_CELL_ID":    "monitor-01",
		"TBP_SALT":               strings.Repeat("01", 16),
		"TBP_REGISTRY_DIR":       "/srv/tbp/monitor",
		"TBP_CELLS_FILE":         "/etc/tbp/cells.json",
		"TBP_CELL_BROKER_SOCKET": "/run/tbp/broker.sock",
	}
}

func TestLoadConfigOK(t *testing.T) {
	cfg, err := loadConfig(mapGetenv(validConfigEnv()))
	if err != nil {
		t.Fatalf("config valide refusée: %v", err)
	}
	if cfg.tick != time.Duration(defaultTickMs)*time.Millisecond {
		t.Fatalf("tick par défaut = %s, attendu %d ms", cfg.tick, defaultTickMs)
	}
	if cfg.consoleSocket != defaultConsoleSocket {
		t.Fatalf("socket console par défaut = %q, attendu %q", cfg.consoleSocket, defaultConsoleSocket)
	}
	env := validConfigEnv()
	env["TBP_TICK_MS"] = "1000" // borne basse incluse
	env["TBP_CONSOLE_SOCKET"] = "/tmp/sup.sock"
	cfg, err = loadConfig(mapGetenv(env))
	if err != nil {
		t.Fatalf("config explicite refusée: %v", err)
	}
	if cfg.tick != time.Second || cfg.consoleSocket != "/tmp/sup.sock" {
		t.Fatalf("valeurs explicites mal lues: %+v", cfg)
	}
	env["TBP_TICK_MS"] = "60000" // borne haute incluse
	if _, err := loadConfig(mapGetenv(env)); err != nil {
		t.Fatalf("borne haute refusée: %v", err)
	}
}

func TestLoadConfigFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(env map[string]string)
		want   string
	}{
		{"monitor_cell_id_absent", func(e map[string]string) { delete(e, "TBP_MONITOR_CELL_ID") }, "TBP_MONITOR_CELL_ID requis"},
		{"salt_absent", func(e map[string]string) { delete(e, "TBP_SALT") }, "TBP_SALT requis"},
		{"salt_trop_court", func(e map[string]string) { e["TBP_SALT"] = "aabb" }, "hex ≥ 16 octets"},
		{"registry_absent", func(e map[string]string) { delete(e, "TBP_REGISTRY_DIR") }, "TBP_REGISTRY_DIR requis"},
		{"cells_file_absent", func(e map[string]string) { delete(e, "TBP_CELLS_FILE") }, "TBP_CELLS_FILE requis"},
		{"broker_socket_absent", func(e map[string]string) { delete(e, "TBP_CELL_BROKER_SOCKET") }, "TBP_CELL_BROKER_SOCKET requis"},
		{"tick_sous_la_borne", func(e map[string]string) { e["TBP_TICK_MS"] = "999" }, "hors bornes"},
		{"tick_au_dessus_de_la_borne", func(e map[string]string) { e["TBP_TICK_MS"] = "60001" }, "hors bornes"},
		{"tick_non_numerique", func(e map[string]string) { e["TBP_TICK_MS"] = "vite" }, "hors bornes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validConfigEnv()
			tc.mutate(env)
			cfg, err := loadConfig(mapGetenv(env))
			if err == nil {
				t.Fatalf("config invalide acceptée: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("erreur %q ne contient pas %q", err, tc.want)
			}
		})
	}
}

// — Chaînes réelles surveillées (même patron que supervision_test) —

type chainFixture struct {
	cellID   string
	origin   string
	dir      string
	signer   note.Signer
	verifier note.Verifier
	vkey     string
	log      *registry.CellLog
	salt     []byte
}

func newChainFixture(t *testing.T, cellID string) *chainFixture {
	t.Helper()
	origin := "tbp/registry/" + cellID
	skey, vkey, err := registry.GenerateCellKey(origin)
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	dir := t.TempDir()
	lg, err := registry.Open(context.Background(), registry.Options{
		Dir: dir, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("Open(%s): %v", cellID, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lg.Close(ctx)
	})
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("sel: %v", err)
	}
	return &chainFixture{
		cellID: cellID, origin: origin, dir: dir,
		signer: signer, verifier: verifier, vkey: vkey, log: lg, salt: salt,
	}
}

func (f *chainFixture) appendLeaf(t *testing.T, kind byte, cellID, payload string) {
	t.Helper()
	if _, err := f.log.Append(context.Background(), registry.Leaf{
		Kind:        kind,
		CellID:      cellID,
		PayloadHash: registry.HashPayload(f.salt, []byte(payload)),
		Timestamp:   time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("Append(%s): %v", f.cellID, err)
	}
}

func (f *chainFixture) waitCheckpoint(t *testing.T, size uint64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(f.dir, "checkpoint"))
		if err == nil {
			if cp, err := registry.ParseCheckpoint(raw, f.verifier); err == nil && cp.Size >= size {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("checkpoint de %s jamais publié à taille ≥ %d", f.dir, size)
}

// writeGenesisManifest publie la genèse de la chaîne de manifestes
// (T31, §6.3) — le moniteur la revérifie à chaque passage.
func writeGenesisManifest(t *testing.T, f *chainFixture, dir string) {
	t.Helper()
	m, err := registry.NewManifester(registry.ManifestOptions{
		CellID:   f.cellID,
		Signer:   f.signer,
		Verifier: f.verifier,
		Leaves:   f.log,
		Salt:     f.salt,
	})
	if err != nil {
		t.Fatalf("NewManifester: %v", err)
	}
	head, _, err := f.log.Head(context.Background())
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	var state registry.ManifestState
	copy(state.PolicyID[:], []byte("policy-p1-v1"))
	state.ChainHead = head
	gen, err := m.Genesis(context.Background(), 0, state)
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	raw, err := registry.MarshalSignedManifest(gen)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest-000000.json"), raw, 0o600); err != nil {
		t.Fatalf("artefact: %v", err)
	}
}

// writeCellsFile écrit le JSON des chaînes surveillées (vkeys en fichiers
// séparés, comme le fait le déploiement — custody D97).
func writeCellsFile(t *testing.T, cell *chainFixture, manifDir string, master *chainFixture) string {
	t.Helper()
	dir := t.TempDir()
	cellVkey := filepath.Join(dir, "cell.vkey")
	if err := os.WriteFile(cellVkey, []byte(cell.vkey), 0o644); err != nil {
		t.Fatalf("vkey cellule: %v", err)
	}
	masterVkey := filepath.Join(dir, "master.vkey")
	if err := os.WriteFile(masterVkey, []byte(master.vkey), 0o644); err != nil {
		t.Fatalf("vkey master: %v", err)
	}
	content := fmt.Sprintf(`{
  "cells": [{"cell_id": %q, "log_dir": %q, "origin": %q, "vkey_file": %q, "manifest_dir": %q}],
  "master": {"cell_id": %q, "log_dir": %q, "origin": %q, "vkey_file": %q}
}`, cell.cellID, cell.dir, cell.origin, cellVkey, manifDir,
		master.cellID, master.dir, master.origin, masterVkey)
	path := filepath.Join(dir, "cells.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cells file: %v", err)
	}
	return path
}

func TestLoadCellsOK(t *testing.T) {
	cell := newChainFixture(t, "cell-a")
	master := newChainFixture(t, "master")
	path := writeCellsFile(t, cell, t.TempDir(), master)
	cells, m, err := loadCells(path)
	if err != nil {
		t.Fatalf("cells file valide refusé: %v", err)
	}
	if len(cells) != 1 || cells[0].CellID != "cell-a" || cells[0].Verifier == nil {
		t.Fatalf("cellules mal chargées: %+v", cells)
	}
	if m.CellID != "master" || m.Verifier == nil {
		t.Fatalf("master mal chargé: %+v", m)
	}
}

func TestLoadCellsFailClosed(t *testing.T) {
	cell := newChainFixture(t, "cell-a")
	master := newChainFixture(t, "master")
	validPath := writeCellsFile(t, cell, t.TempDir(), master)
	validRaw, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatalf("lecture: %v", err)
	}
	writeVariant := func(t *testing.T, content string) string {
		p := filepath.Join(t.TempDir(), "cells.json")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("écriture: %v", err)
		}
		return p
	}
	cases := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{"fichier_absent", func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "nope.json")
		}, "cells file"},
		{"json_invalide", func(t *testing.T) string {
			return writeVariant(t, "{pas du json")
		}, "cells file JSON"},
		{"aucune_cellule", func(t *testing.T) string {
			return writeVariant(t, `{"cells": [], "master": {"cell_id":"m","log_dir":"/x","origin":"o","vkey_file":"/y"}}`)
		}, "au moins une cellule"},
		{"vkey_cellule_absente", func(t *testing.T) string {
			return writeVariant(t, strings.Replace(string(validRaw), "cell.vkey", "absente.vkey", 1))
		}, "vkey"},
		{"vkey_master_illisible", func(t *testing.T) string {
			bad := filepath.Join(t.TempDir(), "bad.vkey")
			if err := os.WriteFile(bad, []byte("ceci n'est pas une clé note"), 0o644); err != nil {
				t.Fatalf("vkey: %v", err)
			}
			return writeVariant(t, strings.Replace(string(validRaw), "master.vkey", filepath.Base(bad), 1))
		}, "vkey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cells, m, err := loadCells(tc.path(t))
			if err == nil {
				t.Fatalf("cells file invalide accepté: %+v / %+v", cells, m)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("erreur %q ne contient pas %q", err, tc.want)
			}
		})
	}
}

// — End-to-end : chaînes réelles + faux brokerd sur socket Unix —

// fakeBrokerd sert les trois vues D109 avec des valeurs REPÉRABLES (le
// test vérifie que la console rend CES valeurs-là, pas des constantes).
type fakeBrokerd struct {
	srv      *http.Server
	lis      net.Listener
	policyID string
	planHash string
}

func startFakeBrokerd(t *testing.T, sock string) *fakeBrokerd {
	t.Helper()
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fb := &fakeBrokerd{
		lis:      lis,
		policyID: strings.Repeat("ab", 32),
		planHash: strings.Repeat("cd", 32),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/supervision/epoch", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"epoch":3,"authority":"cell-a","not_before":%q,"expires_at":%q,"quarantined":[],"auto_failovers_hour":0}`,
			time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	})
	mux.HandleFunc("GET /v1/supervision/stats", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"requests":7,"allows":5,"denies":2,"translation_failures":0,"envelope_evals":0,"envelope_denies":0,"quorum_denies":0,"plan_denies":2,"issuance_failures":0,"leaf_failures":0}`)
	})
	mux.HandleFunc("GET /v1/supervision/arbitration", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"policy_id":%q,"pending":[{"hash":%q,"submitted_at":%q,"expires_at":%q,"steps":3}]}`,
			fb.policyID, fb.planHash,
			time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	})
	fb.srv = &http.Server{Handler: mux}
	go func() { _ = fb.srv.Serve(lis) }()
	t.Cleanup(func() { _ = fb.srv.Close() })
	return fb
}

func (fb *fakeBrokerd) stop(t *testing.T) {
	t.Helper()
	_ = fb.srv.Close()
	_ = fb.lis.Close()
}

func unixClient(t *testing.T, sock string) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func waitSocket(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s jamais en écoute", sock)
}

func consoleGet(t *testing.T, hc *http.Client, path string) (int, string) {
	t.Helper()
	resp, err := hc.Get("http://supervisord" + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: lecture: %v", path, err)
	}
	return resp.StatusCode, string(body)
}

// supervisordEnv assemble l'environnement du démon sur les fixtures.
func supervisordEnv(t *testing.T, cellsFile, brokerSock, consoleSock string) map[string]string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("sel: %v", err)
	}
	return map[string]string{
		"TBP_MONITOR_CELL_ID":    "monitor-01",
		"TBP_SALT":               hex.EncodeToString(salt),
		"TBP_REGISTRY_DIR":       filepath.Join(t.TempDir(), "monitor"),
		"TBP_CELLS_FILE":         cellsFile,
		"TBP_CELL_BROKER_SOCKET": brokerSock,
		"TBP_TICK_MS":            "1000",
		"TBP_CONSOLE_SOCKET":     consoleSock,
	}
}

// TestSupervisordEndToEnd : le démon assemble watchers + moniteur +
// console sur des chaînes RÉELLES ; la console rend l'état des sources
// du brokerd ; une source morte donne 503 — jamais une demi-vérité.
func TestSupervisordEndToEnd(t *testing.T) {
	// Cellule surveillée : une feuille + checkpoint + manifeste de genèse.
	cell := newChainFixture(t, "cell-a")
	cell.appendLeaf(t, registry.KindDecision, cell.cellID, "decision-0")
	cell.waitCheckpoint(t, 1)
	manifDir := t.TempDir()
	writeGenesisManifest(t, cell, manifDir)
	cell.waitCheckpoint(t, 2)

	// Master chain : la cellule y est ancrée (§6.2 — fraîcheur vérifiée).
	master := newChainFixture(t, "master")
	master.appendLeaf(t, registry.KindAnchor, cell.cellID, "anchor-0")
	master.waitCheckpoint(t, 1)

	cellsFile := writeCellsFile(t, cell, manifDir, master)

	sockDir := t.TempDir()
	brokerSock := filepath.Join(sockDir, "broker.sock")
	consoleSock := filepath.Join(sockDir, "supervision.sock")
	fb := startFakeBrokerd(t, brokerSock)

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(supervisordEnv(t, cellsFile, brokerSock, consoleSock))) }()
	waitSocket(t, consoleSock)
	hc := unixClient(t, consoleSock)

	// La console liste la cellule réelle (vue du moniteur).
	code, body := consoleGet(t, hc, "/v1/indicators")
	if code != http.StatusOK {
		t.Fatalf("/v1/indicators: statut %d, corps %s", code, body)
	}
	if !strings.Contains(body, "cell-a") {
		t.Fatalf("/v1/indicators ne liste pas cell-a: %s", body)
	}

	// L'époque vient du brokerd via l'adaptateur (epoch 3, pas 0).
	code, body = consoleGet(t, hc, "/v1/epoch")
	if code != http.StatusOK {
		t.Fatalf("/v1/epoch: statut %d, corps %s", code, body)
	}
	if !strings.Contains(body, `"epoch":3`) || !strings.Contains(body, "cell-a") {
		t.Fatalf("/v1/epoch ne reflète pas la source brokerd: %s", body)
	}

	// L'arbitrage rend le plan du brokerd — hash et policy REPERABLES.
	code, body = consoleGet(t, hc, "/v1/arbitration")
	if code != http.StatusOK {
		t.Fatalf("/v1/arbitration: statut %d, corps %s", code, body)
	}
	if !strings.Contains(body, fb.planHash) || !strings.Contains(body, fb.policyID) {
		t.Fatalf("/v1/arbitration ne reflète pas la source brokerd: %s", body)
	}

	// Témoin d'honnêteté : le brokerd MEURT — la console doit rendre 503
	// sur TOUTES les vues, jamais la dernière valeur en cache.
	fb.stop(t)
	for _, path := range []string{"/v1/indicators", "/v1/epoch", "/v1/arbitration"} {
		code, body = consoleGet(t, hc, path)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("%s avec source morte: statut %d, attendu 503 (corps %s)", path, code, body)
		}
		if !strings.Contains(body, "source indisponible") {
			t.Fatalf("%s avec source morte: corps %s sans « source indisponible »", path, body)
		}
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestSupervisordStartupBrokerInjoignable : un brokerd de cellule mort
// AU DÉMARRAGE est fatal — pas de console dont les sources sont mortes.
func TestSupervisordStartupBrokerInjoignable(t *testing.T) {
	cell := newChainFixture(t, "cell-a")
	cell.appendLeaf(t, registry.KindDecision, cell.cellID, "decision-0")
	cell.waitCheckpoint(t, 1)
	manifDir := t.TempDir()
	writeGenesisManifest(t, cell, manifDir)
	master := newChainFixture(t, "master")
	master.appendLeaf(t, registry.KindAnchor, cell.cellID, "anchor-0")
	master.waitCheckpoint(t, 1)
	cellsFile := writeCellsFile(t, cell, manifDir, master)

	sockDir := t.TempDir()
	err := run(context.Background(), mapGetenv(supervisordEnv(t, cellsFile,
		filepath.Join(sockDir, "broker-absent.sock"),
		filepath.Join(sockDir, "supervision.sock"))))
	if err == nil {
		t.Fatal("démarrage accepté avec brokerd injoignable")
	}
	if !strings.Contains(err.Error(), "sources de console injoignables") {
		t.Fatalf("erreur %q ne contient pas « sources de console injoignables »", err)
	}
}
