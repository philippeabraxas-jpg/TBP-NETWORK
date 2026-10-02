package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// De bout en bout avec le vrai run, DEUX fois sur le même état : ce que le premier démarrage a promu et approuvé
// est retrouvé par le second — sans fichier d'état, depuis le journal ancré dans le log signé. Un arrêt propre
// (cancel) publie le dernier checkpoint ; les droits restaurés sont ceux dont la feuille y figure.
func TestBrokerdPersistenceAcrossRestart(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	agents, _ := json.Marshal(map[string]agentRegistryEntry{"agent-1": {Class: classOf(3)}, "agent-w": {Class: classOf(2)}})
	if err := os.WriteFile(fx.agentsFile, agents, 0o600); err != nil {
		t.Fatal(err)
	}
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			_, _ = w.Write([]byte(`{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":"` + fx.env["TBP_POLICY_ID"] + `"}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	tr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer tr.Close() // le traducteur est TOUJOURS tombé
	fx.env["TBP_TRANSLATOR_GUARD"] = "1"
	fx.env["TBP_TRANSLATOR_PROBE_URL"] = tr.URL + "/health"
	fx.env["TBP_TRANSLATOR_PROBE_INTERVAL_MS"] = "500"
	fx.env["TBP_ARBITRATION"] = "1"

	dir := t.TempDir()
	seed := sha256.Sum256([]byte("cell-b-persist"))
	cellPriv := ed25519.NewKeyFromSeed(seed[:])
	kb, _ := json.Marshal(map[string]string{"cell-b": hex.EncodeToString(cellPriv.Public().(ed25519.PublicKey))})
	keysFile := filepath.Join(dir, "mirror-cell-keys.json")
	_ = os.WriteFile(keysFile, kb, 0o600)
	policy, _ := hex.DecodeString(fx.env["TBP_POLICY_ID"])
	now := time.Now()
	ab, err := cluster.SignAnchors(cluster.AnchorPayload{Anchors: []cluster.AnchorEntry{{
		Epoch: 0, BundleHash: hex.EncodeToString(policy),
		WindowStart: now.Add(-time.Hour).UTC().Format(time.RFC3339), WindowEnd: now.Add(time.Hour).UTC().Format(time.RFC3339),
	}}}, map[int]ed25519.PrivateKey{1: fx.controllerPrivs[0], 2: fx.controllerPrivs[1]})
	if err != nil {
		t.Fatal(err)
	}
	anchorsFile := filepath.Join(dir, "mirror-anchors.json")
	_ = os.WriteFile(anchorsFile, ab, 0o600)
	fx.env["TBP_MIRROR_ANCHORS_FILE"] = anchorsFile
	fx.env["TBP_MIRROR_CELL_KEYS_FILE"] = keysFile

	const act = `{"action":"read","resource":"doc-1","class":0}`
	const actPending = `{"action":"read","resource":"doc-2","class":0}`
	type session struct {
		hc, adminHC *http.Client
		stop        func()
	}
	start := func() *session {
		ctx, cancel := context.WithCancel(context.Background())
		runErr := make(chan error, 1)
		go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
		waitSocket(t, sock)
		waitSocket(t, fx.adminSock)
		return &session{hc: unixClient(t, sock), adminHC: unixClient(t, fx.adminSock), stop: func() {
			cancel()
			if err := <-runErr; err != nil {
				t.Fatalf("run: %v", err)
			}
		}}
	}
	action := func(s *session, subject, intent string) map[string]any {
		b, _ := json.Marshal(map[string]string{"subject": subject, "intent": intent})
		resp, err := s.hc.Post("http://brokerd/v1/actions", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m
	}
	post := func(s *session, path string, v any) int {
		b, _ := json.Marshal(v)
		resp, err := s.adminHC.Post("http://brokerd"+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// --- premier démarrage : promotion du miroir, une demande approuvée, une demande laissée en attente --------
	s1 := start()
	rc := cluster.Receipt{CellID: "cell-b", Epoch: 0, BundleHash: hex.EncodeToString(policy), ReceivedAt: time.Now().UTC().Format(time.RFC3339)}
	canon, _ := json.Marshal(rc)
	receipt, _ := json.Marshal(cluster.SignedReceipt{Receipt: rc, Sig: hex.EncodeToString(ed25519.Sign(cellPriv, canon))})
	if code := post(s1, "/v1/supervision/mirror/promote", json.RawMessage(receipt)); code != http.StatusOK {
		t.Fatalf("promotion : %d", code)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if code := post(s1, "/v1/supervision/degraded/presence", arbPresenceRequest{At: at, Signature: hex.EncodeToString(ed25519.Sign(fx.opPriv, arbiter.PresenceMessage(at)))}); code != http.StatusOK {
		t.Fatalf("présence : %d", code)
	}
	if m := action(s1, "agent-1", act); m["reason"] != "arbitration-pending" {
		t.Fatalf("mise en file : %v", m)
	}
	if m := action(s1, "agent-1", actPending); m["reason"] != "arbitration-pending" {
		t.Fatalf("mise en file : %v", m)
	}
	id := arbiter.IntentID("agent-1", []byte(act))
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	if code := post(s1, "/v1/supervision/degraded/decide", arbDecideRequest{ID: hex.EncodeToString(id[:]), Verdict: "approve", ExpiresAt: exp,
		Signature: hex.EncodeToString(ed25519.Sign(fx.opPriv, arbiter.DecisionMessage(id, arbiter.VerdictApprove, exp)))}); code != http.StatusOK {
		t.Fatalf("approbation : %d", code)
	}
	s1.stop() // arrêt propre : le dernier checkpoint est publié

	// --- second démarrage, mêmes fichiers : l'état est retrouvé, sans rien redéposer ------------------------------
	s2 := start()
	defer s2.stop()
	var ms mirrorStatus
	getJSON(t, s2.adminHC, "http://brokerd/v1/supervision/mirror", &ms)
	if !ms.Available || ms.Cell != "cell-b" {
		t.Fatalf("miroir non restauré : %+v", ms)
	}
	if m := action(s2, "agent-w", act); m["reason"] == "translation-failed" {
		t.Fatalf("le critique doit franchir l'admission grâce à la promotion restaurée : %v", m)
	}
	var st arbStatusView
	getJSON(t, s2.adminHC, "http://brokerd/v1/supervision/degraded", &st)
	if st.Reachable {
		t.Fatalf("la présence ne se restaure pas : %+v", st)
	}
	statuses := map[string]string{}
	for _, e := range st.Pending {
		statuses[e.ID] = e.Status
	}
	idPending := arbiter.IntentID("agent-1", []byte(actPending))
	if statuses[hex.EncodeToString(id[:])] != "approved" || statuses[hex.EncodeToString(idPending[:])] != "pending" {
		t.Fatalf("file restaurée : %+v", st.Pending)
	}
	// la demande en attente est toujours en attente (même sans arbitre joignable) ; l'approuvée est admise UNE fois
	if m := action(s2, "agent-1", actPending); m["reason"] != "arbitration-pending" {
		t.Fatalf("en attente restaurée : %v", m)
	}
	if m := action(s2, "agent-1", act); m["allow"] != true {
		t.Fatalf("l'approbation restaurée doit admettre la demande (OPA autorise) : %v", m)
	}
	if m := action(s2, "agent-1", act); strings.TrimSpace(asString(m["reason"])) == "" || m["allow"] == true {
		t.Fatalf("approbation restaurée consommée deux fois : %v", m)
	}
}

func asString(v any) string { s, _ := v.(string); return s }

// --- mirrorGate.Restore (unitaire : journal réel, log simulé par inLog) ---------------------------------------------

func journaledMirror(t *testing.T, start, end time.Time) (*mirrorHarness, func() []registry.SealedRecord) {
	t.Helper()
	dir := t.TempDir()
	kf := filepath.Join(dir, "k")
	if err := registry.GenerateRecordKey(kf); err != nil {
		t.Fatal(err)
	}
	key, _ := registry.LoadRecordKey(kf)
	path := filepath.Join(dir, "r.jsonl")
	st, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := newMirrorHarness(t, start, end, 5, st)
	return h, func() []registry.SealedRecord {
		recs, err := registry.ReadRecords(path, key)
		if err != nil {
			t.Fatal(err)
		}
		return recs
	}
}

func yes(registry.SealedRecord) bool { return true }
func no(registry.SealedRecord) bool  { return false }

// fresh : une porte NEUVE (le « redémarrage ») sur les mêmes ancres, clés et sel.
func (h *mirrorHarness) fresh(t *testing.T) *mirrorGate {
	t.Helper()
	g, err := newMirrorGate(mirrorConfig{enabled: true, anchorsFile: h.anchors, cellKeysFile: h.keysFile}, "cell-a",
		make([]byte, 16), &sinkLeaves{}, nil, h.ctrlPubs, 2, epochVar{h}, func() time.Time { return time.Unix(h.now.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestMirrorGateRestore(t *testing.T) {
	now := time.Now()
	h, records := journaledMirror(t, now.Add(-time.Hour), now.Add(time.Hour))
	ctx := context.Background()
	if _, err := h.gate.Promote(ctx, h.receipt(t, "cell-b", 5, h.bundle)); err != nil {
		t.Fatal(err)
	}
	// un refus POSTÉRIEUR ne retire rien (comme en fonctionnement : seule une promotion réussie change l'état)
	_, _ = h.gate.Promote(ctx, h.receipt(t, "cell-b", 6, h.bundle))

	g := h.fresh(t)
	if g.Available(ctx) {
		t.Fatal("porte neuve disponible sans restauration")
	}
	if !g.Restore(records(), yes) || !g.Available(ctx) {
		t.Fatal("promotion non restaurée")
	}
	// ancrage au log exigé : sans lui, rien
	for name, inLog := range map[string]func(registry.SealedRecord) bool{"jamais": no, "nil": nil} {
		if g2 := h.fresh(t); g2.Restore(records(), inLog) || g2.Available(ctx) {
			t.Fatalf("%s : une promotion non ancrée au log a été restaurée", name)
		}
	}
	// l'époque de la cellule a changé entre-temps : restaurée mais sans effet (comme avant l'arrêt)
	h.epoch.Store(6)
	if g3 := h.fresh(t); !g3.Restore(records(), yes) || g3.Available(ctx) {
		t.Fatal("la promotion d'une autre époque ne doit pas couvrir l'époque courante")
	}
	h.epoch.Store(5)
	// la fenêtre ancrée est échue : le journal ne la prolonge jamais
	h.now.Store(now.Add(2 * time.Hour).Unix())
	if g4 := h.fresh(t); g4.Restore(records(), yes) {
		t.Fatal("fenêtre ancrée échue : promotion restaurée")
	}
}

func TestMirrorGateRestoreChecksAnchorsAndKeysAgain(t *testing.T) {
	now := time.Now()
	h, records := journaledMirror(t, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := h.gate.Promote(context.Background(), h.receipt(t, "cell-b", 5, h.bundle)); err != nil {
		t.Fatal(err)
	}
	// le fichier d'ancres est remplacé par un fichier INVALIDE : plus d'ancre ⇒ plus de restauration
	if err := os.WriteFile(h.anchors, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h.fresh(t).Restore(records(), yes) {
		t.Fatal("restaurée sans ancre vérifiable")
	}
}

// La cellule promue n'est plus dans les clés (mesurées) : sa promotion ne se restaure pas.
func TestMirrorGateRestoreChecksCellKeysAgain(t *testing.T) {
	now := time.Now()
	h, records := journaledMirror(t, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := h.gate.Promote(context.Background(), h.receipt(t, "cell-b", 5, h.bundle)); err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("cell-c"))
	otherPub := ed25519.NewKeyFromSeed(other[:]).Public().(ed25519.PublicKey)
	kb, _ := json.Marshal(map[string]string{"cell-c": hex.EncodeToString(otherPub)})
	if err := os.WriteFile(h.keysFile, kb, 0o600); err != nil {
		t.Fatal(err)
	}
	if h.fresh(t).Restore(records(), yes) {
		t.Fatal("promotion d'une cellule absente des clés restaurée")
	}
}

func TestParsePromotionRecord(t *testing.T) {
	bundle := sha256.Sum256([]byte("b"))
	good := append([]byte("TBPP1"), 0x01, 6)
	good = append(good, "cell-b"...)
	good = append(good, 0, 0, 0, 0, 0, 0, 0, 5)
	good = append(good, bundle[:]...)
	good = append(good, 2, 'o', 'k')
	cell, epoch, b, promoted, ok := parsePromotionRecord(good)
	if !ok || !promoted || cell != "cell-b" || epoch != 5 || b != bundle {
		t.Fatalf("valide : %v %v %q %d", ok, promoted, cell, epoch)
	}
	refused := append([]byte(nil), good...)
	refused[5] = 0x00
	if _, _, _, promoted, ok := parsePromotionRecord(refused); !ok || promoted {
		t.Fatal("un refus n'est pas une promotion")
	}
	for name, bad := range map[string][]byte{
		"court": good[:6], "tronque": good[:len(good)-1], "trop_long": append(append([]byte(nil), good...), 0),
		"cellule_menteuse": func() []byte { c := append([]byte(nil), good...); c[6] = 200; return c }(),
	} {
		if _, _, _, _, ok := parsePromotionRecord(bad); ok {
			t.Errorf("%s : accepté", name)
		}
	}
}
