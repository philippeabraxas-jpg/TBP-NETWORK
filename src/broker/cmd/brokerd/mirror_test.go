package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func TestMirrorFromEnv(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if cfg, err := mirrorFromEnv(get(nil), false); err != nil || cfg.enabled {
		t.Fatalf("absent : %+v %v", cfg, err)
	}
	both := map[string]string{"TBP_MIRROR_ANCHORS_FILE": "/a", "TBP_MIRROR_CELL_KEYS_FILE": "/k"}
	if cfg, err := mirrorFromEnv(get(both), true); err != nil || !cfg.enabled || cfg.anchorsFile != "/a" || cfg.cellKeysFile != "/k" {
		t.Fatalf("complet : %+v %v", cfg, err)
	}
	for name, c := range map[string]struct {
		env   map[string]string
		guard bool
		want  string
	}{
		"ancres_seules": {map[string]string{"TBP_MIRROR_ANCHORS_FILE": "/a"}, true, "ENSEMBLE"},
		"cles_seules":   {map[string]string{"TBP_MIRROR_CELL_KEYS_FILE": "/k"}, true, "ENSEMBLE"},
		"sans_garde":    {both, false, "sans TBP_TRANSLATOR_GUARD=1"},
	} {
		if _, err := mirrorFromEnv(get(c.env), c.guard); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s : refus %q attendu, got %v", name, c.want, err)
		}
	}
	// via loadConfig : un miroir sans garde est refusé tôt
	env := validConfigEnv()
	env["TBP_MIRROR_ANCHORS_FILE"] = "/a"
	env["TBP_MIRROR_CELL_KEYS_FILE"] = "/k"
	if _, err := loadConfig(mapGetenv(env), statPresent); err == nil || !strings.Contains(err.Error(), "TBP_TRANSLATOR_GUARD=1") {
		t.Fatalf("loadConfig doit refuser un miroir sans garde : %v", err)
	}
}

func TestParseMirrorCellKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	good := `{"cell-b":"` + hex.EncodeToString(pub) + `"}`
	if m, err := parseMirrorCellKeys([]byte(good)); err != nil || len(m["cell-b"]) != 32 {
		t.Fatalf("valide refusé : %v", err)
	}
	for name, bad := range map[string]string{
		"vide":          `{}`,
		"hex_invalide":  `{"cell-b":"zz"}`,
		"trop_courte":   `{"cell-b":"abcd"}`,
		"id_vide":       `{"":"` + hex.EncodeToString(pub) + `"}`,
		"cle_en_double": `{"cell-b":"` + hex.EncodeToString(pub) + `","cell-b":"` + hex.EncodeToString(pub) + `"}`,
		"pas_un_objet":  `[]`,
		"contenu_apres": good + `{}`,
	} {
		if _, err := parseMirrorCellKeys([]byte(bad)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

// mirrorHarness : un miroir cell-b, des ancres signées 2-of-3 par les contrôleurs, un suivi d'époque réglable.
type mirrorHarness struct {
	gate     *mirrorGate
	cellPriv ed25519.PrivateKey
	bundle   [32]byte
	epoch    atomic.Uint64
	now      atomic.Int64 // unix secondes
	anchors  string
}

type epochVar struct{ h *mirrorHarness }

func (e epochVar) CurrentEpoch() (uint64, error) { return e.h.epoch.Load(), nil }

func newMirrorHarness(t *testing.T, windowStart, windowEnd time.Time, anchorEpoch uint64) *mirrorHarness {
	t.Helper()
	h := &mirrorHarness{bundle: sha256.Sum256([]byte("bundle"))}
	ctrlPubs := map[int]ed25519.PublicKey{}
	ctrlPrivs := map[int]ed25519.PrivateKey{}
	for i := 1; i <= 3; i++ {
		seed := sha256.Sum256([]byte{byte(i), 'm'})
		p := ed25519.NewKeyFromSeed(seed[:])
		ctrlPrivs[i], ctrlPubs[i] = p, p.Public().(ed25519.PublicKey)
	}
	seed := sha256.Sum256([]byte("cell-b"))
	h.cellPriv = ed25519.NewKeyFromSeed(seed[:])
	dir := t.TempDir()
	keysFile := filepath.Join(dir, "cell-keys.json")
	kb, _ := json.Marshal(map[string]string{"cell-b": hex.EncodeToString(h.cellPriv.Public().(ed25519.PublicKey))})
	if err := os.WriteFile(keysFile, kb, 0o600); err != nil {
		t.Fatal(err)
	}
	ab, err := cluster.SignAnchors(cluster.AnchorPayload{Anchors: []cluster.AnchorEntry{{
		Epoch: anchorEpoch, BundleHash: hex.EncodeToString(h.bundle[:]),
		WindowStart: windowStart.UTC().Format(time.RFC3339), WindowEnd: windowEnd.UTC().Format(time.RFC3339),
	}}}, map[int]ed25519.PrivateKey{1: ctrlPrivs[1], 2: ctrlPrivs[2]})
	if err != nil {
		t.Fatal(err)
	}
	h.anchors = filepath.Join(dir, "anchors.json")
	if err := os.WriteFile(h.anchors, ab, 0o600); err != nil {
		t.Fatal(err)
	}
	h.epoch.Store(anchorEpoch)
	h.now.Store(time.Now().Unix())
	gate, err := newMirrorGate(mirrorConfig{enabled: true, anchorsFile: h.anchors, cellKeysFile: keysFile}, "cell-a",
		make([]byte, 16), &sinkLeaves{}, nil, ctrlPubs, 2, epochVar{h}, func() time.Time { return time.Unix(h.now.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	h.gate = gate
	return h
}

func (h *mirrorHarness) receipt(t *testing.T, cell string, epoch uint64, bundle [32]byte) []byte {
	t.Helper()
	rc := cluster.Receipt{CellID: cell, Epoch: epoch, BundleHash: hex.EncodeToString(bundle[:]), ReceivedAt: time.Unix(h.now.Load(), 0).UTC().Format(time.RFC3339)}
	canon, _ := json.Marshal(rc)
	body, _ := json.Marshal(cluster.SignedReceipt{Receipt: rc, Sig: hex.EncodeToString(ed25519.Sign(h.cellPriv, canon))})
	return body
}

func TestMirrorGateLifecycle(t *testing.T) {
	now := time.Now()
	h := newMirrorHarness(t, now.Add(-time.Hour), now.Add(time.Hour), 5)
	ctx := context.Background()
	if h.gate.Available(ctx) {
		t.Fatal("miroir disponible sans promotion")
	}
	// refus : mauvais bundle, époque non ancrée
	if _, err := h.gate.Promote(ctx, h.receipt(t, "cell-b", 5, sha256.Sum256([]byte("autre")))); err == nil {
		t.Fatal("bundle ≠ ancre accepté")
	}
	if _, err := h.gate.Promote(ctx, h.receipt(t, "cell-b", 6, h.bundle)); err == nil {
		t.Fatal("époque non ancrée acceptée")
	}
	if h.gate.Available(ctx) {
		t.Fatal("miroir disponible après des refus")
	}
	st, err := h.gate.Promote(ctx, h.receipt(t, "cell-b", 5, h.bundle))
	if err != nil || !st.Available || st.Cell != "cell-b" || st.Epoch != 5 {
		t.Fatalf("promotion valide : %+v %v", st, err)
	}
	if !h.gate.Available(ctx) {
		t.Fatal("miroir indisponible après promotion valide")
	}
	// l'époque de la cellule change : la promotion ne couvre plus rien
	h.epoch.Store(6)
	if h.gate.Available(ctx) {
		t.Fatal("promotion de l'époque 5 encore valable à l'époque 6")
	}
	h.epoch.Store(5)
	if !h.gate.Available(ctx) {
		t.Fatal("retour à l'époque 5 : la promotion devrait de nouveau couvrir")
	}
	// la fenêtre ancrée est échue
	h.now.Store(now.Add(2 * time.Hour).Unix())
	if h.gate.Available(ctx) {
		t.Fatal("fenêtre ancrée échue : miroir encore disponible")
	}
}

func TestMirrorGateRefusesOwnCellAndUnknownCell(t *testing.T) {
	now := time.Now()
	h := newMirrorHarness(t, now.Add(-time.Hour), now.Add(time.Hour), 1)
	// une cellule qui n'est pas dans les clés
	if _, err := h.gate.Promote(context.Background(), h.receipt(t, "cell-x", 1, h.bundle)); err == nil {
		t.Fatal("cellule inconnue acceptée")
	}
	// la cellule locale parmi les clés miroir : refus de construction
	keys := filepath.Join(t.TempDir(), "k.json")
	_ = os.WriteFile(keys, []byte(`{"cell-a":"`+hex.EncodeToString(h.cellPriv.Public().(ed25519.PublicKey))+`"}`), 0o600)
	if _, err := newMirrorGate(mirrorConfig{enabled: true, anchorsFile: h.anchors, cellKeysFile: keys}, "cell-a",
		make([]byte, 16), &sinkLeaves{}, nil, map[int]ed25519.PublicKey{1: h.cellPriv.Public().(ed25519.PublicKey)}, 1, epochVar{h}, nil); err == nil ||
		!strings.Contains(err.Error(), "propre miroir") {
		t.Fatalf("une cellule ne peut pas être son propre miroir : %v", err)
	}
}

// stubMirror : Available réglable.
type stubMirror struct{ ok atomic.Bool }

func (s *stubMirror) Available(context.Context) bool { return s.ok.Load() }

// Dégradé + miroir : un système CRITIQUE structuré est admis, un STANDARD reste refusé (pas d'arbitrage).
func TestTranslatorGuardMirrorFailoverByClass(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	cfg := translatorGuardConfig{enabled: true, probeURL: down.URL + "/h", interval: time.Hour, timeout: time.Second}
	m := &stubMirror{}
	reg := broker.StaticAgentRegistry{
		"agent-w":   {Class: pep.ClassW},
		"agent-f":   {Class: pep.ClassF},
		"agent-i":   {Class: pep.ClassI},
		"agent-out": {Class: pep.ClassOut},
	}
	tr, start, err := setupTranslatorGuard(cfg, broker.StructuredTranslator{}, "cell-a", make([]byte, 16), &sinkLeaves{}, nil, nil, m, systemClassOf(reg))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start(ctx)
	intent := `{"action":"read","resource":"r"}`
	admitted := func(subject string) bool {
		_, err := tr.Translate(ctx, subject, intent)
		return err == nil
	}
	// miroir indisponible : tout est refusé
	for _, a := range []string{"agent-w", "agent-f", "agent-i", "agent-out", "inconnu"} {
		if admitted(a) {
			t.Fatalf("%s admis sans miroir (default-deny attendu)", a)
		}
	}
	m.ok.Store(true)
	for _, a := range []string{"agent-w", "agent-f", "agent-i"} {
		if !admitted(a) {
			t.Fatalf("système critique %s refusé alors que le miroir est disponible", a)
		}
	}
	for _, a := range []string{"agent-out", "inconnu"} {
		if admitted(a) {
			t.Fatalf("système standard %s admis par le miroir (le failover est réservé aux critiques)", a)
		}
	}
	// une intention NON structurée reste refusée par le traducteur interne même quand la garde admet
	if _, err := tr.Translate(ctx, "agent-w", "pas du json"); err == nil || errors.Is(err, nil) {
		t.Fatal("intention illisible admise")
	}
}

// TestBrokerdMirrorFailoverEndToEnd : de bout en bout avec le vrai run. Traducteur tombé : refus total.
// Après la promotion du miroir (reçu signé sur le plan d'administration), un système CRITIQUE (classe W) franchit
// l'admission — il est alors jugé par la suite de la chaîne (ici : quorum exigé, refus ≠ translation-failed) —
// tandis qu'un système standard reste refusé (translation-failed). Une promotion invalide ne change rien.
func TestBrokerdMirrorFailoverEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)

	// registre : agent-w (classe W, critique) en plus d'agent-1 (hors F/I/W, standard)
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

	// miroir : clés de cellule, ancres signées 2-of-3 par les contrôleurs de la genèse, époque 0 (fixture)
	dir := t.TempDir()
	seed := sha256.Sum256([]byte("cell-b-e2e"))
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

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock)
	waitSocket(t, fx.adminSock)
	hc := unixClient(t, sock)
	adminHC := unixClient(t, fx.adminSock)
	const act = `{"action":"read","resource":"doc-1","class":2}`

	// 1. pas de promotion : tout est refusé par la garde
	for _, a := range []string{"agent-w", "agent-1"} {
		if r := postAction(t, hc, a, act); r.Allow || r.Reason != "translation-failed" {
			t.Fatalf("%s sans miroir : translation-failed attendu, got %+v", a, r)
		}
	}
	var st mirrorStatus
	getJSON(t, adminHC, "http://brokerd/v1/supervision/mirror", &st)
	if st.Available {
		t.Fatalf("miroir disponible sans promotion : %+v", st)
	}

	receipt := func(cell string, epoch uint64, bundle []byte, priv ed25519.PrivateKey) []byte {
		rc := cluster.Receipt{CellID: cell, Epoch: epoch, BundleHash: hex.EncodeToString(bundle), ReceivedAt: time.Now().UTC().Format(time.RFC3339)}
		canon, _ := json.Marshal(rc)
		b, _ := json.Marshal(cluster.SignedReceipt{Receipt: rc, Sig: hex.EncodeToString(ed25519.Sign(priv, canon))})
		return b
	}
	post := func(body []byte) (int, string) {
		resp, err := adminHC.Post("http://brokerd/v1/supervision/mirror/promote", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		return resp.StatusCode, b.String()
	}
	// 2. promotions invalides : mauvais bundle, mauvaise signature, cellule inconnue — aucun effet
	wrong := sha256.Sum256([]byte("autre"))
	otherSeed := sha256.Sum256([]byte("intrus"))
	otherPriv := ed25519.NewKeyFromSeed(otherSeed[:])
	for name, body := range map[string][]byte{
		"mauvais_bundle":    receipt("cell-b", 0, wrong[:], cellPriv),
		"mauvaise_cle":      receipt("cell-b", 0, policy, otherPriv),
		"cellule_inconnue":  receipt("cell-z", 0, policy, cellPriv),
		"epoque_non_ancree": receipt("cell-b", 9, policy, cellPriv),
	} {
		if code, _ := post(body); code != http.StatusBadRequest {
			t.Fatalf("%s : 400 attendu, got %d", name, code)
		}
	}
	if r := postAction(t, hc, "agent-w", act); r.Reason != "translation-failed" {
		t.Fatalf("des promotions invalides ne doivent rien ouvrir : %+v", r)
	}

	// 3. promotion valide : le critique franchit l'admission, le standard non
	if code, body := post(receipt("cell-b", 0, policy, cellPriv)); code != http.StatusOK {
		t.Fatalf("promotion valide : %d %s", code, body)
	}
	getJSON(t, adminHC, "http://brokerd/v1/supervision/mirror", &st)
	if !st.Available || st.Cell != "cell-b" {
		t.Fatalf("miroir attendu disponible : %+v", st)
	}
	if r := postAction(t, hc, "agent-w", act); r.Allow || r.Reason == "translation-failed" {
		t.Fatalf("critique : doit franchir l'admission (refusé plus loin, ex. quorum), got %+v", r)
	}
	if r := postAction(t, hc, "agent-1", act); r.Allow || r.Reason != "translation-failed" {
		t.Fatalf("standard : le miroir ne le concerne pas, translation-failed attendu, got %+v", r)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}
