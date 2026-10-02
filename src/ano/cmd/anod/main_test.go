package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

type env map[string]string

func (e env) get(k string) string { return e[k] }

type testEnv struct {
	env    env
	issuer *broker.Issuer
	dir    string
	ctl    []ed25519.PrivateKey // contrôleurs du quorum (#272)
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir, err := os.MkdirTemp("", "anod")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	signer, err := broker.NewDevSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	kid := issuer.KeyID()
	krPath := filepath.Join(dir, "keyring.json")
	kr, _ := json.Marshal(map[string]string{hex.EncodeToString(kid[:]): hex.EncodeToString(signer.Public())})
	if err := os.WriteFile(krPath, kr, 0o600); err != nil {
		t.Fatal(err)
	}
	rulesPath := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(`{"keep_paths":["action"],"mask_paths":["account"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// démarrage mesuré (#272) : deux contrôleurs, k = 2
	ctl1, ctl2 := controllerKey(1), controllerKey(2)
	qkPath := filepath.Join(dir, "quorum-keyring.json")
	if err := os.WriteFile(qkPath, keyringJSON(t, ctl1, ctl2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "witness"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &testEnv{issuer: issuer, dir: dir, ctl: []ed25519.PrivateKey{ctl1, ctl2}, env: env{
		"TBP_ANO_SOCKET":                filepath.Join(dir, "ano.sock"),
		"TBP_KEYRING_FILE":              krPath,
		"TBP_ANO_RULES_FILE":            rulesPath,
		"TBP_CELL_ID":                   "cell-a",
		"TBP_SALT":                      strings.Repeat("0a", 16),
		"TBP_REGISTRY_DIR":              filepath.Join(dir, "registry"),
		"TBP_PROVISIONING_WITNESS_FILE": filepath.Join(dir, "witness", "anod-provisioning.json"),
		"TBP_QUORUM_KEYRING_FILE":       qkPath,
		"TBP_QUORUM_MIN":                "2",
	}}
}

func controllerKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}

func keyringJSON(t *testing.T, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	raw := map[string]string{}
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		kid := pep.KeyIDFromPublicKey(pub)
		raw[hex.EncodeToString(kid[:])] = hex.EncodeToString(pub)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadConfigFailClosed(t *testing.T) {
	good := newTestEnv(t)
	if _, err := loadConfig(good.env.get); err != nil {
		t.Fatalf("config valide refusée: %v", err)
	}
	mutate := func(k, v string) env {
		e := env{}
		for a, b := range good.env {
			e[a] = b
		}
		if v == "" {
			delete(e, k)
		} else {
			e[k] = v
		}
		return e
	}
	notJSON := filepath.Join(good.dir, "bad.json")
	_ = os.WriteFile(notJSON, []byte("{"), 0o600)
	emptyKR := filepath.Join(good.dir, "empty.json")
	_ = os.WriteFile(emptyKR, []byte("{}"), 0o600)
	badKid := filepath.Join(good.dir, "badkid.json")
	_ = os.WriteFile(badKid, []byte(`{"zz":"00"}`), 0o600)
	badRules := filepath.Join(good.dir, "badrules.json")
	_ = os.WriteFile(badRules, []byte(`{"patterns":[{"name":"x","regex":"("}]}`), 0o600)
	for name, e := range map[string]env{
		"trousseau absent":      mutate("TBP_KEYRING_FILE", ""),
		"trousseau introuvable": mutate("TBP_KEYRING_FILE", "/nonexistent"),
		"trousseau non JSON":    mutate("TBP_KEYRING_FILE", notJSON),
		"trousseau vide":        mutate("TBP_KEYRING_FILE", emptyKR),
		"kid illisible":         mutate("TBP_KEYRING_FILE", badKid),
		"règles absentes":       mutate("TBP_ANO_RULES_FILE", ""),
		"règles introuvables":   mutate("TBP_ANO_RULES_FILE", "/nonexistent"),
		"règles invalides":      mutate("TBP_ANO_RULES_FILE", badRules),
		"délai hors bornes":     mutate("TBP_ANO_CLASSIFIER_TIMEOUT_MS", "1000"),
		"délai non entier":      mutate("TBP_ANO_CLASSIFIER_TIMEOUT_MS", "vite"),
		"grâce hors bornes":     mutate("TBP_ANO_RESPONSE_GRACE_S", "601"),
		"max échanges nul":      mutate("TBP_ANO_MAX_EXCHANGES", "0"),
		// démarrage mesuré (#272) : chaque pièce est requise, aucune valeur par défaut
		"cellule absente":         mutate("TBP_CELL_ID", ""),
		"sel absent":              mutate("TBP_SALT", ""),
		"sel trop court":          mutate("TBP_SALT", "0a0b"),
		"sel non hex":             mutate("TBP_SALT", strings.Repeat("zz", 16)),
		"registre absent":         mutate("TBP_REGISTRY_DIR", ""),
		"témoin absent":           mutate("TBP_PROVISIONING_WITNESS_FILE", ""),
		"trousseau quorum absent": mutate("TBP_QUORUM_KEYRING_FILE", ""),
		"trousseau quorum vide":   mutate("TBP_QUORUM_KEYRING_FILE", emptyKR),
		"k absent":                mutate("TBP_QUORUM_MIN", ""),
		"k nul":                   mutate("TBP_QUORUM_MIN", "0"),
		"k > contrôleurs":         mutate("TBP_QUORUM_MIN", "3"),
		"k non entier":            mutate("TBP_QUORUM_MIN", "deux"),
	} {
		if _, err := loadConfig(e.get); err == nil {
			t.Errorf("%s: la configuration doit être refusée au démarrage", name)
		}
	}
}

func TestListenUnixRefusesToClobberNonSocket(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "precious")
	if err := os.WriteFile(p, []byte("données"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenUnix(p); err == nil {
		t.Fatal("un fichier ordinaire ne doit jamais être écrasé")
	}
	if b, _ := os.ReadFile(p); string(b) != "données" {
		t.Fatal("le fichier a été altéré")
	}
	// un socket périmé est remplacé, avec les bonnes permissions
	sock := filepath.Join(dir, "s.sock")
	l1, err := listenUnix(sock)
	if err != nil {
		t.Fatal(err)
	}
	_ = l1.Close()
	l2, err := listenUnix(sock)
	if err != nil {
		t.Fatalf("socket périmé non remplacé: %v", err)
	}
	defer l2.Close()
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o660 {
		t.Fatalf("permissions du socket: %v", fi.Mode().Perm())
	}
}

func TestRunServesMaskAndStopsCleanly(t *testing.T) {
	te := newTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, te.env.get) }()

	sock := te.env["TBP_ANO_SOCKET"]
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}, Timeout: 3 * time.Second}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := hc.Get("http://ano/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("anod ne répond pas: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	wire, err := te.issuer.Issue(broker.IssueParams{
		Subject: "a", Action: "write", Resource: "/x", JTI: [16]byte{1}, Iat: time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(path, body string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, "http://ano"+path, strings.NewReader(body))
		req.Header.Set(pep.DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(wire))
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, masked := post("/v1/mask", `{"action":"pay","account":"FR76-secret"}`)
	if code != 200 || strings.Contains(masked, "FR76-secret") || !strings.Contains(masked, `"action":"pay"`) {
		t.Fatalf("mask: %d %s", code, masked)
	}
	if code, back := post("/v1/unmask", masked); code != 200 || back != `{"action":"pay","account":"FR76-secret"}` {
		t.Fatalf("unmask: %d %s", code, back)
	}
	// sans jeton : refusé
	resp, err := hc.Post("http://ano/v1/mask", "application/json", strings.NewReader(`{}`))
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("appel sans jeton: %v %v", resp, err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("arrêt non propre: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("anod ne s'arrête pas")
	}
}
