package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// newOPASetupCellLog construit un CellLog réel (checkpoints signés) —
// même patron que run() lui-même (loadOrGenerateCellKey + registry.Open).
func newOPASetupCellLog(t *testing.T) *registry.CellLog {
	t.Helper()
	dir := t.TempDir()
	signer, vkey, err := loadOrGenerateCellKey(dir, "cell-test")
	if err != nil {
		t.Fatalf("loadOrGenerateCellKey: %v", err)
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cellLog, err := registry.Open(context.Background(), registry.Options{Dir: dir, Signer: signer, Verifier: verifier})
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cellLog.Close(closeCtx)
	})
	return cellLog
}

var testSalt32 = strings.Repeat("ab", 16) // 32 octets bruts (pas du hex) — sel de test, ≥ 16 requis

func testPolicyID(t *testing.T) [32]byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// ---------------------------------------------------------------------------
// A2 : OPA obligatoire, sauf désactivation dev EXPLICITE.
// ---------------------------------------------------------------------------

func TestSetupOPARequiredByDefault(t *testing.T) {
	_, err := setupOPA(context.Background(), "cell-test", []byte(testSalt32), testPolicyID(t), nil, nil, envOf(nil))
	if err == nil || !strings.Contains(err.Error(), "TBP_OPA_ENDPOINT requis") {
		t.Fatalf("erreur=%v, veut mention de TBP_OPA_ENDPOINT requis (§92.A2)", err)
	}
}

func TestSetupOPADisabledDevExplicit(t *testing.T) {
	res, err := setupOPA(context.Background(), "cell-test", []byte(testSalt32), testPolicyID(t), nil, nil,
		envOf(map[string]string{"TBP_OPA_DISABLED_DEV_UNSAFE": "1"}))
	if err != nil {
		t.Fatalf("désactivation dev explicite refusée: %v", err)
	}
	if res.client != nil || res.watcher != nil {
		t.Fatalf("client/watcher non nil malgré la désactivation: %+v", res)
	}
}

func TestSetupOPAEndpointAndDisabledMutuallyExclusive(t *testing.T) {
	_, err := setupOPA(context.Background(), "cell-test", []byte(testSalt32), testPolicyID(t), nil, nil,
		envOf(map[string]string{
			"TBP_OPA_ENDPOINT":            "http://127.0.0.1:8181/v1/data/tbp/allow",
			"TBP_OPA_DISABLED_DEV_UNSAFE": "1",
		}))
	if err == nil || !strings.Contains(err.Error(), "mutuellement exclusifs") {
		t.Fatalf("erreur=%v, veut mention de mutuelle exclusivité", err)
	}
}

// ---------------------------------------------------------------------------
// A3 : transport Unix + SO_PEERCRED obligatoire, sauf TCP dev EXPLICITE.
// ---------------------------------------------------------------------------

func TestOpaHTTPClientRequiresSocketByDefault(t *testing.T) {
	_, err := opaHTTPClient(envOf(nil))
	if err == nil || !strings.Contains(err.Error(), "TBP_OPA_SOCKET") {
		t.Fatalf("erreur=%v, veut mention de TBP_OPA_SOCKET requis (§92.A3)", err)
	}
}

func TestOpaHTTPClientInsecureTCPDevExplicit(t *testing.T) {
	hc, err := opaHTTPClient(envOf(map[string]string{"TBP_OPA_INSECURE_TCP_DEV": "1"}))
	if err != nil {
		t.Fatalf("TCP dev explicite refusé: %v", err)
	}
	if hc != nil {
		t.Fatalf("client non nil (http.Client par défaut attendu pour TCP): %+v", hc)
	}
}

func TestOpaHTTPClientSocketAndInsecureMutuallyExclusive(t *testing.T) {
	_, err := opaHTTPClient(envOf(map[string]string{
		"TBP_OPA_SOCKET":           "/run/tbp/opa.sock",
		"TBP_OPA_INSECURE_TCP_DEV": "1",
	}))
	if err == nil || !strings.Contains(err.Error(), "mutuellement exclusifs") {
		t.Fatalf("erreur=%v, veut mention de mutuelle exclusivité", err)
	}
}

func TestOpaHTTPClientSocketRequiresExpectedUID(t *testing.T) {
	_, err := opaHTTPClient(envOf(map[string]string{"TBP_OPA_SOCKET": "/run/tbp/opa.sock"}))
	if err == nil || !strings.Contains(err.Error(), "TBP_OPA_EXPECTED_UID") {
		t.Fatalf("erreur=%v, veut mention de TBP_OPA_EXPECTED_UID requis", err)
	}
}

func TestOpaHTTPClientExpectedUIDInvalid(t *testing.T) {
	_, err := opaHTTPClient(envOf(map[string]string{
		"TBP_OPA_SOCKET":       "/run/tbp/opa.sock",
		"TBP_OPA_EXPECTED_UID": "pas-un-uid",
	}))
	if err == nil || !strings.Contains(err.Error(), "TBP_OPA_EXPECTED_UID invalide") {
		t.Fatalf("erreur=%v, veut mention d'UID invalide", err)
	}
}

// TestOpaHTTPClientSocketRealDial : preuve NON-VACUE — avec un socket
// réel et l'UID attendu correct (le processus de test lui-même), le
// client construit RÉUSSIT effectivement une requête via socket Unix.
func TestOpaHTTPClientSocketRealDial(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "opa.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"result":{"allow":true}}`))
	})}
	go srv.Serve(lis)
	defer srv.Close()

	hc, err := opaHTTPClient(envOf(map[string]string{
		"TBP_OPA_SOCKET":       sock,
		"TBP_OPA_EXPECTED_UID": strconv.Itoa(os.Getuid()),
	}))
	if err != nil {
		t.Fatalf("opaHTTPClient: %v", err)
	}
	resp, err := hc.Get("http://opa/v1/data/tbp/allow")
	if err != nil {
		t.Fatalf("GET via socket: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("statut=%d", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// A5 : révision vérifiée au démarrage — écart refuse le démarrage.
// ---------------------------------------------------------------------------

func newOPAStub(t *testing.T, revision string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			fmt.Fprintf(w, `{"result":{"allow":false},"provenance":{"revision":%q}}`, revision)
			return
		}
		fmt.Fprint(w, `{"result":{"allow":false}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSetupOPARevisionMismatchRefusesStartup(t *testing.T) {
	policy := testPolicyID(t)
	srv := newOPAStub(t, "révision-imposteur")
	cellLog := newOPASetupCellLog(t)

	_, err := setupOPA(context.Background(), "cell-test", []byte(testSalt32), policy, cellLog, nil,
		envOf(map[string]string{
			"TBP_OPA_ENDPOINT":         srv.URL + "/v1/data/tbp/allow",
			"TBP_OPA_INSECURE_TCP_DEV": "1",
		}))
	if err == nil || !strings.Contains(err.Error(), "révision OPA non vérifiée") {
		t.Fatalf("erreur=%v, veut refus de démarrage sur révision non vérifiée (§92.A5)", err)
	}
}

func TestSetupOPARevisionMatchStartsAndReturnsWatcher(t *testing.T) {
	policy := testPolicyID(t)
	srv := newOPAStub(t, hex.EncodeToString(policy[:]))
	cellLog := newOPASetupCellLog(t)

	res, err := setupOPA(context.Background(), "cell-test", []byte(testSalt32), policy, cellLog, nil,
		envOf(map[string]string{
			"TBP_OPA_ENDPOINT":         srv.URL + "/v1/data/tbp/allow",
			"TBP_OPA_INSECURE_TCP_DEV": "1",
		}))
	if err != nil {
		t.Fatalf("révision correcte refusée au démarrage: %v", err)
	}
	if res.client == nil || res.watcher == nil {
		t.Fatalf("client/watcher nil malgré une config valide: %+v", res)
	}
	if res.watcher.Mismatch() {
		t.Fatal("watcher en écart alors que la révision correspond")
	}
}

func TestOpaRevisionIntervalInvalid(t *testing.T) {
	for _, v := range []string{"abc", "0", "-5"} {
		if _, err := opaRevisionInterval(envOf(map[string]string{"TBP_OPA_REVISION_CHECK_INTERVAL_MS": v})); err == nil {
			t.Fatalf("intervalle %q accepté", v)
		}
	}
}

func TestOpaRevisionIntervalDefaultAndExplicit(t *testing.T) {
	d, err := opaRevisionInterval(envOf(nil))
	if err != nil || d != 0 {
		t.Fatalf("défaut: d=%v err=%v, veut 0/nil (laisse le défaut du watcher s'appliquer)", d, err)
	}
	d, err = opaRevisionInterval(envOf(map[string]string{"TBP_OPA_REVISION_CHECK_INTERVAL_MS": "5000"}))
	if err != nil || d != 5*time.Second {
		t.Fatalf("explicite: d=%v err=%v, veut 5s/nil", d, err)
	}
}
