package main

// plan_json_test.go — #274 : plan/submit et plan/approve décodent leur corps en mode STRICT, comme
// plan/revoke (#244) et le registre d'agents (#241). « Dernier gagne », un champ inconnu ignoré ou un
// contenu après l'objet font sceller ou approuver autre chose que ce que l'opérateur a relu : un
// différentiel de parseur entre ce que l'opérateur voit et ce que le broker applique.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func postBody(t *testing.T, hc *http.Client, path, body string) (int, string) {
	t.Helper()
	resp, err := hc.Post("http://brokerd"+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

type pendingView struct {
	Pending []struct {
		Hash string `json:"hash"`
	} `json:"pending"`
}

func startPlanBrokerd(t *testing.T) (fx *runFixture, adminHC *http.Client) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx = newRunFixture(t, sock)
	var allow atomic.Bool
	allow.Store(true)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			fmt.Fprintf(w, `{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":%q}}}}`, fx.env["TBP_POLICY_ID"])
			return
		}
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(opa.Close)
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(10 * time.Second):
		}
	})
	waitSocket(t, sock)
	waitSocket(t, fx.adminSock)
	return fx, unixClient(t, fx.adminSock)
}

func pendingHashes(t *testing.T, hc *http.Client) map[string]bool {
	t.Helper()
	var v pendingView
	getJSON(t, hc, "http://brokerd/v1/supervision/arbitration", &v)
	out := map[string]bool{}
	for _, p := range v.Pending {
		out[p.Hash] = true
	}
	return out
}

const goodSubmit = `{"subject":"agent-1","steps":[{"action":"read","resource":"doc-1","params_hex":""}]}`

func TestPlanSubmitIsStrict(t *testing.T) {
	_, hc := startPlanBrokerd(t)
	for name, body := range map[string]string{
		"clé en double à la racine (sujet : dernier gagne)": `{"subject":"agent-2","subject":"agent-1","steps":[{"action":"read","resource":"doc-1","params_hex":""}]}`,
		"clé en double dans une étape":                      `{"subject":"agent-1","steps":[{"action":"read","action":"write","resource":"doc-1","params_hex":""}]}`,
		"ressource en double":                               `{"subject":"agent-1","steps":[{"action":"read","resource":"doc-1","resource":"doc-9","params_hex":""}]}`,
		"champ inconnu à la racine":                         `{"subject":"agent-1","evil":1,"steps":[{"action":"read","resource":"doc-1","params_hex":""}]}`,
		"champ inconnu dans une étape":                      `{"subject":"agent-1","steps":[{"action":"read","resource":"doc-1","params_hex":"","extra":true}]}`,
		"contenu après l'objet":                             goodSubmit + `{"subject":"agent-2"}`,
		"JSON invalide":                                     `{"subject":`,
	} {
		before := pendingHashes(t, hc)
		code, out := postBody(t, hc, "/v1/supervision/plan/submit", body)
		if code != http.StatusBadRequest {
			t.Errorf("%s : statut %d (%s), veut 400", name, code, out)
		}
		if after := pendingHashes(t, hc); len(after) != len(before) {
			t.Errorf("%s : un plan a été scellé malgré le refus (%d → %d)", name, len(before), len(after))
		}
	}
	// voisin : le même plan, propre, est scellé
	code, out := postBody(t, hc, "/v1/supervision/plan/submit", goodSubmit)
	if code != http.StatusOK || !strings.Contains(out, `"plan_hash"`) {
		t.Fatalf("plan valide refusé : %d %s", code, out)
	}
}

func TestPlanApproveAndRevokeAreStrict(t *testing.T) {
	fx, hc := startPlanBrokerd(t)
	code, out := postBody(t, hc, "/v1/supervision/plan/submit", goodSubmit)
	if code != http.StatusOK {
		t.Fatalf("soumission : %d %s", code, out)
	}
	hash := strings.Split(strings.Split(out, `"plan_hash":"`)[1], `"`)[0]
	h32, err := hex.DecodeString(hash)
	if err != nil || len(h32) != 32 {
		t.Fatalf("hash %q", hash)
	}
	var h [32]byte
	copy(h[:], h32)
	expiry := time.Now().Add(10 * time.Minute).UTC()
	sign := func(msg []byte) string { return hex.EncodeToString(ed25519.Sign(fx.opPriv, msg)) }
	approveSig := sign(pep.ApprovalMessage(h, expiry))
	ts := expiry.Format(time.RFC3339)
	body := func(extra string) string {
		return fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signature":%q%s}`, hash, ts, approveSig, extra)
	}

	bad := map[string]string{
		"approbation : champ inconnu":         body(`,"evil":1`),
		"approbation : signature en double":   strings.Replace(body(""), `"signature":"`, `"signature":"00","signature":"`, 1),
		"approbation : plan_hash en double":   strings.Replace(body(""), `"plan_hash"`, fmt.Sprintf(`"plan_hash":%q,"plan_hash"`, strings.Repeat("00", 32)), 1),
		"approbation : contenu après l'objet": body("") + `{"x":1}`,
	}
	for name, b := range bad {
		code, out := postBody(t, hc, "/v1/supervision/plan/approve", b)
		if code != http.StatusBadRequest {
			t.Errorf("%s : statut %d (%s), veut 400", name, code, out)
		}
		if !pendingHashes(t, hc)[hash] {
			t.Fatalf("%s : le plan a quitté la file malgré le refus", name)
		}
	}
	// révocation (déjà stricte depuis #244) : non-régression
	revokeSig := sign(pep.RevocationMessage(h, expiry))
	revokeDup := fmt.Sprintf(`{"plan_hash":%q,"plan_hash":%q,"expires_at":%q,"signature":%q}`, hash, hash, ts, revokeSig)
	if code, out := postBody(t, hc, "/v1/supervision/plan/revoke", revokeDup); code != http.StatusBadRequest {
		t.Errorf("révocation : clé en double acceptée (%d %s)", code, out)
	}

	// voisin : l'approbation propre passe et sort le plan de la file d'attente
	if code, out := postBody(t, hc, "/v1/supervision/plan/approve", body("")); code != http.StatusOK {
		t.Fatalf("approbation propre refusée : %d %s", code, out)
	}
	if pendingHashes(t, hc)[hash] {
		t.Fatal("plan approuvé toujours en attente")
	}
}
