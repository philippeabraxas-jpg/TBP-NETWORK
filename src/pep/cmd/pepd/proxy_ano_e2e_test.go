package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ano "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano"
	svc "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano/svc"
	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func quorumOK(string, pep.QuorumProof) bool { return true }

type quorumStateOK struct{}

func (quorumStateOK) Consume(string, int64) (bool, error) { return true, nil }

// e2eStack assemble la vraie chaîne : émetteur broker → validateur/proxy pepd →
// ano (serveur réel sur socket Unix) → « machine externe » simulée.
type e2eStack struct {
	proxy   *pep.BlockingProxy
	issuer  *broker.Issuer
	leaves  *leafRecorder
	journal string
	jkey    []byte
	backend *httptest.Server
}

func newE2E(t *testing.T, rules ano.RulesConfig, backendHandler http.HandlerFunc) *e2eStack {
	t.Helper()
	salt := bytes.Repeat([]byte{4}, 32)
	policy := [32]byte{1, 2, 3}
	signer, err := broker.NewDevSigner(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: signer, PolicyID: policy})
	if err != nil {
		t.Fatal(err)
	}
	keyring := map[[16]byte]ed25519.PublicKey{issuer.KeyID(): signer.Public()}
	leaves := &leafRecorder{}

	// --- côté pepd : validateur + listener + proxy ---
	fc, err := pep.NewFailClosed(pep.FailClosedOptions{CellID: "cell-a", Salt: salt, Leaves: leaves})
	if err != nil {
		t.Fatal(err)
	}
	mc, err := pep.NewModeController(pep.ModeOptions{
		CellID: "cell-a", Salt: salt, Leaves: leaves, VerifyQuorum: quorumOK, QuorumState: quorumStateOK{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ar, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 64})
	if err != nil {
		t.Fatal(err)
	}
	v, err := pep.NewValidator(pep.ValidatorOptions{
		CellID: "cell-a", Keyring: keyring, PolicyID: policy, Salt: salt, Leaves: leaves, AntiReplay: ar, Gate: fc,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := pep.NewListener(pep.ListenerOptions{Validator: v, Mode: mc})
	if err != nil {
		t.Fatal(err)
	}

	// --- ano : serveur réel, socket Unix ---
	ver, err := pep.NewPossessionVerifier(keyring, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ano.NewRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := ano.New(ano.Options{Rules: r})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := svc.NewServer(svc.ServerOptions{Ano: engine, Verifier: ver})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })

	backend := httptest.NewServer(backendHandler)
	t.Cleanup(backend.Close)
	bu, _ := url.Parse(backend.URL)

	store, journal, jkey := testAuditStore(t)
	opts := pep.ProxyOptions{Listener: listener, Backend: bu}
	if err := applyAno(context.Background(), anoEnv(map[string]string{"TBP_PROXY_ANO_SOCKET": sock}), &opts, leaves, store, "cell-a", salt); err != nil {
		t.Fatal(err)
	}
	proxy, err := pep.NewBlockingProxy(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &e2eStack{proxy: proxy, issuer: issuer, leaves: leaves, journal: journal, jkey: jkey, backend: backend}
}

func (s *e2eStack) request(t *testing.T, n byte, method, path, body string, sealBody bool) *httptest.ResponseRecorder {
	t.Helper()
	cls := pep.ClassF
	p := broker.IssueParams{
		Subject: "agent-1", Action: "write", Resource: path, Class: &cls,
		JTI: [16]byte{n}, Iat: time.Now().Unix(),
	}
	if sealBody {
		seal := sha256.Sum256([]byte(body))
		p.ObjectSeal = &seal
	}
	wire, err := s.issuer.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(pep.DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(wire))
	rec := httptest.NewRecorder()
	s.proxy.ServeHTTP(rec, req)
	return rec
}

func TestE2EExternalMachineNeverSeesClearAndResponseIsRestored(t *testing.T) {
	var seenBody string
	stack := newE2E(t, ano.RulesConfig{KeepPaths: []string{"action"}, MaskPaths: []string{"beneficiary"}},
		func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			seenBody = string(b)
			// la machine externe raisonne sur les jetons et les reprend dans sa réponse
			var in struct {
				Beneficiary string `json:"beneficiary"`
			}
			_ = json.Unmarshal(b, &in)
			_ = json.NewEncoder(w).Encode(map[string]string{"summary": "virement pour " + in.Beneficiary})
		})

	const clear = `{"action":"virement","beneficiary":"Mme Machin"}`
	rec := stack.request(t, 1, http.MethodPost, "/analyse", clear, true) // sceau du corps CLAIR

	if rec.Code != http.StatusOK {
		t.Fatalf("statut=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(seenBody, "Mme Machin") {
		t.Fatalf("la machine externe a reçu du clair: %s", seenBody)
	}
	if !strings.Contains(seenBody, `"action":"virement"`) || !strings.Contains(seenBody, "TBP_VAR_1") {
		t.Fatalf("ce qui est sorti n'est pas la forme masquée attendue: %s", seenBody)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["summary"] != "virement pour Mme Machin" {
		t.Fatalf("réponse non reconstituée: %s (%v)", rec.Body.String(), err)
	}
	// on audite tout : une feuille de télémétrie par opération d'ano (masquage +
	// reconstitution), hash-only ; les feuilles de décision du validateur sont
	// d'un autre genre.
	telemetry := 0
	for _, l := range stack.leaves.leaves {
		if l.Kind == registry.KindTelemetry {
			telemetry++
		}
	}
	if telemetry != 2 {
		t.Fatalf("feuilles d'audit d'ano: %d, veut 2 (masquage + reconstitution)", telemetry)
	}
	// chacune a son clair dans le journal (#271), conforme à son hash
	recs, err := registry.ReadRecords(stack.journal, stack.jkey)
	if err != nil || len(recs) != 2 {
		t.Fatalf("journal d'audit: %d enregistrements, err=%v, veut 2", len(recs), err)
	}
	for i, r := range recs {
		if err := r.VerifyHash(); err != nil {
			t.Fatalf("enregistrement %d: %v", i, err)
		}
		if !bytes.HasPrefix(r.Record, []byte("TBAN1")) {
			t.Fatalf("enregistrement %d: pas un record TBAN1", i)
		}
	}
}

func TestE2EUnrestorableResponseIsNeverReturned(t *testing.T) {
	stack := newE2E(t, ano.RulesConfig{MaskPaths: []string{"beneficiary"}},
		func(w http.ResponseWriter, r *http.Request) {
			// la machine externe invente un jeton qui n'existe pas dans l'échange
			_, _ = w.Write([]byte(`{"summary":"pour TBP_VAR_42"}`))
		})
	rec := stack.request(t, 2, http.MethodPost, "/analyse", `{"beneficiary":"X"}`, false)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("statut=%d, veut 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "TBP_VAR_42") {
		t.Fatalf("une réponse non reconstituée a été rendue: %s", rec.Body.String())
	}
}

func TestE2EUnanalysableBodyNeverLeavesTheCell(t *testing.T) {
	hits := 0
	stack := newE2E(t, ano.RulesConfig{}, func(w http.ResponseWriter, r *http.Request) { hits++ })
	rec := stack.request(t, 3, http.MethodPost, "/upload", "texte libre non JSON avec un secret", false)
	if rec.Code != http.StatusBadGateway || hits != 0 {
		t.Fatalf("status=%d hits=%d — un contenu qu'ano ne sait pas analyser ne doit pas sortir", rec.Code, hits)
	}
}
