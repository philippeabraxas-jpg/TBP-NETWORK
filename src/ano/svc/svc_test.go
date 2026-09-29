package svc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ano "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano"
	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	clk    *clock
	issuer *broker.Issuer
	srv    *httptest.Server
	client *Client
	a      *ano.Ano
}

type answerer bool

func (a answerer) Decide(context.Context, string, string) (bool, error) { return bool(a), nil }

func newFixture(t *testing.T, rules ano.RulesConfig, aopts func(*ano.Options), sopts func(*ServerOptions)) *fixture {
	t.Helper()
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	seed := bytes.Repeat([]byte{7}, 32)
	signer, err := broker.NewDevSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := pep.NewPossessionVerifier(map[[16]byte]ed25519.PublicKey{issuer.KeyID(): signer.Public()}, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ano.NewRules(rules)
	if err != nil {
		t.Fatal(err)
	}
	ao := ano.Options{Rules: r, Classifier: answerer(false), Now: clk.now}
	if aopts != nil {
		aopts(&ao)
	}
	a, err := ano.New(ao)
	if err != nil {
		t.Fatal(err)
	}
	so := ServerOptions{Ano: a, Verifier: ver}
	if sopts != nil {
		sopts(&so)
	}
	s, err := NewServer(so)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &fixture{clk: clk, issuer: issuer, srv: ts, client: NewClient(ts.Client(), ts.URL), a: a}
}

// token émet un jeton dont le jti est déterminé par n.
func (f *fixture) token(t *testing.T, n byte) []byte {
	t.Helper()
	var jti [16]byte
	jti[0] = n
	wire, err := f.issuer.Issue(broker.IssueParams{
		Subject: "agent-1", Action: "write", Resource: "/x", JTI: jti, Iat: f.clk.now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *fixture) post(t *testing.T, path string, wire []byte, body string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(body))
	if wire != nil {
		req.Header.Set(pep.DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(wire))
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestServerMaskUnmaskRoundTripAndIsolation(t *testing.T) {
	f2 := newFixture(t, ano.RulesConfig{KeepPaths: []string{"action"}, MaskPaths: []string{"account", "n"}}, nil, nil)
	tok := f2.token(t, 1)
	code, masked, hdr := f2.post(t, "/v1/mask", tok, `{"action":"pay","account":"FR76-secret","n":42}`)
	if code != 200 || strings.Contains(masked, "FR76-secret") || strings.Contains(masked, "42") || !strings.Contains(masked, `"action":"pay"`) {
		t.Fatalf("mask par règle: %d %s", code, masked)
	}
	var rep wireReport
	if err := json.Unmarshal([]byte(hdr.Get(HeaderReport)), &rep); err != nil || rep.MaskedPath != 2 || rep.Leaves != 3 {
		t.Fatalf("rapport: %v %+v", err, rep)
	}
	// reconstitution avec le MÊME jeton
	code, back, _ := f2.post(t, "/v1/unmask", tok, masked)
	if code != 200 || back != `{"action":"pay","account":"FR76-secret","n":42}` {
		t.Fatalf("unmask: %d %s", code, back)
	}
	// un AUTRE jeton (autre jti) ne joint pas cet échange
	other := f2.token(t, 2)
	if code, body, _ := f2.post(t, "/v1/unmask", other, masked); code != 404 || !strings.Contains(body, "exchange-unknown") {
		t.Fatalf("échange d'un autre jeton joignable: %d %s", code, body)
	}
	// close efface
	if code, _, _ := f2.post(t, "/v1/close", tok, ""); code != 204 {
		t.Fatalf("close: %d", code)
	}
	if code, _, _ := f2.post(t, "/v1/unmask", tok, masked); code != 404 {
		t.Fatalf("après close: %d", code)
	}
}

func TestServerAuthFailures(t *testing.T) {
	f := newFixture(t, ano.RulesConfig{}, nil, nil)
	good := f.token(t, 1)
	// jeton signé par une AUTRE clé
	otherSigner, _ := broker.NewDevSigner(bytes.Repeat([]byte{9}, 32))
	otherIssuer, _ := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: otherSigner})
	forged, err := otherIssuer.Issue(broker.IssueParams{Subject: "a", Action: "x", Resource: "/y", JTI: [16]byte{5}, Iat: f.clk.now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff
	for name, wire := range map[string][]byte{"absent": nil, "forgé": forged, "altéré": tampered, "bruit": []byte("nope")} {
		for _, path := range []string{"/v1/mask", "/v1/mask-query", "/v1/unmask", "/v1/close"} {
			if code, body, _ := f.post(t, path, wire, `{}`); code != 401 || !strings.Contains(body, "token-invalid") {
				t.Errorf("%s %s: %d %s, veut 401 token-invalid", name, path, code, body)
			}
		}
	}
	// en-tête sans « Bearer » ni base64
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v1/mask", strings.NewReader(`{}`))
	req.Header.Set(pep.DefaultTokenHeader, "Bearer !!!pas-du-base64")
	resp, _ := f.srv.Client().Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("base64 invalide: %d", resp.StatusCode)
	}
}

func TestServerFreshnessAndResponseGrace(t *testing.T) {
	f := newFixture(t, ano.RulesConfig{MaskPaths: []string{"v"}}, nil, func(o *ServerOptions) { o.ResponseGrace = 30 * time.Second })
	tok := f.token(t, 1) // valable 45 s
	code, masked, _ := f.post(t, "/v1/mask", tok, `{"v":"secret"}`)
	if code != 200 {
		t.Fatalf("mask: %d", code)
	}
	// après l'expiration du jeton, une réponse tardive est encore reconstituable
	f.clk.advance(60 * time.Second)
	if code, back, _ := f.post(t, "/v1/unmask", tok, masked); code != 200 || back != `{"v":"secret"}` {
		t.Fatalf("unmask dans la grâce: %d %s", code, back)
	}
	// mais un jeton expiré n'ouvre plus d'échange
	if code, body, _ := f.post(t, "/v1/mask", tok, `{"v":"x"}`); code != 401 || !strings.Contains(body, "token-expired") {
		t.Fatalf("mask sur jeton expiré: %d %s", code, body)
	}
	// au-delà de exp + grâce : l'échange a disparu
	f.clk.advance(30 * time.Second)
	if code, body, _ := f.post(t, "/v1/unmask", tok, masked); code != 404 || !strings.Contains(body, "exchange-unknown") {
		t.Fatalf("unmask hors grâce: %d %s", code, body)
	}
}

func TestServerMaskQuery(t *testing.T) {
	f := newFixture(t, ano.RulesConfig{KeepPaths: []string{"query.page"}, MaskPaths: []string{"query.account"}}, nil, nil)
	tok := f.token(t, 1)
	code, out, _ := f.post(t, "/v1/mask-query", tok, "page=2&account=4471829&account=99")
	if code != 200 {
		t.Fatalf("mask-query: %d %s", code, out)
	}
	if strings.Contains(out, "4471829") || strings.Contains(out, "=99") || !strings.Contains(out, "page=2") {
		t.Fatalf("query mal masquée: %s", out)
	}
	if code, _, _ := f.post(t, "/v1/mask-query", tok, "a=%zz"); code != 422 {
		t.Fatalf("query illisible: %d", code)
	}
	if code, _, _ := f.post(t, "/v1/mask-query", tok, strings.Repeat("a=1&", 4000)); code != 413 {
		t.Fatalf("query trop grande: %d", code)
	}
}

func TestServerErrorCodes(t *testing.T) {
	f := newFixture(t, ano.RulesConfig{}, func(o *ano.Options) { o.MaxExchanges = 1 }, func(o *ServerOptions) { o.MaxBody = 200 })
	tok := f.token(t, 1)
	if code, body, _ := f.post(t, "/v1/mask", tok, `pas du json`); code != 422 || !strings.Contains(body, "unparsable") {
		t.Fatalf("non JSON: %d %s", code, body)
	}
	if code, body, _ := f.post(t, "/v1/mask", tok, `{"a":"`+strings.Repeat("x", 300)+`"}`); code != 413 || !strings.Contains(body, "too-large") {
		t.Fatalf("trop gros: %d %s", code, body)
	}
	if code, body, _ := f.post(t, "/v1/mask", tok, `{"a":"TBP_VAR_1"}`); code != 422 || !strings.Contains(body, "reserved-token") {
		t.Fatalf("jeton réservé: %d %s", code, body)
	}
	if code, _, _ := f.post(t, "/v1/unmask", tok, `{"a":"TBP_VAR_5"}`); code != 422 {
		// l'échange existe (ouvert par le mask ci-dessus) mais TBP_VAR_5 n'existe pas
		t.Fatalf("jeton inconnu: %d", code)
	}
	// saturation : le second jeton ne peut pas ouvrir d'échange (1 max), sans éviction
	tok2 := f.token(t, 2)
	if code, body, _ := f.post(t, "/v1/mask", tok2, `{"a":"b"}`); code != 503 || !strings.Contains(body, "saturated") {
		t.Fatalf("saturation: %d %s", code, body)
	}
	// les messages d'erreur ne contiennent jamais de valeur
	for _, body := range []string{`{"secret":"x"`} {
		_, out, _ := f.post(t, "/v1/mask", tok, body)
		if strings.Contains(out, "secret") {
			t.Fatalf("l'erreur fuit du contenu: %s", out)
		}
	}
}

func TestClientRewriteRequestResponseAndDone(t *testing.T) {
	f := newFixture(t, ano.RulesConfig{KeepPaths: []string{"action"}, MaskPaths: []string{"acct", "query.acct"}}, nil, nil)
	tok := f.token(t, 1)
	ctx := context.Background()

	req, _ := http.NewRequest(http.MethodPost, "http://external.example/pay?acct=4471829&page=1", strings.NewReader(`{"action":"pay","acct":"FR76-secret"}`))
	req.Header.Set("Content-Type", "application/json")
	rep, err := f.client.RewriteRequest(ctx, tok, req)
	if err != nil {
		t.Fatal(err)
	}
	if rep.MaskedPath != 2 {
		t.Fatalf("rapport: %+v", rep)
	}
	b, _ := io.ReadAll(req.Body)
	if strings.Contains(string(b), "FR76-secret") || strings.Contains(req.URL.RawQuery, "4471829") {
		t.Fatalf("ce qui sort contient du clair: body=%s query=%s", b, req.URL.RawQuery)
	}
	if req.ContentLength != int64(len(b)) || req.Header.Get("Content-Length") == "" {
		t.Fatalf("Content-Length non recalé: %d vs %d", req.ContentLength, len(b))
	}
	// la machine externe répond en reprenant les jetons
	var m struct {
		Acct string `json:"acct"`
	}
	_ = json.Unmarshal(b, &m)
	resp := &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"ok":true,"for":"` + m.Acct + `"}`)),
	}
	rep, err = f.client.RewriteResponse(ctx, tok, resp)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != `{"ok":true,"for":"FR76-secret"}` || rep.Restored != 1 || resp.ContentLength != int64(len(got)) {
		t.Fatalf("réponse: %s %+v", got, rep)
	}
	// Done efface : le serveur n'a plus d'échange
	f.client.Done(ctx, tok)
	if n := f.a.Exchanges(); n != 0 {
		t.Fatalf("Done n'a pas fermé l'échange: %d", n)
	}
}

func TestClientRefusals(t *testing.T) {
	f := newFixture(t, ano.RulesConfig{}, nil, nil)
	tok := f.token(t, 1)
	ctx := context.Background()

	// non JSON : ne sort pas
	req, _ := http.NewRequest(http.MethodPost, "http://x/", strings.NewReader("texte libre"))
	if _, err := f.client.RewriteRequest(ctx, tok, req); err == nil || OutcomeCode(err) != "unparsable" {
		t.Fatalf("corps non JSON: %v", err)
	}
	// corps compressé
	req, _ = http.NewRequest(http.MethodPost, "http://x/", strings.NewReader("\x1f\x8b"))
	req.Header.Set("Content-Encoding", "gzip")
	if _, err := f.client.RewriteRequest(ctx, tok, req); !errors.Is(err, ErrEncodedBody) {
		t.Fatalf("corps gzip: %v", err)
	}
	// upgrade
	req, _ = http.NewRequest(http.MethodGet, "http://x/", nil)
	req.Header.Set("Upgrade", "websocket")
	if _, err := f.client.RewriteRequest(ctx, tok, req); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("upgrade: %v", err)
	}
	// réponse compressée / 101 / jeton inconnu
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(strings.NewReader("zz"))}
	if _, err := f.client.RewriteResponse(ctx, tok, resp); !errors.Is(err, ErrEncodedBody) {
		t.Fatalf("réponse gzip: %v", err)
	}
	resp = &http.Response{StatusCode: 101, Header: http.Header{}, Body: http.NoBody}
	if _, err := f.client.RewriteResponse(ctx, tok, resp); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("101: %v", err)
	}
	// ouvrir un échange puis recevoir un jeton inexistant
	req, _ = http.NewRequest(http.MethodPost, "http://x/", strings.NewReader(`{"a":"b"}`))
	if _, err := f.client.RewriteRequest(ctx, tok, req); err != nil {
		t.Fatal(err)
	}
	resp = &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"x":"TBP_VAR_77"}`))}
	if _, err := f.client.RewriteResponse(ctx, tok, resp); OutcomeCode(err) != "unknown-placeholder" {
		t.Fatalf("jeton inconnu: %v", err)
	}
	// ano injoignable ⇒ erreur (le proxy refusera)
	dead := NewClient(&http.Client{Timeout: time.Second}, "http://127.0.0.1:1")
	req, _ = http.NewRequest(http.MethodPost, "http://x/", strings.NewReader(`{"a":"b"}`))
	if _, err := dead.RewriteRequest(ctx, tok, req); err == nil || OutcomeCode(err) != "error" {
		t.Fatalf("ano injoignable: %v", err)
	}
	// sans corps ni query : rien à masquer, pas d'appel nécessaire
	req, _ = http.NewRequest(http.MethodGet, "http://x/plain", nil)
	if _, err := dead.RewriteRequest(ctx, tok, req); err != nil {
		t.Fatalf("GET sans corps ni query doit passer sans appeler ano: %v", err)
	}
}

type sink struct{ leaves []registry.Leaf }

func (s *sink) Append(_ context.Context, l registry.Leaf) (uint64, error) {
	s.leaves = append(s.leaves, l)
	return uint64(len(s.leaves)), nil
}

func TestAuditLeafHashOnlyAndDeterministic(t *testing.T) {
	ev := pep.RewriteEvent{Op: pep.RewriteOpMask, JTI: [16]byte{1, 2, 3}, Report: pep.RewriteReport{Leaves: 5, MaskedPath: 2, Spans: 1}}
	r1, r2 := AuditRecord(ev), AuditRecord(ev)
	if !bytes.Equal(r1, r2) || !bytes.HasPrefix(r1, []byte("TBAN1")) {
		t.Fatalf("record non déterministe ou sans version: %x", r1)
	}
	ev2 := ev
	ev2.Err = &Error{Status: 422, Code: "unparsable"}
	if bytes.Equal(AuditRecord(ev2), r1) {
		t.Fatal("l'issue doit changer le record")
	}
	s := &sink{}
	salt := bytes.Repeat([]byte{3}, 32)
	if _, err := AppendAuditLeaf(context.Background(), s, "cell-a", salt, ev, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if len(s.leaves) != 1 || s.leaves[0].Kind != registry.KindTelemetry || s.leaves[0].PayloadHash != registry.HashPayload(salt, r1) {
		t.Fatalf("feuille inattendue: %+v", s.leaves)
	}
	if _, err := AppendAuditLeaf(context.Background(), s, "", salt, ev, time.Now()); err == nil {
		t.Fatal("cellID vide accepté")
	}
	if _, err := AppendAuditLeaf(context.Background(), s, "c", []byte("court"), ev, time.Now()); err == nil {
		t.Fatal("sel court accepté")
	}
	if _, err := AppendAuditLeaf(context.Background(), nil, "c", salt, ev, time.Now()); err == nil {
		t.Fatal("sink absent accepté")
	}
	for err, want := range map[error]string{
		nil: "ok", ErrEncodedBody: "encoded", ErrUnsupported: "unsupported", ErrBodyTooLarge: "too-large",
		errors.New("x"): "error", &Error{Code: "saturated"}: "saturated",
	} {
		if got := OutcomeCode(err); got != want {
			t.Errorf("OutcomeCode(%v)=%q, veut %q", err, got, want)
		}
	}
}

func TestNewServerValidation(t *testing.T) {
	if _, err := NewServer(ServerOptions{}); err == nil {
		t.Fatal("options vides acceptées")
	}
	f := newFixture(t, ano.RulesConfig{}, nil, nil)
	_ = f
	a, _ := ano.New(ano.Options{Rules: mustEmptyRules(t)})
	if _, err := NewServer(ServerOptions{Ano: a}); err == nil {
		t.Fatal("serveur sans vérificateur de jeton accepté (appels anonymes)")
	}
	ver, _ := pep.NewPossessionVerifier(map[[16]byte]ed25519.PublicKey{{1}: make(ed25519.PublicKey, 32)}, nil)
	if _, err := NewServer(ServerOptions{Ano: a, Verifier: ver, ResponseGrace: time.Hour}); err == nil {
		t.Fatal("grâce hors bornes acceptée")
	}
}

func mustEmptyRules(t *testing.T) *ano.Rules {
	t.Helper()
	r, err := ano.NewRules(ano.RulesConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
