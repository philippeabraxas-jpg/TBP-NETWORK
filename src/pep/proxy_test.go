package pep

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func fixedDeriveRequest(action, resource string) func(*http.Request) (Request, error) {
	return func(*http.Request) (Request, error) {
		return Request{Action: action, Resource: resource}, nil
	}
}

func newProxyFixture(t *testing.T, f *listenerFixture, backendURL string, opts ...func(*ProxyOptions)) *BlockingProxy {
	t.Helper()
	backend, err := url.Parse(backendURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	po := ProxyOptions{
		Listener:      f.l,
		Backend:       backend,
		DeriveRequest: fixedDeriveRequest("read.list", "registry/docs/42"),
	}
	for _, o := range opts {
		o(&po)
	}
	p, err := NewBlockingProxy(po)
	if err != nil {
		t.Fatalf("NewBlockingProxy: %v", err)
	}
	return p
}

func bearerReq(t *testing.T, method, target string, tok []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(tok))
	return req
}

// ---------------------------------------------------------------------------
// A6 : le blocage est STRUCTUREL — le backend n'est atteint QUE sur un
// verdict appliqué favorable (forwarded=true).
// ---------------------------------------------------------------------------

func TestBlockingProxyForwardsOnAllowMonitor(t *testing.T) {
	f := newListenerFixture(t, false)
	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("X-Backend", "real")
		w.WriteHeader(http.StatusTeapot) // valeur distinctive : preuve que c'est BIEN le backend qui répond
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, bearerReq(t, http.MethodGet, "/docs/42", mintToken(t, nominalClaims())))

	if hits != 1 {
		t.Fatalf("hits=%d, veut 1 (allow ⇒ transmis au backend)", hits)
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("statut=%d, veut %d (réponse du VRAI backend, pas du proxy)", rec.Code, http.StatusTeapot)
	}
	if rec.Header().Get("X-Backend") != "real" {
		t.Fatal("en-tête du backend absent — le proxy n'a pas transmis la vraie requête")
	}
	if rec.Header().Get("X-TBP-Mode") != "monitor" {
		t.Fatalf("X-TBP-Mode=%q, veut monitor", rec.Header().Get("X-TBP-Mode"))
	}
}

// TestBlockingProxyMonitorForwardsEvenDeny : doctrine §5.3 inchangée par
// le proxy — en monitor, MÊME un deny est transmis (log only). Ceci
// prouve que le proxy réutilise réellement mode.Allows(), pas une
// logique de blocage inventée séparément.
func TestBlockingProxyMonitorForwardsEvenDeny(t *testing.T) {
	f := newListenerFixture(t, false)
	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	claims := nominalClaims()
	claims.action = "write.delete" // portée invalide ⇒ deny scope-mismatch
	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, bearerReq(t, http.MethodGet, "/docs/42", mintToken(t, claims)))

	if hits != 1 {
		t.Fatalf("hits=%d, veut 1 (monitor: deny quand même transmis — log only, §5.3)", hits)
	}
	if rec.Header().Get("X-TBP-Reason") == "" {
		t.Fatal("X-TBP-Reason absent — la raison du deny devrait être exposée même en monitor")
	}
}

// TestBlockingProxyClosedBlocksDeny : preuve NON-VACUE directe de #94.A6
// — en closed, un deny n'atteint JAMAIS le backend.
func TestBlockingProxyClosedBlocksDeny(t *testing.T) {
	f := newListenerFixture(t, false)
	if err := f.mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatalf("SetMode(closed): %v", err)
	}
	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	claims := nominalClaims()
	claims.action = "write.delete" // portée invalide ⇒ deny
	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, bearerReq(t, http.MethodGet, "/docs/42", mintToken(t, claims)))

	if hits != 0 {
		t.Fatalf("hits=%d, veut 0 (closed: deny BLOQUÉ, backend jamais atteint — #94.A6)", hits)
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("statut=%d, veut 403", rec.Code)
	}
}

func TestBlockingProxyClosedForwardsAllow(t *testing.T) {
	f := newListenerFixture(t, false)
	if err := f.mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatalf("SetMode(closed): %v", err)
	}
	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, bearerReq(t, http.MethodGet, "/docs/42", mintToken(t, nominalClaims())))
	if hits != 1 {
		t.Fatalf("hits=%d, veut 1 (closed: allow transmis)", hits)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("statut=%d, veut 200", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// A9 : le jeton et l'action viennent de la VRAIE requête, jamais d'un
// champ auto-déclaré — requête mal formée refusée AVANT toute décision
// (aucune feuille), même doctrine que /v1/evaluate.
// ---------------------------------------------------------------------------

func TestBlockingProxyMissingTokenRejected(t *testing.T) {
	f := newListenerFixture(t, false)
	leavesBefore := f.sink.count()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend atteint sans jeton — #94.A6/A9 non respecté")
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/42", nil) // pas d'Authorization
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("statut=%d, veut 401 (jeton porteur absent)", rec.Code)
	}
	if f.sink.count() != leavesBefore {
		t.Fatalf("feuilles=%d, veut %d (requête mal formée = aucune décision rendue)", f.sink.count(), leavesBefore)
	}
}

func TestBlockingProxyBadBase64TokenRejected(t *testing.T) {
	f := newListenerFixture(t, false)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend atteint avec un jeton illisible")
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/42", nil)
	req.Header.Set("Authorization", "Bearer !!!pas-base64!!!")
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("statut=%d, veut 401 (base64 illisible)", rec.Code)
	}
}

// TestBlockingProxyUnmappedMethodRejected : une méthode sans mapping
// connu (defaultDeriveRequest) est refusée AVANT toute évaluation —
// jamais traitée par défaut comme "read" (ce serait l'auto-déclaration
// malhonnête que #94.A9 signale, déplacée dans le proxy lui-même).
func TestBlockingProxyUnmappedMethodRejected(t *testing.T) {
	f := newListenerFixture(t, false)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("backend atteint avec une méthode sans mapping")
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	p, err := NewBlockingProxy(ProxyOptions{Listener: f.l, Backend: backendURL}) // DeriveRequest par défaut
	if err != nil {
		t.Fatalf("NewBlockingProxy: %v", err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, bearerReq(t, "TRACE", "/docs/42", mintToken(t, nominalClaims())))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("statut=%d, veut 400 (méthode TRACE sans mapping)", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// defaultDeriveRequest / defaultTokenFrom : unités isolées.
// ---------------------------------------------------------------------------

func TestDefaultDeriveRequestMapping(t *testing.T) {
	cases := []struct {
		method     string
		wantAction string
		wantErr    bool
	}{
		{http.MethodGet, "read", false},
		{http.MethodHead, "read", false},
		{http.MethodOptions, "read", false},
		{http.MethodPost, "write", false},
		{http.MethodPut, "write", false},
		{http.MethodPatch, "write", false},
		{http.MethodDelete, "delete", false},
		{"TRACE", "", true},
		{"CONNECT", "", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, "/a/b/c", nil)
		got, err := defaultDeriveRequest(req)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: erreur attendue, obtenu %+v", tc.method, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: erreur inattendue: %v", tc.method, err)
			continue
		}
		if got.Action != tc.wantAction || got.Resource != "/a/b/c" {
			t.Errorf("%s: got=%+v, veut action=%q resource=/a/b/c", tc.method, got, tc.wantAction)
		}
	}
}

func TestDefaultTokenFromBearer(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if _, err := defaultTokenFrom(req); err == nil {
		t.Fatal("en-tête Authorization absent accepté")
	}
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if _, err := defaultTokenFrom(req); err == nil {
		t.Fatal("schéma Basic accepté (Bearer requis)")
	}
	req.Header.Set("Authorization", "Bearer abc123")
	tok, err := defaultTokenFrom(req)
	if err != nil || tok != "abc123" {
		t.Fatalf("tok=%q err=%v, veut abc123/nil", tok, err)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration.
// ---------------------------------------------------------------------------

func TestNewBlockingProxyFailClosed(t *testing.T) {
	f := newListenerFixture(t, false)
	backend, _ := url.Parse("http://127.0.0.1:1")
	if _, err := NewBlockingProxy(ProxyOptions{Backend: backend}); err == nil {
		t.Fatal("listener nil accepté")
	}
	if _, err := NewBlockingProxy(ProxyOptions{Listener: f.l}); err == nil {
		t.Fatal("backend nil accepté")
	}
}
