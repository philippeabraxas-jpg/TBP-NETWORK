package pep

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	req.Header.Set(DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(tok))
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
	req := httptest.NewRequest(http.MethodGet, "/docs/42", nil) // pas de jeton porteur
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
	req.Header.Set(DefaultTokenHeader, "Bearer !!!pas-base64!!!")
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
		t.Fatalf("en-tête %s absent accepté", DefaultTokenHeader)
	}
	req.Header.Set(DefaultTokenHeader, "Basic dXNlcjpwYXNz")
	if _, err := defaultTokenFrom(req); err == nil {
		t.Fatal("schéma Basic accepté (Bearer requis)")
	}
	req.Header.Set(DefaultTokenHeader, "Bearer abc123")
	tok, err := defaultTokenFrom(req)
	if err != nil || tok != "abc123" {
		t.Fatalf("tok=%q err=%v, veut abc123/nil", tok, err)
	}
}

// ---------------------------------------------------------------------------
// Revue de sécurité post-#86 : #107 (query string liée à la ressource),
// #108 (corps scellé), #109 (jeton TBP jamais transmis, Authorization
// libre pour le backend).
// ---------------------------------------------------------------------------

// TestDefaultDeriveRequestBindsQueryString : preuve NON-VACUE de #107 —
// deux requêtes de même chemin mais de query string différente dérivent
// des ressources DIFFÉRENTES ; une politique à correspondance exacte les
// distingue donc désormais (avant #107, la query string n'atteignait
// jamais la décision).
func TestDefaultDeriveRequestBindsQueryString(t *testing.T) {
	plain, err := defaultDeriveRequest(httptest.NewRequest(http.MethodGet, "/reports", nil))
	if err != nil {
		t.Fatalf("sans query string: %v", err)
	}
	if plain.Resource != "/reports" {
		t.Fatalf("resource=%q, veut /reports", plain.Resource)
	}
	tampered, err := defaultDeriveRequest(httptest.NewRequest(http.MethodGet, "/reports?action=delete_all", nil))
	if err != nil {
		t.Fatalf("avec query string: %v", err)
	}
	if tampered.Resource == plain.Resource {
		t.Fatal("query string absente de la ressource dérivée — #107 non fermé")
	}
	if tampered.Resource != "/reports?action=delete_all" {
		t.Fatalf("resource=%q, veut /reports?action=delete_all", tampered.Resource)
	}
}

// TestDefaultDeriveRequestSealsBody : preuve NON-VACUE de #108 — deux
// corps différents produisent des ObjectSeal différents ; le MÊME corps
// produit le MÊME sceau (déterministe, vérifiable par le Validator côté
// jeton).
func TestDefaultDeriveRequestSealsBody(t *testing.T) {
	reqFor := func(body string) Request {
		r := httptest.NewRequest(http.MethodPost, "/transfer", strings.NewReader(body))
		got, err := defaultDeriveRequest(r)
		if err != nil {
			t.Fatalf("corps %q: %v", body, err)
		}
		return got
	}
	small := reqFor(`{"amount":50}`)
	if small.ObjectSeal == nil {
		t.Fatal("corps non vide sans ObjectSeal — #108 non fermé")
	}
	big := reqFor(`{"amount":999999}`)
	if big.ObjectSeal == nil {
		t.Fatal("corps non vide sans ObjectSeal")
	}
	if *small.ObjectSeal == *big.ObjectSeal {
		t.Fatal("deux corps différents produisent le MÊME sceau — #108 non fermé")
	}
	same := reqFor(`{"amount":50}`)
	if *same.ObjectSeal != *small.ObjectSeal {
		t.Fatal("le même corps produit des sceaux différents — non déterministe")
	}

	empty, err := defaultDeriveRequest(httptest.NewRequest(http.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("sans corps: %v", err)
	}
	if empty.ObjectSeal != nil {
		t.Fatal("ObjectSeal posé sur une requête sans corps")
	}
}

// TestDefaultDeriveRequestForwardsExactBody : le corps lu pour le sceau
// est intégralement RESTITUÉ — la lecture pour #108 ne doit jamais
// altérer ce qui sera transmis au backend.
func TestDefaultDeriveRequestForwardsExactBody(t *testing.T) {
	const body = `{"amount":50,"to":"acct-9"}`
	r := httptest.NewRequest(http.MethodPost, "/transfer", strings.NewReader(body))
	if _, err := defaultDeriveRequest(r); err != nil {
		t.Fatalf("defaultDeriveRequest: %v", err)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("relecture du corps: %v", err)
	}
	if string(got) != body {
		t.Fatalf("corps après dérivation=%q, veut %q (identique)", got, body)
	}
	if r.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength=%d, veut %d", r.ContentLength, len(body))
	}
}

// TestDefaultDeriveRequestRejectsOversizedBody : un corps au-delà de
// maxProxyBodySeal est refusé plutôt que scellé sur un préfixe tronqué
// (un sceau partiel serait un sceau sur autre chose que ce qui est
// réellement transmis).
func TestDefaultDeriveRequestRejectsOversizedBody(t *testing.T) {
	oversized := strings.Repeat("a", maxProxyBodySeal+1)
	r := httptest.NewRequest(http.MethodPost, "/transfer", strings.NewReader(oversized))
	if _, err := defaultDeriveRequest(r); err == nil {
		t.Fatal("corps surdimensionné accepté")
	}
}

// TestBlockingProxyStripsTBPTokenHeader : preuve NON-VACUE directe de
// #109 — le backend ne voit JAMAIS l'en-tête portant le jeton TBP.
func TestBlockingProxyStripsTBPTokenHeader(t *testing.T) {
	f := newListenerFixture(t, false)
	var seenHeader string
	var sawHeader bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeader = r.Header.Get(DefaultTokenHeader)
		sawHeader = r.Header.Get(DefaultTokenHeader) != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, bearerReq(t, http.MethodGet, "/docs/42", mintToken(t, nominalClaims())))

	if sawHeader {
		t.Fatalf("le backend a vu %s=%q — le jeton TBP a fuité (#109)", DefaultTokenHeader, seenHeader)
	}
}

// TestBlockingProxyPreservesBackendAuthorization : preuve NON-VACUE
// directe de #109 — l'en-tête Authorization, s'il est posé par l'appelant
// pour SA PROPRE authentification côté backend, arrive intact : le proxy
// ne l'occupe plus pour le jeton TBP (DefaultTokenHeader ≠ Authorization)
// et ne le touche pas.
func TestBlockingProxyPreservesBackendAuthorization(t *testing.T) {
	f := newListenerFixture(t, false)
	const backendAuth = "Bearer backend-own-credential"
	var seenAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL)
	rec := httptest.NewRecorder()
	req := bearerReq(t, http.MethodGet, "/docs/42", mintToken(t, nominalClaims()))
	req.Header.Set("Authorization", backendAuth) // credential du BACKEND, distinct du jeton TBP
	p.ServeHTTP(rec, req)

	if seenAuth != backendAuth {
		t.Fatalf("Authorization vu par le backend=%q, veut %q (#109: libre pour le backend)", seenAuth, backendAuth)
	}
}

// TestBlockingProxyEndToEndBodySealBlocksTamperedAmount : preuve NON-
// VACUE de bout en bout de #108, à travers la VRAIE chaîne de décision
// (pas seulement defaultDeriveRequest en isolation) — un jeton d'écriture
// émis avec un ObjectSeal épinglé sur UN montant précis laisse passer CE
// montant exact, et refuse tout autre corps, alors même que action et
// resource restent identiques (ce que #94.A9 vérifiait déjà) : c'est
// précisément le scénario de l'issue (« un jeton d'écriture sur /transfer
// laisse passer n'importe quel montant »).
func TestBlockingProxyEndToEndBodySealBlocksTamperedAmount(t *testing.T) {
	f := newListenerFixture(t, false)
	// closed : le verdict S'APPLIQUE (monitor transmettrait même un deny
	// — doctrine §5.3, sans rapport avec #108).
	if err := f.mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatalf("SetMode(closed): %v", err)
	}
	const authorizedBody = `{"amount":50}`
	seal := sha256.Sum256([]byte(authorizedBody))

	// Deux jetons DISTINCTS (jti différents, pour isoler le sceau de
	// l'anti-rejeu §T10) mais épinglés sur le MÊME sceau — celui de
	// authorizedBody.
	claims1 := nominalClaims()
	claims1.action, claims1.resource, claims1.objectSeal = "write", "/transfer", seal[:]
	tok1 := mintToken(t, claims1)

	claims2 := nominalClaims()
	claims2.action, claims2.resource, claims2.objectSeal = "write", "/transfer", seal[:]
	j2 := jtiOf(0x99)
	claims2.jti = j2[:]
	tok2 := mintToken(t, claims2)

	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		body, _ := io.ReadAll(r.Body)
		if string(body) != authorizedBody {
			t.Errorf("backend a reçu un corps différent de celui scellé: %q", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := newProxyFixture(t, f, backend.URL, func(po *ProxyOptions) { po.DeriveRequest = nil }) // defaultDeriveRequest réel

	// Le montant EXACT couvert par le sceau : autorisé, transmis.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/transfer", strings.NewReader(authorizedBody))
	req.Header.Set(DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(tok1))
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("montant autorisé refusé: status=%d hits=%d body=%s", rec.Code, hits, rec.Body.String())
	}

	// Un AUTRE jeton, épinglé sur le MÊME sceau, mais un montant
	// DIFFÉRENT dans le corps réellement envoyé : refusé, backend jamais
	// atteint — c'est exactement le trou de #108 (« n'importe quel
	// montant »).
	tamperedBody := `{"amount":999999}`
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/transfer", strings.NewReader(tamperedBody))
	req2.Header.Set(DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(tok2))
	p.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("montant altéré (999999 au lieu de 50) accepté: status=%d — #108 non fermé", rec2.Code)
	}
	if hits != 1 {
		t.Fatalf("backend atteint avec un montant altéré (hits=%d) — #108 non fermé", hits)
	}
	if rec2.Header().Get("X-TBP-Reason") != ReasonSealMismatch {
		t.Fatalf("raison=%q, veut %q", rec2.Header().Get("X-TBP-Reason"), ReasonSealMismatch)
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
