package pep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeRewriter remplace « secret » par « TBP_VAR_1 » à l'aller et l'inverse au
// retour — assez pour prouver l'ordre et le fail-closed du proxy (la vraie
// logique est testée dans src/ano).
type fakeRewriter struct {
	mu       sync.Mutex
	reqErr   error
	respErr  error
	reqCalls int
	done     int
	sawWire  []byte
}

func (f *fakeRewriter) RewriteRequest(_ context.Context, wire []byte, r *http.Request) (RewriteReport, error) {
	f.mu.Lock()
	f.reqCalls++
	f.sawWire = wire
	f.mu.Unlock()
	if f.reqErr != nil {
		return RewriteReport{}, f.reqErr
	}
	rep := RewriteReport{}
	if r.Body != nil && r.Body != http.NoBody {
		b, _ := io.ReadAll(r.Body)
		out := bytes.ReplaceAll(b, []byte("secret"), []byte("TBP_VAR_1"))
		if !bytes.Equal(out, b) {
			rep.MaskedPath = 1
		}
		r.Body = io.NopCloser(bytes.NewReader(out))
		r.ContentLength = int64(len(out))
		r.Header.Set("Content-Length", strconv.Itoa(len(out)))
	}
	r.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, "secret", "TBP_VAR_1")
	return rep, nil
}

func (f *fakeRewriter) RewriteResponse(_ context.Context, _ []byte, resp *http.Response) (RewriteReport, error) {
	if f.respErr != nil {
		return RewriteReport{}, f.respErr
	}
	b, _ := io.ReadAll(resp.Body)
	out := bytes.ReplaceAll(b, []byte("TBP_VAR_1"), []byte("secret"))
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return RewriteReport{Restored: 1}, nil
}

func (f *fakeRewriter) Done(context.Context, []byte) {
	f.mu.Lock()
	f.done++
	f.mu.Unlock()
}

type eventLog struct {
	mu     sync.Mutex
	events []RewriteEvent
	failOp byte // opération dont l'audit échoue (0 ⇒ aucune)
}

func (e *eventLog) add(_ context.Context, ev RewriteEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	if e.failOp != 0 && ev.Op == e.failOp {
		return errors.New("registre indisponible")
	}
	return nil
}

func rewriterProxy(t *testing.T, f *listenerFixture, backendURL string, rw Rewriter, ev *eventLog) *BlockingProxy {
	return newProxyFixture(t, f, backendURL, func(po *ProxyOptions) {
		po.DeriveRequest = nil // defaultDeriveRequest réel : scelle le corps CLAIR
		po.Rewriter = rw
		if ev != nil {
			po.OnRewrite = ev.add
		}
	})
}

func postWithToken(t *testing.T, target, body string, tok []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set(DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(tok))
	return req
}

func TestProxyRewritesOutboundAndRestoresResponse(t *testing.T) {
	f := newListenerFixture(t, false)
	var gotBody, gotQuery, gotAE, gotToken string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotQuery, gotAE, gotToken = string(b), r.URL.RawQuery, r.Header.Get("Accept-Encoding"), r.Header.Get(DefaultTokenHeader)
		// la machine externe répond avec le jeton qu'elle a reçu
		_, _ = w.Write([]byte(`{"echo":"TBP_VAR_1"}`))
	}))
	defer backend.Close()

	rw := &fakeRewriter{}
	ev := &eventLog{}
	p := rewriterProxy(t, f, backend.URL, rw, ev)
	tok := mintToken(t, func() testClaims {
		c := nominalClaims()
		c.action, c.resource = "write", "/pay"
		return c
	}())
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, postWithToken(t, "/pay?acct=secret", `{"acct":"secret"}`, tok))

	if rec.Code != http.StatusOK {
		t.Fatalf("statut=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(gotBody, "secret") || strings.Contains(gotQuery, "secret") {
		t.Fatalf("le backend externe a reçu du clair: body=%q query=%q", gotBody, gotQuery)
	}
	if gotBody != `{"acct":"TBP_VAR_1"}` || gotQuery != "acct=TBP_VAR_1" {
		t.Fatalf("réécriture inattendue: body=%q query=%q", gotBody, gotQuery)
	}
	if rec.Body.String() != `{"echo":"secret"}` {
		t.Fatalf("la réponse n'a pas été reconstituée: %s", rec.Body.String())
	}
	if gotAE != "identity" {
		t.Fatalf("Accept-Encoding=%q, veut identity (une réponse compressée ne peut pas être reconstituée)", gotAE)
	}
	if gotToken != "" {
		t.Fatal("le jeton TBP a fuité vers le backend (#109)")
	}
	if rw.done != 1 || rw.reqCalls != 1 || len(rw.sawWire) == 0 {
		t.Fatalf("Done=%d reqCalls=%d — l'échange doit être libéré une fois", rw.done, rw.reqCalls)
	}
	if len(ev.events) != 2 || ev.events[0].Op != RewriteOpMask || ev.events[1].Op != RewriteOpUnmask ||
		ev.events[0].JTI != testJTI || ev.events[1].JTI != testJTI || ev.events[0].Err != nil || ev.events[1].Err != nil {
		t.Fatalf("événements d'audit inattendus: %+v", ev.events)
	}
	if ev.events[0].Report.MaskedPath != 1 || ev.events[1].Report.Restored != 1 {
		t.Fatalf("comptages d'audit: %+v", ev.events)
	}
}

func TestProxyRewriteRequestFailureBlocksEverything(t *testing.T) {
	f := newListenerFixture(t, false)
	var hits int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer backend.Close()
	rw := &fakeRewriter{reqErr: errors.New("ano injoignable")}
	ev := &eventLog{}
	p := rewriterProxy(t, f, backend.URL, rw, ev)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, postWithToken(t, "/pay", `{"acct":"secret"}`, mintToken(t, nominalClaims())))

	if hits != 0 {
		t.Fatalf("hits=%d — l'anonymisation a échoué mais la requête est sortie en clair", hits)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("statut=%d, veut 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "ano injoignable") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("le refus expose des détails: %q", rec.Body.String())
	}
	if rw.done != 1 {
		t.Fatalf("Done=%d — l'échange ouvert doit être libéré même sur échec", rw.done)
	}
	if len(ev.events) != 1 || ev.events[0].Err == nil || ev.events[0].Op != RewriteOpMask {
		t.Fatalf("l'échec doit laisser sa trace d'audit: %+v", ev.events)
	}
}

func TestProxyRewriteResponseFailureNeverReturnsBackendBody(t *testing.T) {
	f := newListenerFixture(t, false)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"echo":"TBP_VAR_99 réponse non reconstituable"}`))
	}))
	defer backend.Close()
	rw := &fakeRewriter{respErr: errors.New("jeton inconnu")}
	ev := &eventLog{}
	p := rewriterProxy(t, f, backend.URL, rw, ev)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, postWithToken(t, "/pay", `{"acct":"x"}`, mintToken(t, nominalClaims())))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("statut=%d, veut 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "TBP_VAR_99") {
		t.Fatalf("une réponse non reconstituée a été rendue: %q", rec.Body.String())
	}
	if len(ev.events) != 2 || ev.events[1].Op != RewriteOpUnmask || ev.events[1].Err == nil {
		t.Fatalf("audit: %+v", ev.events)
	}
	if rw.done != 1 {
		t.Fatalf("Done=%d", rw.done)
	}
}

// La politique juge le trafic en CLAIR, avant toute réécriture : un refus ne
// déclenche ni masquage ni transmission, et le sceau d'objet (#108) couvre bien
// ce que l'agent a réellement émis.
func TestProxyRewritesOnlyAfterEvaluationOnClearBody(t *testing.T) {
	f := newListenerFixture(t, false)
	if err := f.mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatal(err)
	}
	const authorized = `{"acct":"secret"}`
	seal := sha256.Sum256([]byte(authorized))
	c1 := nominalClaims()
	c1.action, c1.resource, c1.objectSeal = "write", "/pay", seal[:]
	c2 := nominalClaims()
	c2.action, c2.resource, c2.objectSeal = "write", "/pay", seal[:]
	j2 := jtiOf(0x77)
	c2.jti = j2[:]

	var hits int
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	}))
	defer backend.Close()
	rw := &fakeRewriter{}
	p := rewriterProxy(t, f, backend.URL, rw, nil)

	// corps EXACT scellé : autorisé, le backend reçoit la version masquée
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, postWithToken(t, "/pay", authorized, mintToken(t, c1)))
	if rec.Code != http.StatusOK || hits != 1 || got != `{"acct":"TBP_VAR_1"}` {
		t.Fatalf("corps scellé: status=%d hits=%d got=%q", rec.Code, hits, got)
	}
	// corps altéré (sceau ≠) : refusé AVANT la réécriture
	before := rw.reqCalls
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, postWithToken(t, "/pay", `{"acct":"secret","x":1}`, mintToken(t, c2)))
	if rec.Code != http.StatusForbidden || hits != 1 {
		t.Fatalf("corps altéré: status=%d hits=%d", rec.Code, hits)
	}
	if rw.reqCalls != before {
		t.Fatal("la réécriture a été appelée pour une requête refusée par la politique")
	}
}

func TestProxyWithoutRewriterIsUnchanged(t *testing.T) {
	f := newListenerFixture(t, false)
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		_, _ = w.Write([]byte("TBP_VAR_1 reste tel quel"))
	}))
	defer backend.Close()
	p := newProxyFixture(t, f, backend.URL, func(po *ProxyOptions) { po.DeriveRequest = nil })
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, postWithToken(t, "/pay", `{"acct":"secret"}`, mintToken(t, func() testClaims {
		c := nominalClaims()
		c.action, c.resource = "write", "/pay"
		return c
	}())))
	if got != `{"acct":"secret"}` || rec.Body.String() != "TBP_VAR_1 reste tel quel" {
		t.Fatalf("sans Rewriter le trafic doit passer tel quel: got=%q resp=%q", got, rec.Body.String())
	}
}

// « On audite tout » : une réécriture qu'on ne peut pas inscrire au registre est
// un refus — jamais une sortie sans trace.
func TestProxyAuditFailureBlocksMaskAndUnmask(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failOp byte
		hits   int
	}{
		{"audit du masquage", RewriteOpMask, 0},
		{"audit de la reconstitution", RewriteOpUnmask, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newListenerFixture(t, false)
			var hits int
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				_, _ = w.Write([]byte(`{"echo":"TBP_VAR_1"}`))
			}))
			defer backend.Close()
			rw := &fakeRewriter{}
			ev := &eventLog{failOp: tc.failOp}
			p := rewriterProxy(t, f, backend.URL, rw, ev)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, postWithToken(t, "/pay", `{"acct":"secret"}`, mintToken(t, nominalClaims())))
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("statut=%d, veut 502", rec.Code)
			}
			if hits != tc.hits {
				t.Fatalf("hits=%d, veut %d", hits, tc.hits)
			}
			if strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "TBP_VAR_1") {
				t.Fatalf("une charge a été rendue malgré l'échec d'audit: %q", rec.Body.String())
			}
			if rw.done != 1 {
				t.Fatalf("Done=%d", rw.done)
			}
		})
	}
}
