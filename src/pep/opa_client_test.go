package pep

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures T11
// ---------------------------------------------------------------------------

const opaTestCellID = "tbp/registry/cell-alpha-01"

// newOPAClient construit un client de test contre endpoint, avec sink et
// enregistreur d'alarme (rec peut être nil).
func newOPAClient(t *testing.T, endpoint string, sink *stubSink, rec *tripRecorder) *OPAClient {
	t.Helper()
	opts := OPAOptions{
		Endpoint: endpoint,
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
		Now:      func() time.Time { return time.Unix(testIAT+30, 0) },
	}
	if rec != nil {
		opts.OnTrip = rec.trip
	}
	c, err := NewOPAClient(opts)
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	return c
}

func opaNominalInput() OPAInput {
	return OPAInput{
		JTI:      jtiOf(0x5A),
		Subject:  "spiffe://tbp.example/agent/claude",
		Action:   "http.send",
		Resource: "https://api.example.com/v1/messages",
		Class:    ClassI,
		Epoch:    7,
	}
}

// allowServer répond une décision OPA valide {"result":{"allow":allow}}.
func allowServer(t *testing.T, allow bool) *httptest.Server {
	t.Helper()
	body := `{"result":{"allow":false}}`
	if allow {
		body = `{"result":{"allow":true}}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// lastReason retourne la dernière raison d'alarme enregistrée, ou "".
func lastReason(rec *tripRecorder) string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.reasons) == 0 {
		return ""
	}
	return rec.reasons[len(rec.reasons)-1]
}

// ---------------------------------------------------------------------------
// Chemin nominal : allow / deny métier / règle indéfinie — jamais d'alarme.
// ---------------------------------------------------------------------------

func TestOPAAllow(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	c := newOPAClient(t, allowServer(t, true).URL, sink, rec)

	d := c.Eval(context.Background(), opaNominalInput())
	if !d.Allow || d.Reason != ReasonOK {
		t.Fatalf("allow=%v reason=%q err=%v, veut allow/ok", d.Allow, d.Reason, d.Err)
	}
	if !d.LeafWritten || sink.count() != 1 {
		t.Fatalf("feuille: written=%v count=%d, veut 1", d.LeafWritten, sink.count())
	}
	if rec.count() != 0 {
		t.Fatalf("alarme intempestive: %v", rec.reasons)
	}
	if d.Elapsed <= 0 {
		t.Fatal("Elapsed non mesuré")
	}
}

func TestOPAPolicyDeny(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	c := newOPAClient(t, allowServer(t, false).URL, sink, rec)

	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonOPADeny {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonOPADeny)
	}
	if !d.LeafWritten || sink.count() != 1 {
		t.Fatalf("le deny métier aussi laisse une feuille: written=%v count=%d", d.LeafWritten, sink.count())
	}
	if rec.count() != 0 {
		t.Fatalf("deny métier ≠ panne: aucune alarme attendue, eu %v", rec.reasons)
	}
}

func TestOPAUndefined(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`) // règle non définie : pas de "result"
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, rec)

	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonOPAUndefined {
		t.Fatalf("allow=%v reason=%q, veut deny/%q (default-deny §1)", d.Allow, d.Reason, ReasonOPAUndefined)
	}
	if rec.count() != 0 {
		t.Fatalf("règle indéfinie = OPA sain: aucune alarme attendue, eu %v", rec.reasons)
	}
	if !d.LeafWritten {
		t.Fatal("feuille manquante")
	}
}

// ---------------------------------------------------------------------------
// Critère d'acceptation 1 : injection de latence → deny mesuré à ~5 ms,
// sans dépassement silencieux, avec feuille + alarme.
// ---------------------------------------------------------------------------

func TestOPATimeoutCircuitBreaker(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond) // latence artificielle injectée
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, rec)

	if c.Timeout() != EvalTimeout {
		t.Fatalf("timeout=%v, veut %v (§9.1)", c.Timeout(), EvalTimeout)
	}

	in := opaNominalInput()
	d := c.Eval(context.Background(), in)
	if d.Allow || d.Reason != ReasonOPATimeout {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonOPATimeout)
	}
	if !errors.Is(d.Err, context.DeadlineExceeded) {
		t.Fatalf("err=%v, veut context.DeadlineExceeded", d.Err)
	}
	// Mesuré à 5 ms : borné entre le timeout (tolérance timer) et bien moins
	// que la latence injectée — pas de dépassement silencieux.
	if d.Elapsed < EvalTimeout-2*time.Millisecond || d.Elapsed > 40*time.Millisecond {
		t.Fatalf("elapsed=%v, veut ~%v (latence injectée 50 ms)", d.Elapsed, EvalTimeout)
	}
	if lastReason(rec) != ReasonOPATimeout {
		t.Fatalf("alarme=%q, veut %q (couture T14)", lastReason(rec), ReasonOPATimeout)
	}
	// La feuille de deny est prouvée : hash-only, verdict 0, raison opa-timeout.
	if !d.LeafWritten || sink.count() != 1 {
		t.Fatalf("feuille de deny manquante: written=%v count=%d", d.LeafWritten, sink.count())
	}
	want := registry.HashPayload(testSalt, decisionLeafRecord(in.JTI, false, ReasonOPATimeout))
	if got := sink.leaves[0].PayloadHash; got != want {
		t.Fatalf("feuille hash=%x, veut %x", got, want)
	}
	if sink.leaves[0].Kind != registry.KindDecision || sink.leaves[0].CellID != opaTestCellID {
		t.Fatalf("feuille mal formée: %+v", sink.leaves[0])
	}

	// Deuxième dépassement : nouvelle alarme (T14 possède le latch « unique »).
	c.Eval(context.Background(), in)
	if rec.count() != 2 {
		t.Fatalf("alarmes=%d, veut 2 (le latch est l'affaire de T14)", rec.count())
	}
}

// ---------------------------------------------------------------------------
// Critère d'acceptation 2 : OPA arrêté → deny immédiat (pas d'attente).
// ---------------------------------------------------------------------------

func TestOPAUnreachable(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close() // OPA arrêté : connexion refusée

	c := newOPAClient(t, url, sink, rec)
	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonOPAUnreachable {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonOPAUnreachable)
	}
	if d.Err == nil {
		t.Fatal("err nil sur OPA arrêté")
	}
	if d.Elapsed > 40*time.Millisecond {
		t.Fatalf("elapsed=%v : le deny doit être immédiat, sans attendre %v", d.Elapsed, EvalTimeout)
	}
	if lastReason(rec) != ReasonOPAUnreachable {
		t.Fatalf("alarme=%q, veut %q", lastReason(rec), ReasonOPAUnreachable)
	}
	if !d.LeafWritten {
		t.Fatal("feuille de deny manquante")
	}
}

// TestOPACallerContextCancelledNotBlamedOnOPA : quand le contexte de
// l'APPELANT est déjà annulé/expiré (raison qui lui est propre, rien à voir
// avec OPA ni avec le budget de 5 ms), le refus reste fail-closed mais ne
// doit JAMAIS être étiqueté opa-timeout ni déclencher l'alarme T14 comme si
// OPA avait dépassé son circuit-breaker — ce serait exactement le genre de
// signal malhonnête que la doctrine de ce fichier interdit. OPA répond ici
// instantanément, bien en-deçà du budget, pour isoler la cause.
func TestOPACallerContextCancelledNotBlamedOnOPA(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, rec)

	callerCtx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond) // garantit l'expiration avant l'appel

	d := c.Eval(callerCtx, opaNominalInput())
	if d.Allow {
		t.Fatal("un contexte appelant annulé doit rester fail-closed (deny)")
	}
	if d.Reason == ReasonOPATimeout {
		t.Fatalf("reason=%q : accuse OPA à tort d'avoir dépassé le circuit-breaker", d.Reason)
	}
	if d.Reason != ReasonOPACallerCancelled {
		t.Fatalf("reason=%q, veut %q", d.Reason, ReasonOPACallerCancelled)
	}
	if lastReason(rec) == ReasonOPATimeout {
		t.Fatal("alarme T14 opa-timeout déclenchée pour une annulation côté appelant")
	}
	if rec.count() != 0 {
		t.Fatalf("alarme T14 intempestive: %v (l'annulation appelant n'est pas une faute OPA)", rec.reasons)
	}
	if !d.LeafWritten {
		t.Fatal("feuille de deny manquante")
	}
}

// ---------------------------------------------------------------------------
// Autres fautes OPA : statut non 200, corps indécodable — deny + alarme.
// ---------------------------------------------------------------------------

func TestOPAErrorStatus(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, rec)

	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonOPAError {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonOPAError)
	}
	if lastReason(rec) != ReasonOPAError {
		t.Fatalf("alarme=%q, veut %q", lastReason(rec), ReasonOPAError)
	}
	if !d.LeafWritten {
		t.Fatal("feuille manquante")
	}
}

func TestOPABadResponse(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `ceci n'est pas du JSON`)
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, rec)

	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonOPABadResponse {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonOPABadResponse)
	}
	if lastReason(rec) != ReasonOPABadResponse {
		t.Fatalf("alarme=%q, veut %q", lastReason(rec), ReasonOPABadResponse)
	}
}

func TestOPAResultWithoutAllow(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"result":{}}`) // contrat rompu : allow absent
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, rec)

	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonOPABadResponse {
		t.Fatalf("allow=%v reason=%q, veut deny/%q (allow absent ≠ deny métier)", d.Allow, d.Reason, ReasonOPABadResponse)
	}
}

// ---------------------------------------------------------------------------
// Contrat de la requête : l'input envoyé à OPA reflète le jeton (honnêteté
// de schéma — le PEP n'invente rien).
// ---------------------------------------------------------------------------

func TestOPAInputPayload(t *testing.T) {
	sink := &stubSink{}
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(srv.Close)
	c := newOPAClient(t, srv.URL, sink, nil)

	in := opaNominalInput()
	d := c.Eval(context.Background(), in)
	if !d.Allow {
		t.Fatalf("refusé: %s", d.Reason)
	}
	var body struct {
		Input struct {
			JTI      string `json:"jti"`
			Subject  string `json:"subject"`
			Action   string `json:"action"`
			Resource string `json:"resource"`
			Class    int    `json:"class"`
			Epoch    uint64 `json:"epoch"`
		} `json:"input"`
	}
	if err := json.Unmarshal(got, &body); err != nil {
		t.Fatalf("corps reçu illisible: %v (%s)", err, got)
	}
	if body.Input.JTI != hex.EncodeToString(in.JTI[:]) ||
		body.Input.Subject != in.Subject ||
		body.Input.Action != in.Action ||
		body.Input.Resource != in.Resource ||
		body.Input.Class != int(in.Class) ||
		body.Input.Epoch != in.Epoch {
		t.Fatalf("input déformé: %s", got)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed sur la preuve : allow + feuille impossible ⇒ deny
// (même doctrine que T9 : pas de preuve, pas d'accès).
// ---------------------------------------------------------------------------

func TestOPALeafWriteFailureOnAllow(t *testing.T) {
	sink := &stubSink{err: errors.New("registre plein")}
	c := newOPAClient(t, allowServer(t, true).URL, sink, nil)

	d := c.Eval(context.Background(), opaNominalInput())
	if d.Allow || d.Reason != ReasonLeafWriteFailed {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonLeafWriteFailed)
	}
	if d.LeafWritten || d.LeafErr == nil {
		t.Fatalf("written=%v leafErr=%v", d.LeafWritten, d.LeafErr)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration.
// ---------------------------------------------------------------------------

func TestNewOPAClientFailClosed(t *testing.T) {
	base := OPAOptions{
		Endpoint: "http://127.0.0.1:8181/v1/data/tbp/allow",
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   &stubSink{},
	}
	if _, err := NewOPAClient(base); err != nil {
		t.Fatalf("config nominale refusée: %v", err)
	}

	bad := base
	bad.Endpoint = ""
	if _, err := NewOPAClient(bad); err == nil {
		t.Fatal("endpoint vide accepté")
	}
	bad = base
	bad.Leaves = nil
	if _, err := NewOPAClient(bad); err == nil {
		t.Fatal("Leaves nil accepté (§4.1 : chaque décision laisse une feuille)")
	}
	bad = base
	bad.CellID = ""
	if _, err := NewOPAClient(bad); err == nil {
		t.Fatal("CellID vide accepté")
	}
	bad = base
	bad.Salt = []byte("trop-court")
	if _, err := NewOPAClient(bad); err == nil {
		t.Fatal("sel < 16 o accepté (§6.2)")
	}
	bad = base
	bad.Timeout = -time.Millisecond
	if _, err := NewOPAClient(bad); err == nil {
		t.Fatal("timeout négatif accepté")
	}
}

// ---------------------------------------------------------------------------
// Concurrence (-race) : le client est sûr pour un usage parallèle.
// ---------------------------------------------------------------------------

func TestOPAConcurrent(t *testing.T) {
	sink := &stubSink{}
	// Timeout élargi : sous -race, 32 allers-retours parallèles en boucle
	// locale peuvent dépasser le budget de 5 ms — le comportement fail-closed
	// sous contention est couvert par TestOPATimeoutCircuitBreaker ; ici on
	// éprouve la sûreté mémoire et la complétude des feuilles.
	c, err := NewOPAClient(OPAOptions{
		Endpoint: allowServer(t, true).URL,
		Timeout:  2 * time.Second,
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
	})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}

	const n = 32
	var wg sync.WaitGroup
	var failed atomic.Bool
	for g := 0; g < n; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			in := opaNominalInput()
			in.JTI = jtiNum(1000 + g)
			if d := c.Eval(context.Background(), in); !d.Allow {
				failed.Store(true)
			}
		}(g)
	}
	wg.Wait()
	if failed.Load() {
		t.Fatal("un Eval concurrent a été refusé")
	}
	if sink.count() != n {
		t.Fatalf("feuilles=%d, veut %d (une par décision)", sink.count(), n)
	}
}

// ---------------------------------------------------------------------------
// Budget §9.1 : un Eval allow reste très en-deçà de 5 ms en boucle locale.
// ---------------------------------------------------------------------------

func BenchmarkOPAEvalAllow(b *testing.B) {
	sink := &stubSink{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	defer srv.Close()
	c, err := NewOPAClient(OPAOptions{
		Endpoint: srv.URL,
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
	})
	if err != nil {
		b.Fatalf("NewOPAClient: %v", err)
	}
	in := opaNominalInput()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		in.JTI = jtiNum(i)
		if d := c.Eval(context.Background(), in); !d.Allow {
			b.Fatalf("refusé: %s", d.Reason)
		}
	}
}
