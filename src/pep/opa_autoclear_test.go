package pep

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Issue #205 (R-18) — l'événement devient un taux : une faute OPA isolée ne
// verrouille plus la cellule, une reprise vérifiée lève le latch.
// ---------------------------------------------------------------------------

// flakyOPA répond 200/allow quand healthy, 503 sinon.
func flakyOPA(t *testing.T, healthy *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newThresholdClient(t *testing.T, endpoint string, tripAfter int, rec *tripRecorder) *OPAClient {
	t.Helper()
	c, err := NewOPAClient(OPAOptions{
		Endpoint: endpoint, CellID: opaTestCellID, Salt: testSalt, Leaves: &stubSink{},
		Now: func() time.Time { return time.Unix(testIAT+30, 0) }, OnTrip: rec.trip, TripAfter: tripAfter,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSingleOPAFaultDeniesTheRequestButDoesNotLatch(t *testing.T) {
	var healthy atomic.Bool
	rec := &tripRecorder{}
	c := newThresholdClient(t, flakyOPA(t, &healthy).URL, 3, rec)

	d := c.Eval(context.Background(), opaNominalInput()) // OPA en panne
	if d.Allow || d.Reason != ReasonOPAError {
		t.Fatalf("faute OPA : allow=%v reason=%s — le verdict par requête doit rester un deny fail-closed", d.Allow, d.Reason)
	}
	if rec.count() != 0 {
		t.Fatal("une faute isolée a basculé le latch (R-18)")
	}
	healthy.Store(true)
	if d := c.Eval(context.Background(), opaNominalInput()); !d.Allow {
		t.Fatalf("OPA revenu, requête suivante refusée : %s", d.Reason)
	}
}

func TestConsecutiveOPAFaultsLatchAtTheThreshold(t *testing.T) {
	var healthy atomic.Bool
	rec := &tripRecorder{}
	c := newThresholdClient(t, flakyOPA(t, &healthy).URL, 3, rec)

	for i := 1; i <= 2; i++ {
		c.Eval(context.Background(), opaNominalInput())
		if rec.count() != 0 {
			t.Fatalf("latch basculé dès la faute %d sur 3", i)
		}
	}
	c.Eval(context.Background(), opaNominalInput())
	if rec.count() != 1 || lastReason(rec) != ReasonOPAError {
		t.Fatalf("3e faute consécutive : alarmes=%d reason=%q", rec.count(), lastReason(rec))
	}
}

func TestHealthyDecisionResetsTheFaultStreak(t *testing.T) {
	var healthy atomic.Bool
	rec := &tripRecorder{}
	c := newThresholdClient(t, flakyOPA(t, &healthy).URL, 3, rec)

	c.Eval(context.Background(), opaNominalInput())
	c.Eval(context.Background(), opaNominalInput())
	healthy.Store(true)
	c.Eval(context.Background(), opaNominalInput()) // décision saine : compteur à zéro
	healthy.Store(false)
	c.Eval(context.Background(), opaNominalInput())
	c.Eval(context.Background(), opaNominalInput())
	if rec.count() != 0 {
		t.Fatal("des fautes non consécutives ont basculé le latch")
	}
}

func TestBadResponseLatchesImmediately(t *testing.T) {
	rec := &tripRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"result":{}}`) // result sans allow : contrat rompu
	}))
	defer srv.Close()
	c := newThresholdClient(t, srv.URL, 3, rec)
	c.Eval(context.Background(), opaNominalInput())
	if rec.count() != 1 || lastReason(rec) != ReasonOPABadResponse {
		t.Fatalf("contrat rompu : alarmes=%d reason=%q — jamais transitoire, bascule immédiate", rec.count(), lastReason(rec))
	}
}

func TestTripAfterDefaultsToTheHistoricalBehaviour(t *testing.T) {
	var healthy atomic.Bool
	rec := &tripRecorder{}
	c := newThresholdClient(t, flakyOPA(t, &healthy).URL, 0, rec)
	c.Eval(context.Background(), opaNominalInput())
	if rec.count() != 1 {
		t.Fatal("TripAfter=0 doit garder le latch à la première faute")
	}
	if _, err := NewOPAClient(OPAOptions{Endpoint: "http://x", CellID: "c", Salt: testSalt, Leaves: &stubSink{}, TripAfter: -1}); err == nil {
		t.Fatal("TripAfter négatif accepté")
	}
}

// ---------------------------------------------------------------------------
// FailClosed.AutoClear : jamais une condition classe W.
// ---------------------------------------------------------------------------

func TestAutoClearRefusesClassWAndIsTraced(t *testing.T) {
	sink := &stubSink{}
	fc := newTestFailClosed(t, sink, nil)
	_ = fc.Register(ReasonOPARevisionMismatch, ClassW)
	_ = fc.Register(ReasonOPAUnreachable, ClassI)
	fc.Trip(ReasonOPARevisionMismatch, "")
	fc.Trip(ReasonOPAUnreachable, "")

	if err := fc.AutoClear(ReasonOPARevisionMismatch); !errors.Is(err, ErrAutoClearRefusedClassW) {
		t.Fatalf("levée auto d'une condition W : %v", err)
	}
	if err := fc.AutoClear(ReasonOPAUnreachable); err != nil {
		t.Fatal(err)
	}
	if got := sink.leaves[len(sink.leaves)-1].PayloadHash; got != tripLeafHash(failClosedActionClear, ReasonOPAUnreachable, "auto") {
		t.Fatal("la levée automatique n'est pas tracée avec la source « auto »")
	}
	if names := fc.Tripped(); len(names) != 1 || names[0].Name != ReasonOPARevisionMismatch {
		t.Fatalf("conditions basculées = %v", names)
	}
}

// ---------------------------------------------------------------------------
// OPAAutoClearer
// ---------------------------------------------------------------------------

type clearerFixture struct {
	fc      *FailClosed
	healthy atomic.Bool
	now     atomic.Int64
	a       *OPAAutoClearer
}

func newClearerFixture(t *testing.T, probes int) *clearerFixture {
	t.Helper()
	f := &clearerFixture{fc: newTestFailClosed(t, &stubSink{}, nil)}
	f.now.Store(testIAT)
	_ = f.fc.Register(ReasonOPAUnreachable, ClassI)
	_ = f.fc.Register(ReasonOPABadResponse, ClassI)
	_ = f.fc.Register(ReasonOPARevisionMismatch, ClassW)
	a, err := NewOPAAutoClearer(OPAAutoClearOptions{
		FailClosed: f.fc, Probes: probes,
		Conditions: []string{ReasonOPAUnreachable, ReasonOPARevisionMismatch},
		Probe: func(context.Context) error {
			if f.healthy.Load() {
				return nil
			}
			return errors.New("opa down")
		},
		Now: func() time.Time { return time.Unix(f.now.Load(), 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.a = a
	return f
}

func TestAutoClearLiftsAfterConsecutiveHealthyProbes(t *testing.T) {
	f := newClearerFixture(t, 3)
	f.fc.Trip(ReasonOPAUnreachable, "")
	ctx := context.Background()

	f.a.Tick(ctx) // OPA toujours en panne
	if f.fc.Gate() == nil {
		t.Fatal("levé alors que la sonde est en échec")
	}
	f.healthy.Store(true)
	f.a.Tick(ctx)
	f.a.Tick(ctx)
	if f.fc.Gate() == nil {
		t.Fatal("levé avant 3 sondes saines consécutives")
	}
	f.a.Tick(ctx)
	if ref := f.fc.Gate(); ref != nil {
		t.Fatalf("toujours basculé après 3 sondes saines : %v", ref)
	}
}

func TestAFailedProbeRestartsTheStreak(t *testing.T) {
	f := newClearerFixture(t, 3)
	f.fc.Trip(ReasonOPAUnreachable, "")
	ctx := context.Background()
	f.healthy.Store(true)
	f.a.Tick(ctx)
	f.a.Tick(ctx)
	f.healthy.Store(false)
	f.a.Tick(ctx) // la série repart de zéro
	f.healthy.Store(true)
	f.a.Tick(ctx)
	f.a.Tick(ctx)
	if f.fc.Gate() == nil {
		t.Fatal("série interrompue mais levée quand même")
	}
	f.a.Tick(ctx)
	if f.fc.Gate() != nil {
		t.Fatal("3 sondes saines consécutives n'ont pas levé")
	}
}

func TestAutoClearNeverTouchesClassWOrBadResponse(t *testing.T) {
	f := newClearerFixture(t, 1)
	f.healthy.Store(true)
	f.fc.Trip(ReasonOPARevisionMismatch, "")
	f.fc.Trip(ReasonOPABadResponse, "")
	for i := 0; i < 5; i++ {
		f.a.Tick(context.Background())
	}
	got := map[string]bool{}
	for _, c := range f.fc.Tripped() {
		got[c.Name] = true
	}
	if !got[ReasonOPARevisionMismatch] || !got[ReasonOPABadResponse] {
		t.Fatalf("une condition W (bundle substitué) ou un contrat rompu a été levé seul : %v", got)
	}
}

func TestFlappingOPADoublesTheRequiredProbes(t *testing.T) {
	f := newClearerFixture(t, 2)
	f.healthy.Store(true)
	ctx := context.Background()

	f.fc.Trip(ReasonOPAUnreachable, "")
	f.a.Tick(ctx)
	f.a.Tick(ctx) // 2 sondes : levé
	if f.fc.Gate() != nil {
		t.Fatal("première levée attendue après 2 sondes")
	}
	// Rebascule immédiate (dans la fenêtre anti-battement) : 4 sondes exigées.
	f.fc.Trip(ReasonOPAUnreachable, "")
	for i := 0; i < 3; i++ {
		f.a.Tick(ctx)
	}
	if f.fc.Gate() == nil {
		t.Fatal("OPA qui flappe : levé après seulement 3 sondes, le doublement n'est pas appliqué")
	}
	f.a.Tick(ctx)
	if f.fc.Gate() != nil {
		t.Fatal("4 sondes saines devraient lever")
	}
	// Loin après la fenêtre : retour à l'exigence de base.
	f.now.Add(int64(autoClearFlapWindow/time.Second) + 1)
	f.fc.Trip(ReasonOPAUnreachable, "")
	f.a.Tick(ctx)
	f.a.Tick(ctx)
	if f.fc.Gate() != nil {
		t.Fatal("hors fenêtre, 2 sondes doivent suffire de nouveau")
	}
}

func TestNewOPAAutoClearerConfig(t *testing.T) {
	fc := newTestFailClosed(t, &stubSink{}, nil)
	ok := func(context.Context) error { return nil }
	for name, o := range map[string]OPAAutoClearOptions{
		"sans point fail-closed": {Probe: ok, Conditions: []string{"x"}},
		"sans sonde":             {FailClosed: fc, Conditions: []string{"x"}},
		"sans condition":         {FailClosed: fc, Probe: ok},
		"sondes négatives":       {FailClosed: fc, Probe: ok, Conditions: []string{"x"}, Probes: -1},
	} {
		if _, err := NewOPAAutoClearer(o); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Route d'administration
// ---------------------------------------------------------------------------

func newFailClosedAdmin(t *testing.T) (http.Handler, *FailClosed) {
	t.Helper()
	f := newListenerFixture(t, false)
	fc := newTestFailClosed(t, &stubSink{}, nil)
	_ = fc.Register(ReasonOPAUnreachable, ClassI)
	_ = fc.Register(ReasonOPARevisionMismatch, ClassW)
	l, err := NewListener(ListenerOptions{Validator: f.l.validator, Mode: f.mc, FailClosed: fc})
	if err != nil {
		t.Fatal(err)
	}
	return l.AdminHandler(), fc
}

func adminPost(h http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

func TestAdminClearLiftsAClassIConditionAndListsIt(t *testing.T) {
	h, fc := newFailClosedAdmin(t)
	fc.Trip(ReasonOPAUnreachable, "test")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/failclosed", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), ReasonOPAUnreachable) || !strings.Contains(rec.Body.String(), `"class":"I"`) {
		t.Fatalf("liste : %d %s", rec.Code, rec.Body.String())
	}
	if rec := adminPost(h, "/v1/failclosed/clear", `{"condition":"`+ReasonOPAUnreachable+`"}`); rec.Code != 200 {
		t.Fatalf("levée classe I : %d %s", rec.Code, rec.Body.String())
	}
	if fc.Gate() != nil {
		t.Fatal("condition encore basculée après la levée")
	}
}

func TestAdminClearRefusesClassWWithoutAValidQuorum(t *testing.T) {
	h, fc := newFailClosedAdmin(t)
	fc.Trip(ReasonOPARevisionMismatch, "bundle substitué")
	rec := adminPost(h, "/v1/failclosed/clear", `{"condition":"`+ReasonOPARevisionMismatch+`"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("classe W sans preuve : %d %s", rec.Code, rec.Body.String())
	}
	if fc.Gate() == nil {
		t.Fatal("condition W levée sans quorum")
	}
}

func TestAdminClearErrorsAndBounds(t *testing.T) {
	h, fc := newFailClosedAdmin(t)
	if rec := adminPost(h, "/v1/failclosed/clear", `{"condition":"inconnue"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("condition inconnue : %d", rec.Code)
	}
	if rec := adminPost(h, "/v1/failclosed/clear", `{"condition":"`+ReasonOPAUnreachable+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("condition non basculée : %d", rec.Code)
	}
	if rec := adminPost(h, "/v1/failclosed/clear", `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("sans condition : %d", rec.Code)
	}
	big := `{"condition":"` + strings.Repeat("a", maxFailClosedBody) + `"}`
	if rec := adminPost(h, "/v1/failclosed/clear", big); rec.Code != http.StatusBadRequest {
		t.Fatalf("corps hors borne : %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/failclosed/clear", bytes.NewReader(nil)))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET sur clear : %d", rec.Code)
	}
	_ = fc
}

func TestFailClosedRoutesAbsentWithoutFailClosed(t *testing.T) {
	f := newListenerFixture(t, false)
	rec := httptest.NewRecorder()
	f.l.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/failclosed", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("route servie sans FailClosed : %d", rec.Code)
	}
}

// Levée W par la route d'administration avec de VRAIES signatures : acceptée
// une fois, rejouée refusée (#105), signée pour une autre condition refusée.
func TestAdminClearClassWWithRealQuorumAndReplay(t *testing.T) {
	h, fc := newFailClosedAdmin(t)
	pub, priv := mustGenKey(t)
	kid := [16]byte{9}
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, map[[16]byte]ed25519.PublicKey{kid: pub}, 1, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	fc.SetQuorumVerifier(verify)
	fc.SetQuorumState(NewFileQuorumStateStore(filepath.Join(t.TempDir(), "q.json")))

	body := func(condition, signedFor string, expiry time.Time) string {
		sig := signQuorum(priv, kid, signedFor, opaTestCellID, expiry)
		return fmt.Sprintf(`{"condition":%q,"expiry":%d,"signatures":[{"key_id":%q,"signature":%q}]}`,
			condition, expiry.Unix(), hex.EncodeToString(kid[:]), hex.EncodeToString(sig.Signature))
	}
	expiry := time.Now().Add(time.Minute).Truncate(time.Second)

	fc.Trip(ReasonOPARevisionMismatch, "bundle substitué")
	// signée pour une AUTRE condition : refusée.
	if rec := adminPost(h, "/v1/failclosed/clear", body(ReasonOPARevisionMismatch, "mode-closed", expiry)); rec.Code != http.StatusForbidden {
		t.Fatalf("preuve liée à une autre condition : %d", rec.Code)
	}
	if rec := adminPost(h, "/v1/failclosed/clear", body(ReasonOPARevisionMismatch, ReasonOPARevisionMismatch, expiry)); rec.Code != http.StatusOK {
		t.Fatalf("levée W quorée : %d %s", rec.Code, rec.Body.String())
	}
	// rejeu : la condition rebascule, la MÊME preuve ne la relève pas.
	fc.Trip(ReasonOPARevisionMismatch, "de nouveau")
	if rec := adminPost(h, "/v1/failclosed/clear", body(ReasonOPARevisionMismatch, ReasonOPARevisionMismatch, expiry)); rec.Code != http.StatusForbidden {
		t.Fatalf("preuve rejouée : %d", rec.Code)
	}
	if fc.Gate() == nil {
		t.Fatal("condition W levée par une preuve rejouée")
	}
}
