package pep

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// revisionStub sert un faux OPA dont la révision servie (provenance.revision)
// est modifiable en cours de test — simule un bundle qui change (rotation
// légitime) ou un imposteur (bundle substitué, #92.A5).
type revisionStub struct {
	revision atomic.Value // string
	srv      *httptest.Server
	requests atomic.Int64
}

func newRevisionStub(t *testing.T, revision string) *revisionStub {
	t.Helper()
	s := &revisionStub{}
	s.revision.Store(revision)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") != "true" {
			// Témoin de câblage : le watcher DOIT demander provenance=true.
			fmt.Fprint(w, `{"result":{"allow":false}}`)
			return
		}
		fmt.Fprintf(w, `{"result":{"allow":false},"provenance":{"revision":%q}}`, s.revision.Load().(string))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *revisionStub) setRevision(r string) { s.revision.Store(r) }

func newTestWatcher(t *testing.T, endpoint, expected string, onTrip func(string)) *OPARevisionWatcher {
	t.Helper()
	sink := &stubSink{}
	w, err := NewOPARevisionWatcher(OPARevisionWatcherOptions{
		Endpoint: endpoint,
		Expected: expected,
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
		OnTrip:   onTrip,
		Now:      func() time.Time { return time.Unix(testIAT, 0) },
	})
	if err != nil {
		t.Fatalf("NewOPARevisionWatcher: %v", err)
	}
	return w
}

func TestOPARevisionWatcherMatchOK(t *testing.T) {
	stub := newRevisionStub(t, "deadbeef")
	w := newTestWatcher(t, stub.srv.URL+"/v1/data/tbp/allow", "deadbeef", nil)
	w.Check(context.Background())
	if w.Mismatch() {
		t.Fatalf("mode=%v, veut OK (révision identique)", w.Mode())
	}
	if stub.requests.Load() != 1 {
		t.Fatalf("requêtes OPA=%d, veut 1", stub.requests.Load())
	}
}

// TestOPARevisionWatcherMismatchTrips : preuve NON-VACUE directe de
// #92.A5 — un bundle substitué (révision servie ≠ TBP_POLICY_ID épinglé)
// doit basculer en écart ET alarmer T14.
func TestOPARevisionWatcherMismatchTrips(t *testing.T) {
	stub := newRevisionStub(t, "imposteur-revision")
	var tripped []string
	w := newTestWatcher(t, stub.srv.URL+"/v1/data/tbp/allow", "deadbeef", func(reason string) {
		tripped = append(tripped, reason)
	})
	w.Check(context.Background())
	if !w.Mismatch() {
		t.Fatal("révision imposteur acceptée — #92.A5 non détecté")
	}
	if w.Reason() != ReasonOPARevisionMismatch {
		t.Fatalf("raison=%q, veut %q", w.Reason(), ReasonOPARevisionMismatch)
	}
	if len(tripped) != 1 || tripped[0] != ReasonOPARevisionMismatch {
		t.Fatalf("alarme T14=%v, veut [%q]", tripped, ReasonOPARevisionMismatch)
	}
}

func TestOPARevisionWatcherUnreachableTrips(t *testing.T) {
	var tripped []string
	w := newTestWatcher(t, "http://127.0.0.1:1/opa", "deadbeef", func(reason string) {
		tripped = append(tripped, reason)
	})
	w.Check(context.Background())
	if !w.Mismatch() {
		t.Fatal("OPA injoignable accepté comme vérifié — fail-closed attendu")
	}
	if w.Reason() != ReasonOPARevisionUnverifiable {
		t.Fatalf("raison=%q, veut %q", w.Reason(), ReasonOPARevisionUnverifiable)
	}
	if len(tripped) != 1 || tripped[0] != ReasonOPARevisionUnverifiable {
		t.Fatalf("alarme T14=%v, veut [%q]", tripped, ReasonOPARevisionUnverifiable)
	}
}

// TestOPARevisionWatcherMissingProvenanceTrips : un OPA qui ne rend
// jamais provenance.revision (bundle non versionné, --revision omis au
// build) est TOUT AUSSI invérifiable qu'un OPA injoignable — fail-closed,
// jamais une confiance par défaut faute de preuve.
func TestOPARevisionWatcherMissingProvenanceTrips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"allow":false}}`) // pas de provenance du tout
	}))
	defer srv.Close()

	w := newTestWatcher(t, srv.URL+"/v1/data/tbp/allow", "deadbeef", nil)
	w.Check(context.Background())
	if !w.Mismatch() {
		t.Fatal("réponse sans provenance.revision acceptée comme vérifiée")
	}
	if w.Reason() != ReasonOPARevisionUnverifiable {
		t.Fatalf("raison=%q, veut %q", w.Reason(), ReasonOPARevisionUnverifiable)
	}
}

// TestOPARevisionWatcherRecoversAndTraces : un retour à la révision
// attendue (rotation légitime alignée, ou correction d'un imposteur)
// repasse en OK et l'écrit (transition tracée, même doctrine que
// clock-resync).
func TestOPARevisionWatcherRecoversAndTraces(t *testing.T) {
	stub := newRevisionStub(t, "wrong")
	sink := &stubSink{}
	w, err := NewOPARevisionWatcher(OPARevisionWatcherOptions{
		Endpoint: stub.srv.URL + "/v1/data/tbp/allow",
		Expected: "deadbeef",
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
		Now:      func() time.Time { return time.Unix(testIAT, 0) },
	})
	if err != nil {
		t.Fatalf("NewOPARevisionWatcher: %v", err)
	}
	w.Check(context.Background())
	if !w.Mismatch() {
		t.Fatal("écart initial attendu")
	}
	before := sink.count()

	stub.setRevision("deadbeef")
	w.Check(context.Background())
	if w.Mismatch() {
		t.Fatal("retour à la révision attendue non détecté")
	}
	if sink.count() != before+1 {
		t.Fatalf("feuilles=%d, veut %d (retour à OK tracé)", sink.count(), before+1)
	}

	// Idempotence : un second Check déjà OK ne réécrit pas de feuille.
	w.Check(context.Background())
	if sink.count() != before+1 {
		t.Fatalf("feuilles=%d après second Check OK, veut %d (pas de doublon)", sink.count(), before+1)
	}
}

func TestOPARevisionWatcherRun(t *testing.T) {
	stub := newRevisionStub(t, "wrong")
	var tripped atomic.Int64
	w, err := NewOPARevisionWatcher(OPARevisionWatcherOptions{
		Endpoint: stub.srv.URL + "/v1/data/tbp/allow",
		Expected: "deadbeef",
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   &stubSink{},
		Interval: 5 * time.Millisecond,
		OnTrip:   func(string) { tripped.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewOPARevisionWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done
	if tripped.Load() < 2 {
		t.Fatalf("alarmes=%d, veut ≥ 2 (Check immédiat + au moins un tick)", tripped.Load())
	}
}

func TestNewOPARevisionWatcherFailClosed(t *testing.T) {
	sink := &stubSink{}
	base := OPARevisionWatcherOptions{
		Endpoint: "http://127.0.0.1:8181/v1/data/tbp/allow",
		Expected: "deadbeef",
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
	}
	cases := []func(OPARevisionWatcherOptions) OPARevisionWatcherOptions{
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.Endpoint = ""; return o },
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.Expected = ""; return o },
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.CellID = ""; return o },
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.Salt = []byte("court"); return o },
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.Leaves = nil; return o },
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.Interval = -1; return o },
		func(o OPARevisionWatcherOptions) OPARevisionWatcherOptions { o.Timeout = -1; return o },
	}
	for i, mutate := range cases {
		if _, err := NewOPARevisionWatcher(mutate(base)); err == nil {
			t.Fatalf("case %d: config invalide acceptée", i)
		}
	}
}
