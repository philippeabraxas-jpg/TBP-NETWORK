package pep

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// revisionStub sert un faux OPA dont la révision servie
// (provenance.bundles.<clé>.revision, forme réelle d'OPA 1.20.2 pour un
// bundle non nommé) est modifiable en cours de test — simule un bundle
// qui change (rotation légitime) ou un imposteur (bundle substitué,
// #92.A5).
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
		// Forme RÉELLE d'OPA 1.20.2 pour un bundle non nommé (revue #86) :
		// provenance.bundles.<clé>.revision, pas provenance.revision — un
		// faux OPA au mauvais format aurait laissé passer un bug qui
		// casse TOUT démarrage réel (le selftest contre un vrai OPA était
		// rouge alors que ces tests unitaires, avec l'ancien stub,
		// passaient tous).
		fmt.Fprintf(w, `{"result":{"allow":false},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":%q}}}}`, s.revision.Load().(string))
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

// TestExtractProvenanceRevision : preuve NON-VACUE que le décodage gère
// les DEUX formes vues chez OPA — et refuse fail-closed le reste. Revue
// #86 : l'ancien code ne lisait QUE provenance.revision, jamais peuplé
// par OPA 1.20.2 pour un bundle chargé sans nom explicite (la forme
// utilisée par `opa run bundle.tar.gz`, celle de ce déploiement) — ce qui
// faisait échouer TOUT démarrage réel malgré des tests unitaires tous
// verts (le faux OPA des tests avait le même défaut de format).
func TestExtractProvenanceRevision(t *testing.T) {
	mustJSON := func(body string) opaProvenanceResponse {
		var decoded opaProvenanceResponse
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("corps de test illisible: %v", err)
		}
		return decoded
	}

	t.Run("bundle non nommé (OPA 1.20.2 réel)", func(t *testing.T) {
		rev, err := extractProvenanceRevision(mustJSON(
			`{"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":"deadbeef"}}}}`))
		if err != nil || rev != "deadbeef" {
			t.Fatalf("rev=%q err=%v, veut deadbeef/nil", rev, err)
		}
	})

	t.Run("clé de bundle arbitraire — un seul bundle, révision prise quand même", func(t *testing.T) {
		rev, err := extractProvenanceRevision(mustJSON(
			`{"provenance":{"bundles":{"n'importe-quoi":{"revision":"cafebabe"}}}}`))
		if err != nil || rev != "cafebabe" {
			t.Fatalf("rev=%q err=%v, veut cafebabe/nil", rev, err)
		}
	})

	t.Run("forme historique provenance.revision", func(t *testing.T) {
		rev, err := extractProvenanceRevision(mustJSON(
			`{"provenance":{"revision":"deadbeef"}}`))
		if err != nil || rev != "deadbeef" {
			t.Fatalf("rev=%q err=%v, veut deadbeef/nil", rev, err)
		}
	})

	t.Run("provenance absente — invérifiable", func(t *testing.T) {
		if _, err := extractProvenanceRevision(mustJSON(`{}`)); err == nil {
			t.Fatal("provenance absente acceptée")
		}
	})

	t.Run("ni revision ni bundles — invérifiable", func(t *testing.T) {
		if _, err := extractProvenanceRevision(mustJSON(`{"provenance":{}}`)); err == nil {
			t.Fatal("provenance sans révision acceptée")
		}
	})

	t.Run("bundles vide — invérifiable", func(t *testing.T) {
		if _, err := extractProvenanceRevision(mustJSON(`{"provenance":{"bundles":{}}}`)); err == nil {
			t.Fatal("bundles vide accepté")
		}
	})

	t.Run("révision de bundle vide — invérifiable", func(t *testing.T) {
		if _, err := extractProvenanceRevision(mustJSON(
			`{"provenance":{"bundles":{"x":{"revision":""}}}}`)); err == nil {
			t.Fatal("révision vide acceptée")
		}
	})

	t.Run("plusieurs bundles — ambigu, jamais un choix arbitraire", func(t *testing.T) {
		if _, err := extractProvenanceRevision(mustJSON(
			`{"provenance":{"bundles":{"a":{"revision":"1"},"b":{"revision":"2"}}}}`)); err == nil {
			t.Fatal("plusieurs bundles acceptés sans ambiguïté détectée")
		}
	})
}

// TestOPARevisionWatcherAgainstRealOPA : la même preuve que le selftest
// (revue #86) mais en test unitaire rapide — un VRAI binaire OPA, pas un
// faux serveur qui peut diverger silencieusement du format réel. Ignoré
// si `opa` est absent du PATH (environnement de build sans OPA installé).
func TestOPARevisionWatcherAgainstRealOPA(t *testing.T) {
	opaBin, err := exec.LookPath("opa")
	if err != nil {
		t.Skip("binaire opa introuvable dans PATH — voir deploy/selftest pour la preuve d'intégration complète")
	}

	dir := t.TempDir()
	regoPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte("package tbp\n\ndefault allow := false\n"), 0o644); err != nil {
		t.Fatalf("écriture policy.rego: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	build := exec.Command(opaBin, "build", "--revision", "deadbeef1234", regoPath, "-o", bundlePath)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("opa build: %v — %s", err, out)
	}

	addr := "127.0.0.1:0"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("réservation de port: %v", err)
	}
	addr = ln.Addr().String()
	ln.Close()

	run := exec.Command(opaBin, "run", "--server", "--addr", addr, bundlePath)
	if err := run.Start(); err != nil {
		t.Fatalf("opa run: %v", err)
	}
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_ = run.Wait()
	})

	endpoint := "http://" + addr + "/v1/data/tbp/allow"
	var w *OPARevisionWatcher
	for i := 0; i < 50; i++ {
		w = newTestWatcher(t, endpoint, "deadbeef1234", nil)
		w.Check(context.Background())
		if !w.Mismatch() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if w.Mismatch() {
		t.Fatalf("révision correcte (deadbeef1234) rejetée contre un OPA réel — raison=%q", w.Reason())
	}

	wrong := newTestWatcher(t, endpoint, "autre-revision", nil)
	wrong.Check(context.Background())
	if !wrong.Mismatch() {
		t.Fatal("révision incorrecte acceptée contre un OPA réel")
	}
	if wrong.Reason() != ReasonOPARevisionMismatch {
		t.Fatalf("raison=%q, veut %q (pas unverifiable — la lecture DOIT réussir, juste être fausse)", wrong.Reason(), ReasonOPARevisionMismatch)
	}
}
