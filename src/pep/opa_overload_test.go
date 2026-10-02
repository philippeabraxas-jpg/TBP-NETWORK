package pep

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// opaWith construit un client contre endpoint avec options et horloge contrôlées.
func opaWith(t *testing.T, endpoint string, sink *stubSink, rec *tripRecorder, clk *fakeClock, mut func(*OPAOptions)) *OPAClient {
	t.Helper()
	opts := OPAOptions{
		Endpoint: endpoint,
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
		Now:      clk.now,
	}
	if rec != nil {
		opts.OnTrip = rec.trip
	}
	if mut != nil {
		mut(&opts)
	}
	c, err := NewOPAClient(opts)
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	return c
}

// gatedServer retient chaque requête jusqu'à close(gate) ; started compte les requêtes reçues.
func gatedServer(t *testing.T) (srv *httptest.Server, gate chan struct{}, started *atomic.Int64) {
	t.Helper()
	gate = make(chan struct{})
	started = &atomic.Int64{}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Add(1)
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
		srv.Close()
	})
	return
}

func TestOPAOverloadedDoesNotReachOPANorCountAsFault(t *testing.T) {
	srv, gate, started := gatedServer(t)
	sink := &stubSink{}
	rec := &tripRecorder{}
	clk := newFakeClock()
	c := opaWith(t, srv.URL, sink, rec, clk, func(o *OPAOptions) {
		o.Admission = AdmissionOptions{MaxInflight: 1, MaxQueue: 0}
		o.TripAfter = 1
	})
	_ = gate

	// Occupe la seule place : la requête attend le portail (5 ms puis délai dépassé).
	hold := make(chan OPADecision, 1)
	go func() { hold <- c.Eval(context.Background(), opaNominalInput()) }()
	for started.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	in := opaNominalInput()
	in.Subject = "spiffe://tbp.example/agent/other"
	d := c.Eval(context.Background(), in)
	if d.Allow || d.Reason != ReasonOPAOverloaded {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d.Allow, d.Reason, ReasonOPAOverloaded)
	}
	if d.Err == nil {
		t.Fatal("l'erreur d'admission doit expliquer la cause")
	}
	if started.Load() != 1 {
		t.Fatalf("OPA a reçu %d requêtes : un refus de la file ne doit pas le solliciter", started.Load())
	}
	if !d.LeafWritten {
		t.Fatal("une feuille par refus (doctrine inchangée) : feuille manquante")
	}
	<-hold // la requête retenue expire (5 ms) : c'est la seule faute d'OPA
	if got := c.faults.Load(); got != 1 {
		t.Fatalf("fautes consécutives=%d : le refus de file ne doit pas compter, seule la requête expirée oui", got)
	}
	for _, r := range rec.reasons {
		if r == ReasonOPAOverloaded {
			t.Fatal("un refus de file ne doit pas déclencher l'alarme T14")
		}
	}
}

func TestOPAOverloadedKeepsFaultCounterAtZero(t *testing.T) {
	srv := allowServer(t, true)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, &tripRecorder{}, clk, func(o *OPAOptions) {
		o.Admission = AdmissionOptions{MaxInflight: 1}
	})
	// Un refus de file ne remet pas non plus à zéro un compteur de fautes réel.
	c.faults.Store(2)
	rel, _ := c.adm.acquire(context.Background(), "x", far(clk))
	d := c.Eval(context.Background(), opaNominalInput())
	rel()
	if d.Reason != ReasonOPAOverloaded {
		t.Fatalf("reason=%q", d.Reason)
	}
	if c.faults.Load() != 2 {
		t.Fatalf("fautes=%d : un refus de file ne prouve pas la santé d'OPA", c.faults.Load())
	}
}

func TestOPACallerCancelWhileQueuedIsNotOverload(t *testing.T) {
	srv := allowServer(t, true)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, nil, clk, func(o *OPAOptions) {
		o.Admission = AdmissionOptions{MaxInflight: 1, MaxQueue: 4}
	})
	rel, _ := c.adm.acquire(context.Background(), "x", far(clk))
	defer rel()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan OPADecision, 1)
	go func() { done <- c.Eval(ctx, opaNominalInput()) }()
	waitQueued(t, c.adm, 1)
	cancel()
	d := <-done
	if d.Reason != ReasonOPACallerCancelled {
		t.Fatalf("reason=%q, veut %q : l'annulation de l'appelant n'est pas une surcharge", d.Reason, ReasonOPACallerCancelled)
	}
}

func TestOPAAdmissionServesNormallyUnderCapacity(t *testing.T) {
	srv := allowServer(t, true)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, nil, clk, func(o *OPAOptions) {
		o.Admission = AdmissionOptions{MaxInflight: 2, MaxQueue: 4}
	})
	for i := 0; i < 20; i++ {
		if d := c.Eval(context.Background(), opaNominalInput()); !d.Allow {
			t.Fatalf("requête %d refusée sous la capacité : %q", i, d.Reason)
		}
	}
	if st := c.adm.snapshot(); st.Inflight != 0 || st.Queued != 0 {
		t.Fatalf("fuite de places : %+v", st)
	}
}

func TestOPAStallDetection(t *testing.T) {
	srv, gate, _ := gatedServer(t)
	_ = gate
	rec := &tripRecorder{}
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, rec, clk, func(o *OPAOptions) {
		o.StallWindow = 3 * time.Second
	})
	eval := func() { c.Eval(context.Background(), opaNominalInput()) }

	// Moins de minUnansweredForStall demandes sans réponse : pas de blocage, même après la fenêtre.
	eval()
	eval()
	clk.advance(10 * time.Second)
	if c.Stalled() {
		t.Fatal("2 demandes sans réponse ne suffisent pas")
	}
	// Troisième sans réponse + silence > fenêtre : bloqué, alarme émise.
	n := rec.count()
	eval()
	if !c.Stalled() {
		t.Fatal("3 demandes sans réponse et 10 s de silence : OPA doit être tenu pour bloqué")
	}
	found := false
	for _, r := range rec.reasons[n:] {
		if r == ReasonOPAStalled {
			found = true
		}
	}
	if !found {
		t.Fatalf("alarme %q attendue, reçues %v", ReasonOPAStalled, rec.reasons[n:])
	}
	if st := c.Status(); st.State != "stalled" || !st.Stalled || st.Unanswered < 3 || st.SilentMS < 10_000 {
		t.Fatalf("status=%+v", st)
	}
}

func TestOPAStallClearsOnAnyResponse(t *testing.T) {
	var slow atomic.Bool
	slow.Store(true)
	unblock := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			select {
			case <-r.Context().Done():
			case <-unblock:
			}
			return
		}
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(func() { close(unblock); srv.Close() })
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, &tripRecorder{}, clk, func(o *OPAOptions) { o.StallWindow = time.Second })
	for i := 0; i < 3; i++ {
		c.Eval(context.Background(), opaNominalInput())
	}
	clk.advance(2 * time.Second)
	if !c.Stalled() {
		t.Fatal("OPA doit être bloqué")
	}
	slow.Store(false)
	if d := c.Eval(context.Background(), opaNominalInput()); !d.Allow {
		t.Fatalf("OPA revenu : allow attendu, reason=%q", d.Reason)
	}
	if c.Stalled() || c.Status().State == "stalled" {
		t.Fatal("une réponse d'OPA doit lever l'état bloqué")
	}
}

func TestOPAStallDisabledAndIdleIsNotStalled(t *testing.T) {
	srv, _, _ := gatedServer(t)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, &tripRecorder{}, clk, nil) // StallWindow 0
	for i := 0; i < 5; i++ {
		c.Eval(context.Background(), opaNominalInput())
	}
	clk.advance(time.Hour)
	if c.Stalled() {
		t.Fatal("StallWindow 0 ⇒ détection désactivée")
	}
	// Inactif (aucune demande) : un silence long n'est pas un blocage.
	c2 := opaWith(t, srv.URL, &stubSink{}, nil, clk, func(o *OPAOptions) { o.StallWindow = time.Second })
	clk.advance(time.Hour)
	if c2.Stalled() || c2.Status().State != "healthy" {
		t.Fatalf("un OPA inactif n'est pas bloqué : %+v", c2.Status())
	}
}

func TestOPAStallCallerCancelIsNotUnanswered(t *testing.T) {
	srv, _, _ := gatedServer(t)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, nil, clk, func(o *OPAOptions) { o.StallWindow = time.Second })
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		c.Eval(ctx, opaNominalInput())
	}
	clk.advance(time.Minute)
	if c.Stalled() || c.Status().Unanswered != 0 {
		t.Fatalf("l'annulation appelant n'est pas un silence d'OPA : %+v", c.Status())
	}
}

func TestOPAStatusReportsOverload(t *testing.T) {
	srv := allowServer(t, true)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, nil, clk, func(o *OPAOptions) {
		o.Admission = AdmissionOptions{MaxInflight: 1}
	})
	if st := c.Status(); st.State != "healthy" || st.Admission == nil {
		t.Fatalf("départ sain attendu : %+v", st)
	}
	rel, _ := c.adm.acquire(context.Background(), "x", far(clk))
	d := c.Eval(context.Background(), opaNominalInput())
	rel()
	if d.Reason != ReasonOPAOverloaded {
		t.Fatalf("reason=%q", d.Reason)
	}
	if st := c.Status(); st.State != "overloaded" || st.Admission.ShedQueueFull != 1 {
		t.Fatalf("status=%+v", st)
	}
	clk.advance(overloadedHoldMS*time.Millisecond + time.Second)
	if st := c.Status(); st.State != "healthy" {
		t.Fatalf("après %d ms sans refus : sain attendu, %+v", overloadedHoldMS, st)
	}
}

func TestNewOPAClientRejectsBadAdmissionAndStall(t *testing.T) {
	base := OPAOptions{Endpoint: "http://127.0.0.1:1", CellID: opaTestCellID, Salt: testSalt, Leaves: &stubSink{}}
	for name, mut := range map[string]func(*OPAOptions){
		"stall négatif":    func(o *OPAOptions) { o.StallWindow = -1 },
		"inflight négatif": func(o *OPAOptions) { o.Admission.MaxInflight = -1 },
		"file négative":    func(o *OPAOptions) { o.Admission = AdmissionOptions{MaxInflight: 1, MaxQueue: -1} },
		"part > 100":       func(o *OPAOptions) { o.Admission = AdmissionOptions{MaxInflight: 1, SubjectShare: 101} },
		"service négatif":  func(o *OPAOptions) { o.Admission = AdmissionOptions{MaxInflight: 1, MinService: -1} },
	} {
		o := base
		mut(&o)
		if _, err := NewOPAClient(o); err == nil {
			t.Errorf("%s : refus attendu", name)
		}
	}
}

// Une demande dont il reste moins de MinService quand sa place se libère n'est pas envoyée à OPA : travail déjà perdu.
func TestOPAQueuedRequestWithNoBudgetLeftIsNotSent(t *testing.T) {
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sent.Add(1)
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(srv.Close)
	clk := newFakeClock()
	c := opaWith(t, srv.URL, &stubSink{}, nil, clk, func(o *OPAOptions) {
		o.Admission = AdmissionOptions{MaxInflight: 1, MaxQueue: 4, MinService: 2 * time.Millisecond}
	})
	rel, _ := c.adm.acquire(context.Background(), "x", far(clk))
	done := make(chan OPADecision, 1)
	go func() { done <- c.Eval(context.Background(), opaNominalInput()) }()
	waitQueued(t, c.adm, 1)
	clk.advance(c.Timeout() - time.Millisecond) // il lui reste 1 ms < MinService 2 ms
	rel()
	d := <-done
	if d.Reason != ReasonOPAOverloaded || sent.Load() != 0 {
		t.Fatalf("reason=%q envoyées=%d : une demande sans budget ne doit pas atteindre OPA", d.Reason, sent.Load())
	}
}
