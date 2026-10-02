package main

// Contrat avec le PEP : le chien de garde lit le VRAI statut rendu par pep.OPAStatusHandler, produit par un VRAI
// pep.OPAClient devant un OPA muet — de bout en bout, sans redémarreur réel.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type nopSink struct{}

func (nopSink) Append(context.Context, registry.Leaf) (uint64, error) { return 1, nil }

// Un champ ajouté à pep.OPAStatus sans mise à jour d'opaStatus rend le statut illisible (strictjson) et le chien de garde
// aveugle : ce test le voit avant le déploiement.
func TestStatusStructMirrorsPepStatus(t *testing.T) {
	full := pep.OPAStatus{State: "stalled", Stalled: true, SilentMS: 1, Unanswered: 2, ConsecutiveFaults: 3,
		Admission: &pep.AdmissionStats{Inflight: 1, Queued: 2, Admitted: 3, ShedQueueFull: 4, ShedSubjectShare: 5, ShedExpired: 6, SinceLastShedMS: 7}}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	src := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(b) }))
	st, err := SocketStatusFetcher()(context.Background(), src)
	if err != nil {
		t.Fatalf("le statut complet du PEP doit être lisible : %v", err)
	}
	if st.State != "stalled" || st.Admission == nil || st.Admission.ShedExpired != 6 || st.Admission.SinceLastShedMS != 7 {
		t.Fatalf("st=%+v", st)
	}
	// sans file (Admission nil, omitempty) : lisible aussi
	b, _ = json.Marshal(pep.OPAStatus{State: "healthy"})
	src = unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(b) }))
	if _, err := SocketStatusFetcher()(context.Background(), src); err != nil {
		t.Fatalf("statut sans file : %v", err)
	}
	// les constantes d'état du chien de garde sont celles du PEP
	if stateStalled != "stalled" || stateHealthy != "healthy" || stateOverloaded != "overloaded" {
		t.Fatal("états désalignés")
	}
}

type peerClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *peerClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *peerClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestEndToEndStalledOPAIsRestarted(t *testing.T) {
	var muted atomic.Bool
	unblock := make(chan struct{})
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if muted.Load() {
			select {
			case <-r.Context().Done():
			case <-unblock:
			}
			return
		}
		_, _ = io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(func() { close(unblock); opa.Close() })

	pc := &peerClock{t: time.Unix(1_800_000_000, 0)}
	client, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint: opa.URL, CellID: "tbp/registry/cell-alpha-01", Salt: make([]byte, 32), Leaves: nopSink{},
		Now: pc.now, StallWindow: time.Second, Admission: pep.AdmissionOptions{MaxInflight: 2, MaxQueue: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "admin.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(statusPath, pep.OPAStatusHandler(client))
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	rs := &fakeRestarter{}
	w, err := NewWatchdog(Settings{Sources: []Source{{"pepd", sock}}, Unit: "tbp-opa.service", Confirm: 2, Cooldown: time.Second, MaxPerHour: 3},
		SocketStatusFetcher(), rs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := pep.OPAInput{Subject: "spiffe://tbp.example/agent/a", Action: "http.send", Resource: "https://api.example.com/x", Class: pep.ClassI, Epoch: 1}

	// sain : un relevé ne fait rien
	if d := client.Eval(context.Background(), in); !d.Allow {
		t.Fatalf("OPA sain : allow attendu (%s)", d.Reason)
	}
	if o := w.Tick(context.Background()); o != OutcomeHealthy {
		t.Fatalf("outcome=%s", o)
	}

	// OPA se tait : des demandes restent sans réponse, le silence dépasse la fenêtre
	muted.Store(true)
	for i := 0; i < 4; i++ {
		client.Eval(context.Background(), in)
	}
	pc.advance(2 * time.Second)
	if st := client.Status(); st.State != "stalled" {
		t.Fatalf("le PEP doit se dire « stalled » : %+v", st)
	}
	if o := w.Tick(context.Background()); o != OutcomeSuspect {
		t.Fatalf("1er relevé : %s", o)
	}
	if o := w.Tick(context.Background()); o != OutcomeRestarted || len(rs.calls) != 1 {
		t.Fatalf("2e relevé : %s appels=%v", o, rs.calls)
	}
}
