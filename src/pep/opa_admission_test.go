package pep

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Unix(1_800_000_000, 0).UnixNano())
	return c
}
func (c *fakeClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func far(c *fakeClock) time.Time { return c.now().Add(time.Hour) }

// waitQueued attend que n demandes soient en file (la file se remplit dans des goroutines).
func waitQueued(t *testing.T, a *admission, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a.snapshot().Queued == n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("file : %d en attente attendues, %+v", n, a.snapshot())
}

func TestAdmissionDisabledByZeroInflight(t *testing.T) {
	if newAdmission(AdmissionOptions{}, time.Now) != nil || newAdmission(AdmissionOptions{MaxQueue: 5}, time.Now) != nil {
		t.Fatal("MaxInflight 0 doit désactiver la file (concurrence non bornée, historique)")
	}
}

func TestAdmissionBoundsInflightAndQueue(t *testing.T) {
	clk := newFakeClock()
	a := newAdmission(AdmissionOptions{MaxInflight: 2, MaxQueue: 1}, clk.now)
	ctx := context.Background()
	r1, s := a.acquire(ctx, "a", far(clk))
	r2, _ := a.acquire(ctx, "b", far(clk))
	if r1 == nil || r2 == nil || s != "" {
		t.Fatal("les deux premières places doivent être accordées")
	}
	// la troisième attend ; la quatrième est refusée (file pleine)
	got := make(chan bool, 1)
	go func() {
		r, _ := a.acquire(ctx, "c", far(clk))
		if r != nil {
			r()
		}
		got <- r != nil
	}()
	waitQueued(t, a, 1)
	if r, shed := a.acquire(ctx, "d", far(clk)); r != nil || shed != shedQueueFull {
		t.Fatalf("file pleine : refus attendu, got %v %q", r != nil, shed)
	}
	r1() // libère : la demande en attente passe
	if !<-got {
		t.Fatal("la demande en attente n'a pas été servie")
	}
	r2()
	if st := a.snapshot(); st.Inflight != 0 || st.Queued != 0 || st.ShedQueueFull != 1 {
		t.Fatalf("état final : %+v", st)
	}
}

func TestAdmissionReleaseIsIdempotent(t *testing.T) {
	clk := newFakeClock()
	a := newAdmission(AdmissionOptions{MaxInflight: 1}, clk.now)
	r, _ := a.acquire(context.Background(), "a", far(clk))
	r()
	r()
	r()
	if st := a.snapshot(); st.Inflight != 0 {
		t.Fatalf("libérations multiples : %+v", st)
	}
	if r2, _ := a.acquire(context.Background(), "a", far(clk)); r2 == nil {
		t.Fatal("la place doit être de nouveau libre")
	}
}

// Un sujet qui inonde ne dépasse pas sa part, quel que soit l'état de la file.
func TestAdmissionSubjectShareCapsAFlooder(t *testing.T) {
	clk := newFakeClock()
	// capacité 2 + 4 = 6 ; part 50 % ⇒ 3 par sujet
	a := newAdmission(AdmissionOptions{MaxInflight: 2, MaxQueue: 4, SubjectShare: 50}, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var rel []func()
	for i := 0; i < 2; i++ {
		r, _ := a.acquire(ctx, "flood", far(clk))
		rel = append(rel, r)
	}
	go func() { a.acquire(ctx, "flood", far(clk)) }() // 3e : en attente (plafond atteint : 3)
	waitQueued(t, a, 1)
	if r, shed := a.acquire(ctx, "flood", far(clk)); r != nil || shed != shedSubjectShare {
		t.Fatalf("4e demande du même sujet : refus de part attendu, got %v %q", r != nil, shed)
	}
	// un AUTRE sujet passe encore (file) : la part ne bloque que l'inondateur
	go func() { a.acquire(ctx, "legit", far(clk)) }()
	waitQueued(t, a, 2)
	if st := a.snapshot(); st.ShedSubjectShare != 1 {
		t.Fatalf("%+v", st)
	}
	for _, r := range rel {
		r()
	}
}

// Ordre ÉQUITABLE : à la libération, le sujet sans requête en vol passe avant celui qui occupe déjà les places.
func TestAdmissionServesTheLeastServedSubjectFirst(t *testing.T) {
	clk := newFakeClock()
	a := newAdmission(AdmissionOptions{MaxInflight: 2, MaxQueue: 8}, clk.now)
	ctx := context.Background()
	r1, _ := a.acquire(ctx, "flood", far(clk))
	r2, _ := a.acquire(ctx, "flood", far(clk))
	order := make(chan string, 4)
	enqueue := func(subj string) {
		go func() {
			r, _ := a.acquire(ctx, subj, far(clk))
			if r != nil {
				order <- subj
				// la place reste occupée : l'ordre de service est ce qu'on observe
			}
		}()
	}
	enqueue("flood") // plus ancienne
	waitQueued(t, a, 1)
	enqueue("flood")
	waitQueued(t, a, 2)
	enqueue("legit") // la plus récente, mais son sujet n'a rien en vol
	waitQueued(t, a, 3)
	r1() // une place : doit aller à « legit », pas à la plus ancienne « flood »
	if first := <-order; first != "legit" {
		t.Fatalf("premier servi : %q, attendu legit (le sujet qui n'a rien en vol)", first)
	}
	r2()
	if second := <-order; second != "flood" {
		t.Fatalf("deuxième servi : %q", second)
	}
}

// Une demande en attente dont le budget s'épuise n'est PAS envoyée à OPA, et la file se vide proprement.
func TestAdmissionQueuedRequestExpiresWithoutLeak(t *testing.T) {
	clk := newFakeClock()
	a := newAdmission(AdmissionOptions{MaxInflight: 1, MaxQueue: 4}, clk.now)
	r, _ := a.acquire(context.Background(), "a", far(clk))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	res := make(chan string, 1)
	go func() {
		rr, shed := a.acquire(ctx, "b", clk.now().Add(20*time.Millisecond))
		if rr != nil {
			rr()
			res <- "servie"
			return
		}
		res <- shed
	}()
	if got := <-res; got != shedExpired {
		t.Fatalf("budget épuisé en file : %q", got)
	}
	st := a.snapshot()
	if st.Queued != 0 || st.ShedExpired != 1 || st.Inflight != 1 {
		t.Fatalf("fuite d'état : %+v", st)
	}
	r()
	if st := a.snapshot(); st.Inflight != 0 {
		t.Fatalf("%+v", st)
	}
}

// À la libération, une demande dont il reste moins de MinService est écartée au lieu d'être envoyée à OPA.
func TestAdmissionSkipsRequestsWithNoBudgetLeft(t *testing.T) {
	clk := newFakeClock()
	a := newAdmission(AdmissionOptions{MaxInflight: 1, MaxQueue: 4, MinService: time.Millisecond}, clk.now)
	r, _ := a.acquire(context.Background(), "a", far(clk))
	res := make(chan string, 1)
	go func() {
		rr, shed := a.acquire(context.Background(), "b", clk.now().Add(2*time.Millisecond))
		if rr != nil {
			rr()
			res <- "servie"
			return
		}
		res <- shed
	}()
	waitQueued(t, a, 1)
	clk.advance(1500 * time.Microsecond) // il reste 0,5 ms < MinService
	r()
	if got := <-res; got != shedExpired {
		t.Fatalf("demande sans budget : %q, attendu écartée", got)
	}
	if st := a.snapshot(); st.Inflight != 0 || st.Queued != 0 || st.Admitted != 1 {
		t.Fatalf("la demande écartée n'a pas à être comptée admise : %+v", st)
	}
}

func TestAdmissionStressIsRaceFree(t *testing.T) {
	a := newAdmission(AdmissionOptions{MaxInflight: 3, MaxQueue: 8, SubjectShare: 50}, time.Now)
	var wg sync.WaitGroup
	var maxSeen atomic.Int64
	var cur atomic.Int64
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
				r, _ := a.acquire(ctx, []string{"x", "y", "z"}[g%3], time.Now().Add(3*time.Millisecond))
				if r != nil {
					n := cur.Add(1)
					for {
						m := maxSeen.Load()
						if n <= m || maxSeen.CompareAndSwap(m, n) {
							break
						}
					}
					time.Sleep(50 * time.Microsecond)
					cur.Add(-1)
					r()
				}
				cancel()
			}
		}(g)
	}
	wg.Wait()
	if maxSeen.Load() > 3 {
		t.Fatalf("plus de MaxInflight (3) simultanés : %d", maxSeen.Load())
	}
	if st := a.snapshot(); st.Inflight != 0 || st.Queued != 0 {
		t.Fatalf("fuite d'état après le stress : %+v", st)
	}
	a.mu.Lock()
	leak := len(a.perSubject) + len(a.running)
	a.mu.Unlock()
	if leak != 0 {
		t.Fatalf("compteurs par sujet non remis à zéro : %d", leak)
	}
}
