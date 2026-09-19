package pep

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixtures T10
// ---------------------------------------------------------------------------

func jtiOf(b byte) [16]byte {
	var j [16]byte
	for i := range j {
		j[i] = b
	}
	return j
}

func jtiNum(i int) [16]byte {
	var j [16]byte
	for k := 0; k < 8; k++ {
		j[15-k] = byte(uint(i) >> (8 * k))
	}
	return j
}

type tripRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (r *tripRecorder) trip(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
}

func (r *tripRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reasons)
}

// newTestCache construit un cache à horloge contrôlable.
func newTestCache(t *testing.T, capacity int, rec *tripRecorder) (*AntiReplay, *atomic.Int64) {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(1_800_000_000)
	opts := AntiReplayOptions{
		Capacity: capacity,
		Now:      func() time.Time { return time.Unix(clock.Load(), 0) },
	}
	if rec != nil {
		opts.OnTrip = rec.trip
	}
	c, err := NewAntiReplay(opts)
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	return c, clock
}

func expIn(clock *atomic.Int64, secs int64) time.Time {
	return time.Unix(clock.Load()+secs, 0)
}

// ---------------------------------------------------------------------------
// Nominal
// ---------------------------------------------------------------------------

func TestAntiReplayNominal(t *testing.T) {
	c, clock := newTestCache(t, 8, nil)

	if !c.CheckAndConsume(jtiOf(0xAA), expIn(clock, 60)) {
		t.Fatal("premier jti refusé")
	}
	if c.CheckAndConsume(jtiOf(0xAA), expIn(clock, 60)) {
		t.Fatal("replay accepté")
	}
	if !c.CheckAndConsume(jtiOf(0xBB), expIn(clock, 60)) {
		t.Fatal("jti distinct refusé")
	}
	if c.CheckAndConsume(jtiOf(0xAA), expIn(clock, 60)) {
		t.Fatal("replay ancien accepté après insertion d'un autre jti")
	}
	if c.Len() != 2 {
		t.Fatalf("Len=%d, veut 2", c.Len())
	}
	if c.Tripped() {
		t.Fatal("trip sans saturation")
	}
}

// ---------------------------------------------------------------------------
// Inondation (critère d'acceptation) : aucun jti non expiré n'est évincé ;
// saturation ⇒ refus + alarme, jamais d'éviction silencieuse.
// ---------------------------------------------------------------------------

func TestAntiReplayFloodNoEviction(t *testing.T) {
	const capacity = 512
	rec := &tripRecorder{}
	c, clock := newTestCache(t, capacity, rec)

	// Remplissage à capacité : jetons distincts, individuellement valides.
	for i := 0; i < capacity; i++ {
		if !c.CheckAndConsume(jtiNum(i), expIn(clock, 60)) {
			t.Fatalf("jti %d refusé avant saturation", i)
		}
	}
	if c.Len() != capacity {
		t.Fatalf("Len=%d, veut %d", c.Len(), capacity)
	}

	// Saturation : refus + alarme, pas d'éviction.
	if c.CheckAndConsume(jtiNum(capacity), expIn(clock, 60)) {
		t.Fatal("jeton accepté au-delà de la capacité")
	}
	if !c.Tripped() {
		t.Fatal("saturation sans trip (couture T14)")
	}
	if rec.count() != 1 {
		t.Fatalf("alarmes=%d, veut 1", rec.count())
	}

	// Pression prolongée : 10 000 jti distincts de plus — tous refusés…
	for i := capacity; i < capacity+10000; i++ {
		if c.CheckAndConsume(jtiNum(i), expIn(clock, 60)) {
			t.Fatalf("jti %d accepté sous pression", i)
		}
	}
	// …et AUCUN des 512 jti non expirés n'a été évincé (re-check = replay).
	for i := 0; i < capacity; i++ {
		if c.CheckAndConsume(jtiNum(i), expIn(clock, 60)) {
			t.Fatalf("jti %d évincé sous pression — garantie anti-replay cassée", i)
		}
	}
	if c.Len() != capacity {
		t.Fatalf("Len=%d après inondation, veut %d", c.Len(), capacity)
	}
}

// ---------------------------------------------------------------------------
// Purge TTL : les slots expirés se libèrent, la saturation se résout.
// ---------------------------------------------------------------------------

func TestAntiReplayTTLPurge(t *testing.T) {
	const capacity = 64
	rec := &tripRecorder{}
	c, clock := newTestCache(t, capacity, rec)

	for i := 0; i < capacity; i++ {
		if !c.CheckAndConsume(jtiNum(i), expIn(clock, 5)) {
			t.Fatalf("jti %d refusé", i)
		}
	}
	// Saturation tant que rien n'a expiré.
	if c.CheckAndConsume(jtiNum(capacity), expIn(clock, 5)) {
		t.Fatal("accepté à saturation")
	}

	// L'horloge NTS avance au-delà du TTL : les slots se libèrent.
	clock.Add(6)
	for i := 0; i < capacity; i++ {
		if !c.CheckAndConsume(jtiNum(1000+i), expIn(clock, 60)) {
			t.Fatalf("jti %d refusé après purge TTL", 1000+i)
		}
	}
	// Un seul trip (la saturation transitoire), collant et non répété.
	if rec.count() != 1 {
		t.Fatalf("alarmes=%d, veut 1", rec.count())
	}
}

// TestAntiReplayExpBoundaryNoReplay : la frontière de purge doit être
// stricte (exp < now), pas inclusive (exp <= now) — le validateur (T9,
// validator.go) traite un jeton comme encore frais tant que now ≤ exp
// (« iat ≤ now ≤ exp », borne haute incluse). Si la purge évinçait dès
// exp == now, la première consommation d'un jeton purgerait sa PROPRE
// entrée avant même le contrôle d'appartenance suivant, et une seconde
// requête sur le même jeton dans la même seconde serait acceptée comme
// neuve — une fenêtre de rejeu à la dernière seconde de validité de
// CHAQUE jeton.
func TestAntiReplayExpBoundaryNoReplay(t *testing.T) {
	c, clock := newTestCache(t, 8, nil)

	jti := jtiOf(0xAB)
	exp := expIn(clock, 0) // exp == now dès la première consommation

	if !c.CheckAndConsume(jti, exp) {
		t.Fatal("première consommation refusée")
	}
	// Même jti, même instant (now == exp, encore valide côté T9) : doit
	// être un rejeu, pas un jeton « neuf ».
	if c.CheckAndConsume(jti, exp) {
		t.Fatal("rejeu accepté à la frontière now == exp (purge trop précoce)")
	}
	// Une fois l'horloge strictement au-delà de exp, l'entrée se libère
	// normalement (purge de tête toujours bornée en coût).
	clock.Add(1)
	if !c.CheckAndConsume(jtiOf(0xCD), expIn(clock, 5)) {
		t.Fatal("slot non libéré une fois now strictement > exp")
	}
}

// ---------------------------------------------------------------------------
// Chemin froid : la purge de tête est bornée, mais à saturation un scan
// complet libère les expirés même au milieu du ring (pas de faux trip).
// ---------------------------------------------------------------------------

func TestAntiReplayColdScanAtSaturation(t *testing.T) {
	const capacity = 8
	rec := &tripRecorder{}
	c, clock := newTestCache(t, capacity, rec)

	// Tête longue (60 s) insérée d'abord, puis 7 entrées courtes (1 s).
	if !c.CheckAndConsume(jtiOf(0x01), expIn(clock, 60)) {
		t.Fatal("tête refusée")
	}
	for i := 0; i < capacity-1; i++ {
		if !c.CheckAndConsume(jtiNum(100+i), expIn(clock, 1)) {
			t.Fatalf("jti court %d refusé", i)
		}
	}

	// Les 7 entrées courtes expirent ; la tête (non expirée) bloque la purge
	// de tête. Le prochain insert déclenche le scan complet à saturation.
	clock.Add(2)
	if !c.CheckAndConsume(jtiOf(0x02), expIn(clock, 60)) {
		t.Fatal("scan complet à saturation n'a pas libéré les expirés du milieu")
	}
	if rec.count() != 0 {
		t.Fatalf("faux trip : %d alarme(s)", rec.count())
	}
	// La tête longue est toujours là.
	if c.CheckAndConsume(jtiOf(0x01), expIn(clock, 60)) {
		t.Fatal("tête longue évincée")
	}
}

// ---------------------------------------------------------------------------
// Empreinte mémoire plafonnée : structure allouée au démarrage, jamais de
// croissance — l'inondation ne fait pas gonfler le tas au-delà du plafond.
// ---------------------------------------------------------------------------

func TestAntiReplayMemoryBounded(t *testing.T) {
	const capacity = 4096
	c, clock := newTestCache(t, capacity, nil)

	if c.Capacity() != capacity {
		t.Fatalf("Capacity=%d", c.Capacity())
	}
	if c.Len() != 0 {
		t.Fatalf("Len=%d sur cache neuf", c.Len())
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Inondation : 4× la capacité en jti distincts.
	for i := 0; i < 4*capacity; i++ {
		c.CheckAndConsume(jtiNum(i), expIn(clock, 60))
	}
	if c.Len() != capacity {
		t.Fatalf("Len=%d, veut plafond %d", c.Len(), capacity)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	// Diff signée : le GC peut avoir libéré entre les deux mesures.
	growth := max(int64(after.HeapInuse)-int64(before.HeapInuse), 0)
	// Plafond théorique : ring 4096×25 o + set 4096×~50 o ≈ 310 Kio.
	// Marge ×4 pour l'allocateur — l'essentiel est l'absence de croissance
	// liée aux 12 288 jti refusés.
	const ceiling = 4 * 4096 * 80
	if growth > ceiling {
		t.Fatalf("croissance tas = %d o > plafond %d o", growth, ceiling)
	}
	t.Logf("croissance tas mesurée pour %d jti (capacité %d) : %d o", 4*capacity, capacity, growth)
}

// ---------------------------------------------------------------------------
// Atomicité (-race) : CheckAndConsume est atomique même sous concurrence.
// ---------------------------------------------------------------------------

func TestAntiReplayAtomicConcurrent(t *testing.T) {
	c, clock := newTestCache(t, 1024, nil)

	// 64 goroutines, le MÊME jti : exactement une consomme.
	var won atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.CheckAndConsume(jtiOf(0x77), expIn(clock, 60)) {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("gagnants=%d, veut exactement 1 (atomicité)", won.Load())
	}

	// 8 goroutines × 64 jti distincts : tout passe, pas de doublon fantôme.
	var accepted atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 64; i++ {
				if c.CheckAndConsume(jtiNum(10000+g*64+i), expIn(clock, 60)) {
					accepted.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if accepted.Load() != 512 {
		t.Fatalf("acceptés=%d, veut 512", accepted.Load())
	}
	if c.Len() != 512+1 {
		t.Fatalf("Len=%d, veut 513", c.Len())
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration
// ---------------------------------------------------------------------------

func TestNewAntiReplayFailClosed(t *testing.T) {
	if _, err := NewAntiReplay(AntiReplayOptions{Capacity: 0}); err == nil {
		t.Fatal("capacité 0 acceptée")
	}
	if _, err := NewAntiReplay(AntiReplayOptions{Capacity: -10}); err == nil {
		t.Fatal("capacité négative acceptée")
	}
}

// ---------------------------------------------------------------------------
// Soudure T9↔T10 : le cache réel derrière le validateur.
// ---------------------------------------------------------------------------

func TestValidatorWithRealAntiReplay(t *testing.T) {
	rec := &tripRecorder{}
	// Horloge du cache cohérente avec la fenêtre du jeton T9 (iat+30 < exp).
	cache, clock := newTestCache(t, 16, rec)
	clock.Store(testIAT + 30)
	sink := &stubSink{}
	v := newValidator(t, sink, cache, nil)
	tok := mintToken(t, nominalClaims())

	d1 := v.Validate(t.Context(), tok, nominalRequest())
	if !d1.Allow {
		t.Fatalf("premier usage refusé: %s", d1.Reason)
	}
	d2 := v.Validate(t.Context(), tok, nominalRequest())
	if d2.Allow || d2.Reason != ReasonReplay {
		t.Fatalf("rejeu: allow=%v reason=%q, veut deny/replay", d2.Allow, d2.Reason)
	}
	if cache.Len() != 1 {
		t.Fatalf("cache Len=%d, veut 1 (le deny n'a pas re-consommé)", cache.Len())
	}
	if sink.count() != 2 {
		t.Fatalf("feuilles=%d, veut 2", sink.count())
	}
}

func BenchmarkAntiReplay(b *testing.B) {
	c, _ := NewAntiReplay(AntiReplayOptions{Capacity: 1 << 16})
	exp := time.Now().Add(60 * time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.CheckAndConsume(jtiNum(i), exp)
	}
}

func ExampleAntiReplay() {
	c, _ := NewAntiReplay(AntiReplayOptions{Capacity: 1024})
	jti := jtiOf(0x42)
	fmt.Println(c.CheckAndConsume(jti, time.Now().Add(time.Minute)))
	fmt.Println(c.CheckAndConsume(jti, time.Now().Add(time.Minute)))
	// Output:
	// true
	// false
}
