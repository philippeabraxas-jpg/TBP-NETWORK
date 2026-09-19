package pep

import (
	"errors"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures T12
// ---------------------------------------------------------------------------

type cutCall struct {
	jti    [16]byte
	reason string
}

type cutRecorder struct {
	mu    sync.Mutex
	calls []cutCall
}

func (r *cutRecorder) cut(jti [16]byte, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, cutCall{jti: jti, reason: reason})
}

func (r *cutRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func (r *cutRecorder) last() cutCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		return cutCall{}
	}
	return r.calls[len(r.calls)-1]
}

// newTestLedger construit un registre de compteurs à horloge contrôlable.
func newTestLedger(t *testing.T, maxPassports int, sink *stubSink, rec *tripRecorder, cuts *cutRecorder) (*QuotaLedger, *atomic.Int64) {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(1_800_000_000)
	opts := QuotaLedgerOptions{
		MaxPassports: maxPassports,
		CellID:       opaTestCellID,
		Salt:         testSalt,
		Leaves:       sink,
		Now:          func() time.Time { return time.Unix(clock.Load(), 0) },
	}
	if rec != nil {
		opts.OnTrip = rec.trip
	}
	if cuts != nil {
		opts.OnCut = cuts.cut
	}
	l, err := NewQuotaLedger(opts)
	if err != nil {
		t.Fatalf("NewQuotaLedger: %v", err)
	}
	return l, clock
}

// passportToken forge un jeton-passeport (vecteur quota §4.1-bis).
func passportToken(jti [16]byte, exp int64, volumeMax, windowS uint64) *Token {
	return &Token{
		JTI: jti,
		Exp: exp,
		Quota: &Quota{
			Resource:  "storage.artifacts",
			Operation: "append",
			VolumeMax: volumeMax,
			WindowS:   windowS,
		},
	}
}

func openPassport(t *testing.T, l *QuotaLedger, jti [16]byte, exp int64, volumeMax, windowS uint64) *PassportCounter {
	t.Helper()
	c, err := l.Open(passportToken(jti, exp, volumeMax, windowS))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return c
}

// ---------------------------------------------------------------------------
// Nominal : décrément, puis dépassement → coupure nette + refus + feuille.
// ---------------------------------------------------------------------------

func TestQuotaConsumeNominal(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	cuts := &cutRecorder{}
	l, clock := newTestLedger(t, 16, sink, rec, cuts)

	jti := jtiOf(0x01)
	c := openPassport(t, l, jti, clock.Load()+120, 1024, 60)

	if err := c.Consume(512); err != nil {
		t.Fatalf("Consume(512): %v", err)
	}
	if c.Remaining() != 512 {
		t.Fatalf("Remaining=%d, veut 512", c.Remaining())
	}
	if err := c.Consume(512); err != nil {
		t.Fatalf("Consume(512) bis: %v", err)
	}
	if c.Remaining() != 0 {
		t.Fatalf("Remaining=%d, veut 0", c.Remaining())
	}

	// Dépassement : coupure nette, refus explicite, feuille au jti.
	if err := c.Consume(1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err=%v, veut ErrQuotaExceeded", err)
	}
	if !c.Closed() {
		t.Fatal("compteur non fermé après dépassement (fuite partielle)")
	}
	if cuts.count() != 1 || cuts.last() != (cutCall{jti: jti, reason: ReasonQuotaExceeded}) {
		t.Fatalf("coupures=%+v, veut 1 × %s sur le jti", cuts.calls, ReasonQuotaExceeded)
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
	want := registry.HashPayload(testSalt, decisionLeafRecord(jti, false, ReasonQuotaExceeded))
	if got := sink.leaves[0].PayloadHash; got != want {
		t.Fatalf("feuille hash=%x, veut %x (verdict deny, raison %s)", got, want, ReasonQuotaExceeded)
	}
	if !l.Exhausted(jti) {
		t.Fatal("Exhausted=false après dépassement (couture T9)")
	}

	// Après coupure : plus aucune fuite, même petite.
	if err := c.Consume(1); !errors.Is(err, ErrPassportClosed) {
		t.Fatalf("err=%v, veut ErrPassportClosed (coupure nette)", err)
	}
	if c.Remaining() != 0 {
		t.Fatalf("Remaining=%d après coupure, veut 0 (pas de décrément fantôme)", c.Remaining())
	}
}

// ---------------------------------------------------------------------------
// Pas de fuite partielle : un quantum qui dépasse n'est PAS consommé.
// ---------------------------------------------------------------------------

func TestQuotaExceededNoPartialLeak(t *testing.T) {
	sink := &stubSink{}
	cuts := &cutRecorder{}
	l, clock := newTestLedger(t, 16, sink, nil, cuts)

	c := openPassport(t, l, jtiOf(0x02), clock.Load()+120, 100, 60)
	if err := c.Consume(60); err != nil {
		t.Fatalf("Consume(60): %v", err)
	}
	if err := c.Consume(41); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err=%v, veut ErrQuotaExceeded", err)
	}
	if c.Remaining() != 40 {
		t.Fatalf("Remaining=%d, veut 40 (le quantum refusé n'a pas été prélevé)", c.Remaining())
	}
}

// ---------------------------------------------------------------------------
// Passeport expiré : coupure SANS décrémenter, feuille passport-expired.
// ---------------------------------------------------------------------------

func TestQuotaExpiredNoDecrement(t *testing.T) {
	sink := &stubSink{}
	cuts := &cutRecorder{}
	l, clock := newTestLedger(t, 16, sink, nil, cuts)

	jti := jtiOf(0x03)
	c := openPassport(t, l, jti, clock.Load()+5, 1024, 60)

	clock.Add(6) // TTL du passeport écoulé
	if err := c.Consume(1); !errors.Is(err, ErrPassportExpired) {
		t.Fatalf("err=%v, veut ErrPassportExpired", err)
	}
	if c.Remaining() != 1024 {
		t.Fatalf("Remaining=%d, veut 1024 (un expiré ne décrémente pas)", c.Remaining())
	}
	if cuts.count() != 1 || cuts.last() != (cutCall{jti: jti, reason: ReasonPassportExpired}) {
		t.Fatalf("coupures=%+v, veut 1 × %s", cuts.calls, ReasonPassportExpired)
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
	want := registry.HashPayload(testSalt, decisionLeafRecord(jti, false, ReasonPassportExpired))
	if got := sink.leaves[0].PayloadHash; got != want {
		t.Fatalf("feuille hash=%x, veut %x (raison %s)", got, want, ReasonPassportExpired)
	}
}

// ---------------------------------------------------------------------------
// Fenêtre : le volume se recharge à chaque window_s (quota = débit, pas
// capital) — mais le TTL du passeport reste l'échéance absolue.
// ---------------------------------------------------------------------------

func TestQuotaWindowReset(t *testing.T) {
	sink := &stubSink{}
	l, clock := newTestLedger(t, 16, sink, nil, nil)

	c := openPassport(t, l, jtiOf(0x04), clock.Load()+120, 100, 10)
	if err := c.Consume(60); err != nil {
		t.Fatalf("Consume(60): %v", err)
	}
	if c.Remaining() != 40 {
		t.Fatalf("Remaining=%d, veut 40", c.Remaining())
	}

	clock.Add(10) // frontière exacte de fenêtre : rechargement
	if err := c.Consume(60); err != nil {
		t.Fatalf("Consume(60) après fenêtre: %v (le volume doit se recharger)", err)
	}
	if c.Remaining() != 40 {
		t.Fatalf("Remaining=%d après rechargement, veut 40", c.Remaining())
	}
	if sink.count() != 0 {
		t.Fatalf("feuilles=%d, veut 0 (aucune coupure)", sink.count())
	}
}

// TestQuotaWindowSExtremeValueStillCaps : window_s est un uint64 SANS borne
// supérieure côté schéma (schema.cddl : `.gt 0` seulement, aucun maximum).
// Une valeur ≥ 2^63 ne doit PAS faire basculer la fenêtre en négatif et
// rouvrir le volume à chaque Consume — le plafond volume_max doit tenir
// quelle que soit l'ampleur de window_s.
func TestQuotaWindowSExtremeValueStillCaps(t *testing.T) {
	sink := &stubSink{}
	cuts := &cutRecorder{}
	l, clock := newTestLedger(t, 16, sink, nil, cuts)

	const hugeWindowS = math.MaxUint64 // > 2^63 : bascule négative si castée en int64 sans précaution
	jti := jtiOf(0x0A)
	c := openPassport(t, l, jti, clock.Load()+3600, 100, hugeWindowS)

	if err := c.Consume(100); err != nil {
		t.Fatalf("Consume(100): %v", err)
	}
	if err := c.Consume(1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err=%v, veut ErrQuotaExceeded (le plafond doit tenir même avec window_s énorme)", err)
	}
	if !c.Closed() {
		t.Fatal("compteur non fermé — le plafond a été contourné par la fenêtre")
	}
}

// ---------------------------------------------------------------------------
// Mémoire bornée (§4.3, pattern T10) : saturation = refus + alarme latchée,
// jamais d'éviction ; la purge TTL libère.
// ---------------------------------------------------------------------------

func TestQuotaLedgerBounded(t *testing.T) {
	sink := &stubSink{}
	rec := &tripRecorder{}
	const maxPassports = 64
	l, clock := newTestLedger(t, maxPassports, sink, rec, nil)

	exp := clock.Load() + 120
	for i := 0; i < maxPassports; i++ {
		openPassport(t, l, jtiNum(i), exp, 1024, 60)
	}
	if l.Len() != maxPassports {
		t.Fatalf("Len=%d, veut %d", l.Len(), maxPassports)
	}

	// Saturation : refus + alarme unique (latch local, comme T10).
	if _, err := l.Open(passportToken(jtiNum(maxPassports), exp, 1024, 60)); !errors.Is(err, ErrLedgerSaturated) {
		t.Fatalf("err=%v, veut ErrLedgerSaturated", err)
	}
	if _, err := l.Open(passportToken(jtiNum(maxPassports+1), exp, 1024, 60)); !errors.Is(err, ErrLedgerSaturated) {
		t.Fatalf("err=%v, veut ErrLedgerSaturated (2e)", err)
	}
	if rec.count() != 1 || lastReason(rec) != TripReasonQuotaSaturated {
		t.Fatalf("alarmes=%v, veut 1 × %s", rec.reasons, TripReasonQuotaSaturated)
	}

	// TTL écoulé : la purge libère, le registre se rouvre.
	clock.Add(121)
	openPassport(t, l, jtiNum(9000), clock.Load()+120, 1024, 60)
}

// ---------------------------------------------------------------------------
// Ouvertures invalides — fail-closed dès l'entrée.
// ---------------------------------------------------------------------------

func TestQuotaLedgerDuplicateJTI(t *testing.T) {
	sink := &stubSink{}
	l, clock := newTestLedger(t, 16, sink, nil, nil)

	jti := jtiOf(0x05)
	openPassport(t, l, jti, clock.Load()+120, 1024, 60)
	if _, err := l.Open(passportToken(jti, clock.Load()+120, 1024, 60)); !errors.Is(err, ErrPassportDuplicate) {
		t.Fatalf("err=%v, veut ErrPassportDuplicate (jti unique §4.1)", err)
	}
}

func TestQuotaOpenFailClosed(t *testing.T) {
	sink := &stubSink{}
	l, clock := newTestLedger(t, 16, sink, nil, nil)

	if _, err := l.Open(nil); err == nil {
		t.Fatal("jeton nil accepté")
	}
	if _, err := l.Open(&Token{JTI: jtiOf(0x06), Exp: clock.Load() + 120}); err == nil {
		t.Fatal("passeport sans vecteur quota accepté (§4.1-bis : quota-unverified)")
	}
	bad := passportToken(jtiOf(0x07), clock.Load()+120, 1024, 0) // window_s = 0
	if _, err := l.Open(bad); err == nil {
		t.Fatal("vecteur quota avec window_s=0 accepté")
	}
}

func TestNewQuotaLedgerFailClosed(t *testing.T) {
	base := QuotaLedgerOptions{
		MaxPassports: 16,
		CellID:       opaTestCellID,
		Salt:         testSalt,
		Leaves:       &stubSink{},
	}
	if _, err := NewQuotaLedger(base); err != nil {
		t.Fatalf("config nominale refusée: %v", err)
	}

	bad := base
	bad.MaxPassports = 0
	if _, err := NewQuotaLedger(bad); err == nil {
		t.Fatal("capacité 0 acceptée (§4.3 : borné en mémoire)")
	}
	bad = base
	bad.MaxPassports = -8
	if _, err := NewQuotaLedger(bad); err == nil {
		t.Fatal("capacité négative acceptée")
	}
	bad = base
	bad.CellID = ""
	if _, err := NewQuotaLedger(bad); err == nil {
		t.Fatal("CellID vide accepté")
	}
	bad = base
	bad.Salt = []byte("court")
	if _, err := NewQuotaLedger(bad); err == nil {
		t.Fatal("sel < 16 o accepté (§6.2)")
	}
	bad = base
	bad.Leaves = nil
	if _, err := NewQuotaLedger(bad); err == nil {
		t.Fatal("Leaves nil accepté (§4.1)")
	}
}

// ---------------------------------------------------------------------------
// Scénario §8 « passeport épuisé » — soudure T9↔T12 : le validateur (T9)
// admet le passeport, le compteur (T12) l'épuise à l'exécution, et la
// décision suivante est refusée quota-exhausted AVANT le contrôle anti-rejeu.
// ---------------------------------------------------------------------------

func TestValidatorExhaustedPassport(t *testing.T) {
	sink := &stubSink{}
	cuts := &cutRecorder{}
	ledger, clock := newTestLedger(t, 16, sink, nil, cuts)
	clock.Store(testIAT + 30) // horloge du ledger dans la fenêtre du jeton T9
	ar, err := NewAntiReplay(AntiReplayOptions{
		Capacity: 16,
		Now:      func() time.Time { return time.Unix(clock.Load(), 0) },
	})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	v := newValidator(t, sink, ar, ledger) // QuotaChecker = le registre réel

	claims := nominalClaims()
	claims.quota = map[int]any{1: "storage.artifacts", 2: "append", 3: 1000, 4: 60}
	tok := mintToken(t, claims)

	// Admission : le passeport est frais, quota non épuisé → allow.
	d1 := v.Validate(t.Context(), tok, nominalRequest())
	if !d1.Allow {
		t.Fatalf("admission refusée: %s", d1.Reason)
	}
	if d1.Token.Quota == nil || d1.Token.Quota.VolumeMax != 1000 {
		t.Fatalf("vecteur quota perdu: %+v", d1.Token.Quota)
	}

	// Exécution data-plane : le terminator consomme tout le volume.
	counter, err := ledger.Open(d1.Token)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := counter.Consume(1000); err != nil {
		t.Fatalf("Consume(1000): %v", err)
	}
	if err := counter.Consume(1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("err=%v, veut ErrQuotaExceeded", err)
	}

	// Décision suivante sur ce passeport : deny quota-exhausted — vérifié
	// AVANT l'anti-rejeu (sinon la raison serait « replay »).
	d2 := v.Validate(t.Context(), tok, nominalRequest())
	if d2.Allow || d2.Reason != ReasonQuotaExhausted {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", d2.Allow, d2.Reason, ReasonQuotaExhausted)
	}
	if cuts.count() != 1 || cuts.last().reason != ReasonQuotaExceeded {
		t.Fatalf("coupures=%+v, veut 1 × %s", cuts.calls, ReasonQuotaExceeded)
	}
	// 3 feuilles : allow T9, coupure T12, deny quota-exhausted T9.
	if sink.count() != 3 {
		t.Fatalf("feuilles=%d, veut 3 (allow, coupure, deny)", sink.count())
	}
}

// ---------------------------------------------------------------------------
// Concurrence (-race) : décrément atomique — jamais de sur-consommation.
// ---------------------------------------------------------------------------

func TestQuotaConcurrent(t *testing.T) {
	sink := &stubSink{}
	l, clock := newTestLedger(t, 16, sink, nil, nil)

	const volume = 4096
	c := openPassport(t, l, jtiOf(0x08), clock.Load()+120, volume, 3600)

	var ok, exceeded, closed atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 128; i++ {
				switch err := c.Consume(1); {
				case err == nil:
					ok.Add(1)
				case errors.Is(err, ErrQuotaExceeded):
					exceeded.Add(1)
				case errors.Is(err, ErrPassportClosed):
					closed.Add(1)
				default:
					t.Errorf("erreur inattendue: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	if ok.Load() != volume {
		t.Fatalf("consommés=%d, veut exactement %d (jamais de sur-consommation)", ok.Load(), volume)
	}
	if exceeded.Load() != 1 {
		t.Fatalf("ErrQuotaExceeded=%d, veut exactement 1 (la coupure est unique)", exceeded.Load())
	}
	if closed.Load() != 64*128-volume-1 {
		t.Fatalf("closed=%d, veut %d", closed.Load(), 64*128-volume-1)
	}
	if c.Remaining() != 0 {
		t.Fatalf("Remaining=%d, veut 0", c.Remaining())
	}
}

// ---------------------------------------------------------------------------
// Empreinte mémoire plafonnée : l'état total est borné par MaxPassports,
// l'inondation d'ouvertures refusées ne fait pas gonfler le tas.
// ---------------------------------------------------------------------------

func TestQuotaMemoryBounded(t *testing.T) {
	sink := &stubSink{}
	const maxPassports = 4096
	l, clock := newTestLedger(t, maxPassports, sink, nil, nil)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	exp := clock.Load() + 3600
	for i := 0; i < 4*maxPassports; i++ {
		_, _ = l.Open(passportToken(jtiNum(i), exp, 1024, 60))
	}
	if l.Len() != maxPassports {
		t.Fatalf("Len=%d, veut plafond %d", l.Len(), maxPassports)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	growth := max(int64(after.HeapInuse)-int64(before.HeapInuse), 0)
	// Plafond : 4096 compteurs × ~200 o ≈ 800 Kio, marge ×5 pour l'allocateur.
	const ceiling = 5 * 4096 * 200
	if growth > ceiling {
		t.Fatalf("croissance tas = %d o > plafond %d o", growth, ceiling)
	}
	t.Logf("croissance tas mesurée pour %d ouvertures (plafond %d) : %d o", 4*maxPassports, maxPassports, growth)
}

// ---------------------------------------------------------------------------
// Chemin chaud : Consume reste O(1) — budget data-plane.
// ---------------------------------------------------------------------------

func BenchmarkQuotaConsume(b *testing.B) {
	l, err := NewQuotaLedger(QuotaLedgerOptions{
		MaxPassports: 16,
		CellID:       opaTestCellID,
		Salt:         testSalt,
		Leaves:       &stubSink{},
	})
	if err != nil {
		b.Fatalf("NewQuotaLedger: %v", err)
	}
	c, err := l.Open(passportToken(jtiOf(0x09), time.Now().Add(time.Hour).Unix(), math.MaxUint64, math.MaxUint32))
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := c.Consume(1); err != nil {
			b.Fatalf("Consume: %v", err)
		}
	}
}
