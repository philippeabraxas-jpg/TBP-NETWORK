// src/registry/backpressure_test.go — T5 (issue #5)
//
// Tests du backpressure disque : dimensionnement du quota, échantillonnage,
// engagement à 80 % avec arrêt tracé (dernière feuille KindBackpressure) et
// alarmé (classe W, §5.3), garde hôte statfs, reprise après remédiation.
// Intégration réelle sur Tessera POSIX — aucun mock du log.
package registry

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// ---------------------------------------------------------------------------
// Dimensionnement du quota (critère d'acceptation : taux mesuré, pas estimé)
// ---------------------------------------------------------------------------

func TestSizeQuotaBytes(t *testing.T) {
	// 10 feuilles/s × 120 s (fencing §6.2) × marge 3 × 512 octets.
	got := SizeQuotaBytes(10, 120*time.Second, 3.0)
	want := uint64(10 * 120 * 3 * leafStorageBytes)
	if got != want {
		t.Fatalf("SizeQuotaBytes = %d, attendu %d", got, want)
	}
	// Marge par défaut quand 0.
	if SizeQuotaBytes(10, 120*time.Second, 0) != want {
		t.Fatal("safetyMultiple=0 n'utilise pas la marge par défaut")
	}
	// Entrées invalides → 0 (le quota invalide doit être rejeté par NewMonitor).
	if SizeQuotaBytes(0, time.Minute, 1) != 0 {
		t.Fatal("taux nul accepté")
	}
	if SizeQuotaBytes(1, 0, 1) != 0 {
		t.Fatal("horizon nul accepté")
	}
	// Monotonie : plus de débit ou d'horizon ⇒ plus de quota.
	if SizeQuotaBytes(20, 120*time.Second, 3.0) <= got {
		t.Fatal("quota non monotone en débit")
	}
	if SizeQuotaBytes(10, 240*time.Second, 3.0) <= got {
		t.Fatal("quota non monotone en horizon")
	}
}

// ---------------------------------------------------------------------------
// Échantillonneurs
// ---------------------------------------------------------------------------

func TestDirSampler(t *testing.T) {
	dir := t.TempDir()
	// Layout arborescent façon tlog-tiles.
	sub := filepath.Join(dir, "tile", "0", "x000")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]int{
		filepath.Join(dir, "checkpoint"):           100,
		filepath.Join(sub, "000.p"):                250,
		filepath.Join(dir, "entries", "x000", "0"): 50,
	}
	var want uint64
	for name, size := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, make([]byte, size), 0o644); err != nil {
			t.Fatal(err)
		}
		want += uint64(size)
	}
	got, err := (DirSampler{}).UsedBytes(dir)
	if err != nil {
		t.Fatalf("UsedBytes: %v", err)
	}
	if got != want {
		t.Fatalf("UsedBytes = %d, attendu %d", got, want)
	}
	if _, err := (DirSampler{}).UsedBytes(filepath.Join(dir, "inexistant")); err == nil {
		t.Fatal("répertoire inexistant mesuré sans erreur")
	}
}

func TestStatfsStats(t *testing.T) {
	free, err := (StatfsStats{}).FreeBytes(t.TempDir())
	if err != nil {
		t.Fatalf("FreeBytes: %v", err)
	}
	if free == 0 {
		t.Fatal("statfs rapporte 0 octet libre sur un tmpfs vivant")
	}
	if _, err := (StatfsStats{}).FreeBytes("/chemin/inexistant/t5"); err == nil {
		t.Fatal("statfs sur chemin inexistant accepté")
	}
}

// ---------------------------------------------------------------------------
// Monitor — intégration réelle CellLog + Tessera POSIX
// ---------------------------------------------------------------------------

// fakeFs simule l'espace libre hôte.
type fakeFs struct{ free uint64 }

func (f fakeFs) FreeBytes(string) (uint64, error) { return f.free, nil }

// failingSampler simule une mesure impossible (fail-closed attendu).
type failingSampler struct{}

func (failingSampler) UsedBytes(string) (uint64, error) { return 0, errors.New("mesure impossible") }

// wireMonitor réalise le câblage documenté : le moniteur est créé AVANT
// Open (c'est lui le BackpressureChecker de la couture T4), puis lié au
// log pour tracer l'arrêt.
func wireMonitor(t *testing.T, ctx context.Context, dir string, opts MonitorOptions) (*CellLog, *Monitor) {
	t.Helper()
	opts.Dir = dir
	mon, err := NewMonitor(opts)
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	log, _ := openTestLog(t, ctx, dir, mon)
	if err := mon.Bind(log); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	return log, mon
}

// reopenTestLog rouvre un log existant avec la MÊME clé (comme en
// production, où cell_log.key est stable) — rouvrir avec une autre clé
// briserait la continuité de signature des checkpoints.
func reopenTestLog(t *testing.T, ctx context.Context, dir string, bp BackpressureChecker, signer note.Signer, verifier note.Verifier) *CellLog {
	t.Helper()
	log, err := Open(ctx, Options{
		Dir: dir, Signer: signer, Verifier: verifier, Backpressure: bp,
		BatchSize: 1, BatchAge: 10 * time.Millisecond, CheckpointInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Open (reopen): %v", err)
	}
	return log
}

// alarmBox capture l'alarme émise par la goroutine du moniteur sans race.
type alarmBox struct{ v atomic.Value }

func (b *alarmBox) store(a Alarm) { b.v.Store(a) }
func (b *alarmBox) load() Alarm {
	if v := b.v.Load(); v != nil {
		return v.(Alarm)
	}
	return Alarm{}
}

// readLeafAt relit la feuille d'index donné depuis le bundle Tessera
// (format tlog-tiles : préfixe uint16 big-endian par entrée) — vérifie ce
// qui est RÉELLEMENT dans le registre, pas ce que le moniteur prétend y
// avoir écrit.
func readLeafAt(t *testing.T, log *CellLog, size, idx uint64) Leaf {
	t.Helper()
	if size == 0 || idx >= size {
		t.Fatalf("readLeafAt(%d) avec taille %d", idx, size)
	}
	bundleIdx := idx / 256
	var p uint8
	if rem := size % 256; bundleIdx == size/256 && rem != 0 {
		p = uint8(rem)
	}
	raw, err := log.reader.ReadEntryBundle(context.Background(), bundleIdx, p)
	if err != nil {
		t.Fatalf("ReadEntryBundle: %v", err)
	}
	want := int(idx % 256)
	off := 0
	for i := 0; ; i++ {
		if off+2 > len(raw) {
			t.Fatalf("bundle tronqué avant l'entrée %d", want)
		}
		n := int(binary.BigEndian.Uint16(raw[off : off+2]))
		off += 2
		if off+n > len(raw) {
			t.Fatalf("entrée %d tronquée", i)
		}
		if i == want {
			leaf, err := UnmarshalLeaf(raw[off : off+n])
			if err != nil {
				t.Fatalf("UnmarshalLeaf entrée %d: %v", i, err)
			}
			return leaf
		}
		off += n
	}
}

// waitEngaged attend l'engagement du moniteur (le ticker est asynchrone).
func waitEngaged(t *testing.T, m *Monitor, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.Engaged() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("moniteur non engagé dans le délai imparti")
}

// waitAlarm attend l'émission de l'alarme — la barrière correcte quand le
// test vérifie ensuite le registre : l'alarme est émise APRÈS l'écriture
// (awaitée) de la feuille d'arrêt, alors que le verrou Engaged() tombe
// avant. Attendre l'alarme garantit que la feuille KindBackpressure est
// intégrée au log.
func waitAlarm(t *testing.T, box *alarmBox, timeout time.Duration) Alarm {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if a := box.load(); a.Reason != "" {
			return a
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("alarme non émise dans le délai imparti")
	return Alarm{}
}

// TestMonitorTripAtThreshold est le critère d'acceptation de l'issue #5 :
// remplissage simulé → arrêt propre à 80 % du quota, dernière feuille =
// KindBackpressure, alarme émise, aucune écriture ultérieure ne passe.
func TestMonitorTripAtThreshold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Calibrage : on initialise le log, on MESURE l'usage du répertoire,
	// puis on fixe le quota pour que 80 % tombe après ~4 feuilles —
	// le quota est dimensionné sur une mesure, pas une estimation (critère
	// d'acceptation).
	dir := t.TempDir()
	skey, vkey, err := GenerateCellKey(testOrigin)
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	initLog := reopenTestLog(t, ctx, dir, nil, signer, verifier)
	if err := initLog.Close(ctx); err != nil {
		t.Fatalf("Close init: %v", err)
	}
	used, err := (DirSampler{}).UsedBytes(dir)
	if err != nil {
		t.Fatalf("UsedBytes: %v", err)
	}
	quota := (used + 4*leafStorageBytes) * 10 / 8 // 80 % ≈ usage actuel + 4 feuilles

	var trips, alarms int32
	var box alarmBox
	mon, err := NewMonitor(MonitorOptions{
		Dir: dir, CellID: "cell-t5", QuotaBytes: quota,
		Interval: 5 * time.Millisecond,
		OnTrip:  func(Alarm) { atomic.AddInt32(&trips, 1) },
		OnAlarm: func(a Alarm) { atomic.AddInt32(&alarms, 1); box.store(a) },
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	log := reopenTestLog(t, ctx, dir, mon, signer, verifier)
	if err := mon.Bind(log); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer log.Close(ctx)
	go mon.Run(ctx)

	// Remplissage : chaque feuille rapproche du seuil, jusqu'au refus.
	var lastErr error
	var writes int
	for i := 0; i < 100; i++ {
		_, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-t5", PayloadHash: HashPayload([]byte("s"), []byte{byte(i)}), Timestamp: int64(i + 1)})
		if err != nil {
			lastErr = err
			break
		}
		writes++
	}
	if !errors.Is(lastErr, ErrBackpressure) {
		t.Fatalf("dernière écriture: err=%v, attendu ErrBackpressure après %d écritures", lastErr, writes)
	}

	gotAlarm := waitAlarm(t, &box, 10*time.Second)

	// Arrêt propre tracé : la DERNIÈRE feuille du registre est KindBackpressure.
	_, size, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	last := readLeafAt(t, log, size, size-1)
	if last.Kind != KindBackpressure {
		t.Fatalf("dernière feuille kind=%d, attendu KindBackpressure(%d)", last.Kind, KindBackpressure)
	}
	if last.CellID != "cell-t5" {
		t.Fatalf("feuille d'arrêt cellID=%q", last.CellID)
	}

	// Aucune écriture ultérieure ne passe.
	if _, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-t5", PayloadHash: HashPayload([]byte("s"), []byte("x")), Timestamp: 999}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("écriture post-engagement: err=%v, attendu ErrBackpressure", err)
	}
	_, size2, _ := log.Head(ctx)
	if size2 != size {
		t.Fatalf("taille %d → %d après refus", size, size2)
	}

	// Alarmé et trippé — une fois exactement (classe W, §5.3 : pas muet).
	if atomic.LoadInt32(&trips) != 1 {
		t.Fatalf("OnTrip appelé %d fois, attendu 1", trips)
	}
	if atomic.LoadInt32(&alarms) != 1 {
		t.Fatalf("OnAlarm appelé %d fois, attendu 1", alarms)
	}
	if gotAlarm.Reason != "registry-disk-80%" {
		t.Fatalf("alarme reason=%q", gotAlarm.Reason)
	}
	if gotAlarm.QuotaBytes != quota || gotAlarm.CellID != "cell-t5" {
		t.Fatalf("alarme incohérente: %+v", gotAlarm)
	}
}

// TestMonitorHostFloor : la garde hôte (statfs) engage le backpressure même
// sous quota — un autre locataire du filesystem peut remplir le disque.
func TestMonitorHostFloor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var box alarmBox
	log, mon := wireMonitor(t, ctx, t.TempDir(), MonitorOptions{
		CellID: "cell-t5",
		QuotaBytes:    1 << 40, // quota énorme : seul le plancher hôte peut tirer
		HostFloorBytes: 1 << 30,
		Fs:            fakeFs{free: 1 << 20}, // 1 Mio libre « mesuré » < plancher
		Interval:      5 * time.Millisecond,
		OnAlarm:       func(a Alarm) { box.store(a) },
	})
	defer log.Close(ctx)
	go mon.Run(ctx)

	if reason := waitAlarm(t, &box, 10*time.Second).Reason; reason != "registry-host-disk-low" {
		t.Fatalf("reason=%q, attendu registry-host-disk-low", reason)
	}
	if _, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-t5", Timestamp: 1}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("Append: err=%v, attendu ErrBackpressure", err)
	}
}

// TestMonitorSamplerError : une mesure impossible engage le backpressure —
// un moniteur aveugle n'est pas un feu vert (fail-closed).
func TestMonitorSamplerError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var box alarmBox
	log, mon := wireMonitor(t, ctx, t.TempDir(), MonitorOptions{
		CellID: "cell-t5",
		QuotaBytes: 1 << 40, Sampler: failingSampler{},
		Interval: 5 * time.Millisecond,
		OnAlarm:  func(a Alarm) { box.store(a) },
	})
	defer log.Close(ctx)
	go mon.Run(ctx)

	if reason := waitAlarm(t, &box, 10*time.Second).Reason; reason != "registry-sampler-error" {
		t.Fatalf("reason=%q, attendu registry-sampler-error", reason)
	}
}

// TestMonitorDisengage : après remédiation (quota agrandi), l'opérateur
// lève le backpressure et l'écriture reprend — décision humaine.
func TestMonitorDisengage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var box alarmBox
	log, mon := wireMonitor(t, ctx, t.TempDir(), MonitorOptions{
		CellID: "cell-t5",
		QuotaBytes: 1, // déjà dépassé → engagement au premier échantillon
		Interval:   5 * time.Millisecond,
		OnAlarm:    func(a Alarm) { box.store(a) },
	})
	defer log.Close(ctx)
	go mon.Run(ctx)

	waitAlarm(t, &box, 10*time.Second) // alarme ⇒ feuille d'arrêt intégrée
	if _, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-t5", Timestamp: 1}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("Append engagé: err=%v", err)
	}

	mon.Disengage()
	idx, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-t5", Timestamp: 2})
	if err != nil {
		t.Fatalf("Append après Disengage: %v", err)
	}
	if idx != 1 { // la feuille d'arrêt occupe l'index 0
		t.Fatalf("index %d après reprise, attendu 1", idx)
	}
}

// TestMonitorBelowThreshold : sous le seuil, le moniteur n'engage jamais.
func TestMonitorBelowThreshold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var alarms int32
	log, mon := wireMonitor(t, ctx, t.TempDir(), MonitorOptions{
		CellID: "cell-t5",
		QuotaBytes: 1 << 40, Interval: 5 * time.Millisecond,
		Fs:      fakeFs{free: 1 << 40},
		OnAlarm: func(Alarm) { atomic.AddInt32(&alarms, 1) },
	})
	defer log.Close(ctx)
	go mon.Run(ctx)

	for i := 0; i < 5; i++ {
		if _, err := log.Append(ctx, Leaf{Kind: KindTelemetry, CellID: "cell-t5", Timestamp: int64(i + 1)}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	time.Sleep(50 * time.Millisecond) // plusieurs ticks
	if mon.Engaged() {
		t.Fatal("engagé sous le seuil")
	}
	if atomic.LoadInt32(&alarms) != 0 {
		t.Fatal("alarme émise sous le seuil")
	}
}

// TestMonitorValidation : configuration invalide rejetée (fail-closed —
// pas de moniteur muet).
func TestMonitorValidation(t *testing.T) {
	dir := t.TempDir()

	cases := map[string]MonitorOptions{
		"dir vide":       {CellID: "c", QuotaBytes: 1},
		"cellID vide":    {Dir: dir, QuotaBytes: 1},
		"quota nul":      {Dir: dir, CellID: "c"},
		"seuil négatif":  {Dir: dir, CellID: "c", QuotaBytes: 1, Threshold: -0.5},
		"seuil ≥ 1":      {Dir: dir, CellID: "c", QuotaBytes: 1, Threshold: 1.0},
		"interval négat": {Dir: dir, CellID: "c", QuotaBytes: 1, Interval: -time.Second},
	}
	for name, opts := range cases {
		if _, err := NewMonitor(opts); err == nil {
			t.Fatalf("%s accepté", name)
		}
	}
	// Valeurs par défaut appliquées.
	mon, err := NewMonitor(MonitorOptions{Dir: dir, CellID: "c", QuotaBytes: 1 << 20})
	if err != nil {
		t.Fatalf("options minimales: %v", err)
	}
	if mon.threshold != DefaultThreshold || mon.interval != DefaultInterval {
		t.Fatalf("défauts non appliqués: seuil=%v intervalle=%v", mon.threshold, mon.interval)
	}
}

// TestMonitorBind : liaison invalide rejetée ; double liaison refusée.
func TestMonitorBind(t *testing.T) {
	ctx := context.Background()
	mon, err := NewMonitor(MonitorOptions{Dir: t.TempDir(), CellID: "c", QuotaBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := mon.Bind(nil); err == nil {
		t.Fatal("Bind(nil) accepté")
	}
	// Non lié : Run refuse explicitement (pas de moniteur muet).
	if err := mon.Run(ctx); !errors.Is(err, ErrMonitorNotBound) {
		t.Fatalf("Run non lié: err=%v, attendu ErrMonitorNotBound", err)
	}
	log, _ := openTestLog(t, ctx, t.TempDir(), mon)
	defer log.Close(ctx)
	if err := mon.Bind(log); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := mon.Bind(log); err == nil {
		t.Fatal("double Bind accepté")
	}
}

// TestMonitorLeafWriteFailureStillTrips : si la feuille d'arrêt ne peut pas
// être écrite (log fermé = disque inutilisable), le verrouillage a QUAND
// MÊME lieu — fail-closed, et l'alarme le signale.
func TestMonitorLeafWriteFailureStillTrips(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var box alarmBox
	log, mon := wireMonitor(t, ctx, t.TempDir(), MonitorOptions{
		CellID: "cell-t5",
		QuotaBytes: 1, // déjà dépassé
		Interval:  5 * time.Millisecond,
		OnAlarm:  func(a Alarm) { box.store(a) },
	})
	// Le log est fermé AVANT l'engagement : la feuille d'arrêt échouera.
	if err := log.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	go mon.Run(ctx)

	gotAlarm := waitAlarm(t, &box, 10*time.Second)
	const suffix = "+leaf-write-failed"
	if len(gotAlarm.Reason) < len(suffix) || gotAlarm.Reason[len(gotAlarm.Reason)-len(suffix):] != suffix {
		t.Fatalf("alarme=%q, attendu suffixe %q", gotAlarm.Reason, suffix)
	}
}

// TestMonitorClosed : Run sur un moniteur arrêté refuse explicitement.
func TestMonitorClosed(t *testing.T) {
	ctx := context.Background()
	mon, err := NewMonitor(MonitorOptions{Dir: t.TempDir(), CellID: "c", QuotaBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	mon.Close()
	if err := mon.Run(ctx); !errors.Is(err, ErrMonitorClosed) {
		t.Fatalf("Run après Close: err=%v, attendu ErrMonitorClosed", err)
	}
}
