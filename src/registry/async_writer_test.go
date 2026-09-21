// src/registry/async_writer_test.go — T38 (issue #71)
//
// Tests du writer async borné — réels (driver POSIX de Tessera, checkpoints
// signés), non-vacuoles : chaque contrôle est une faute précise qui DOIT
// être prise.
//
//   - acceptation rapide : un Append synchrone coûterait ≥ 150 ms par
//     feuille (plancher POSIX mesuré au spike T27) — 20 acceptations en
//     moins d'1 seconde condamnent toute réintroduction d'attente ;
//   - coupure réelle : un signataire de checkpoint bloqué (couture de
//     test) fige la publication SANS figer le batcher — la fenêtre
//     déborde, le refus est immédiat, le rattrapage est tracé ;
//   - contrôle négatif : sans faute, AUCUNE coupure parasite ne doit
//     naître (mutation « cutWatch déclenche tout le temps » prise) ;
//   - drain T5 : signataire bloqué + moniteur engagé — sans la couture
//     Drain, la feuille d'arrêt passerait AVANT les feuilles async ;
//   - concurrence (-race), backpressure, file bornée, fermeture.
package registry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

const asyncTestOrigin = "tbp/registry/async-test"

// gatedSigner enveloppe un signataire note et permet au test de GELER la
// publication des checkpoints (le batcher, lui, continue d'intégrer) —
// c'est la faute « publication en panne » de l'issue #71, reproductible
// et déterministe.
type gatedSigner struct {
	inner note.Signer
	mu    sync.RWMutex
	gate  chan struct{} // non nil ⇒ Sign bloque jusqu'à sa fermeture
}

func (g *gatedSigner) Name() string    { return g.inner.Name() }
func (g *gatedSigner) KeyHash() uint32 { return g.inner.KeyHash() }
func (g *gatedSigner) Sign(msg []byte) ([]byte, error) {
	g.mu.RLock()
	ch := g.gate
	g.mu.RUnlock()
	if ch != nil {
		<-ch
	}
	return g.inner.Sign(msg)
}

// block gèle la prochaine signature de checkpoint ; unblock la libère.
func (g *gatedSigner) block() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gate == nil {
		g.gate = make(chan struct{})
	}
}

func (g *gatedSigner) unblock() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gate != nil {
		close(g.gate)
		g.gate = nil
	}
}

// openAsyncLog ouvre un log de test avec signataire contrôlé et intervalle
// de checkpoint choisi (BatchSize 1 : chaque feuille est intégrée vite —
// seule la PUBLICATION est contrôlée par le test).
func openAsyncLog(t *testing.T, ctx context.Context, dir string, signer note.Signer, verifier note.Verifier, bp BackpressureChecker, cpInterval time.Duration) *CellLog {
	t.Helper()
	log, err := Open(ctx, Options{
		Dir:                dir,
		Signer:             signer,
		Verifier:           verifier,
		Backpressure:       bp,
		BatchSize:          1,
		BatchAge:           10 * time.Millisecond,
		CheckpointInterval: cpInterval,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return log
}

func asyncTestKeys(t *testing.T) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := GenerateCellKey(asyncTestOrigin)
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
	return signer, verifier
}

func asyncLeaf(i int) Leaf {
	return Leaf{
		Kind:        KindDecision,
		CellID:      "cell-async",
		PayloadHash: HashPayload([]byte("sel-async-16o!!"), []byte{byte(i), byte(i >> 8)}),
		Timestamp:   int64(1000 + i),
	}
}

// waitHead poll Head jusqu'à size ≥ want (la publication est asynchrone).
func waitHead(t *testing.T, ctx context.Context, log *CellLog, want uint64, timeout time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, size, err := log.Head(ctx)
		if err == nil && size >= want {
			return size
		}
		time.Sleep(30 * time.Millisecond)
	}
	_, size, _ := log.Head(ctx)
	t.Fatalf("taille %d jamais atteinte (courante %d) en %v", want, size, timeout)
	return 0
}

// TestAsyncWriterConfigFailClosed : une configuration invalide est refusée
// à la construction — jamais un writer silencieusement sans fenêtre.
func TestAsyncWriterConfigFailClosed(t *testing.T) {
	ctx := context.Background()
	signer, verifier := asyncTestKeys(t)
	salt := []byte("sel-async-16oct!")

	if _, err := NewAsyncWriter(nil, AsyncOptions{CellID: "c", Salt: salt}); err == nil {
		t.Fatal("CellLog nil accepté")
	}
	log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = log.Close(c)
	}()

	if _, err := NewAsyncWriter(log, AsyncOptions{Salt: salt}); err == nil {
		t.Fatal("CellID vide accepté")
	}
	if _, err := NewAsyncWriter(log, AsyncOptions{CellID: "c", Salt: []byte("court")}); err == nil {
		t.Fatal("sel < 16 octets accepté (§6.2)")
	}
	if _, err := NewAsyncWriter(log, AsyncOptions{CellID: "c", Salt: salt, Window: -time.Second}); err == nil {
		t.Fatal("fenêtre négative acceptée")
	}
	// Plancher 4× checkpoint (100 ms) = 400 ms : en dessous, les coupures
	// seraient parasites — refusé à la construction.
	if _, err := NewAsyncWriter(log, AsyncOptions{CellID: "c", Salt: salt, Window: 399 * time.Millisecond}); err == nil {
		t.Fatal("fenêtre sous le plancher 4× checkpoint acceptée")
	}
	if _, err := NewAsyncWriter(log, AsyncOptions{CellID: "c", Salt: salt, Window: 400 * time.Millisecond}); err != nil {
		t.Fatalf("fenêtre au plancher refusée : %v", err)
	}
	if _, err := NewAsyncWriter(log, AsyncOptions{CellID: "c", Salt: salt, QueueCapacity: -1}); err == nil {
		t.Fatal("capacité négative acceptée")
	}
}

// TestAsyncWriterFastAccept : le chemin chaud n'attend PAS la publication.
// Mutation prise : réintroduire l'attente du checkpoint dans Append
// coûterait ≥ 150 ms × 20 = 3 s — le budget d'1 s casse.
func TestAsyncWriterFastAccept(t *testing.T) {
	ctx := context.Background()
	signer, verifier := asyncTestKeys(t)
	log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = log.Close(c)
	}()
	w, err := NewAsyncWriter(log, AsyncOptions{CellID: "cell-async", Salt: []byte("sel-async-16oct!")})
	if err != nil {
		t.Fatalf("NewAsyncWriter: %v", err)
	}

	start := time.Now()
	for i := 0; i < 20; i++ {
		idx, err := w.Append(ctx, asyncLeaf(i))
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if idx != 0 {
			t.Fatalf("Append %d: index %d — l'index n'est opposable qu'à publication, le contrat impose 0", i, idx)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("20 acceptations en %v — le chemin chaud attend la publication (plancher sync ~150 ms/feuille)", elapsed)
	}

	// Rattrapage : tout est publié, dans l'ordre, sans intervention.
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := w.WaitOutstanding(drainCtx); err != nil {
		t.Fatalf("WaitOutstanding: %v", err)
	}
	size := waitHead(t, ctx, log, 20, 5*time.Second)
	if size != 20 {
		t.Fatalf("taille %d, attendu 20", size)
	}
	for i := 0; i < 20; i++ {
		if leaf := readLeafAt(t, log, size, uint64(i)); leaf.Kind != KindDecision {
			t.Fatalf("feuille %d kind=%d, attendu KindDecision", i, leaf.Kind)
		}
	}
	stats := w.Snapshot()
	if stats.Accepted != 20 || stats.Confirmed != 20 || stats.Tripped || stats.CutEpisodes != 0 {
		t.Fatalf("compteurs %+v — accepté=confirmé=20, aucune coupure attendue", stats)
	}
	closeCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	if err := w.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAsyncWriterNoSpuriousCut : contrôle négatif — une publication SAINE
// ne déclenche jamais la coupure, même au voisinage de la fenêtre.
// Mutation prise : un cutWatch qui déclencherait sans faute casse ici.
func TestAsyncWriterNoSpuriousCut(t *testing.T) {
	ctx := context.Background()
	signer, verifier := asyncTestKeys(t)
	log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = log.Close(c)
	}()
	tripped := atomic.Int32{}
	w, err := NewAsyncWriter(log, AsyncOptions{
		CellID: "cell-async", Salt: []byte("sel-async-16oct!"),
		Window: 500 * time.Millisecond, // plancher 400 ms — marge minimale honnête
		OnTrip: func(string) { tripped.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewAsyncWriter: %v", err)
	}
	// Trafic continu pendant 4× la fenêtre : la publication suit (cp
	// 100 ms + poll 50 ms ≪ 500 ms) — aucune coupure ne doit naître.
	deadline := time.Now().Add(2 * time.Second)
	i := 0
	for time.Now().Before(deadline) {
		if _, err := w.Append(ctx, asyncLeaf(i)); err != nil {
			t.Fatalf("Append %d sur publication saine: %v", i, err)
		}
		i++
		time.Sleep(25 * time.Millisecond)
	}
	if n := tripped.Load(); n != 0 {
		t.Fatalf("%d coupure(s) parasite(s) sur publication saine", n)
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := w.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAsyncWriterCutAndRecover : la faute réelle de l'issue — publication
// en panne (signataire gelé) — produit, dans l'ordre doctrinal : coupure,
// refus IMMÉDIAT fail-closed, alarme, reprise, feuille de rattrapage.
func TestAsyncWriterCutAndRecover(t *testing.T) {
	ctx := context.Background()
	rawSigner, verifier := asyncTestKeys(t)
	signer := &gatedSigner{inner: rawSigner}
	log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = log.Close(c)
	}()

	trips := make(chan string, 4)
	clears := make(chan struct{}, 4)
	w, err := NewAsyncWriter(log, AsyncOptions{
		CellID: "cell-async", Salt: []byte("sel-async-16oct!"),
		Window:  500 * time.Millisecond,
		OnTrip:  func(detail string) { trips <- detail },
		OnClear: func() { clears <- struct{}{} },
	})
	if err != nil {
		t.Fatalf("NewAsyncWriter: %v", err)
	}

	// Publication gelée APRÈS l'ouverture : le checkpoint initial existe,
	// les suivants n'arrivent plus. Le batcher intègre toujours.
	signer.block()
	for i := 0; i < 3; i++ {
		if _, err := w.Append(ctx, asyncLeaf(i)); err != nil {
			t.Fatalf("Append %d avant coupure: %v", i, err)
		}
	}

	// Coupure : la plus vieille feuille dépasse la fenêtre (500 ms).
	select {
	case detail := <-trips:
		if detail == "" {
			t.Fatal("alarme de coupure sans diagnostic")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("coupure jamais déclenchée — la fenêtre d'opposabilité ne mord pas")
	}
	if stats := w.Snapshot(); !stats.Tripped || stats.CutEpisodes != 1 {
		t.Fatalf("état %+v — coupure attendue (1 épisode)", stats)
	}

	// Refus IMMÉDIAT pendant la coupure — pas de file infinie, pas
	// d'attente : le chemin chaud reste borné MÊME en panne.
	for i := 0; i < 2; i++ {
		start := time.Now()
		_, err := w.Append(ctx, asyncLeaf(100+i))
		if !errors.Is(err, ErrDurabilityCut) {
			t.Fatalf("Append en coupure: err=%v, attendu ErrDurabilityCut", err)
		}
		if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
			t.Fatalf("refus en coupure en %v — le refus fail-closed doit être immédiat", elapsed)
		}
	}
	if stats := w.Snapshot(); stats.RefusedAtCut != 2 {
		t.Fatalf("refus comptés %d, attendu 2", stats.RefusedAtCut)
	}

	// Reprise : la publication reprend → rattrapage complet, feuille
	// d'épisode SYNCHRONE, OnClear.
	signer.unblock()
	select {
	case <-clears:
	case <-time.After(10 * time.Second):
		t.Fatal("rattrapage jamais confirmé (OnClear absent)")
	}
	drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := w.WaitOutstanding(drainCtx); err != nil {
		t.Fatalf("WaitOutstanding: %v", err)
	}
	// 3 décisions + 1 feuille de rattrapage KindTelemetry — la preuve
	// arrive à rattrapage, tracée (exigence de l'issue).
	size := waitHead(t, ctx, log, 4, 5*time.Second)
	if size != 4 {
		t.Fatalf("taille %d, attendu 4 (3 décisions + rattrapage)", size)
	}
	last := readLeafAt(t, log, size, size-1)
	if last.Kind != KindTelemetry {
		t.Fatalf("dernière feuille kind=%d, attendu KindTelemetry (rattrapage tracé)", last.Kind)
	}
	if last.CellID != "cell-async" {
		t.Fatalf("feuille de rattrapage cellID=%q", last.CellID)
	}
	if stats := w.Snapshot(); stats.Tripped {
		t.Fatal("coupure encore basculée après rattrapage")
	}

	// Le service reprend normalement après la coupure.
	if _, err := w.Append(ctx, asyncLeaf(200)); err != nil {
		t.Fatalf("Append après rattrapage: %v", err)
	}
	waitHead(t, ctx, log, 5, 5*time.Second)
	closeCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	if err := w.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestAsyncWriterBackpressureDrainKeepsStopLeafLast : la couture Drain du
// moniteur T5 garantit que KindBackpressure reste littéralement la
// DERNIÈRE feuille, même avec des feuilles async en vol. Mutation prise :
// sans Drain, la feuille d'arrêt est écrite pendant que les 5 feuilles
// async sont gelées — elle ne serait PAS dernière.
func TestAsyncWriterBackpressureDrainKeepsStopLeafLast(t *testing.T) {
	ctx := context.Background()
	rawSigner, verifier := asyncTestKeys(t)
	signer := &gatedSigner{inner: rawSigner}
	mon, err := NewMonitor(MonitorOptions{
		Dir: t.TempDir(), CellID: "cell-async", QuotaBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	dir := t.TempDir()
	mon.dir = dir // mesure cohérente avec le log ouvert ensuite
	log := openAsyncLog(t, ctx, dir, signer, verifier, mon, 100*time.Millisecond)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = log.Close(c)
	}()
	if err := mon.Bind(log); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	w, err := NewAsyncWriter(log, AsyncOptions{CellID: "cell-async", Salt: []byte("sel-async-16oct!")})
	if err != nil {
		t.Fatalf("NewAsyncWriter: %v", err)
	}
	mon.drain = w.WaitOutstanding

	// 5 feuilles async acceptées, publication gelée : elles ne peuvent
	// être confirmées qu'après dégel — le drain du moniteur devra attendre.
	signer.block()
	for i := 0; i < 5; i++ {
		if _, err := w.Append(ctx, asyncLeaf(i)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	engaged := make(chan struct{})
	go func() {
		mon.engage(ctx, Alarm{Reason: "registry-disk-80%", CellID: "cell-async", At: time.Now().UTC()})
		close(engaged)
	}()

	// Tant que la publication est gelée, l'engagement ne peut PAS
	// terminer : le drain attend les feuilles async (sans Drain, engage
	// serait déjà reparti et la feuille d'arrêt écrite).
	select {
	case <-engaged:
		t.Fatal("engage terminé avec des feuilles async non confirmées — Drain absent ou inefficace")
	case <-time.After(500 * time.Millisecond):
	}

	signer.unblock()
	select {
	case <-engaged:
	case <-time.After(10 * time.Second):
		t.Fatal("engage jamais terminé après dégel — drain bloqué")
	}

	// 5 décisions + feuille d'arrêt EN DERNIER.
	size := waitHead(t, ctx, log, 6, 5*time.Second)
	if size != 6 {
		t.Fatalf("taille %d, attendu 6", size)
	}
	for i := 0; i < 5; i++ {
		if leaf := readLeafAt(t, log, size, uint64(i)); leaf.Kind != KindDecision {
			t.Fatalf("feuille %d kind=%d, attendu KindDecision", i, leaf.Kind)
		}
	}
	if last := readLeafAt(t, log, size, size-1); last.Kind != KindBackpressure {
		t.Fatalf("dernière feuille kind=%d, attendu KindBackpressure(%d) — la feuille d'arrêt n'est plus dernière", last.Kind, KindBackpressure)
	}
	// Le verrou tient pour l'async aussi.
	if _, err := w.Append(ctx, asyncLeaf(99)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("Append async post-engagement: err=%v, attendu ErrBackpressure", err)
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = w.Close(closeCtx) // la coupure liée au gel peut subsister — l'arrêt reste propre
	// Invariant : le refus ci-dessus n'a laissé AUCUNE feuille orpheline —
	// la taille reste 6 (la feuille d'arrêt est TOUJOURS la dernière).
	if _, sizeAfter, err := log.Head(ctx); err != nil || sizeAfter != 6 {
		t.Fatalf("taille finale %d (err=%v), attendu 6 — un Append refusé a quand même écrit", sizeAfter, err)
	}
}

// TestAsyncWriterBacklogBound : la file est bornée — refus immédiat au-delà
// de la capacité (garde-fou mémoire), compté.
func TestAsyncWriterBacklogBound(t *testing.T) {
	ctx := context.Background()
	rawSigner, verifier := asyncTestKeys(t)
	signer := &gatedSigner{inner: rawSigner}
	log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = log.Close(c)
	}()
	w, err := NewAsyncWriter(log, AsyncOptions{
		CellID: "cell-async", Salt: []byte("sel-async-16oct!"), QueueCapacity: 2,
	})
	if err != nil {
		t.Fatalf("NewAsyncWriter: %v", err)
	}
	signer.block()
	defer signer.unblock()
	for i := 0; i < 2; i++ {
		if _, err := w.Append(ctx, asyncLeaf(i)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if _, err := w.Append(ctx, asyncLeaf(2)); !errors.Is(err, ErrDurabilityBacklog) {
		t.Fatalf("3ᵉ feuille sur file de 2: err=%v, attendu ErrDurabilityBacklog", err)
	}
	if stats := w.Snapshot(); stats.RefusedBacklog != 1 {
		t.Fatalf("refus file comptés %d, attendu 1", stats.RefusedBacklog)
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = w.Close(closeCtx)
}

// TestAsyncWriterConcurrentAndClosed : concurrence réelle (-race) puis
// fermeture — après Close, Append refuse immédiatement.
func TestAsyncWriterConcurrentAndClosed(t *testing.T) {
	ctx := context.Background()
	signer, verifier := asyncTestKeys(t)
	log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
	// Fenêtre large à dessein : 160 feuilles intégrées une par une
	// (BatchSize 1) sous -race ne rattrapent pas la fenêtre d'1 s — la
	// coupure est le sujet de TestAsyncWriterCutAndRecover, pas de ce test
	// (concurrence + invariant « refusé = sans effet de bord »).
	w, err := NewAsyncWriter(log, AsyncOptions{
		CellID: "cell-async", Salt: []byte("sel-async-16oct!"),
		Window: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAsyncWriter: %v", err)
	}
	_ = log // fermé explicitement en fin de test (erreur contrôlée)

	var wg sync.WaitGroup
	errs := make(chan error, 16*10)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if _, err := w.Append(ctx, asyncLeaf(g*10+i)); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Append concurrent: %v", err)
	}
	drainCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := w.WaitOutstanding(drainCtx); err != nil {
		t.Fatalf("WaitOutstanding: %v", err)
	}
	if stats := w.Snapshot(); stats.Accepted != 160 || stats.Confirmed != 160 {
		t.Fatalf("compteurs %+v — 160 acceptées/confirmées attendues", stats)
	}

	closeCtx, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	if err := w.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := w.Append(ctx, asyncLeaf(999)); !errors.Is(err, ErrAsyncClosed) {
		t.Fatalf("Append après Close: err=%v, attendu ErrAsyncClosed", err)
	}
	// Fermeture idempotente.
	if err := w.Close(closeCtx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := log.Close(context.Background()); err != nil {
		t.Fatalf("log.Close: %v", err)
	}
	// Invariant : un Append REFUSÉ n'a aucun effet de bord — la taille
	// reste 160 (une feuille orpheline trahirait un Add avant contrôle).
	if _, size, err := log.Head(ctx); err != nil || size != 160 {
		t.Fatalf("taille finale %d (err=%v), attendu 160 — un Append refusé a quand même écrit", size, err)
	}
}
