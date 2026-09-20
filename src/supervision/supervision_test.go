// src/supervision/supervision_test.go — T34a (issue #60)
//
// Doctrine de test : chaînes RÉELLES (driver POSIX Tessera, checkpoints
// signés Ed25519), corruptions RÉELLES sur fichiers (bundle d'entrées,
// checkpoint), alarmes relues depuis le log de supervision par un
// ChainWatcher — le moniteur est audité par ses propres mécaniques (§7.1).
package supervision

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------- fixtures ----------

var testCtx = context.Background()

// fakeClock : horloge contrôlée (même patron que les autres packages).
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// cellFixture : une cellule réelle — log POSIX, clé, ancreur simulé par
// écriture directe de feuilles KindAnchor dans la master chain.
type cellFixture struct {
	cellID   string
	origin   string
	dir      string
	signer   note.Signer
	verifier note.Verifier
	log      *registry.CellLog
	salt     []byte
	n        uint64 // feuilles écrites — le fichier checkpoint suit à 100 ms
}

// openCellFixture crée un log de cellule avec sa clé note (origine =
// nom de clé, §6).
func openCellFixture(t *testing.T, cellID string) *cellFixture {
	t.Helper()
	origin := "tbp/registry/" + cellID
	skey, vkey, err := registry.GenerateCellKey(origin)
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	dir := t.TempDir()
	log, err := registry.Open(testCtx, registry.Options{
		Dir: dir, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("Open(%s): %v", cellID, err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("sel: %v", err)
	}
	return &cellFixture{
		cellID: cellID, origin: origin, dir: dir,
		signer: signer, verifier: verifier, log: log, salt: salt,
	}
}

// appendLeaf écrit une feuille et attend sa publication (Append l'attend
// déjà — ce helper pose surtout le timestamp).
func (f *cellFixture) appendLeaf(t *testing.T, kind byte, payload string, ts time.Time) uint64 {
	t.Helper()
	idx, err := f.log.Append(testCtx, registry.Leaf{
		Kind:        kind,
		CellID:      f.cellID,
		PayloadHash: registry.HashPayload(f.salt, []byte(payload)),
		Timestamp:   ts.UnixNano(),
	})
	if err != nil {
		t.Fatalf("Append(%s): %v", f.cellID, err)
	}
	f.n++
	return idx
}

// waitCheckpoint attend que le checkpoint PUBLIÉ (fichier lu comme le
// ferait le moniteur) couvre size — Append attend la publication de la
// feuille, le fichier checkpoint suit à CheckpointInterval (100 ms).
func waitCheckpoint(t *testing.T, dir string, verifier note.Verifier, size uint64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
		if err == nil {
			if cp, err := registry.ParseCheckpoint(raw, verifier); err == nil && cp.Size >= size {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("checkpoint de %s jamais publié à taille ≥ %d", dir, size)
}

// writeManifestChain produit une vraie chaîne de manifestes (genèse +
// transitions) feuillée dans le log de la cellule, et publie les artefacts
// JSON dans dir. skipSeq retire un artefact de la publication (chaîne
// cassée) ; corruptSig altère la signature du dernier artefact publié.
func writeManifestChain(t *testing.T, f *cellFixture, clk *fakeClock, dir string, skipSeq int, corruptSig bool) {
	t.Helper()
	m, err := registry.NewManifester(registry.ManifestOptions{
		CellID:   f.cellID,
		Signer:   f.signer,
		Verifier: f.verifier,
		Leaves:   f.log,
		Salt:     f.salt,
		Now:      clk.now,
	})
	if err != nil {
		t.Fatalf("NewManifester: %v", err)
	}
	var state registry.ManifestState
	copy(state.PolicyID[:], []byte("policy-p1-v1"))
	head, _, err := f.log.Head(testCtx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	state.ChainHead = head
	gen, err := m.Genesis(testCtx, 0, state)
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	state.OPAConfigHash[0] = 0x42 // changement de composant ⇒ transition
	head2, _, err := f.log.Head(testCtx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	state.ChainHead = head2
	tr, err := m.Transition(testCtx, 0, state)
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	for i, sm := range []registry.SignedManifest{gen, tr} {
		if i == skipSeq {
			continue
		}
		raw, err := registry.MarshalSignedManifest(sm)
		if err != nil {
			t.Fatalf("MarshalSignedManifest: %v", err)
		}
		if corruptSig && i == 1 {
			// Altère un caractère hex de la signature (artefact falsifié
			// APRÈS publication — hexadécimal valide, signature fausse).
			pos := bytes.LastIndexByte(raw, '"') - 1
			if raw[pos] == '0' {
				raw[pos] = '1'
			} else {
				raw[pos] = '0'
			}
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("manifest-%06d.json", i)), raw, 0o600); err != nil {
			t.Fatalf("WriteFile artefact: %v", err)
		}
	}
}

// monitorFixture assemble un moniteur complet : master chain, une cellule,
// log de supervision. L'ancreur est simulé par des feuilles KindAnchor
// écrites directement dans la master chain (comme le fait T6).
type monitorFixture struct {
	clk      *fakeClock
	master   *cellFixture
	cell     *cellFixture
	sup      *cellFixture // log de supervision du moniteur
	manifDir string
	sink     *[]Alert
	monitor  *Monitor
}

func newMonitorFixture(t *testing.T) *monitorFixture {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	fx := &monitorFixture{
		clk:    clk,
		master: openCellFixture(t, "master"),
		cell:   openCellFixture(t, "cell-alpha-01"),
		sup:    openCellFixture(t, "monitor-01"),
	}
	// La master chain et la cellule ont au moins une feuille publiée avant
	// l'ouverture du moniteur (checkpoint initial requis, fail-closed).
	fx.master.appendLeaf(t, registry.KindAnchor, "anchor-init", clk.t.Add(-time.Minute))
	waitCheckpoint(t, fx.master.dir, fx.master.verifier, 1)
	fx.cell.appendLeaf(t, registry.KindDecision, "decision-0", clk.t.Add(-time.Minute))
	waitCheckpoint(t, fx.cell.dir, fx.cell.verifier, 1)
	fx.manifDir = t.TempDir()
	writeManifestChain(t, fx.cell, clk, fx.manifDir, -1, false)
	waitCheckpoint(t, fx.cell.dir, fx.cell.verifier, 3) // decision + genesis + transition
	fx.sup.appendLeaf(t, registry.KindTelemetry, "monitor-boot", clk.t)
	waitCheckpoint(t, fx.sup.dir, fx.sup.verifier, 1)

	var got []Alert
	fx.sink = &got
	mon, err := NewMonitor(testCtx, MonitorOptions{
		MonitorCellID: fx.sup.cellID,
		Log:           fx.sup.log,
		Cells: []CellSpec{{
			CellID:      fx.cell.cellID,
			LogDir:      fx.cell.dir,
			Origin:      fx.cell.origin,
			Verifier:    fx.cell.verifier,
			ManifestDir: fx.manifDir,
		}},
		Master: MasterSpec{
			CellID:   fx.master.cellID,
			LogDir:   fx.master.dir,
			Origin:   fx.master.origin,
			Verifier: fx.master.verifier,
		},
		Sink: AlarmSinkFunc(func(ctx context.Context, a Alert) error {
			*fx.sink = append(*fx.sink, a)
			return nil
		}),
		Now: clk.now,
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	fx.monitor = mon
	return fx
}

// check enveloppe CheckOnce en tenant le compteur de feuilles du log de
// supervision à jour (le moniteur y append lui-même ses alertes).
func (fx *monitorFixture) check(t *testing.T) []Alert {
	t.Helper()
	alerts, err := fx.monitor.CheckOnce(testCtx)
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	fx.sup.n += uint64(len(alerts))
	return alerts
}

// anchorAt écrit un ancrage de la cellule à ts dans la master chain et
// attend sa publication.
func (fx *monitorFixture) anchorAt(t *testing.T, ts time.Time) {
	t.Helper()
	if _, err := fx.master.log.Append(testCtx, registry.Leaf{
		Kind:        registry.KindAnchor,
		CellID:      fx.cell.cellID, // ancrage DE la cellule, écrit DANS la master chain (T6)
		PayloadHash: registry.HashPayload(fx.master.salt, []byte("anchor")),
		Timestamp:   ts.UnixNano(),
	}); err != nil {
		t.Fatalf("Append anchor: %v", err)
	}
	fx.master.n++
	waitCheckpoint(t, fx.master.dir, fx.master.verifier, fx.master.n)
}

// supervisionLeaves relit le log de supervision avec un ChainWatcher
// indépendant — dogfooding : le lecteur est le mécanisme T34a lui-même.
func (fx *monitorFixture) supervisionLeaves(t *testing.T) []registry.Leaf {
	t.Helper()
	waitCheckpoint(t, fx.sup.dir, fx.sup.verifier, fx.sup.n)
	leaves, w, err := NewChainWatcher(testCtx, fx.sup.cellID, fx.sup.dir, fx.sup.origin, fx.sup.verifier, 0)
	if err != nil {
		t.Fatalf("ChainWatcher supervision: %v", err)
	}
	more, err := w.Tick(testCtx)
	if err != nil {
		t.Fatalf("Tick supervision: %v", err)
	}
	return append(leaves, more...)
}

// ---------- record « TBPS1 » ----------

func TestAlertRecordRoundTrip(t *testing.T) {
	for _, ev := range []byte{AlertEventChainFault, AlertEventAnchorStale, AlertEventManifestFault, AlertEventFailoverTrigger, AlertEventFailoverRefused} {
		for _, v := range []byte{AlertVerdictAlarm, AlertVerdictNotice} {
			rec := AlertRecord{
				Event:      ev,
				CellID:     "cell-alpha-01",
				DetailHash: registry.HashPayload([]byte("s"), []byte("detail")),
				Verdict:    v,
				Reason:     "anchor-stale",
			}
			raw, err := MarshalAlertRecord(rec)
			if err != nil {
				t.Fatalf("event=%d verdict=%d : Marshal: %v", ev, v, err)
			}
			if !bytes.HasPrefix(raw, []byte(alertMagic)) {
				t.Fatalf("magie absente")
			}
			back, err := ParseAlertRecord(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if back != rec {
				t.Fatalf("round-trip : %+v ≠ %+v", back, rec)
			}
		}
	}
}

func TestAlertRecordRejectsMalformed(t *testing.T) {
	good, err := MarshalAlertRecord(AlertRecord{
		Event: AlertEventAnchorStale, CellID: "c1", Verdict: AlertVerdictAlarm, Reason: "anchor-stale",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	cases := map[string][]byte{
		"vide":             {},
		"magie absente":    bytes.Replace(good, []byte(alertMagic), []byte("XXXXX"), 1),
		"version inconnue": bytes.Replace(good, []byte{alertVersion}, []byte{99}, 1),
		"troncature":       good[:len(good)-2],
	}
	// event inconnu
	ev := bytes.Clone(good)
	ev[len(alertMagic)+1] = 77
	cases["event inconnu"] = ev
	// verdict inconnu (position : magic+v+event+len+cellID+32)
	vp := bytes.Clone(good)
	vp[len(alertMagic)+1+1+1+2+32] = 55
	cases["verdict inconnu"] = vp
	for name, data := range cases {
		if _, err := ParseAlertRecord(data); err == nil {
			t.Fatalf("%s : accepté, devait être rejeté", name)
		}
	}
	// Marshal refuse aussi : reason vide, event inconnu.
	if _, err := MarshalAlertRecord(AlertRecord{Event: AlertEventChainFault, CellID: "c1", Verdict: AlertVerdictAlarm}); err == nil {
		t.Fatalf("reason vide acceptée")
	}
	if _, err := MarshalAlertRecord(AlertRecord{Event: 200, CellID: "c1", Verdict: AlertVerdictAlarm, Reason: "x"}); err == nil {
		t.Fatalf("event inconnu accepté à l'émission")
	}
}

// ---------- ChainWatcher ----------

func TestChainWatcherCleanTick(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	cell := openCellFixture(t, "cell-beta-02")
	cell.appendLeaf(t, registry.KindDecision, "d0", clk.t)
	waitCheckpoint(t, cell.dir, cell.verifier, 1)

	leaves, w, err := NewChainWatcher(testCtx, cell.cellID, cell.dir, cell.origin, cell.verifier, 0)
	if err != nil {
		t.Fatalf("NewChainWatcher: %v", err)
	}
	if len(leaves) != 1 || leaves[0].Kind != registry.KindDecision {
		t.Fatalf("bootstrap : %d feuilles, kind %v", len(leaves), leaves)
	}
	// Nouvelles feuilles après ouverture : le tick les voit, vérifiées.
	cell.appendLeaf(t, registry.KindTelemetry, "t1", clk.t)
	cell.appendLeaf(t, registry.KindDecision, "d2", clk.t)
	waitCheckpoint(t, cell.dir, cell.verifier, 3)
	got, err := w.Tick(testCtx)
	if err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if len(got) != 2 || got[0].Kind != registry.KindTelemetry || got[1].Kind != registry.KindDecision {
		t.Fatalf("tick : %+v", got)
	}
	if w.Size() != 3 {
		t.Fatalf("taille %d, attendu 3", w.Size())
	}
	// Tick sans nouveauté : rien, pas d'erreur.
	got, err = w.Tick(testCtx)
	if err != nil || len(got) != 0 {
		t.Fatalf("tick à vide : leaves=%d err=%v", len(got), err)
	}
}

func TestChainWatcherDetectsEntryCorruption(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	cell := openCellFixture(t, "cell-gamma-03")
	cell.appendLeaf(t, registry.KindDecision, "d0", clk.t)
	waitCheckpoint(t, cell.dir, cell.verifier, 1)
	_, w, err := NewChainWatcher(testCtx, cell.cellID, cell.dir, cell.origin, cell.verifier, 1)
	if err != nil {
		t.Fatalf("NewChainWatcher: %v", err)
	}
	// Nouvelle feuille PUIS corruption de son bundle d'entrées sur disque —
	// le re-hash contre les tuiles doit la rejeter (§3).
	cell.appendLeaf(t, registry.KindTelemetry, "t1", clk.t)
	waitCheckpoint(t, cell.dir, cell.verifier, 2)
	corruptAllFiles(t, filepath.Join(cell.dir, "tile", "entries"))
	if _, err := w.Tick(testCtx); err == nil {
		t.Fatalf("corruption du bundle non détectée")
	} else if !strings.Contains(err.Error(), ErrChainDivergence.Error()) {
		t.Fatalf("erreur inattendue : %v", err)
	}
	// Sticky : le tick suivant rend la MÊME faute (pas d'amnésie, §5.3).
	if _, err := w.Tick(testCtx); err == nil {
		t.Fatalf("faute non sticky : second tick silencieux")
	}
}

func TestChainWatcherDetectsCheckpointTamper(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	cell := openCellFixture(t, "cell-delta-04")
	cell.appendLeaf(t, registry.KindDecision, "d0", clk.t)
	waitCheckpoint(t, cell.dir, cell.verifier, 1)
	_, w, err := NewChainWatcher(testCtx, cell.cellID, cell.dir, cell.origin, cell.verifier, 0)
	if err != nil {
		t.Fatalf("NewChainWatcher: %v", err)
	}
	// Checkpoint réécrit avec une signature invalide (corbeille) : la
	// vérification de signature le rejette au tick.
	if err := os.WriteFile(filepath.Join(cell.dir, "checkpoint"), []byte("garbage\n— not a signed checkpoint\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := w.Tick(testCtx); err == nil {
		t.Fatalf("checkpoint falsifié accepté")
	}
}

// corruptAllFiles inverse le premier ET le dernier octet de CHAQUE fichier
// sous root — le driver POSIX laisse les anciens bundles partiels à côté
// du courant (tile/entries/000.p/1, 000.p/2…) : corrompre « un » fichier
// pourrait toucher une version périmée que le lecteur ne consulte plus.
// Premier+dernier octet : quel que soit le sous-ensemble d'entrées relu
// (bundle partiel, offset), au moins une entrée lue est touchée.
func corruptAllFiles(t *testing.T, root string) {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data[0] ^= 0xFF
		data[len(data)-1] ^= 0xFF
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		n++
		return nil
	})
	if err != nil || n == 0 {
		t.Fatalf("aucun fichier sous %s : %v", root, err)
	}
}

// ---------- Monitor : trois vérificateurs ----------

func TestMonitorHealthyNoAlerts(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.anchorAt(t, fx.clk.t) // ancrage frais dans la borne
	alerts := fx.check(t)
	if len(alerts) != 0 {
		t.Fatalf("cellule saine : %d alertes (%+v)", len(alerts), alerts)
	}
	if len(*fx.sink) != 0 {
		t.Fatalf("sink notifié sans faute")
	}
}

func TestMonitorAnchorStale(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.anchorAt(t, fx.clk.t.Add(-10*time.Minute)) // hors borne §6.2 (120 s)
	alerts := fx.check(t)
	if len(alerts) != 1 {
		t.Fatalf("attendu 1 alerte, %d : %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Record.Event != AlertEventAnchorStale || a.Record.Reason != "anchor-stale" || a.Record.CellID != fx.cell.cellID {
		t.Fatalf("alerte inattendue : %+v", a.Record)
	}
	// L'ancrage observé reste le vieux — la fraîcheur ne recule pas mais
	// n'avance pas non plus sans nouvel ancrage.
	if ts, ok := fx.monitor.LastAnchor(fx.cell.cellID); !ok || !ts.Equal(fx.clk.t.Add(-10*time.Minute)) {
		t.Fatalf("LastAnchor = %v, %v", ts, ok)
	}
}

func TestMonitorAnchorMissing(t *testing.T) {
	fx := newMonitorFixture(t)
	// Le bootstrap du fixture n'ancre que "master" (anchor-init de la
	// master chain elle-même porte CellID=master) : jamais d'ancrage pour
	// la cellule.
	alerts := fx.check(t)
	if len(alerts) != 1 || alerts[0].Record.Reason != "anchor-missing" {
		t.Fatalf("attendu anchor-missing seul, %+v", alerts)
	}
}

func TestMonitorManifestChainGap(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.anchorAt(t, fx.clk.t)
	// Retire l'artefact de genèse : seq 1 publié sans seq 0.
	if err := os.Remove(filepath.Join(fx.manifDir, "manifest-000000.json")); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	alerts := fx.check(t)
	if len(alerts) != 1 || alerts[0].Record.Event != AlertEventManifestFault {
		t.Fatalf("attendu manifest-chain-fault, %+v", alerts)
	}
}

func TestMonitorManifestSignatureForged(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 9, 21, 13, 0, 0, 0, time.UTC)}
	cell := openCellFixture(t, "cell-epsilon-05")
	master := openCellFixture(t, "master")
	sup := openCellFixture(t, "monitor-02")
	master.appendLeaf(t, registry.KindAnchor, "a0", clk.t)
	waitCheckpoint(t, master.dir, master.verifier, 1)
	cell.appendLeaf(t, registry.KindDecision, "d0", clk.t)
	waitCheckpoint(t, cell.dir, cell.verifier, 1)
	sup.appendLeaf(t, registry.KindTelemetry, "boot", clk.t)
	waitCheckpoint(t, sup.dir, sup.verifier, 1)
	manifDir := t.TempDir()
	writeManifestChain(t, cell, clk, manifDir, -1, true) // signature forgée
	// Ancrage frais DE la cellule, écrit dans la master chain (T6).
	if _, err := master.log.Append(testCtx, registry.Leaf{
		Kind:        registry.KindAnchor,
		CellID:      cell.cellID,
		PayloadHash: registry.HashPayload(master.salt, []byte("a")),
		Timestamp:   clk.t.UnixNano(),
	}); err != nil {
		t.Fatalf("Append anchor: %v", err)
	}
	master.n++
	waitCheckpoint(t, master.dir, master.verifier, master.n)

	mon, err := NewMonitor(testCtx, MonitorOptions{
		MonitorCellID: sup.cellID,
		Log:           sup.log,
		Cells: []CellSpec{{CellID: cell.cellID, LogDir: cell.dir, Origin: cell.origin,
			Verifier: cell.verifier, ManifestDir: manifDir}},
		Master: MasterSpec{CellID: master.cellID, LogDir: master.dir, Origin: master.origin, Verifier: master.verifier},
		Now:    clk.now,
	})
	if err != nil {
		t.Fatalf("NewMonitor: %v", err)
	}
	alerts, err := mon.CheckOnce(testCtx)
	if err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Record.Event != AlertEventManifestFault {
		t.Fatalf("signature forgée non détectée : %+v", alerts)
	}
}

func TestMonitorCellChainCorruptionAlerted(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.anchorAt(t, fx.clk.t)
	// Corrompt le checkpoint de la CELLULE : le prochain tick la voit en
	// faute (alerte event=1) pendant que l'ancrage, lui, reste frais —
	// les vérificateurs sont indépendants.
	if err := os.WriteFile(filepath.Join(fx.cell.dir, "checkpoint"), []byte("forged\n"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	alerts := fx.check(t)
	if len(alerts) != 1 || alerts[0].Record.Event != AlertEventChainFault || alerts[0].Record.CellID != fx.cell.cellID {
		t.Fatalf("attendu cell-chain-fault sur %s : %+v", fx.cell.cellID, alerts)
	}
}

func TestMonitorAlertLeafedBeforeSink(t *testing.T) {
	fx := newMonitorFixture(t)
	// Pas d'ancrage frais ⇒ alerte ; sink déjà câblé dans le fixture.
	alerts := fx.check(t)
	if len(alerts) != 1 {
		t.Fatalf("attendu 1 alerte, %d", len(alerts))
	}
	a := alerts[0]
	// 1. La feuille existe AVANT la notification : le sink a reçu une
	//    alerte avec LeafIndex valide et LeafHash = sha256(sel ‖ record).
	if len(*fx.sink) != 1 || (*fx.sink)[0].LeafIndex != a.LeafIndex {
		t.Fatalf("sink : %+v", *fx.sink)
	}
	if a.LeafHash != registry.HashPayload(a.Salt, a.Raw) {
		t.Fatalf("LeafHash ne correspond pas à sha256(sel ‖ record)")
	}
	if len(a.Salt) < 16 {
		t.Fatalf("sel < 16 octets")
	}
	// 2. La feuille est RELISIBLE dans le log de supervision par un lecteur
	//    indépendant (ChainWatcher dogfood) : kind 12, hash identique.
	leaves := fx.supervisionLeaves(t)
	var found *registry.Leaf
	for i := range leaves {
		if leaves[i].Kind == registry.KindSupervision {
			found = &leaves[i]
		}
	}
	if found == nil {
		t.Fatalf("aucune feuille KindSupervision dans le log de supervision")
	}
	if found.PayloadHash != a.LeafHash || found.CellID != fx.sup.cellID {
		t.Fatalf("feuille relue ≠ alerte : %+v", found)
	}
	// 3. Le record canonique se reparse (preuve à tiers : révéler sel +
	//    record permet de re-vérifier le hash de la feuille).
	rec, err := ParseAlertRecord(a.Raw)
	if err != nil || rec != a.Record {
		t.Fatalf("record non reparseable : %v", err)
	}
}

// ---------- fail-closed construction ----------

func TestNewMonitorFailClosedConfig(t *testing.T) {
	fx := newMonitorFixture(t)
	base := MonitorOptions{
		MonitorCellID: "m", Log: fx.sup.log,
		Cells:  []CellSpec{{CellID: "c", LogDir: fx.cell.dir, Origin: fx.cell.origin, Verifier: fx.cell.verifier, ManifestDir: fx.manifDir}},
		Master: MasterSpec{CellID: "master", LogDir: fx.master.dir, Origin: fx.master.origin, Verifier: fx.master.verifier},
	}
	cases := map[string]func(o *MonitorOptions){
		"sans log":       func(o *MonitorOptions) { o.Log = nil },
		"sans cellules":  func(o *MonitorOptions) { o.Cells = nil },
		"sans master":    func(o *MonitorOptions) { o.Master = MasterSpec{} },
		"sans monitorID": func(o *MonitorOptions) { o.MonitorCellID = "" },
		"cellSpec incomplète": func(o *MonitorOptions) {
			o.Cells = []CellSpec{{CellID: "c"}}
		},
		"cellule en double": func(o *MonitorOptions) {
			o.Cells = append(o.Cells, o.Cells[0])
		},
	}
	for name, mutate := range cases {
		o := base
		mutate(&o)
		if _, err := NewMonitor(testCtx, o); err == nil {
			t.Fatalf("%s : construction acceptée, devait refuser", name)
		}
	}
}

// ---------- doctrine §9.1 : chemin froid ----------

// TestNoHotPathImport vérifie D84 : aucun composant du chemin chaud
// (broker, pep) n'importe la supervision — la supervision n'ajoute AUCUNE
// latence au chemin tier-1 par construction (pas d'appel, pas de latence).
func TestNoHotPathImport(t *testing.T) {
	const sup = "TBP-NETWORK/src/supervision"
	for _, pkg := range []string{"broker", "pep"} {
		root := filepath.Join("..", pkg)
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(sup)) {
				t.Errorf("%s importe la supervision — chemin froid rompu (§9.1, D84)", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s : %v", pkg, err)
		}
	}
}
