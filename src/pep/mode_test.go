package pep

import (
	"sync"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures T15 (mode)
// ---------------------------------------------------------------------------

func newTestModeController(t *testing.T, sink *stubSink, alarm *tripRecorder, verifier QuorumVerifier) *ModeController {
	t.Helper()
	opts := ModeOptions{
		CellID:       opaTestCellID,
		Salt:         testSalt,
		Leaves:       sink,
		VerifyQuorum: verifier,
		Now:          func() time.Time { return time.Unix(testIAT+30, 0) },
	}
	if alarm != nil {
		opts.OnAlarm = alarm.trip
	}
	mc, err := NewModeController(opts)
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}
	return mc
}

func acceptQuorum(string, QuorumProof) bool { return true }
func rejectQuorum(string, QuorumProof) bool { return false }

// ---------------------------------------------------------------------------
// Doctrine §5.3 : le mode par défaut est MONITOR — jamais closed au premier
// déploiement. En monitor, rien n'est bloqué (log seulement).
// ---------------------------------------------------------------------------

func TestModeDefaultsMonitor(t *testing.T) {
	sink := &stubSink{}
	mc := newTestModeController(t, sink, nil, acceptQuorum)

	if mc.Mode() != ModeMonitor {
		t.Fatalf("mode=%v, veut monitor (défaut doctrinal §5.3)", mc.Mode())
	}
	if mc.Mode().String() != "monitor" {
		t.Fatalf("String()=%q", mc.Mode().String())
	}
	if sink.count() != 0 {
		t.Fatalf("feuilles=%d, veut 0 (aucune bascule)", sink.count())
	}

	// Monitor ne bloque JAMAIS : même un deny est « log seulement ».
	if !mc.Allows(Decision{Allow: false, Reason: ReasonReplay}) {
		t.Fatal("monitor a bloqué un deny (doctrine : log, aucun blocage)")
	}
	if !mc.Allows(Decision{Allow: true, Reason: ReasonOK}) {
		t.Fatal("monitor a bloqué un allow")
	}
}

// ---------------------------------------------------------------------------
// Bascule monitor → closed : acte GOUVERNÉ (quorum §5.3), tracé (feuille
// hash-only) et alarmé. En closed, le verdict s'applique.
// ---------------------------------------------------------------------------

func TestModeSwitchToClosedGovernedTraced(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}

	// Sans vérifieur de quorum : la bascule est impossible (fail-closed).
	mc := newTestModeController(t, sink, alarm, nil)
	if err := mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err == nil {
		t.Fatal("bascule closed acceptée sans vérifieur de quorum")
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("mode a basculé sans quorum")
	}
	if sink.count() != 0 {
		t.Fatalf("feuilles=%d, veut 0 (bascule refusée = rien à tracer)", sink.count())
	}

	// Vérifieur qui rejette : toujours monitor.
	mc.SetQuorumVerifier(rejectQuorum)
	if err := mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err == nil {
		t.Fatal("bascule closed acceptée avec preuve rejetée")
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("mode a basculé malgré le rejet du quorum")
	}

	// Quorum valide : bascule tracée et alarmée.
	mc.SetQuorumVerifier(acceptQuorum)
	if err := mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}, {KeyID: [16]byte{2}}}}); err != nil {
		t.Fatalf("SetMode(closed) avec quorum: %v", err)
	}
	if mc.Mode() != ModeClosed {
		t.Fatal("pas en closed après bascule quorée")
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1 (bascule tracée)", sink.count())
	}
	leaf := sink.leaves[0]
	if leaf.Kind != registry.KindTelemetry {
		t.Fatalf("kind=%d, veut KindTelemetry", leaf.Kind)
	}
	if got := leaf.PayloadHash; got != registry.HashPayload(testSalt, modeChangeRecord(ModeClosed)) {
		t.Fatalf("hash=%x, veut engagement mode-closed", got)
	}
	if alarm.count() != 1 || lastReason(alarm) != "mode-closed" {
		t.Fatalf("alarmes=%v, veut 1 × mode-closed", alarm.reasons)
	}

	// En closed, le verdict S'APPLIQUE : deny bloqué, allow passé.
	if mc.Allows(Decision{Allow: false, Reason: ReasonReplay}) {
		t.Fatal("closed n'a pas bloqué un deny")
	}
	if !mc.Allows(Decision{Allow: true, Reason: ReasonOK}) {
		t.Fatal("closed a bloqué un allow")
	}
}

// ---------------------------------------------------------------------------
// Bascule idempotente : redemander le mode courant est un no-op non gouverné
// (rien à tracer) ; la bascule retour vers monitor est aussi gouvernée et
// tracée.
// ---------------------------------------------------------------------------

func TestModeSwitchIdempotentAndBack(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	mc := newTestModeController(t, sink, alarm, acceptQuorum)

	// monitor → monitor : no-op, même sans preuve.
	if err := mc.SetMode(ModeMonitor, QuorumProof{}); err != nil {
		t.Fatalf("SetMode(monitor) idempotent: %v", err)
	}
	if sink.count() != 0 {
		t.Fatalf("feuilles=%d, veut 0 (no-op)", sink.count())
	}

	if err := mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatalf("SetMode(closed): %v", err)
	}
	// closed → closed : no-op (pas de doublon).
	if err := mc.SetMode(ModeClosed, QuorumProof{}); err != nil {
		t.Fatalf("SetMode(closed) idempotent: %v", err)
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1 (pas de doublon)", sink.count())
	}

	// Retour à monitor : gouverné et tracé aussi.
	if err := mc.SetMode(ModeMonitor, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatalf("SetMode(monitor) retour: %v", err)
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("pas revenu en monitor")
	}
	if sink.count() != 2 {
		t.Fatalf("feuilles=%d, veut 2 (aller + retour tracés)", sink.count())
	}
	if got := sink.leaves[1].PayloadHash; got != registry.HashPayload(testSalt, modeChangeRecord(ModeMonitor)) {
		t.Fatalf("2e feuille hash=%x, veut engagement mode-monitor", got)
	}
	if alarm.count() != 2 || lastReason(alarm) != "mode-monitor" {
		t.Fatalf("alarmes=%v, veut 2 dont mode-monitor", alarm.reasons)
	}
}

// ---------------------------------------------------------------------------
// Revue de sécurité #93 : redémarrage (StartRefused) — refus TOTAL, même
// d'un allow, jusqu'à reconfirmation EXPLICITE par quorum. Le premier
// déploiement (StartRefused=false, comportement par défaut ci-dessus)
// n'est PAS affecté.
// ---------------------------------------------------------------------------

func TestModeStartRefusedBlocksEverythingUntilReconfirmed(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	mc, err := NewModeController(ModeOptions{
		CellID:       opaTestCellID,
		Salt:         testSalt,
		Leaves:       sink,
		OnAlarm:      alarm.trip,
		VerifyQuorum: acceptQuorum,
		StartRefused: true,
		Now:          func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}

	if mc.Mode() != ModeRefused {
		t.Fatalf("mode=%v, veut refused (redémarrage, §93)", mc.Mode())
	}
	if mc.Mode().String() != "refused" {
		t.Fatalf("String()=%q, veut %q", mc.Mode().String(), "refused")
	}

	// Refus TOTAL : même un allow ne passe pas (contrairement à closed,
	// qui laisse passer un allow).
	if mc.Allows(Decision{Allow: true, Reason: ReasonOK}) {
		t.Fatal("refused a laissé passer un allow — refus total attendu (§93)")
	}
	if mc.Allows(Decision{Allow: false, Reason: ReasonReplay}) {
		t.Fatal("refused a laissé passer un deny")
	}

	// L'entrée en refused elle-même est un événement de gouvernance :
	// tracé et alarmé, comme toute transition de posture — jamais
	// silencieux (c'est exactement le défaut que #93 corrige).
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1 (entrée en refused tracée)", sink.count())
	}
	if got := sink.leaves[0].PayloadHash; got != registry.HashPayload(testSalt, modeChangeRecord(ModeRefused)) {
		t.Fatalf("hash=%x, veut engagement mode-refused", got)
	}
	if alarm.count() != 1 || lastReason(alarm) != "mode-refused-restart" {
		t.Fatalf("alarmes=%v, veut 1 × mode-refused-restart", alarm.reasons)
	}

	// Seule sortie : quorum reconfirmant EXPLICITEMENT une posture — pas
	// de vérifieur ⇒ toujours bloqué.
	mc2, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: &stubSink{},
		StartRefused: true, Now: func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}
	if err := mc2.SetMode(ModeMonitor, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err == nil {
		t.Fatal("reconfirmation de monitor acceptée SANS vérifieur de quorum")
	}
	if mc2.Mode() != ModeRefused {
		t.Fatal("mode a quitté refused sans quorum")
	}

	// Reconfirmer MONITOR (même la posture "par défaut") exige un quorum
	// valide — ce n'est PAS un no-op comme le redemander en monitor
	// l'était pour un contrôleur déjà en monitor : refused est un état
	// DISTINCT.
	if err := mc.SetMode(ModeMonitor, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}, {KeyID: [16]byte{2}}}}); err != nil {
		t.Fatalf("reconfirmation de monitor avec quorum valide: %v", err)
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("pas passé en monitor après reconfirmation quorée")
	}
	if !mc.Allows(Decision{Allow: true, Reason: ReasonOK}) {
		t.Fatal("monitor reconfirmé bloque encore un allow")
	}
}

// TestModeDefaultDeploymentNotRefused : sans StartRefused (premier
// déploiement, doctrine §5.3 inchangée), le contrôleur démarre en
// monitor — PAS en refused. Témoin de non-régression du chemin par
// défaut.
func TestModeDefaultDeploymentNotRefused(t *testing.T) {
	mc := newTestModeController(t, &stubSink{}, nil, acceptQuorum)
	if mc.Mode() != ModeMonitor {
		t.Fatalf("premier déploiement: mode=%v, veut monitor (§5.3 inchangé)", mc.Mode())
	}
}

// ---------------------------------------------------------------------------
// Parsing de mode (API HTTP du listener).
// ---------------------------------------------------------------------------

func TestParsePEPMode(t *testing.T) {
	for s, want := range map[string]PEPMode{"monitor": ModeMonitor, "closed": ModeClosed} {
		m, err := ParsePEPMode(s)
		if err != nil || m != want {
			t.Fatalf("ParsePEPMode(%q)=%v,%v", s, m, err)
		}
	}
	if _, err := ParsePEPMode("closedd"); err == nil {
		t.Fatal("mode inconnu accepté")
	}
	if _, err := ParsePEPMode(""); err == nil {
		t.Fatal("mode vide accepté")
	}
	// refused n'est JAMAIS une cible atteignable sur le fil (§93) — un
	// état de démarrage exclusivement, jamais un acte gouverné qu'un
	// opérateur pourrait demander.
	if _, err := ParsePEPMode("refused"); err == nil {
		t.Fatal("« refused » accepté comme cible sur le fil — devrait être exclusivement un état de démarrage (§93)")
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration.
// ---------------------------------------------------------------------------

func TestNewModeControllerFailClosed(t *testing.T) {
	base := ModeOptions{
		CellID: opaTestCellID,
		Salt:   testSalt,
		Leaves: &stubSink{},
	}
	if _, err := NewModeController(base); err != nil {
		t.Fatalf("config nominale refusée: %v", err)
	}
	bad := base
	bad.CellID = ""
	if _, err := NewModeController(bad); err == nil {
		t.Fatal("CellID vide accepté")
	}
	bad = base
	bad.Salt = []byte("court")
	if _, err := NewModeController(bad); err == nil {
		t.Fatal("sel < 16 o accepté (§6.2)")
	}
	bad = base
	bad.Leaves = nil
	if _, err := NewModeController(bad); err == nil {
		t.Fatal("Leaves nil accepté (la bascule doit être tracée)")
	}
}

// ---------------------------------------------------------------------------
// Concurrence : SetMode/Mode/Allows simultanés (sous -race).
// ---------------------------------------------------------------------------

func TestModeControllerConcurrent(t *testing.T) {
	sink := &stubSink{}
	mc := newTestModeController(t, sink, nil, acceptQuorum)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 64; i++ {
				_ = mc.Mode()
				_ = mc.Allows(Decision{Allow: i%2 == 0})
				if g%4 == 0 {
					_ = mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}})
					_ = mc.SetMode(ModeMonitor, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}})
				}
			}
		}(g)
	}
	wg.Wait()
}
