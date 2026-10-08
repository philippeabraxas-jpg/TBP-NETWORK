package pep

// mode_restrict_test.go — restreindre n'est pas élargir (revue des consoles, point C1) : la bascule
// monitor → closed peut passer avec un quorum réduit ; le retour à monitor et la sortie de ModeRefused
// exigent toujours le quorum complet. Chaque refus a son cas voisin accepté ; chaque test échoue si on retire
// la règle qu'il couvre.

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// reducedController : le vérifieur complet et le vérifieur réduit sont des doubles que le test pilote.
func reducedController(t *testing.T, sink *stubSink, alarm *tripRecorder, full, restrict QuorumVerifier, startRefused bool) *ModeController {
	t.Helper()
	mc, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: sink, OnAlarm: alarm.trip,
		VerifyQuorum: full, VerifyRestrict: restrict, QuorumState: acceptQuorumState{},
		StartRefused: startRefused, Now: func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return mc
}

var oneSig = QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}

func TestModeClosingMayUseAReducedQuorum(t *testing.T) {
	sink, alarm := &stubSink{}, &tripRecorder{}
	mc := reducedController(t, sink, alarm, rejectQuorum, acceptQuorum, false)
	if err := mc.SetMode(ModeClosed, oneSig); err != nil {
		t.Fatalf("fermer avec le quorum réduit refusé : %v", err)
	}
	if mc.Mode() != ModeClosed {
		t.Fatal("pas en closed")
	}
	// la feuille habituelle ET la trace de la réduction
	if sink.count() != 2 {
		t.Fatalf("feuilles=%d, veut 2 (bascule + quorum réduit)", sink.count())
	}
	if got := sink.leaves[0].PayloadHash; got != hashOf(modeChangeRecord(ModeClosed)) {
		t.Fatal("la première feuille n'est pas la bascule habituelle")
	}
	if got := sink.leaves[1].PayloadHash; got != hashOf(modeReducedRecord(ModeClosed)) {
		t.Fatal("la seconde feuille n'est pas la trace du quorum réduit")
	}
	if len(alarm.reasons) != 2 || alarm.reasons[0] != "mode-closed" || alarm.reasons[1] != ReasonModeReducedQuorum {
		t.Fatalf("alarmes=%v, veut mode-closed puis %s", alarm.reasons, ReasonModeReducedQuorum)
	}
}

// Cas voisin : une preuve COMPLÈTE passe comme avant, sans trace de réduction.
func TestModeClosingWithFullQuorumLeavesNoReductionTrace(t *testing.T) {
	sink, alarm := &stubSink{}, &tripRecorder{}
	mc := reducedController(t, sink, alarm, acceptQuorum, acceptQuorum, false)
	if err := mc.SetMode(ModeClosed, oneSig); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 1 || len(alarm.reasons) != 1 || alarm.reasons[0] != "mode-closed" {
		t.Fatalf("feuilles=%d alarmes=%v : une preuve complète ne doit laisser aucune trace de réduction", sink.count(), alarm.reasons)
	}
}

// Élargir exige TOUJOURS le quorum complet : le vérifieur réduit n'est jamais consulté pour le retour à monitor.
func TestModeLooseningNeverUsesTheReducedQuorum(t *testing.T) {
	sink, alarm := &stubSink{}, &tripRecorder{}
	mc := reducedController(t, sink, alarm, acceptQuorum, rejectQuorum, false)
	if err := mc.SetMode(ModeClosed, oneSig); err != nil {
		t.Fatal(err)
	}
	// le quorum complet se met à refuser ; le réduit, lui, accepterait
	mc.SetQuorumVerifier(rejectQuorum)
	mc.SetRestrictVerifier(acceptQuorum)
	if err := mc.SetMode(ModeMonitor, oneSig); !errors.Is(err, ErrQuorumRejected) {
		t.Fatalf("retour à monitor avec le seul quorum réduit : %v", err)
	}
	if mc.Mode() != ModeClosed {
		t.Fatal("le mode a changé malgré le refus")
	}
	// cas voisin : le quorum complet rouvre
	mc.SetQuorumVerifier(acceptQuorum)
	if err := mc.SetMode(ModeMonitor, oneSig); err != nil {
		t.Fatalf("retour à monitor avec le quorum complet : %v", err)
	}
}

// Sortir de ModeRefused (#93) est un élargissement, même vers closed.
func TestModeLeavingRefusedNeverUsesTheReducedQuorum(t *testing.T) {
	for _, target := range []PEPMode{ModeClosed, ModeMonitor} {
		sink, alarm := &stubSink{}, &tripRecorder{}
		mc := reducedController(t, sink, alarm, rejectQuorum, acceptQuorum, true)
		if mc.Mode() != ModeRefused {
			t.Fatal("le contrôleur ne démarre pas refusé")
		}
		if err := mc.SetMode(target, oneSig); !errors.Is(err, ErrQuorumRejected) {
			t.Fatalf("sortie de refused vers %s avec le quorum réduit : %v", target, err)
		}
		if mc.Mode() != ModeRefused {
			t.Fatalf("le mode a quitté refused vers %s malgré le refus", target)
		}
		mc.SetQuorumVerifier(acceptQuorum)
		if err := mc.SetMode(target, oneSig); err != nil {
			t.Fatalf("sortie de refused vers %s avec le quorum complet : %v", target, err)
		}
	}
}

// Sans vérifieur réduit, aucune réduction : le comportement historique.
func TestModeWithoutRestrictVerifierKeepsTheFullQuorum(t *testing.T) {
	sink, alarm := &stubSink{}, &tripRecorder{}
	mc := reducedController(t, sink, alarm, rejectQuorum, nil, false)
	if err := mc.SetMode(ModeClosed, oneSig); !errors.Is(err, ErrQuorumRejected) {
		t.Fatalf("fermer sans quorum complet ni vérifieur réduit : %v", err)
	}
}

// Un quorum réduit reste soumis à l'antirejeu persistant : une preuve consommée ne sert pas deux fois.
type replayedState struct{}

func (replayedState) Consume(string, int64) (bool, error) { return false, nil }

func TestModeReducedQuorumIsStillReplayProtected(t *testing.T) {
	sink, alarm := &stubSink{}, &tripRecorder{}
	mc := reducedController(t, sink, alarm, rejectQuorum, acceptQuorum, false)
	mc.SetQuorumState(replayedState{})
	if err := mc.SetMode(ModeClosed, oneSig); !errors.Is(err, ErrQuorumReplayed) {
		t.Fatalf("preuve réduite rejouée : %v", err)
	}
	if mc.Mode() != ModeMonitor || sink.count() != 0 {
		t.Fatal("un rejeu a changé le mode ou laissé une feuille")
	}
}

// De bout en bout avec de vraies signatures : 3 contrôleurs, k = 2, fermeture à 1.
func TestModeRestrictionWithRealSignatures(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	pub3, _ := mustGenKey(t)
	kid1, kid2, kid3 := [16]byte{1}, [16]byte{2}, [16]byte{3}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2, kid3: pub3}
	full, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	reduced, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 1, 5*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink, alarm := &stubSink{}, &tripRecorder{}
	mc := reducedController(t, sink, alarm, full, reduced, false)
	exp := time.Now().Add(time.Minute)

	// un inconnu ne ferme rien
	_, strangerPriv := mustGenKey(t)
	if err := mc.SetMode(ModeClosed, QuorumProof{Expiry: exp, Signatures: []QuorumSignature{signQuorum(strangerPriv, [16]byte{9}, "mode-closed", opaTestCellID, exp)}}); err == nil {
		t.Fatal("un inconnu a fermé la cellule")
	}
	// une signature d'un contrôleur du trousseau ferme
	if err := mc.SetMode(ModeClosed, QuorumProof{Expiry: exp, Signatures: []QuorumSignature{signQuorum(priv1, kid1, "mode-closed", opaTestCellID, exp)}}); err != nil {
		t.Fatalf("une signature de contrôleur n'a pas fermé : %v", err)
	}
	// rouvrir avec UNE signature : refusé
	exp2 := time.Now().Add(time.Minute)
	if err := mc.SetMode(ModeMonitor, QuorumProof{Expiry: exp2, Signatures: []QuorumSignature{signQuorum(priv1, kid1, "mode-monitor", opaTestCellID, exp2)}}); err == nil {
		t.Fatal("rouvrir avec une seule signature")
	}
	// une preuve de FERMETURE ne rouvre pas (condition liée)
	if err := mc.SetMode(ModeMonitor, QuorumProof{Expiry: exp, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-closed", opaTestCellID, exp), signQuorum(priv2, kid2, "mode-closed", opaTestCellID, exp)}}); err == nil {
		t.Fatal("une preuve de fermeture a rouvert la cellule")
	}
	// deux signatures de la condition juste rouvrent
	if err := mc.SetMode(ModeMonitor, QuorumProof{Expiry: exp2, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-monitor", opaTestCellID, exp2), signQuorum(priv2, kid2, "mode-monitor", opaTestCellID, exp2)}}); err != nil {
		t.Fatalf("rouvrir avec k signatures : %v", err)
	}
}

// hashOf : l'engagement d'un record de feuille (même sel que les tests de mode).
func hashOf(record []byte) [32]byte { return registry.HashPayload(testSalt, record) }
