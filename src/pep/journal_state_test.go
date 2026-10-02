package pep

// journal_state_test.go — #275 : les feuilles d'ÉTAT et d'ALARME du PEP (déclenchement
// fail-closed, horloge, bascule de mode, révision OPA, télémétrie dry-run) laissent
// leur clair dans le journal ; un journal qui refuse d'écrire ⇒ aucune feuille et
// l'alarme leaf-write-failed.

import (
	"context"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type stateProducer struct {
	name   string
	prefix string
	// build construit le producteur avec le journal j ; trigger écrit UNE feuille ;
	// alarms rend les raisons d'alarme levées.
	build func(t *testing.T, sink *stubSink, j *registry.RecordStore) (trigger func(), alarms func() []string)
}

func stateProducers() []stateProducer {
	now := func() time.Time { return time.Unix(testIAT+30, 0) }
	return []stateProducer{
		{"failclosed", "TBFF1", func(t *testing.T, sink *stubSink, j *registry.RecordStore) (func(), func() []string) {
			rec := &tripRecorder{}
			fc, err := NewFailClosed(FailClosedOptions{CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Journal: j, OnAlarm: rec.trip, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			return func() { fc.Trip(ReasonOPAUnreachable, "sidecar injoignable") }, func() []string { return rec.reasons }
		}},
		{"clock", "TBPC1", func(t *testing.T, sink *stubSink, j *registry.RecordStore) (func(), func() []string) {
			rec := &tripRecorder{}
			p := &stubProbe{}
			p.set(ClockSample{Unsync: true, EstError: time.Millisecond}, nil)
			w, err := NewClockWatchdog(ClockOptions{Probe: p.probe, LocalIssuer: localTestIssuer, CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Journal: j, OnTrip: rec.trip, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			return func() { w.Check() }, func() []string { return rec.reasons }
		}},
		{"mode", "TBPM1", func(t *testing.T, sink *stubSink, j *registry.RecordStore) (func(), func() []string) {
			rec := &tripRecorder{}
			mc, err := NewModeController(ModeOptions{CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Journal: j, VerifyQuorum: acceptQuorum, QuorumState: acceptQuorumState{}, OnAlarm: rec.trip, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			proof := QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}, {KeyID: [16]byte{2}}}}
			return func() { _ = mc.SetMode(ModeClosed, proof) }, func() []string { return rec.reasons }
		}},
		{"opa-revision", "TBPR1", func(t *testing.T, sink *stubSink, j *registry.RecordStore) (func(), func() []string) {
			stub := newRevisionStub(t, "imposteur-revision")
			var reasons []string
			w, err := NewOPARevisionWatcher(OPARevisionWatcherOptions{
				Endpoint: stub.srv.URL + "/v1/data/tbp/allow", Expected: "deadbeef", CellID: opaTestCellID, Salt: testSalt,
				Leaves: sink, Journal: j, OnTrip: func(r string) { reasons = append(reasons, r) }, Now: now,
			})
			if err != nil {
				t.Fatal(err)
			}
			return func() { w.Check(context.Background()) }, func() []string { return reasons }
		}},
		{"dryrun-telemetry", "TBPF2", func(t *testing.T, sink *stubSink, j *registry.RecordStore) (func(), func() []string) {
			var reasons []string
			g, err := NewDryRunGate(DryRunGateOptions{
				Runner: &stubRunner{diff: nominalDiff()}, CellID: "cell-a", Salt: testSalt, Leaves: sink, Journal: j,
				OnAlarm: func(r string) { reasons = append(reasons, r) },
			})
			if err != nil {
				t.Fatal(err)
			}
			return func() { g.Execute(context.Background(), [16]byte{1}, "transfer", "account/42") }, func() []string { return reasons }
		}},
	}
}

func TestStateAndAlarmLeavesAreJournaled(t *testing.T) {
	for _, p := range stateProducers() {
		t.Run(p.name, func(t *testing.T) {
			sink := &stubSink{}
			j, path, key := testJournal(t)
			trigger, _ := p.build(t, sink, j)
			trigger()
			if sink.count() == 0 {
				t.Fatal("aucune feuille écrite : le déclencheur de test est sans effet")
			}
			assertJournaled(t, path, key, sink, p.prefix)

		})
		// journal HS : une instance NEUVE (ces producteurs sont verrouillés/idempotents une fois
		// déclenchés) — aucune feuille, alarme leaf-write-failed
		t.Run(p.name+"/journal-hs", func(t *testing.T) {
			sink := &stubSink{}
			j, _, _ := testJournal(t)
			_ = j.Close()
			trigger, alarms := p.build(t, sink, j)
			trigger()
			if sink.count() != 0 {
				t.Fatalf("%d feuille(s) inscrite(s) sans clair journalisé", sink.count())
			}
			found := false
			for _, r := range alarms() {
				if r == ReasonLeafWriteFailed {
					found = true
				}
			}
			if !found {
				t.Fatalf("alarmes %v, veut %s", alarms(), ReasonLeafWriteFailed)
			}
		})
	}
}
