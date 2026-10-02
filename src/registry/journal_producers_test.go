package registry

// journal_producers_test.go — #275 : les producteurs de feuilles de ce paquet (manifeste, provisionnement,
// ancrage, arrêt de backpressure, épisode de durabilité) laissent leur clair dans le journal AVANT leur
// feuille ; un journal qui refuse d'écrire ⇒ aucune feuille inscrite.

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openProducerJournal(t *testing.T) (*RecordStore, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{9}, RecordKeyLen)
	j, err := OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j, path, key
}

// requireJournaled : le journal porte exactement un enregistrement, que sa feuille est la feuille inscrite,
// que le hash est celui du clair, et que le clair commence par prefix.
func requireJournaled(t *testing.T, path string, key []byte, leaf Leaf, prefix string) {
	t.Helper()
	recs, err := ReadRecords(path, key)
	if err != nil || len(recs) != 1 {
		t.Fatalf("journal : %d enregistrements (err=%v), attendu 1", len(recs), err)
	}
	if recs[0].Leaf != leaf {
		t.Fatalf("la feuille du journal n'est pas celle inscrite :\n journal %+v\n inscrite %+v", recs[0].Leaf, leaf)
	}
	if err := recs[0].VerifyHash(); err != nil {
		t.Fatalf("hash du clair : %v", err)
	}
	if !bytes.HasPrefix(recs[0].Record, []byte(prefix)) {
		t.Fatalf("clair %q ne commence pas par %q", recs[0].Record, prefix)
	}
}

func TestManifestLeafIsJournaled(t *testing.T) {
	ctx := context.Background()
	j, path, key := openProducerJournal(t)
	sink := &stubMaster{}
	signer, verifier := manifestTestKey(t)
	m, err := NewManifester(ManifestOptions{
		CellID: manifestCellID, Signer: signer, Verifier: verifier,
		Leaves: sink, Journal: j, Salt: manifestSalt, Now: newFakeClock(time.Unix(1_780_000_000, 0)).now,
	})
	if err != nil {
		t.Fatal(err)
	}
	st := manifestStateFixture("p", "o", "b", "a", [32]byte{1})
	if _, err := m.Genesis(ctx, 7, st); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	ls := sink.taken()
	if len(ls) != 1 {
		t.Fatalf("%d feuilles", len(ls))
	}
	requireJournaled(t, path, key, ls[0], "TBPL2")

	// journal HS : la transition n'inscrit aucune feuille
	_ = j.Close()
	if _, err := m.Transition(ctx, 8, manifestStateFixture("p2", "o", "b", "a", [32]byte{2})); err == nil {
		t.Fatal("transition acceptée sans clair journalisé — fail-closed violé")
	}
	if n := len(sink.taken()); n != 1 {
		t.Fatalf("%d feuilles : une feuille a été inscrite sans clair journalisé", n)
	}
}

func TestProvisioningLeafIsJournaled(t *testing.T) {
	ctx := context.Background()
	j, path, key := openProducerJournal(t)
	e := newProvEnv(t, func(o *ProvisioningGuardOptions) { o.Journal = j })
	if err := e.guard().Check(ctx); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	if e.leaves.count() != 1 {
		t.Fatalf("%d feuilles", e.leaves.count())
	}
	requireJournaled(t, path, key, e.leaves.got[0], "TBPL3")

	// journal HS : plus de feuille ⇒ le garde refuse (ErrProvisioningLeafFault), jamais « conforme »
	_ = j.Close()
	e.log.size = 1
	if err := e.guard().Check(ctx); err == nil {
		t.Fatal("démarrage accepté sans clair journalisé — fail-closed violé")
	}
	if e.leaves.count() != 1 {
		t.Fatalf("%d feuilles : une feuille a été inscrite sans clair journalisé", e.leaves.count())
	}
}

func TestAnchorLeafIsJournaled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	j, path, key := openProducerJournal(t)
	clock := newFakeClock(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC))
	a, cell, master := newTestAnchorer(t, ctx, clock, &fakeTSA{genTime: clock.now}, &anchorTripLog{}, &anchorTripLog{},
		func(o *AnchorerOptions) { o.Journal = j })
	seedCell(t, ctx, cell)
	if err := a.AnchorOnce(ctx); err != nil {
		t.Fatalf("AnchorOnce : %v", err)
	}
	_, size, err := master.Head(ctx)
	if err != nil || size != 1 {
		t.Fatalf("master : taille %d (err=%v)", size, err)
	}
	requireJournaled(t, path, key, readLeafAt(t, master, size, 0), "")

	// journal HS : l'ancrage échoue (rattrapé plus tard) et la master ne reçoit aucune feuille
	_ = j.Close()
	clock.advance(time.Minute)
	if err := a.AnchorOnce(ctx); err == nil {
		t.Fatal("ancrage accepté sans clair journalisé — fail-closed violé")
	}
	if _, size2, _ := master.Head(ctx); size2 != 1 {
		t.Fatalf("master : %d feuilles, une feuille d'ancrage a été inscrite sans clair journalisé", size2)
	}
}

func TestBackpressureStopLeafIsJournaled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, journalDown := range []bool{false, true} {
		j, path, key := openProducerJournal(t)
		if journalDown {
			_ = j.Close()
		}
		var box alarmBox
		log, mon := wireMonitor(t, ctx, t.TempDir(), MonitorOptions{
			CellID: "cell-t5", QuotaBytes: 1 << 40, HostFloorBytes: 1 << 30,
			Fs: fakeFs{free: 1 << 20}, Interval: 5 * time.Millisecond, Journal: j,
			OnAlarm: func(a Alarm) { box.store(a) },
		})
		go mon.Run(ctx)
		alarm := waitAlarm(t, &box, 10*time.Second)
		_, size, err := log.Head(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if journalDown {
			// le verrouillage tient, la feuille n'est pas inscrite, l'alarme le dit
			if size != 0 || !bytes.HasSuffix([]byte(alarm.Reason), []byte("+leaf-write-failed")) {
				t.Fatalf("journal HS : taille %d, alarme %q — feuille inscrite sans clair, ou défaillance non signalée", size, alarm.Reason)
			}
		} else {
			if size != 1 {
				t.Fatalf("taille %d, attendu la feuille d'arrêt", size)
			}
			requireJournaled(t, path, key, readLeafAt(t, log, size, 0), `{"reason"`)
		}
		_ = log.Close(ctx)
	}
}

func TestAsyncEpisodeLeafIsJournaled(t *testing.T) {
	ctx := context.Background()
	for _, journalDown := range []bool{false, true} {
		j, path, key := openProducerJournal(t)
		rawSigner, verifier := asyncTestKeys(t)
		signer := &gatedSigner{inner: rawSigner}
		log := openAsyncLog(t, ctx, t.TempDir(), signer, verifier, nil, 100*time.Millisecond)
		trips := make(chan string, 4)
		clears := make(chan struct{}, 4)
		w, err := NewAsyncWriter(log, AsyncOptions{
			CellID: "cell-async", Salt: []byte("sel-async-16oct!"), Window: 500 * time.Millisecond, Journal: j,
			OnTrip: func(d string) { trips <- d }, OnClear: func() { clears <- struct{}{} },
		})
		if err != nil {
			t.Fatal(err)
		}
		signer.block()
		for i := 0; i < 3; i++ {
			if _, err := w.Append(ctx, asyncLeaf(i)); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case <-trips:
		case <-time.After(4 * time.Second):
			t.Fatal("coupure jamais déclenchée")
		}
		if journalDown {
			_ = j.Close()
		}
		signer.unblock()
		select {
		case <-clears:
		case <-time.After(10 * time.Second):
			t.Fatal("rattrapage jamais confirmé")
		}
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		if err := w.WaitOutstanding(dctx); err != nil {
			t.Fatal(err)
		}
		dcancel()
		if journalDown {
			time.Sleep(300 * time.Millisecond)
			if size := waitHead(t, ctx, log, 3, 5*time.Second); size != 3 {
				t.Fatalf("taille %d : une feuille d'épisode a été inscrite sans clair journalisé", size)
			}
		} else {
			size := waitHead(t, ctx, log, 4, 5*time.Second)
			if size != 4 {
				t.Fatalf("taille %d, attendu 4", size)
			}
			requireJournaled(t, path, key, readLeafAt(t, log, size, 3), `{"record":"TBAD1"`)
		}
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = w.Close(c)
		_ = log.Close(c)
		cancel()
	}
}
