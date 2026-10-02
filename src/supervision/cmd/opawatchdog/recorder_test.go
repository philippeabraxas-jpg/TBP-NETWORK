package main

// Le vrai enregistreur : une vraie chaîne (CellLog signé) et un vrai journal d'audit. Ce qui est feuillé est exactement ce
// qu'un auditeur vérifiera avec `tbp-audit verify`.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/client"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

func TestLeafRecorderWritesVerifiableLeafAndJournal(t *testing.T) {
	ctx := context.Background()
	regDir := filepath.Join(t.TempDir(), "reg")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		t.Fatal(err)
	}
	signer, vkey, err := loadOrGenerateCellKey(regDir, "opawd-cell-a")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := registry.Open(ctx, registry.Options{Dir: regDir, Signer: signer, Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	jpath := filepath.Join(t.TempDir(), "audit.jnl")
	key := bytes.Repeat([]byte{9}, registry.RecordKeyLen)
	j, err := registry.OpenRecordStore(jpath, key)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	rec := &leafRecorder{sink: lg, journal: j, logID: "opawd-cell-a", cellID: "cell-a", now: time.Now}
	detail := []byte(`{"unit":"tbp-opa.service"}`)
	if err := rec.Record(ctx, supervision.AlertEventOPARestart, supervision.AlertVerdictNotice, "opa-restart-requested", detail); err != nil {
		t.Fatal(err)
	}

	recs, err := registry.ReadRecords(jpath, key)
	if err != nil || len(recs) != 1 {
		t.Fatalf("journal : %d enregistrements (err=%v)", len(recs), err)
	}
	r := recs[0]
	if r.Leaf.Kind != registry.KindSupervision || r.Leaf.CellID != "opawd-cell-a" || r.VerifyHash() != nil {
		t.Fatalf("feuille = %+v", r.Leaf)
	}
	parsed, err := supervision.ParseAlertRecord(r.Record)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Event != supervision.AlertEventOPARestart || parsed.CellID != "cell-a" || parsed.Reason != "opa-restart-requested" || parsed.Verdict != supervision.AlertVerdictNotice {
		t.Fatalf("record = %+v", parsed)
	}
	// l'inclusion dans le log signé (ce que vérifie un auditeur)
	var vErr error
	for try := 0; try < 100; try++ {
		if _, vErr = r.VerifyInLog(ctx, client.FileFetcher{Root: regDir}, verifier); vErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if vErr != nil {
		t.Fatalf("la feuille doit être prouvée dans le log signé : %v", vErr)
	}

	// un journal HS ⇒ erreur (la feuille n'existe pas) : l'appelant ne redémarre pas
	_ = j.Close()
	if err := rec.Record(ctx, supervision.AlertEventOPARestart, supervision.AlertVerdictNotice, "opa-restart-requested", detail); err == nil {
		t.Fatal("journal fermé : une erreur est attendue (pas de feuille sans clair journalisé)")
	}
	_ = lg.Close(ctx)
}
