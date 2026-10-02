package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

var salt = []byte("sel-de-test-16-octets+")

type fixture struct {
	logDir, records, keyFile, vkey string
	store                          *registry.RecordStore
	log                            *registry.CellLog
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{logDir: t.TempDir()}
	dir := t.TempDir()
	f.keyFile = filepath.Join(dir, "records.key")
	f.records = filepath.Join(dir, "records.jsonl")
	var out, errb bytes.Buffer
	if code := run([]string{"keygen", "-out", f.keyFile}, &out, &errb); code != 0 {
		t.Fatalf("keygen : %d %s", code, errb.String())
	}
	skey, vkey, err := registry.GenerateCellKey("tbp/registry/audit-test")
	if err != nil {
		t.Fatal(err)
	}
	f.vkey = vkey
	signer, _ := note.NewSigner(skey)
	verifier, _ := registry.NewVerifier(vkey)
	f.log, err = registry.Open(ctx, registry.Options{Dir: f.logDir, Signer: signer, Verifier: verifier,
		BatchSize: 1, BatchAge: 10 * time.Millisecond, CheckpointInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.log.Close(ctx) })
	key, err := registry.LoadRecordKey(f.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = registry.OpenRecordStore(f.records, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	for i, rec := range []string{"decision:allow", "decision:deny"} {
		if _, err := registry.AppendSealed(ctx, f.log, f.store, registry.KindDecision, "cell-a", salt, []byte(rec), time.Date(2026, 10, 1, 0, 0, i, 0, time.UTC).UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) verify(extra ...string) (int, string, string) {
	var out, errb bytes.Buffer
	args := append([]string{"verify", "-records", f.records, "-key", f.keyFile}, extra...)
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVerifyAllIncluded(t *testing.T) {
	f := newFixture(t)
	code, out, errs := f.verify("-log", f.logDir, "-vkey", f.vkey, "-reveal")
	if code != 0 {
		t.Fatalf("code %d\n%s%s", code, out, errs)
	}
	for _, want := range []string{"inclus index=0", "inclus index=1", base64.StdEncoding.EncodeToString([]byte("decision:deny")), "0 échec"} {
		if !strings.Contains(out, want) {
			t.Fatalf("sortie sans %q :\n%s", want, out)
		}
	}
	// Sans -reveal, le clair n'est pas affiché.
	_, out, _ = f.verify("-log", f.logDir, "-vkey", f.vkey)
	if strings.Contains(out, "record=") {
		t.Fatalf("clair affiché sans -reveal :\n%s", out)
	}
	// Hors-ligne (sans log) : correspondance du hash seule.
	if code, out, _ := f.verify(); code != 0 || !strings.Contains(out, "hash-ok") {
		t.Fatalf("verify sans log : %d\n%s", code, out)
	}
	// -index ne garde que la feuille demandée.
	code, out, _ = f.verify("-log", f.logDir, "-vkey", f.vkey, "-index", "1")
	if code != 0 || strings.Contains(out, "index=0") || !strings.Contains(out, "index=1") {
		t.Fatalf("-index 1 : %d\n%s", code, out)
	}
	if code, _, _ := f.verify("-log", f.logDir, "-vkey", f.vkey, "-index", "9"); code != 1 {
		t.Fatalf("-index inexistant : code %d, attendu 1", code)
	}
}

func TestVerifyOrphanFails(t *testing.T) {
	f := newFixture(t)
	orphan := registry.Leaf{Kind: registry.KindDecision, CellID: "cell-a", PayloadHash: registry.HashPayload(salt, []byte("jamais-inscrit")), Timestamp: 99}
	if err := f.store.Put(orphan, salt, []byte("jamais-inscrit")); err != nil {
		t.Fatal(err)
	}
	code, out, _ := f.verify("-log", f.logDir, "-vkey", f.vkey)
	if code != 1 || !strings.Contains(out, "ORPHELIN") || !strings.Contains(out, "1 échec") {
		t.Fatalf("orphelin : code %d\n%s", code, out)
	}
	// Hors-ligne, l'orphelin n'est pas détectable (pas de log) : seul le hash est contrôlé.
	if code, _, _ := f.verify(); code != 0 {
		t.Fatalf("hash seul : code %d", code)
	}
}

func TestVerifyRequiresTrustedKey(t *testing.T) {
	f := newFixture(t)
	if code, _, errs := f.verify("-log", f.logDir); code != 2 || !strings.Contains(errs, "vkey") {
		t.Fatalf("-log sans clé publique : code %d %s", code, errs)
	}
	_, otherV, _ := registry.GenerateCellKey("tbp/registry/autre")
	if code, out, _ := f.verify("-log", f.logDir, "-vkey", otherV); code != 1 || !strings.Contains(out, "REJETÉ") {
		t.Fatalf("clé publique d'un autre log : code %d\n%s", code, out)
	}
	if code, _, _ := f.verify("-index", "0"); code != 2 {
		t.Fatalf("-index sans -log : code %d", code)
	}
}

func TestVerifyBadKeyOrJournal(t *testing.T) {
	f := newFixture(t)
	other := filepath.Join(t.TempDir(), "autre.key")
	var o, e bytes.Buffer
	run([]string{"keygen", "-out", other}, &o, &e)
	var out, errb bytes.Buffer
	if code := run([]string{"verify", "-records", f.records, "-key", other}, &out, &errb); code != 2 {
		t.Fatalf("mauvaise clé : code %d", code)
	}
	if err := os.Chmod(f.keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.verify(); code != 2 {
		t.Fatalf("clé lisible par tous : code %d", code)
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("sans sous-commande : code %d", code)
	}
}

// -coverage : la vérification INVERSE. Une feuille du log sans entrée de journal (feuille d'arrêt
// inscrite nue quand le journal refuse, ou antérieure au journal) est listée et fait échouer la commande ;
// sans elle, `verify` ne la voit pas (il va du journal vers le log, pas du log vers le journal).
func TestCoverageListsLeavesWithoutAJournalEntry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// voisin : toutes les feuilles ont leur clair ⇒ couverture complète, code 0
	var code int
	var out, errs string
	for i := 0; i < 100; i++ { // le checkpoint signé suit les feuilles avec un léger retard
		code, out, errs = f.verify("-log", f.logDir, "-vkey", f.vkey, "-coverage")
		if code == 0 || !strings.Contains(out+errs, "absente") && !strings.Contains(out+errs, "checkpoint") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 0 || !strings.Contains(out, "2 feuille(s) dans le log, 0 sans entrée de journal") {
		t.Fatalf("couverture complète refusée : code %d\n%s%s", code, out, errs)
	}

	// une feuille NUE : inscrite sans clair (comme la feuille d'arrêt quand le journal refuse)
	bare := registry.Leaf{Kind: registry.KindBackpressure, CellID: "cell-a", PayloadHash: registry.HashPayload(salt, []byte("arret")), Timestamp: time.Date(2026, 10, 1, 0, 0, 9, 0, time.UTC).UnixNano()}
	if _, err := f.log.Append(ctx, bare); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		code, out, errs = f.verify("-log", f.logDir, "-vkey", f.vkey, "-coverage")
		if strings.Contains(out, "3 feuille(s) dans le log") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 1 || !strings.Contains(out, "index=2 kind=3") || !strings.Contains(out, "SANS-CLAIR") || !strings.Contains(out, "3 feuille(s) dans le log, 1 sans entrée de journal") {
		t.Fatalf("feuille nue non listée : code %d\n%s%s", code, out, errs)
	}
	// sans -coverage, verify ne la voit pas : le journal est intact (c'est la raison d'être du mode)
	if code, out, errs := f.verify("-log", f.logDir, "-vkey", f.vkey); code != 0 {
		t.Fatalf("verify sans -coverage : code %d\n%s%s", code, out, errs)
	}
	// -coverage exige -log
	if code, _, errs := f.verify("-coverage"); code != 2 || !strings.Contains(errs, "-coverage exige -log") {
		t.Fatalf("-coverage sans -log : code %d %s", code, errs)
	}
}
