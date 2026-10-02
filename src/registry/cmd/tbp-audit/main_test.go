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
	// couverture par défaut : le log est illisible sous cette clé, mais les enregistrements déjà rejetés font un échec (1), pas un usage (2)
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
	// la couverture est le DÉFAUT avec -log : sans le drapeau, la feuille nue est vue quand même
	if code, out, _ := f.verify("-log", f.logDir, "-vkey", f.vkey); code != 1 || !strings.Contains(out, "SANS-CLAIR") {
		t.Fatalf("verify avec -log seul doit vérifier la couverture : code %d\n%s", code, out)
	}
	// -no-coverage la désactive EXPLICITEMENT, et le dit : « 0 échec » ne dit pas « journal complet »
	if code, out, errs := f.verify("-log", f.logDir, "-vkey", f.vkey, "-no-coverage"); code != 0 || strings.Contains(out, "SANS-CLAIR") ||
		!strings.Contains(errs, "couverture NON vérifiée") {
		t.Fatalf("-no-coverage : code %d\n%s%s", code, out, errs)
	}
	// -coverage exige -log
	if code, _, errs := f.verify("-coverage"); code != 2 || !strings.Contains(errs, "-coverage exige -log") {
		t.Fatalf("-coverage sans -log : code %d %s", code, errs)
	}
}

// Revue tierce du 2 octobre, 4.5 : une entrée EFFACÉE du journal passait avec « 0 échec » tant que la couverture
// n'était pas demandée. Désormais -log la vérifie par défaut.
func TestDeletedJournalEntryIsDetectedByDefault(t *testing.T) {
	f := newFixture(t)
	// le journal de 2 entrées : on efface la seconde
	raw, err := os.ReadFile(f.records)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("journal de %d lignes, 2 attendues", len(lines))
	}
	if err := os.WriteFile(f.records, append(lines[0], '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var code int
	var out, errs string
	for i := 0; i < 100; i++ { // le checkpoint signé suit les feuilles avec un léger retard
		code, out, errs = f.verify("-log", f.logDir, "-vkey", f.vkey)
		if strings.Contains(out, "2 feuille(s) dans le log") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 1 || !strings.Contains(out, "SANS-CLAIR") || !strings.Contains(out, "2 feuille(s) dans le log, 1 sans entrée de journal") {
		t.Fatalf("entrée effacée non détectée : code %d\n%s%s", code, out, errs)
	}
	// l'ancien comportement reste possible, mais explicite et signalé
	if code, _, errs := f.verify("-log", f.logDir, "-vkey", f.vkey, "-no-coverage"); code != 0 || !strings.Contains(errs, "couverture NON vérifiée") {
		t.Fatalf("-no-coverage : code %d %s", code, errs)
	}
}

func TestCoverageFlagsAndWarnings(t *testing.T) {
	f := newFixture(t)
	// les deux drapeaux s'excluent
	if code, _, errs := f.verify("-log", f.logDir, "-vkey", f.vkey, "-coverage", "-no-coverage"); code != 2 || !strings.Contains(errs, "s'excluent") {
		t.Fatalf("-coverage -no-coverage : code %d %s", code, errs)
	}
	// hash seul (sans -log) : l'avertissement dit ce qui n'est PAS vérifié
	if code, _, errs := f.verify(); code != 0 || !strings.Contains(errs, "seule la correspondance hash") {
		t.Fatalf("sans -log : code %d %s", code, errs)
	}
	// -index : vérification ciblée, pas de couverture (et le dit) ; -coverage la rétablit
	var out, errs string
	var code int
	for i := 0; i < 100; i++ {
		code, out, errs = f.verify("-log", f.logDir, "-vkey", f.vkey, "-index", "0")
		if code == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if code != 0 || strings.Contains(out, "feuille(s) dans le log") || !strings.Contains(errs, "couverture NON vérifiée") {
		t.Fatalf("-index : code %d\n%s%s", code, out, errs)
	}
	if code, out, errs := f.verify("-log", f.logDir, "-vkey", f.vkey, "-index", "0", "-coverage"); code != 0 || !strings.Contains(out, "feuille(s) dans le log") || strings.Contains(errs, "NON vérifiée") {
		t.Fatalf("-index -coverage : code %d\n%s%s", code, out, errs)
	}
	// couverture complète, sans avertissement
	if code, out, errs := f.verify("-log", f.logDir, "-vkey", f.vkey); code != 0 || !strings.Contains(out, "0 sans entrée de journal") || errs != "" {
		t.Fatalf("complet : code %d\n%s%s", code, out, errs)
	}
}
