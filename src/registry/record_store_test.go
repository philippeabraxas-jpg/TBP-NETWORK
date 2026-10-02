// src/registry/record_store_test.go — #271
package registry

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/client"
)

func testRecordKey(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "records.key")
	if err := GenerateRecordKey(p); err != nil {
		t.Fatalf("GenerateRecordKey: %v", err)
	}
	k, err := LoadRecordKey(p)
	if err != nil {
		t.Fatalf("LoadRecordKey: %v", err)
	}
	return k
}

var testSalt = []byte("sel-de-test-16-octets+")

func TestRecordStoreRoundTripAndInclusion(t *testing.T) {
	ctx := context.Background()
	logDir := t.TempDir()
	log, verifier := openTestLog(t, ctx, logDir, nil)
	defer log.Close(ctx)

	key := testRecordKey(t)
	storePath := filepath.Join(t.TempDir(), "records.jsonl")
	store, err := OpenRecordStore(storePath, key)
	if err != nil {
		t.Fatalf("OpenRecordStore: %v", err)
	}
	defer store.Close()

	records := [][]byte{[]byte("decision:allow:jti-1"), []byte("decision:deny:jti-2"), []byte("manifest:boot")}
	for i, rec := range records {
		ts := time.Date(2026, 10, 1, 12, 0, i, 0, time.UTC).UnixNano()
		idx, err := AppendSealed(ctx, log, store, KindDecision, "cell-a", testSalt, rec, ts)
		if err != nil {
			t.Fatalf("AppendSealed(%d): %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("index %d, attendu %d", idx, i)
		}
	}

	got, err := ReadRecords(storePath, key)
	if err != nil {
		t.Fatalf("ReadRecords: %v", err)
	}
	if len(got) != len(records) {
		t.Fatalf("%d enregistrements relus, attendu %d", len(got), len(records))
	}
	// Le log est relu par un auditeur qui n'a que la clé publique et le répertoire.
	fetch := client.FileFetcher{Root: logDir}
	for i, r := range got {
		if !bytes.Equal(r.Record, records[i]) || !bytes.Equal(r.Salt, testSalt) {
			t.Fatalf("enregistrement %d : clair relu différent", i)
		}
		idx, err := r.VerifyInLog(ctx, fetch, verifier)
		if err != nil {
			t.Fatalf("VerifyInLog(%d): %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("enregistrement %d retrouvé à l'index %d", i, idx)
		}
	}

	// Le fichier ne contient ni le clair ni le sel.
	raw, _ := os.ReadFile(storePath)
	for _, secret := range [][]byte{records[0], testSalt} {
		if bytes.Contains(raw, secret) {
			t.Fatalf("le journal contient %q en clair", secret)
		}
	}
}

func TestRecordStoreRefusesRecordNotMatchingLeaf(t *testing.T) {
	store, err := OpenRecordStore(filepath.Join(t.TempDir(), "r.jsonl"), testRecordKey(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	leaf := Leaf{Kind: KindDecision, CellID: "c", PayloadHash: HashPayload(testSalt, []byte("vrai")), Timestamp: 1}
	if err := store.Put(leaf, testSalt, []byte("faux")); !errors.Is(err, ErrRecordHashMismatch) {
		t.Fatalf("Put d'un clair qui n'explique pas la feuille : %v, attendu ErrRecordHashMismatch", err)
	}
	// Voisin : le bon clair passe.
	if err := store.Put(leaf, testSalt, []byte("vrai")); err != nil {
		t.Fatalf("Put du bon clair : %v", err)
	}
	// Sel trop court / horodatage nul refusés.
	if err := store.Put(leaf, []byte("court"), []byte("vrai")); err == nil {
		t.Fatal("sel court accepté")
	}
	leaf.Timestamp = 0
	if err := store.Put(leaf, testSalt, []byte("vrai")); err == nil {
		t.Fatal("horodatage nul accepté")
	}
}

// Un journal qui refuse d'écrire ne doit laisser AUCUNE feuille au registre :
// pas de feuille dont le clair n'existe pas.
func TestAppendSealedNoLeafWhenStoreRefuses(t *testing.T) {
	ctx := context.Background()
	log, _ := openTestLog(t, ctx, t.TempDir(), nil)
	defer log.Close(ctx)
	store, err := OpenRecordStore(filepath.Join(t.TempDir(), "r.jsonl"), testRecordKey(t))
	if err != nil {
		t.Fatal(err)
	}
	store.Close() // l'écriture échouera

	if _, err := AppendSealed(ctx, log, store, KindDecision, "cell-a", testSalt, []byte("x"), 1); err == nil {
		t.Fatal("AppendSealed a réussi alors que le journal est fermé")
	}
	_, size, err := log.Head(ctx)
	if err == nil && size != 0 {
		t.Fatalf("une feuille a été inscrite sans clair (taille %d)", size)
	}
}

func TestRecordStoreTamperAndWrongKey(t *testing.T) {
	key := testRecordKey(t)
	path := filepath.Join(t.TempDir(), "r.jsonl")
	store, _ := OpenRecordStore(path, key)
	l1 := Leaf{Kind: KindDecision, CellID: "c", PayloadHash: HashPayload(testSalt, []byte("a")), Timestamp: 1}
	l2 := Leaf{Kind: KindDecision, CellID: "c", PayloadHash: HashPayload(testSalt, []byte("b")), Timestamp: 2}
	if err := store.Put(l1, testSalt, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(l2, testSalt, []byte("b")); err != nil {
		t.Fatal(err)
	}
	store.Close()

	if _, err := ReadRecords(path, testRecordKey(t)); !errors.Is(err, ErrRecordUndecryptable) {
		t.Fatalf("mauvaise clé : %v, attendu ErrRecordUndecryptable", err)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	// Feuille éditée dans le fichier (même ciphertext) : l'AAD ne correspond plus.
	d1, _ := l1.Marshal()
	d2, _ := l2.Marshal()
	edited := strings.Replace(lines[0], hexOf(d1), hexOf(d2), 1)
	if edited == lines[0] {
		t.Fatal("édition de test sans effet")
	}
	writeLines(t, path, edited, lines[1])
	if _, err := ReadRecords(path, key); !errors.Is(err, ErrRecordUndecryptable) {
		t.Fatalf("feuille éditée : %v, attendu ErrRecordUndecryptable", err)
	}

	// Entrées permutées sous l'autre feuille : idem.
	swapped := swapField(t, lines[0], lines[1])
	writeLines(t, path, swapped, lines[1])
	if _, err := ReadRecords(path, key); !errors.Is(err, ErrRecordUndecryptable) {
		t.Fatalf("entrée déplacée sous une autre feuille : %v", err)
	}

	// Octet de ciphertext altéré.
	writeLines(t, path, strings.Replace(lines[0], `"ct":"`, `"ct":"AAAA`, 1), lines[1])
	if _, err := ReadRecords(path, key); err == nil {
		t.Fatal("ciphertext altéré accepté")
	}

	// Voisin : le fichier d'origine se relit.
	writeLines(t, path, lines...)
	if got, err := ReadRecords(path, key); err != nil || len(got) != 2 {
		t.Fatalf("fichier intact : %d entrées, err=%v", len(got), err)
	}

	// Champ inconnu / ligne vide : refus strict.
	writeLines(t, path, strings.Replace(lines[0], `{"v":1,`, `{"v":1,"x":1,`, 1))
	if _, err := ReadRecords(path, key); err == nil {
		t.Fatal("champ inconnu accepté")
	}
	writeLines(t, path, lines[0], "")
	if _, err := ReadRecords(path, key); err == nil {
		t.Fatal("ligne vide acceptée")
	}
}

func TestVerifyInLogRejects(t *testing.T) {
	ctx := context.Background()
	logDir := t.TempDir()
	log, verifier := openTestLog(t, ctx, logDir, nil)
	defer log.Close(ctx)
	store, _ := OpenRecordStore(filepath.Join(t.TempDir(), "r.jsonl"), testRecordKey(t))
	defer store.Close()
	if _, err := AppendSealed(ctx, log, store, KindDecision, "cell-a", testSalt, []byte("dans-le-log"), 5); err != nil {
		t.Fatal(err)
	}
	fetch := client.FileFetcher{Root: logDir}

	// Orphelin : clair journalisé, feuille jamais inscrite.
	orphan := Leaf{Kind: KindDecision, CellID: "cell-a", PayloadHash: HashPayload(testSalt, []byte("orphelin")), Timestamp: 6}
	if err := store.Put(orphan, testSalt, []byte("orphelin")); err != nil {
		t.Fatal(err)
	}
	od, _ := orphan.Marshal()
	r := SealedRecord{Leaf: orphan, LeafData: od, Salt: testSalt, Record: []byte("orphelin")}
	if _, err := r.VerifyInLog(ctx, fetch, verifier); !errors.Is(err, ErrRecordNotInLog) {
		t.Fatalf("orphelin : %v, attendu ErrRecordNotInLog", err)
	}

	// Clair altéré par rapport à la feuille inscrite.
	in := Leaf{Kind: KindDecision, CellID: "cell-a", PayloadHash: HashPayload(testSalt, []byte("dans-le-log")), Timestamp: 5}
	id, _ := in.Marshal()
	bad := SealedRecord{Leaf: in, LeafData: id, Salt: testSalt, Record: []byte("autre-chose")}
	if _, err := bad.VerifyInLog(ctx, fetch, verifier); !errors.Is(err, ErrRecordHashMismatch) {
		t.Fatalf("clair altéré : %v, attendu ErrRecordHashMismatch", err)
	}

	// Mauvais vérificateur : checkpoint non opposable.
	_, otherV := openTestLog(t, ctx, t.TempDir(), nil)
	good := SealedRecord{Leaf: in, LeafData: id, Salt: testSalt, Record: []byte("dans-le-log")}
	if _, err := good.VerifyInLog(ctx, fetch, otherV); err == nil {
		t.Fatal("checkpoint accepté avec la clé publique d'un autre log")
	}
	// Voisin : le bon passe.
	if _, err := good.VerifyInLog(ctx, fetch, verifier); err != nil {
		t.Fatalf("enregistrement valide : %v", err)
	}
}

func TestLoadRecordKeyRefusesLoosePermsAndBadContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k")
	if err := GenerateRecordKey(p); err != nil {
		t.Fatal(err)
	}
	if err := GenerateRecordKey(p); err == nil {
		t.Fatal("GenerateRecordKey a écrasé une clé existante")
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecordKey(p); err == nil {
		t.Fatal("clé 0644 acceptée")
	}
	if err := os.WriteFile(p, []byte("pas-de-l-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRecordKey(p); err == nil {
		t.Fatal("clé invalide acceptée")
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return string(out)
}

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// swapField remplace le champ "leaf" de a par celui de b.
func swapField(t *testing.T, a, b string) string {
	t.Helper()
	get := func(s string) string {
		i := strings.Index(s, `"leaf":"`) + len(`"leaf":"`)
		return s[i : i+strings.Index(s[i:], `"`)]
	}
	return strings.Replace(a, get(a), get(b), 1)
}

func TestAppendLeafSealedOrBare(t *testing.T) {
	ctx := context.Background()
	rec := []byte("record-de-test")
	// sans journal : feuille nue historique
	bare := &captureSink{}
	if _, err := AppendLeaf(ctx, bare, nil, KindDecision, "c", testSalt, rec, 42); err != nil {
		t.Fatal(err)
	}
	want := Leaf{Kind: KindDecision, CellID: "c", PayloadHash: HashPayload(testSalt, rec), Timestamp: 42}
	if len(bare.leaves) != 1 || bare.leaves[0] != want {
		t.Fatalf("feuille nue %+v, veut %+v", bare.leaves, want)
	}
	// avec journal : clair journalisé, même feuille
	key := testRecordKey(t)
	path := filepath.Join(t.TempDir(), "r.jsonl")
	st, err := OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := &captureSink{}
	if _, err := AppendLeaf(ctx, sealed, st, KindDecision, "c", testSalt, rec, 42); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadRecords(path, key)
	if err != nil || len(recs) != 1 || recs[0].Leaf != sealed.leaves[0] || !bytes.Equal(recs[0].Record, rec) {
		t.Fatalf("journal %+v err=%v", recs, err)
	}
	// journal fermé : aucune feuille
	_ = st.Close()
	none := &captureSink{}
	if _, err := AppendLeaf(ctx, none, st, KindDecision, "c", testSalt, rec, 43); err == nil || len(none.leaves) != 0 {
		t.Fatalf("journal HS : err=%v feuilles=%d", err, len(none.leaves))
	}
}

func TestOpenRecordStoreFiles(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "k")
	if err := GenerateRecordKey(keyFile); err != nil {
		t.Fatal(err)
	}
	if st, err := OpenRecordStoreFiles(filepath.Join(dir, "j"), keyFile); err != nil {
		t.Fatalf("configuration valide : %v", err)
	} else {
		_ = st.Close()
	}
	for name, args := range map[string][2]string{
		"chemin vide": {"", keyFile}, "clé vide": {filepath.Join(dir, "j"), ""},
		"clé absente": {filepath.Join(dir, "j"), filepath.Join(dir, "absent")},
	} {
		if st, err := OpenRecordStoreFiles(args[0], args[1]); err == nil {
			_ = st.Close()
			t.Errorf("%s : accepté", name)
		}
	}
}

type captureSink struct{ leaves []Leaf }

func (c *captureSink) Append(_ context.Context, l Leaf) (uint64, error) {
	c.leaves = append(c.leaves, l)
	return uint64(len(c.leaves)), nil
}

// VerifyRecordsInLog : un seul passage pour plusieurs enregistrements ; chacun reçoit SON verdict.
func TestVerifyRecordsInLogBatch(t *testing.T) {
	ctx := context.Background()
	logDir := t.TempDir()
	log, verifier := openTestLog(t, ctx, logDir, nil)
	defer log.Close(ctx)
	key := testRecordKey(t)
	path := filepath.Join(t.TempDir(), "r.jsonl")
	store, _ := OpenRecordStore(path, key)
	defer store.Close()
	for i, rec := range []string{"un", "deux", "trois"} {
		if _, err := AppendSealed(ctx, log, store, KindDecision, "cell-a", testSalt, []byte(rec), int64(i+1)); err != nil {
			t.Fatal(err)
		}
	}
	// orphelin : clair journalisé, feuille jamais inscrite
	orphan := Leaf{Kind: KindDecision, CellID: "cell-a", PayloadHash: HashPayload(testSalt, []byte("orphelin")), Timestamp: 9}
	if err := store.Put(orphan, testSalt, []byte("orphelin")); err != nil {
		t.Fatal(err)
	}
	recs, err := ReadRecords(path, key)
	if err != nil || len(recs) != 4 {
		t.Fatalf("relecture : %d %v", len(recs), err)
	}
	// clair altéré : même feuille, autre contenu
	forged := recs[0]
	forged.Record = []byte("falsifie")
	recs = append(recs, forged)

	got, err := VerifyRecordsInLogDir(ctx, logDir, verifier, recs)
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, true, true, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("enregistrement %d : %v, attendu %v", i, got[i], want[i])
		}
	}
	// mauvais vérificateur : checkpoint non opposable ⇒ erreur, rien n'est tenu pour vérifié
	_, otherV := openTestLog(t, ctx, t.TempDir(), nil)
	got, err = VerifyRecordsInLogDir(ctx, logDir, otherV, recs)
	if err == nil {
		t.Fatal("checkpoint accepté avec la clé publique d'un autre log")
	}
	for i, g := range got {
		if g {
			t.Errorf("enregistrement %d tenu pour vérifié malgré l'erreur", i)
		}
	}
	// log illisible
	if got, err = VerifyRecordsInLogDir(ctx, t.TempDir(), verifier, recs); err == nil {
		t.Fatal("log vide accepté")
	}
	// aucune entrée : rien à vérifier
	if got, err = VerifyRecordsInLogDir(ctx, logDir, verifier, nil); err != nil || len(got) != 0 {
		t.Fatalf("vide : %v %v", got, err)
	}
}
