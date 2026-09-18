// src/registry/cell_log_test.go — T4 (issue #8)
//
// Tests du registre de cellule : format de feuille hash-only (leaf.go) et
// intégration réelle sur le driver POSIX de Tessera (cell_log.go) — aucun
// mock du log : le chaînage Merkle et les checkpoints signés sont ceux de
// Tessera, exécutés dans un répertoire temporaire.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// ---------------------------------------------------------------------------
// leaf.go — format de feuille hash-only
// ---------------------------------------------------------------------------

func TestHashPayload(t *testing.T) {
	salt := bytes.Repeat([]byte{0xA5}, 16)
	payload := []byte(`{"action":"http.send","decision":"allow"}`)

	got := HashPayload(salt, payload)
	want := sha256.Sum256(append(append([]byte{}, salt...), payload...))
	if got != want {
		t.Fatalf("HashPayload ≠ sha256(salt‖payload) : %x ≠ %x", got, want)
	}
	// Déterminisme (§11.3).
	if HashPayload(salt, payload) != got {
		t.Fatal("HashPayload non déterministe")
	}
	// Sensibilité au sel : un sel différent change le hash (c'est ce qui
	// rend la feuille non inversable par un lecteur du registre, §6.2).
	otherSalt := bytes.Repeat([]byte{0x5A}, 16)
	if HashPayload(otherSalt, payload) == got {
		t.Fatal("le sel n'influence pas le hash")
	}
	// Sensibilité au contenu.
	if HashPayload(salt, []byte("autre contenu")) == got {
		t.Fatal("le contenu n'influence pas le hash")
	}
}

func TestLeafMarshalUnmarshalRoundTrip(t *testing.T) {
	for _, kind := range []byte{KindDecision, KindTelemetry, KindBackpressure} {
		leaf := Leaf{
			Kind:        kind,
			CellID:      "cell-alpha-01",
			PayloadHash: HashPayload([]byte("sel-test"), []byte("contenu")),
			Timestamp:   time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC).UnixNano(),
		}
		data, err := leaf.Marshal()
		if err != nil {
			t.Fatalf("kind %d : Marshal: %v", kind, err)
		}
		// Layout fixe documenté : version | kind | ts(8) | len | id | hash(32).
		if data[0] != 0x01 {
			t.Fatalf("kind %d : version = %#x, attendu 0x01", kind, data[0])
		}
		if data[1] != kind {
			t.Fatalf("kind %d : octet kind = %d", kind, data[1])
		}
		if want := 1 + 1 + 8 + 1 + len(leaf.CellID) + 32; len(data) != want {
			t.Fatalf("kind %d : %d octets, attendu %d", kind, len(data), want)
		}
		back, err := UnmarshalLeaf(data)
		if err != nil {
			t.Fatalf("kind %d : UnmarshalLeaf: %v", kind, err)
		}
		if back != leaf {
			t.Fatalf("kind %d : round-trip différent :\n got %+v\nwant %+v", kind, back, leaf)
		}
	}
}

func TestLeafMarshalErrors(t *testing.T) {
	valid := Leaf{Kind: KindDecision, CellID: "c1", Timestamp: 1}

	noID := valid
	noID.CellID = ""
	if _, err := noID.Marshal(); err == nil {
		t.Fatal("cellID vide accepté")
	}

	longID := valid
	longID.CellID = strings.Repeat("x", maxCellIDLen+1)
	if _, err := longID.Marshal(); err == nil {
		t.Fatal("cellID de 256 octets accepté")
	}

	badKind := valid
	badKind.Kind = 0
	if _, err := badKind.Marshal(); err == nil {
		t.Fatal("kind 0 accepté")
	}
	badKind.Kind = 42
	if _, err := badKind.Marshal(); err == nil {
		t.Fatal("kind 42 accepté")
	}
}

func TestLeafMarshalBoundary(t *testing.T) {
	leaf := Leaf{Kind: KindTelemetry, CellID: strings.Repeat("y", maxCellIDLen), Timestamp: 1}
	data, err := leaf.Marshal()
	if err != nil {
		t.Fatalf("cellID de %d octets refusé : %v", maxCellIDLen, err)
	}
	back, err := UnmarshalLeaf(data)
	if err != nil || back.CellID != leaf.CellID {
		t.Fatalf("round-trip cellID max : err=%v", err)
	}
}

func TestUnmarshalLeafErrors(t *testing.T) {
	valid := Leaf{Kind: KindDecision, CellID: "c1", Timestamp: 1}
	data, err := valid.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if _, err := UnmarshalLeaf(data[:10]); err == nil {
		t.Fatal("feuille tronquée acceptée")
	}

	badVersion := append([]byte{}, data...)
	badVersion[0] = 0x02
	if _, err := UnmarshalLeaf(badVersion); err == nil {
		t.Fatal("version inconnue acceptée")
	}

	badKind := append([]byte{}, data...)
	badKind[1] = 0x7F
	if _, err := UnmarshalLeaf(badKind); err == nil {
		t.Fatal("kind inconnu accepté")
	}

	if _, err := UnmarshalLeaf(data[:len(data)-1]); err == nil {
		t.Fatal("hash tronqué accepté (longueur incohérente)")
	}
	if _, err := UnmarshalLeaf(append(append([]byte{}, data...), 0x00)); err == nil {
		t.Fatal("octet surnuméraire accepté (longueur incohérente)")
	}
}

// ---------------------------------------------------------------------------
// cell_log.go — intégration réelle Tessera POSIX (répertoire temporaire)
// ---------------------------------------------------------------------------

const testOrigin = "tbp/registry/cell-test"

// openTestLog crée un CellLog dans t.TempDir() avec une clé note fraîche.
// BatchSize 1 / BatchAge 10 ms : publication rapide des checkpoints en test.
func openTestLog(t *testing.T, ctx context.Context, dir string, bp BackpressureChecker) (*CellLog, note.Verifier) {
	t.Helper()
	skey, vkey, err := GenerateCellKey(testOrigin)
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
	log, err := Open(ctx, Options{
		Dir:                dir,
		Signer:             signer,
		Verifier:           verifier,
		Backpressure:       bp,
		BatchSize:          1,
		BatchAge:           10 * time.Millisecond,
		CheckpointInterval: 100 * time.Millisecond, // minimum du driver POSIX
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return log, verifier
}

func TestKeyManagement(t *testing.T) {
	skey, vkey, err := GenerateCellKey(testOrigin)
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	if _, _, err := GenerateCellKey(""); err == nil {
		t.Fatal("origine vide acceptée")
	}

	dir := t.TempDir()
	if err := SaveSignerKey(dir, skey); err != nil {
		t.Fatalf("SaveSignerKey: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "cell_log.key"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("clé privée en %o, attendu 0600", perm)
	}
	if _, err := LoadSigner(dir); err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	if _, err := NewVerifier(vkey); err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := NewVerifier("pas-une-clé"); err == nil {
		t.Fatal("clé publique invalide acceptée")
	}
}

func TestOpenValidation(t *testing.T) {
	ctx := context.Background()
	skey, vkey, _ := GenerateCellKey(testOrigin)
	signer, _ := note.NewSigner(skey)
	verifier, _ := NewVerifier(vkey)

	if _, err := Open(ctx, Options{Signer: signer, Verifier: verifier}); err == nil {
		t.Fatal("Dir vide accepté")
	}
	if _, err := Open(ctx, Options{Dir: t.TempDir(), Verifier: verifier}); err == nil {
		t.Fatal("Signer nil accepté")
	}
	if _, err := Open(ctx, Options{Dir: t.TempDir(), Signer: signer}); err == nil {
		t.Fatal("Verifier nil accepté")
	}
}

func TestCellLogAppendAndHead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log, _ := openTestLog(t, ctx, t.TempDir(), nil)
	defer log.Close(ctx)

	leaves := []Leaf{
		{Kind: KindDecision, CellID: "cell-a", PayloadHash: HashPayload([]byte("s1"), []byte("d1")), Timestamp: 1},
		{Kind: KindTelemetry, CellID: "cell-a", PayloadHash: HashPayload([]byte("s2"), []byte("t1")), Timestamp: 2},
		{Kind: KindBackpressure, CellID: "cell-a", PayloadHash: HashPayload([]byte("s3"), []byte("bp")), Timestamp: 3},
	}
	for i, leaf := range leaves {
		idx, err := log.Append(ctx, leaf)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("Append %d : index %d, attendu %d", i, idx, i)
		}
	}

	root, size, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if size != uint64(len(leaves)) {
		t.Fatalf("taille %d, attendu %d", size, len(leaves))
	}
	if root == ([32]byte{}) {
		t.Fatal("racine Merkle nulle")
	}
}

// TestCellLogCheckpointThirdParty vérifie qu'un TIERS peut vérifier le
// checkpoint avec la seule clé publique du log (§6 : opposabilité), et qu'un
// checkpoint signé par une autre clé est rejeté.
func TestCellLogCheckpointThirdParty(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dir := t.TempDir()
	log, verifier := openTestLog(t, ctx, dir, nil)
	defer log.Close(ctx)

	if _, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-a", PayloadHash: HashPayload([]byte("s"), []byte("x")), Timestamp: 1}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Le tiers lit le fichier checkpoint brut (layout tlog-tiles).
	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatalf("lecture checkpoint: %v", err)
	}
	cp, err := ParseCheckpoint(raw, verifier)
	if err != nil {
		t.Fatalf("ParseCheckpoint (bonne clé): %v", err)
	}
	if cp.Size != 1 {
		t.Fatalf("checkpoint taille %d, attendu 1", cp.Size)
	}
	_, size, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if cp.Size != size {
		t.Fatalf("checkpoint (%d) et Head (%d) divergent", cp.Size, size)
	}

	// Mauvais vérificateur : rejet obligatoire (fail-closed).
	_, otherVkey, err := GenerateCellKey("tbp/registry/cell-attaquant")
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	otherVerifier, err := NewVerifier(otherVkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := ParseCheckpoint(raw, otherVerifier); err == nil {
		t.Fatal("checkpoint vérifié avec une clé étrangère")
	}
	// Checkpoint corrompu : rejet.
	if _, err := ParseCheckpoint([]byte("n'importe quoi"), verifier); err == nil {
		t.Fatal("checkpoint malformé accepté")
	}
}

// TestCellLogBackpressure vérifie la couture T5 : quand le backpressure disque
// est engagé, Append refuse avec ErrBackpressure — arrêt propre, fail-closed.
// Doctrine README : la dernière feuille écrite AVANT l'engagement est une
// feuille KindBackpressure (l'arrêt est lui-même tracé).
func TestCellLogBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engaged := false
	log, _ := openTestLog(t, ctx, t.TempDir(), BackpressureFunc(func() bool { return engaged }))
	defer log.Close(ctx)

	mk := func(kind byte, ts int64) Leaf {
		return Leaf{Kind: kind, CellID: "cell-a", PayloadHash: HashPayload([]byte("s"), []byte{kind}), Timestamp: ts}
	}
	if _, err := log.Append(ctx, mk(KindDecision, 1)); err != nil {
		t.Fatalf("Append décision: %v", err)
	}
	// L'arrêt est tracé : dernière feuille avant engagement.
	if idx, err := log.Append(ctx, mk(KindBackpressure, 2)); err != nil || idx != 1 {
		t.Fatalf("Append backpressure: idx=%d err=%v", idx, err)
	}

	engaged = true
	if _, err := log.Append(ctx, mk(KindDecision, 3)); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("Append sous backpressure: err=%v, attendu ErrBackpressure", err)
	}

	// Aucune écriture n'est passée : la tête reste à 2 feuilles.
	_, size, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if size != 2 {
		t.Fatalf("taille %d après refus, attendu 2", size)
	}

	// Désengagé, l'écriture reprend.
	engaged = false
	if idx, err := log.Append(ctx, mk(KindDecision, 3)); err != nil || idx != 2 {
		t.Fatalf("reprise: idx=%d err=%v", idx, err)
	}
}

// TestCellLogReopen vérifie la persistance : Close flushe, et la réouverture
// du même répertoire retrouve la tête et poursuit les index.
func TestCellLogReopen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dir := t.TempDir()
	skey, vkey, err := GenerateCellKey(testOrigin)
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	if err := SaveSignerKey(dir, skey); err != nil {
		t.Fatalf("SaveSignerKey: %v", err)
	}
	signer, err := LoadSigner(dir)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}
	verifier, err := NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	opts := Options{
		Dir: dir, Signer: signer, Verifier: verifier,
		BatchSize: 1, BatchAge: 10 * time.Millisecond, CheckpointInterval: 100 * time.Millisecond,
	}

	log1, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := log1.Append(ctx, Leaf{Kind: KindDecision, CellID: "cell-a", PayloadHash: HashPayload([]byte("s"), []byte{byte(i)}), Timestamp: int64(i + 1)}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	root1, size1, err := log1.Head(ctx)
	if err != nil {
		t.Fatalf("Head 1: %v", err)
	}
	if err := log1.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if size1 != 3 {
		t.Fatalf("taille avant close %d, attendu 3", size1)
	}

	// Réouverture : même répertoire, même clé.
	log2, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer log2.Close(ctx)
	root2, size2, err := log2.Head(ctx)
	if err != nil {
		t.Fatalf("Head 2: %v", err)
	}
	if size2 != 3 || root2 != root1 {
		t.Fatalf("tête non persistée : (%d, %x…) ≠ (%d, %x…)", size2, root2[:4], size1, root1[:4])
	}
	// Les index continuent où le log s'était arrêté.
	if idx, err := log2.Append(ctx, Leaf{Kind: KindTelemetry, CellID: "cell-a", PayloadHash: HashPayload([]byte("s"), []byte("z")), Timestamp: 4}); err != nil || idx != 3 {
		t.Fatalf("Append après réouverture: idx=%d err=%v, attendu idx=3", idx, err)
	}
}

// TestAppendDefaultsTimestamp : Timestamp 0 → horloge locale (défaut dev) ;
// la feuille est acceptée et couverte par un checkpoint.
func TestAppendDefaultsTimestamp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log, _ := openTestLog(t, ctx, t.TempDir(), nil)
	defer log.Close(ctx)

	before := time.Now().UTC().UnixNano()
	idx, err := log.Append(ctx, Leaf{Kind: KindTelemetry, CellID: "cell-a", PayloadHash: HashPayload([]byte("s"), []byte("v"))})
	if err != nil {
		t.Fatalf("Append Timestamp=0: %v", err)
	}
	if idx != 0 {
		t.Fatalf("index %d, attendu 0", idx)
	}
	after := time.Now().UTC().UnixNano()
	if after < before {
		t.Fatal("horloge non monotone")
	}
	_, size, err := log.Head(ctx)
	if err != nil || size != 1 {
		t.Fatalf("Head: size=%d err=%v, attendu 1", size, err)
	}
}

// TestAppendRejectsInvalidLeaf : une feuille invalide est refusée AVANT
// d'atteindre Tessera — fail-closed, pas de feuille corrompue dans le log.
func TestAppendRejectsInvalidLeaf(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log, _ := openTestLog(t, ctx, t.TempDir(), nil)
	defer log.Close(ctx)

	if _, err := log.Append(ctx, Leaf{Kind: KindDecision, CellID: "", Timestamp: 1}); err == nil {
		t.Fatal("cellID vide appendu")
	}
	if _, err := log.Append(ctx, Leaf{Kind: 99, CellID: "cell-a", Timestamp: 1}); err == nil {
		t.Fatal("kind inconnu appendu")
	}
	_, size, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if size != 0 {
		t.Fatalf("%d feuille(s) écrite(s) malgré les refus", size)
	}
}
