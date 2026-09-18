// src/registry/veritrail_test.go — T7 (issue #7)
//
// Batterie de conformité RFC 6962 / veritrail (§6) : le registre de cellule
// (T4) et la master chain (T6) doivent produire des arbres de Merkle et des
// preuves vérifiables PAR UN TIERS, sans relire notre code — « une preuve
// vérifiable par un tiers perd sa valeur si l'auditeur doit relire votre
// code » (§6). Trois chemins indépendants doivent converger :
//
//  1. les vecteurs publiés (testdata/rfc6962/vectors.json — valeurs croisées
//     à la génération contre l'implémentation de référence
//     transparency-dev/merkle et recalculables à la main, cf. provenance) ;
//  2. une réimplémentation « scratch » du MTH écrite ici directement d'après
//     RFC 6962 §2.1 (mth6962 / leafHash6962 / nodeHash6962 ci-dessous) ;
//  3. l'arbre de référence testonly de transparency-dev/merkle et les
//     racines RÉELLES produites par Tessera via CellLog (driver POSIX).
//
// Les preuves d'inclusion et de consistance sont GÉNÉRÉES depuis les tuiles
// réelles du log (client.NewProofBuilder, le parcours client officiel
// Tessera) et VÉRIFIÉES par la bibliothèque tierce (proof.VerifyInclusion /
// proof.VerifyConsistency) — exactement ce que ferait un auditeur externe
// (§3, §6). Aucun réseau, aucune horloge murale : la batterie est
// déterministe et rejouable en CI.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/bits"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"github.com/transparency-dev/tessera/client"
)

// ---------------------------------------------------------------------------
// Vecteurs publiés (testdata/rfc6962/vectors.json)
// ---------------------------------------------------------------------------

type rfc6962Vectors struct {
	Provenance       string `json:"provenance"`
	HashStrategy     string `json:"hashStrategy"`
	EmptyRoot        string `json:"emptyRoot"`
	LeafHashEmpty    string `json:"leafHashEmpty"`
	LeafHashL123456  string `json:"leafHashL123456"`
	NodeHashN123N456 string `json:"nodeHashN123N456"`
	Tree             struct {
		LeavesHex []string `json:"leavesHex"`
		RootsHex  []string `json:"rootsHex"`
	} `json:"tree"`
}

func loadRFC6962Vectors(t *testing.T) rfc6962Vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rfc6962", "vectors.json"))
	if err != nil {
		t.Fatalf("lecture des vecteurs RFC 6962: %v", err)
	}
	var v rfc6962Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vecteurs RFC 6962 illisibles: %v", err)
	}
	if len(v.Tree.LeavesHex) != 8 || len(v.Tree.RootsHex) != 8 {
		t.Fatalf("vecteurs incomplets : %d feuilles, %d racines (8 attendues)",
			len(v.Tree.LeavesHex), len(v.Tree.RootsHex))
	}
	return v
}

func mustHex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s : hex invalide: %v", name, err)
	}
	return b
}

// ---------------------------------------------------------------------------
// MTH « scratch » — réimplémentation directe de RFC 6962 §2.1, écrite pour
// cette batterie, indépendante de transparency-dev/merkle.
// ---------------------------------------------------------------------------

// leafHash6962 : SHA-256(0x00 ‖ data) — §2.1, hachage de feuille.
func leafHash6962(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// nodeHash6962 : SHA-256(0x01 ‖ left ‖ right) — §2.1, hachage de nœud.
func nodeHash6962(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// mth6962 : Merkle Tree Hash — §2.1 :
//
//	MTH(∅)      = SHA-256("")
//	MTH({d})    = SHA-256(0x00 ‖ d)
//	MTH(D[n>1]) = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))
//
// avec k = plus grande puissance de 2 strictement inférieure à n.
func mth6962(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		e := sha256.Sum256(nil)
		return e[:]
	}
	if n == 1 {
		return leafHash6962(leaves[0])
	}
	k := 1
	for k*2 < n {
		k *= 2
	}
	return nodeHash6962(mth6962(leaves[:k]), mth6962(leaves[k:]))
}

// ---------------------------------------------------------------------------
// 1. Constantes publiées : le hasher utilisé par Tessera est bien celui de
//    la RFC, et la réimplémentation scratch converge.
// ---------------------------------------------------------------------------

func TestRFC6962GoldenHasher(t *testing.T) {
	v := loadRFC6962Vectors(t)
	h := rfc6962.DefaultHasher

	cases := []struct {
		name    string
		lib     []byte // transparency-dev/merkle (celle de Tessera)
		scratch []byte // réimplémentation d'après la RFC
		wantHex string
	}{
		{"MTH(∅)", h.EmptyRoot(), mth6962(nil), v.EmptyRoot},
		{"HashLeaf(\"\")", h.HashLeaf(nil), leafHash6962(nil), v.LeafHashEmpty},
		{"HashLeaf(\"L123456\")", h.HashLeaf([]byte("L123456")), leafHash6962([]byte("L123456")), v.LeafHashL123456},
		{"HashChildren(N123,N456)", h.HashChildren([]byte("N123"), []byte("N456")), nodeHash6962([]byte("N123"), []byte("N456")), v.NodeHashN123N456},
	}
	for _, c := range cases {
		want := mustHex(t, c.name, c.wantHex)
		if !bytes.Equal(c.lib, want) {
			t.Fatalf("%s : hasher Tessera = %x, vecteur publié %x", c.name, c.lib, want)
		}
		if !bytes.Equal(c.scratch, want) {
			t.Fatalf("%s : scratch = %x, vecteur publié %x", c.name, c.scratch, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Vecteurs d'arbre : tailles 1..8, deux chemins indépendants sur les
//    valeurs publiées.
// ---------------------------------------------------------------------------

func TestRFC6962TreeVectors(t *testing.T) {
	v := loadRFC6962Vectors(t)

	leaves := make([][]byte, len(v.Tree.LeavesHex))
	for i, lh := range v.Tree.LeavesHex {
		leaves[i] = mustHex(t, "feuille", lh)
		// Sanité : HashLeaf de la bibliothèque == scratch, feuille par feuille.
		if got, want := rfc6962.DefaultHasher.HashLeaf(leaves[i]), leafHash6962(leaves[i]); !bytes.Equal(got, want) {
			t.Fatalf("feuille %d : HashLeaf %x ≠ scratch %x", i, got, want)
		}
	}

	// Arbre de référence (transparency-dev/merkle/testonly).
	ref := testonly.New(rfc6962.DefaultHasher)
	ref.AppendData(leaves...)

	for size := 1; size <= len(leaves); size++ {
		want := mustHex(t, "racine", v.Tree.RootsHex[size-1])
		if got := mth6962(leaves[:size]); !bytes.Equal(got, want) {
			t.Fatalf("taille %d : MTH scratch = %x, vecteur publié %x", size, got, want)
		}
		if got := ref.HashAt(uint64(size)); !bytes.Equal(got, want) {
			t.Fatalf("taille %d : arbre de référence = %x, vecteur publié %x", size, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Amorçage partagé : un registre de cellule RÉEL (driver POSIX Tessera),
// 8 feuilles de kinds variés — KindBackpressure (T5) et KindAnchor (T6)
// inclus : la master chain de §7.1 est la même mécanique, cette batterie
// vaut donc aussi pour elle. Retourne les feuilles marshaled et les racines
// de checkpoint à chaque taille (roots[i] = racine à la taille i+1), en
// assertant à chaque append la convergence Tessera == scratch == référence.
// ---------------------------------------------------------------------------

func seedRFC6962Log(t *testing.T, ctx context.Context, salt string) (*CellLog, [][]byte, [][32]byte) {
	t.Helper()
	log, _ := openTestLog(t, ctx, t.TempDir(), nil)

	kinds := []byte{KindDecision, KindTelemetry, KindBackpressure, KindAnchor,
		KindDecision, KindAnchor, KindTelemetry, KindBackpressure}
	marshaled := make([][]byte, 0, len(kinds))
	roots := make([][32]byte, 0, len(kinds))
	ref := testonly.New(rfc6962.DefaultHasher)

	for i, kind := range kinds {
		leaf := Leaf{
			Kind:        kind,
			CellID:      "cell-rfc6962",
			PayloadHash: HashPayload([]byte(salt), []byte{byte(i), 0xA5}),
			Timestamp:   time.Date(2026, 9, 19, 12, 0, i, 0, time.UTC).UnixNano(),
		}
		data, err := leaf.Marshal()
		if err != nil {
			t.Fatalf("feuille %d : Marshal: %v", i, err)
		}
		idx, err := log.Append(ctx, leaf)
		if err != nil {
			t.Fatalf("feuille %d : Append: %v", i, err)
		}
		if idx != uint64(i) {
			t.Fatalf("feuille %d : index %d", i, idx)
		}
		marshaled = append(marshaled, data)
		ref.AppendData(data)

		root, size, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("feuille %d : Head: %v", i, err)
		}
		if size != uint64(i+1) {
			t.Fatalf("après %d feuilles, checkpoint taille %d", i+1, size)
		}
		// Convergence n°1 : la racine du checkpoint signé Tessera est le MTH
		// RFC 6962 des feuilles marshaled (réimplémentation scratch).
		if want := mth6962(marshaled); !bytes.Equal(root[:], want) {
			t.Fatalf("taille %d : racine Tessera %x ≠ MTH RFC 6962 %x", size, root, want)
		}
		// Convergence n°2 : l'arbre de référence alimenté des MÊMES feuilles
		// produit la même racine.
		if want := ref.Hash(); !bytes.Equal(root[:], want) {
			t.Fatalf("taille %d : racine Tessera %x ≠ arbre de référence %x", size, root, want)
		}
		roots = append(roots, root)
	}
	return log, marshaled, roots
}

// ---------------------------------------------------------------------------
// 3. Racines réelles du registre de cellule : conformité et propriétés
//    globales.
// ---------------------------------------------------------------------------

func TestCellLogRootsRFC6962(t *testing.T) {
	ctx := context.Background()
	log, marshaled, roots := seedRFC6962Log(t, ctx, "sel-vecteur-rfc6962")
	defer log.Close(ctx)

	// La convergence Tessera == scratch == référence est assertée à chaque
	// append dans seedRFC6962Log ; on vérifie ici les propriétés globales.
	if len(marshaled) != 8 || len(roots) != 8 {
		t.Fatalf("amorçage incomplet : %d feuilles, %d racines", len(marshaled), len(roots))
	}
	// Chaque append fait évoluer la racine : toutes distinctes.
	seen := map[[32]byte]int{}
	for i, r := range roots {
		if j, ok := seen[r]; ok {
			t.Fatalf("racines identiques aux tailles %d et %d", j+1, i+1)
		}
		seen[r] = i
	}
}

// ---------------------------------------------------------------------------
// 4. Preuves d'inclusion : générées depuis les tuiles réelles du log, véri-
//    fiées par la bibliothèque tierce contre la racine du checkpoint signé.
// ---------------------------------------------------------------------------

func TestInclusionProofsRFC6962(t *testing.T) {
	ctx := context.Background()
	log, marshaled, roots := seedRFC6962Log(t, ctx, "sel-vecteur-rfc6962")
	defer log.Close(ctx)

	size := uint64(len(marshaled))
	root := roots[size-1]
	h := rfc6962.DefaultHasher

	pb, err := client.NewProofBuilder(ctx, size, log.reader.ReadTile)
	if err != nil {
		t.Fatalf("NewProofBuilder: %v", err)
	}

	for idx := uint64(0); idx < size; idx++ {
		p, err := pb.InclusionProof(ctx, idx)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		leafHash := h.HashLeaf(marshaled[idx])
		if err := proof.VerifyInclusion(h, idx, size, leafHash, p, root[:]); err != nil {
			t.Fatalf("preuve d'inclusion feuille %d rejetée : %v", idx, err)
		}
		// La racine reconstruite depuis la seule preuve est celle du checkpoint.
		derived, err := proof.RootFromInclusionProof(h, idx, size, leafHash, p)
		if err != nil {
			t.Fatalf("RootFromInclusionProof(%d): %v", idx, err)
		}
		if !bytes.Equal(derived, root[:]) {
			t.Fatalf("feuille %d : racine dérivée %x ≠ checkpoint %x", idx, derived, root)
		}
		// O(log n) : arbre parfait de 8 feuilles ⇒ exactement 3 nœuds.
		if want := bits.Len64(size) - 1; len(p) != want {
			t.Fatalf("preuve d'inclusion feuille %d : %d nœuds, attendu %d (O(log n))", idx, len(p), want)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. Preuves de consistance O(log n) : pour tout couple (i<j), la preuve
//    générée depuis le log réel lie les racines des checkpoints i et j —
//    le mécanisme de rattrapage des entrants tardifs et du fencing d'époque
//    (§3, §7.2).
// ---------------------------------------------------------------------------

func TestConsistencyProofsRFC6962(t *testing.T) {
	ctx := context.Background()
	log, _, roots := seedRFC6962Log(t, ctx, "sel-vecteur-rfc6962")
	defer log.Close(ctx)

	size := uint64(len(roots))
	h := rfc6962.DefaultHasher

	pb, err := client.NewProofBuilder(ctx, size, log.reader.ReadTile)
	if err != nil {
		t.Fatalf("NewProofBuilder: %v", err)
	}

	for i := uint64(1); i <= size; i++ {
		for j := i + 1; j <= size; j++ {
			p, err := pb.ConsistencyProof(ctx, i, j)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d,%d): %v", i, j, err)
			}
			if err := proof.VerifyConsistency(h, i, j, p, roots[i-1][:], roots[j-1][:]); err != nil {
				t.Fatalf("consistance (%d,%d) rejetée : %v", i, j, err)
			}
			// Borne O(log n) : au plus log2(j)+2 nœuds (ici j ≤ 8 ⇒ ≤ 5).
			if max := bits.Len64(j) + 1; len(p) > max {
				t.Fatalf("consistance (%d,%d) : %d nœuds > borne O(log n) %d", i, j, len(p), max)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 6. Falsification : tous les cas doivent être DÉTECTÉS — fail-closed (§1) :
//    une discontinuité inexpliquée est une corruption et vaut refus (§3).
// ---------------------------------------------------------------------------

func TestFalsificationDetectee(t *testing.T) {
	ctx := context.Background()
	log, marshaled, roots := seedRFC6962Log(t, ctx, "sel-vecteur-rfc6962")
	defer log.Close(ctx)

	size := uint64(len(marshaled))
	h := rfc6962.DefaultHasher

	pb, err := client.NewProofBuilder(ctx, size, log.reader.ReadTile)
	if err != nil {
		t.Fatalf("NewProofBuilder: %v", err)
	}

	// 1. Preuve d'inclusion falsifiée : un octet d'un nœud flipé.
	p, err := pb.InclusionProof(ctx, 3)
	if err != nil {
		t.Fatalf("InclusionProof(3): %v", err)
	}
	tampered := make([][]byte, len(p))
	for i := range p {
		tampered[i] = bytes.Clone(p[i])
	}
	tampered[0][0] ^= 0xFF
	if err := proof.VerifyInclusion(h, 3, size, h.HashLeaf(marshaled[3]), tampered, roots[size-1][:]); err == nil {
		t.Fatal("preuve d'inclusion falsifiée ACCEPTÉE")
	}

	// 2. Preuve valide, feuille étrangère (contenu d'un autre index).
	if err := proof.VerifyInclusion(h, 3, size, h.HashLeaf(marshaled[4]), p, roots[size-1][:]); err == nil {
		t.Fatal("inclusion d'une feuille étrangère ACCEPTÉE")
	}

	// 3. Preuve valide, racine d'une autre taille (7 au lieu de 8).
	if err := proof.VerifyInclusion(h, 3, size, h.HashLeaf(marshaled[3]), p, roots[6][:]); err == nil {
		t.Fatal("inclusion contre la racine d'une autre taille ACCEPTÉE")
	}

	// 4. Preuve de consistance falsifiée.
	c, err := pb.ConsistencyProof(ctx, 3, size)
	if err != nil {
		t.Fatalf("ConsistencyProof(3,%d): %v", size, err)
	}
	ct := make([][]byte, len(c))
	for i := range c {
		ct[i] = bytes.Clone(c[i])
	}
	ct[0][0] ^= 0xFF
	if err := proof.VerifyConsistency(h, 3, size, ct, roots[2][:], roots[size-1][:]); err == nil {
		t.Fatal("preuve de consistance falsifiée ACCEPTÉE")
	}

	// 5. Racines inversées (ancienne/nouvelle permutées).
	if err := proof.VerifyConsistency(h, 3, size, c, roots[size-1][:], roots[2][:]); err == nil {
		t.Fatal("consistance avec racines inversées ACCEPTÉE")
	}

	// 6. Fork / discontinuité : un second log dont les feuilles divergent
	// dès l'index 0. La preuve de consistance générée DEPUIS le fork lie
	// honnêtement fork(3) → fork(8), mais ne peut pas lier la racine
	// LÉGITIME de taille 3 à la racine du fork : refus obligatoire (§3).
	fork, _, forkRoots := seedRFC6962Log(t, ctx, "sel-FORK-rfc6962")
	defer fork.Close(ctx)
	if bytes.Equal(roots[0][:], forkRoots[0][:]) {
		t.Fatal("amorçage du fork incorrect : les racines devraient diverger dès la taille 1")
	}
	fpb, err := client.NewProofBuilder(ctx, size, fork.reader.ReadTile)
	if err != nil {
		t.Fatalf("NewProofBuilder (fork): %v", err)
	}
	fp, err := fpb.ConsistencyProof(ctx, 3, size)
	if err != nil {
		t.Fatalf("ConsistencyProof fork (3,%d): %v", size, err)
	}
	if err := proof.VerifyConsistency(h, 3, size, fp, roots[2][:], forkRoots[size-1][:]); err == nil {
		t.Fatal("consistance entre logs divergents ACCEPTÉE — discontinuité non détectée")
	}
}
