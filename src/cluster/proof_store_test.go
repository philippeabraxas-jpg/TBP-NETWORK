package cluster

// Issue #206 (red team R-19) : une preuve de quorum classe W vaut UNE
// autorisation. Chaque test provoque une faute précise ; sans la
// consommation, le second appel de TestProofIsConsumedOnce passerait.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func newGateWithStore(t *testing.T, clk *manualClock, leaves *leafRecorder, store ProofStore) *QuorumGate {
	t.Helper()
	return newGate(t, clk, leaves, func(c *QuorumGateConfig) { c.Consumed = store })
}

func TestProofIsConsumedOnce(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	g := newGate(t, clk, leaves)
	proof := mintQuorumProof(t, privs, "shutdown.cluster", "prod/eu", testPolicyID, 7, t0.Add(60*time.Second), 1, 2)

	if err := g.VerifyClassW(context.Background(), proof, "shutdown.cluster", "prod/eu", 7); err != nil {
		t.Fatalf("première présentation refusée : %v", err)
	}
	err := g.VerifyClassW(context.Background(), proof, "shutdown.cluster", "prod/eu", 7)
	if !errors.Is(err, ErrQuorumProofReplayed) {
		t.Fatalf("même preuve présentée deux fois : %v — R-19, une preuve = une autorisation", err)
	}
	ls := leaves.all()
	if len(ls) != 2 {
		t.Fatalf("feuilles=%d, veut 2 (admission puis refus de rejeu)", len(ls))
	}
	want := registry.HashPayload(testSalt, quorumRecord(0x00, 2, 2, 7, "shutdown.cluster", "quorum-proof-replayed"))
	if ls[1].PayloadHash != want {
		t.Fatal("le rejeu n'est pas tracé par une feuille KindQuorum prouvable")
	}
}

func TestDistinctStatementsAreDistinctAuthorizations(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	g := newGate(t, clk, &leafRecorder{})
	ctx := context.Background()
	// autre expiry, autre ressource, autre époque : trois autorisations.
	for i, p := range [][]byte{
		mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(60*time.Second), 1, 2),
		mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(61*time.Second), 1, 2),
		mintQuorumProof(t, privs, "a", "r2", testPolicyID, 7, t0.Add(60*time.Second), 1, 2),
	} {
		res := "r"
		if i == 2 {
			res = "r2"
		}
		if err := g.VerifyClassW(ctx, p, "a", res, 7); err != nil {
			t.Fatalf("autorisation %d distincte refusée : %v", i, err)
		}
	}
}

// Un autre sous-ensemble de signataires du MÊME énoncé est la même
// autorisation : l'identité est l'énoncé, pas les signatures.
func TestSameStatementOtherSignersIsAReplay(t *testing.T) {
	_, privs := testControllers(t)
	g := newGate(t, newClock(t0), &leafRecorder{})
	ctx := context.Background()
	exp := t0.Add(60 * time.Second)
	if err := g.VerifyClassW(ctx, mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, exp, 1, 2), "a", "r", 7); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyClassW(ctx, mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, exp, 2, 3), "a", "r", 7); !errors.Is(err, ErrQuorumProofReplayed) {
		t.Fatalf("mêmes énoncé, signataires {2,3} : %v", err)
	}
}

// Une preuve INVALIDE ne brûle jamais l'énoncé : sinon quiconque connaît un
// énoncé en cours de collecte de signatures pourrait le griller.
func TestInvalidProofDoesNotBurnTheStatement(t *testing.T) {
	_, privs := testControllers(t)
	g := newGate(t, newClock(t0), &leafRecorder{})
	ctx := context.Background()
	exp := t0.Add(60 * time.Second)
	if err := g.VerifyClassW(ctx, mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, exp, 1), "a", "r", 7); !errors.Is(err, ErrQuorumInsufficient) {
		t.Fatalf("1 signature sur k=2 : %v", err)
	}
	if err := g.VerifyClassW(ctx, mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, exp, 1, 2), "a", "r", 7); err != nil {
		t.Fatalf("la preuve valide du même énoncé a été brûlée par une preuve invalide : %v", err)
	}
}

func TestConsumedEntriesArePurgedAtExpiryAndNeverEvicted(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	store, err := NewMemoryProofStore(2)
	if err != nil {
		t.Fatal(err)
	}
	g := newGateWithStore(t, clk, &leafRecorder{}, store)
	ctx := context.Background()
	mint := func(res string, ttl time.Duration) []byte {
		return mintQuorumProof(t, privs, "a", res, testPolicyID, 7, clk.now().Add(ttl), 1, 2)
	}
	p1, p2, p3 := mint("r1", 30*time.Second), mint("r2", 90*time.Second), mint("r3", 90*time.Second)
	if err := g.VerifyClassW(ctx, p1, "a", "r1", 7); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyClassW(ctx, p2, "a", "r2", 7); err != nil {
		t.Fatal(err)
	}
	// Plein : refus fail-closed, et p1/p2 ne sont PAS évincées pour faire de la place.
	if err := g.VerifyClassW(ctx, p3, "a", "r3", 7); !errors.Is(err, ErrProofStoreFull) {
		t.Fatalf("registre plein : %v", err)
	}
	if err := g.VerifyClassW(ctx, p2, "a", "r2", 7); !errors.Is(err, ErrQuorumProofReplayed) {
		t.Fatalf("une preuve encore valide a été évincée : %v", err)
	}
	// p1 expire : sa place se libère, p3 passe ; p1 elle-même est expirée, donc refusée.
	clk.advance(40 * time.Second)
	if err := g.VerifyClassW(ctx, p3, "a", "r3", 7); err != nil {
		t.Fatalf("après expiration de p1, p3 devrait passer : %v", err)
	}
	if err := g.VerifyClassW(ctx, p1, "a", "r1", 7); !errors.Is(err, ErrQuorumProofExpired) {
		t.Fatalf("p1 expirée : %v", err)
	}
}

func TestFileProofStoreSurvivesARestart(t *testing.T) {
	_, privs := testControllers(t)
	path := filepath.Join(t.TempDir(), "quorum_proofs_consumed.json")
	exp := t0.Add(60 * time.Second)
	proof := mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, exp, 1, 2)

	first, err := NewFileProofStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := newGateWithStore(t, newClock(t0), &leafRecorder{}, first).VerifyClassW(context.Background(), proof, "a", "r", 7); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %v", st.Mode().Perm())
	}

	// « redémarrage » : nouveau magasin, nouveau gate, même fichier.
	second, err := NewFileProofStore(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = newGateWithStore(t, newClock(t0), &leafRecorder{}, second).VerifyClassW(context.Background(), proof, "a", "r", 7)
	if !errors.Is(err, ErrQuorumProofReplayed) {
		t.Fatalf("preuve rejouée après redémarrage : %v", err)
	}
}

func TestFileProofStoreRefusesACorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quorum_proofs_consumed.json")
	if err := os.WriteFile(path, []byte("{pas du json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileProofStore(path, 0); err == nil || !strings.Contains(err.Error(), "illisible") {
		t.Fatalf("registre corrompu accepté (replie-t-il sur un registre vide ?) : %v", err)
	}
	if _, err := NewFileProofStore("", 0); err == nil {
		t.Fatal("chemin vide accepté")
	}
}

// Écriture impossible ⇒ refus fail-closed, et la preuve n'est pas brûlée en
// mémoire pour autant (elle n'a rien autorisé).
func TestStoreWriteFailureFailsClosed(t *testing.T) {
	_, privs := testControllers(t)
	dir := t.TempDir()
	store, err := NewFileProofStore(filepath.Join(dir, "sous", "absent.json"), 0) // répertoire inexistant
	if err != nil {
		t.Fatal(err)
	}
	g := newGateWithStore(t, newClock(t0), &leafRecorder{}, store)
	proof := mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(60*time.Second), 1, 2)
	if err := g.VerifyClassW(context.Background(), proof, "a", "r", 7); !errors.Is(err, ErrQuorumProofStoreFail) {
		t.Fatalf("écriture impossible : %v — la preuve ne doit JAMAIS être admise sans consommation durable", err)
	}
	if store.Len() != 0 {
		t.Fatal("une entrée non persistée est restée en mémoire")
	}
	// Le répertoire réapparaît : la même preuve, qui n'a rien autorisé, passe.
	if err := os.MkdirAll(filepath.Join(dir, "sous"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyClassW(context.Background(), proof, "a", "r", 7); err != nil {
		t.Fatalf("après réparation : %v", err)
	}
}

// Concurrence : N présentations simultanées de la même preuve, UNE admission.
func TestConcurrentPresentationsAdmitExactlyOne(t *testing.T) {
	_, privs := testControllers(t)
	g := newGate(t, newClock(t0), &leafRecorder{})
	proof := mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(60*time.Second), 1, 2)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.VerifyClassW(context.Background(), proof, "a", "r", 7) == nil {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := admitted.Load(); n != 1 {
		t.Fatalf("%d admissions pour une seule preuve", n)
	}
}
