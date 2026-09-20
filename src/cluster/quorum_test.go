package cluster

// Tests du QuorumGate (§7.5) : « a single cell, adversarial or captured,
// cannot authorize the maximal irreversible ». Chaque refus est provoqué
// par une faute PRÉCISE (mutation) — un test qui passerait sans la faute
// est non-vacuole.

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

var testPolicyID [32]byte // zéros — comme le vecteur de schema.md §9

// mintQuorumProof frappe une preuve liée à (action, resource, policyID,
// epoch), expirant à expiry, signée par les contrôleurs donnés.
func mintQuorumProof(t *testing.T, privs map[int]ed25519.PrivateKey, action, resource string, policyID [32]byte, epoch uint64, expiry time.Time, signers ...int) []byte {
	t.Helper()
	st := QuorumStatement{
		Action:   action,
		Resource: resource,
		PolicyID: hex.EncodeToString(policyID[:]),
		Epoch:    epoch,
		Expiry:   expiry.UTC().Format(time.RFC3339),
	}
	canonical, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("statement : %v", err)
	}
	proof := QuorumProof{Statement: st, Quorum: "2-of-3"}
	for _, id := range signers {
		sig := ed25519.Sign(privs[id], canonical)
		proof.Signatures = append(proof.Signatures, ControllerSignature{KeyID: id, Sig: hex.EncodeToString(sig)})
	}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("proof : %v", err)
	}
	return data
}

func newGate(t *testing.T, clk *manualClock, leaves *leafRecorder, opts ...func(*QuorumGateConfig)) *QuorumGate {
	t.Helper()
	pubs, _ := testControllers(t)
	cfg := QuorumGateConfig{
		CellID: "cell-a", Salt: testSalt, Leaves: leaves,
		Controllers: pubs, K: 2, PolicyID: testPolicyID, Now: clk.now,
	}
	for _, f := range opts {
		f(&cfg)
	}
	g, err := NewQuorumGate(cfg)
	if err != nil {
		t.Fatalf("NewQuorumGate: %v", err)
	}
	return g
}

// quorumRecord reconstruit le record « TBPQ1 » attendu — preuve à
// révélation du sel (§6.2).
func quorumRecord(verdict byte, valid, k int8, epoch uint64, action, reason string) []byte {
	rec := append([]byte("TBPQ1"), verdict, byte(valid), byte(k))
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	rec = append(rec, eb[:]...)
	rec = append(rec, byte(len(action)))
	rec = append(rec, action...)
	rec = append(rec, byte(len(reason)))
	rec = append(rec, reason...)
	return rec
}

func TestQuorumGateConfigFailClosed(t *testing.T) {
	pubs, _ := testControllers(t)
	full := QuorumGateConfig{
		CellID: "cell-a", Salt: testSalt, Leaves: &leafRecorder{},
		Controllers: pubs, K: 2, PolicyID: testPolicyID,
	}
	if _, err := NewQuorumGate(full); err != nil {
		t.Fatalf("config complète refusée : %v", err)
	}
	cases := map[string]func(*QuorumGateConfig){
		"cellID vide":       func(c *QuorumGateConfig) { c.CellID = "" },
		"sel court":         func(c *QuorumGateConfig) { c.Salt = []byte("court") },
		"feuilles absentes": func(c *QuorumGateConfig) { c.Leaves = nil },
		"sans contrôleurs":  func(c *QuorumGateConfig) { c.Controllers = nil },
		"k=0":               func(c *QuorumGateConfig) { c.K = 0 },
		"k > n":             func(c *QuorumGateConfig) { c.K = 4 },
		"TTL négatif":       func(c *QuorumGateConfig) { c.MaxProofTTLSeconds = -1 },
	}
	for name, mutate := range cases {
		cfg := full
		mutate(&cfg)
		if _, err := NewQuorumGate(cfg); err == nil {
			t.Fatalf("%s : config acceptée", name)
		}
	}
}

// TestQuorumRefusals : chaque faute précise ⇒ refus tracé. Sans la faute,
// la même preuve est admise (prouvé par TestQuorumAllow).
func TestQuorumRefusals(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	g := newGate(t, clk, leaves)
	expiry := t0.Add(60 * time.Second)

	var wrongPolicy [32]byte
	wrongPolicy[0] = 0xff

	cases := map[string]struct {
		proof  []byte
		action string
		epoch  uint64
		want   error
	}{
		"preuve absente":       {nil, "a", 7, ErrQuorumProofRequired},
		"preuve malformée":     {[]byte(`{pas json`), "a", 7, ErrQuorumProofRequired},
		"liaison action":       {mintQuorumProof(t, privs, "autre", "r", testPolicyID, 7, expiry, 1, 2), "a", 7, ErrQuorumBinding},
		"liaison ressource":    {mintQuorumProof(t, privs, "a", "autre", testPolicyID, 7, expiry, 1, 2), "a", 7, ErrQuorumBinding},
		"liaison époque":       {mintQuorumProof(t, privs, "a", "r", testPolicyID, 6, expiry, 1, 2), "a", 7, ErrQuorumBinding},
		"liaison policy":       {mintQuorumProof(t, privs, "a", "r", wrongPolicy, 7, expiry, 1, 2), "a", 7, ErrQuorumBinding},
		"preuve expirée":       {mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(-time.Second), 1, 2), "a", 7, ErrQuorumProofExpired},
		"TTL hors bornes":      {mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(time.Hour), 1, 2), "a", 7, ErrQuorumProofTTLLong},
		"quorum k-1":           {mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, expiry, 1), "a", 7, ErrQuorumInsufficient},
		"signataire en double": {mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, expiry, 1, 1), "a", 7, ErrQuorumInsufficient},
	}
	for name, tc := range cases {
		err := g.VerifyClassW(context.Background(), tc.proof, tc.action, "r", tc.epoch)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s : err=%v, veut %v", name, err, tc.want)
		}
	}
	if got := leaves.countKind(registry.KindQuorum); got != len(cases) {
		t.Fatalf("%d feuilles KindQuorum, veut %d (chaque refus est tracé)", got, len(cases))
	}
	// Preuve de la feuille « quorum k-1 » par re-hash (verdict deny, 1/2).
	want := registry.HashPayload(testSalt, quorumRecord(0x00, 1, 2, 7, "a", "quorum-insufficient"))
	found := false
	for _, l := range leaves.all() {
		if l.PayloadHash == want {
			found = true
		}
	}
	if !found {
		t.Fatal("feuille quorum-insufficient non prouvable par re-hash (§6.2)")
	}
}

// TestQuorumAllow : preuve 2-of-3 valide ⇒ admission tracée — c'est le
// positif qui rend les mutations de TestQuorumRefusals non-vacuoles.
func TestQuorumAllow(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	g := newGate(t, clk, leaves)

	proof := mintQuorumProof(t, privs, "shutdown.cluster", "prod/eu-west", testPolicyID, 7, t0.Add(60*time.Second), 1, 3)
	if err := g.VerifyClassW(context.Background(), proof, "shutdown.cluster", "prod/eu-west", 7); err != nil {
		t.Fatalf("preuve 2-of-3 valide refusée : %v", err)
	}
	ls := leaves.all()
	if len(ls) != 1 || ls[0].Kind != registry.KindQuorum {
		t.Fatalf("feuilles=%+v, veut 1 KindQuorum", ls)
	}
	want := registry.HashPayload(testSalt, quorumRecord(0x01, 2, 2, 7, "shutdown.cluster", "ok"))
	if ls[0].PayloadHash != want {
		t.Fatal("feuille d'admission non prouvable par re-hash (§6.2)")
	}
}

// TestQuorumAllowWithoutLeafFailsClosed : une admission dont la feuille ne
// peut être écrite redevient un refus — pas de preuve, pas d'accès (même
// doctrine que T9/T33).
func TestQuorumAllowWithoutLeafFailsClosed(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{err: errors.New("disque plein simulé")}
	g := newGate(t, clk, leaves)

	proof := mintQuorumProof(t, privs, "a", "r", testPolicyID, 7, t0.Add(60*time.Second), 1, 2)
	if err := g.VerifyClassW(context.Background(), proof, "a", "r", 7); err == nil {
		t.Fatal("quorum admis sans feuille — fail-closed violé (§4.1)")
	}
}

// TestQuorumGateImplementsBrokerSeam : verrou de compilation — le gate
// implémente la couture broker.QuorumGate (câblage T29, revue #30).
func TestQuorumGateImplementsBrokerSeam(t *testing.T) {
	clk := newClock(t0)
	g := newGate(t, clk, &leafRecorder{})
	var _ interface {
		VerifyClassW(context.Context, []byte, string, string, uint64) error
	} = g
	_ = fmt.Sprintf // (importé pour les messages des helpers)
}
