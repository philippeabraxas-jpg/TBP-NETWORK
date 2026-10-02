package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	translator "github.com/philippeabraxas-jpg/TBP-NETWORK/src/translator"
)

func TestArbIDMatchesTheBrokersIdentifier(t *testing.T) {
	var out bytes.Buffer
	if err := cmdArbID([]string{"-subject", "agent-1", "-intent", `{"action":"read"}`}, &out); err != nil {
		t.Fatal(err)
	}
	want := arbiter.IntentID("agent-1", []byte(`{"action":"read"}`))
	if strings.TrimSpace(out.String()) != hex.EncodeToString(want[:]) {
		t.Fatalf("id = %q, attendu %x", out.String(), want)
	}
	// depuis un fichier : octets EXACTS (un saut de ligne final change l'identifiant)
	dir := t.TempDir()
	f := filepath.Join(dir, "intent.json")
	_ = os.WriteFile(f, []byte(`{"action":"read"}`+"\n"), 0o600)
	var out2 bytes.Buffer
	if err := cmdArbID([]string{"-subject", "agent-1", "-intent-file", f}, &out2); err != nil {
		t.Fatal(err)
	}
	if out2.String() == out.String() {
		t.Fatal("un saut de ligne final doit changer l'identifiant (octets exacts)")
	}
	for name, a := range map[string][]string{
		"sans_sujet":  {"-intent", "x"},
		"sans_intent": {"-subject", "a"},
		"les_deux":    {"-subject", "a", "-intent", "x", "-intent-file", f},
	} {
		if err := cmdArbID(a, &bytes.Buffer{}); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

// Les corps produits par les trois gestes sont acceptés par la file : mêmes messages signés que le démon.
func TestArbToolsProduceWhatTheQueueAccepts(t *testing.T) {
	dir := t.TempDir()
	priv, kf := keyFile(t, dir, "op.key", 5)
	q, err := arbiter.NewQueue(arbiter.Options{
		CellID: "cell-a", Salt: make([]byte, 16), Leaves: nopLeaves{}, OperatorKeys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func(p string) map[string]string {
		var m map[string]string
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(b, &m)
		return m
	}
	// présence
	pp := filepath.Join(dir, "presence.json")
	if err := cmdArbPresence([]string{"-cell", "cell-a", "-key", kf, "-out", pp}); err != nil {
		t.Fatal(err)
	}
	pm := read(pp)
	at, _ := time.Parse(time.RFC3339, pm["at"])
	sig, _ := hex.DecodeString(pm["signature"])
	if err := q.Heartbeat(t.Context(), at, sig); err != nil {
		t.Fatalf("présence refusée par la file : %v", err)
	}
	// décision
	it := arbiter.IntentID("agent-1", []byte("x"))
	_ = q.Enqueue(t.Context(), itemOf("agent-1", "x"))
	ticket := q.Snapshot()[0].Ticket // ce que l'opérateur lit dans GET /v1/supervision/degraded
	dp := filepath.Join(dir, "decision.json")
	if err := cmdArbDecide([]string{"-cell", "cell-a", "-id", hex.EncodeToString(it[:]), "-ticket", hex.EncodeToString(ticket[:]), "-verdict", "approve", "-ttl", "120", "-key", kf, "-out", dp}); err != nil {
		t.Fatal(err)
	}
	dm := read(dp)
	exp, _ := time.Parse(time.RFC3339, dm["expires_at"])
	dsig, _ := hex.DecodeString(dm["signature"])
	if dm["verdict"] != "approve" || dm["id"] != hex.EncodeToString(it[:]) {
		t.Fatalf("corps : %v", dm)
	}
	if err := q.Decide(t.Context(), it, arbiter.VerdictApprove, exp, dsig); err != nil {
		t.Fatalf("décision refusée par la file : %v", err)
	}
	// le fichier est en 0600
	if fi, _ := os.Stat(dp); fi.Mode().Perm() != 0o600 {
		t.Fatalf("droits %v", fi.Mode().Perm())
	}
}

func TestArbDecideRefusesBadInputs(t *testing.T) {
	dir := t.TempDir()
	_, kf := keyFile(t, dir, "op.key", 5)
	id := strings.Repeat("ab", 32)
	tk := strings.Repeat("cd", 16)
	out := filepath.Join(dir, "o.json")
	for name, a := range map[string][]string{
		"sans_id":         {"-cell", "cell-a", "-ticket", tk, "-verdict", "approve", "-key", kf, "-out", out},
		"sans_cellule":    {"-id", id, "-ticket", tk, "-verdict", "approve", "-key", kf, "-out", out},
		"sans_ticket":     {"-cell", "cell-a", "-id", id, "-verdict", "approve", "-key", kf, "-out", out},
		"ticket_court":    {"-cell", "cell-a", "-id", id, "-ticket", "abcd", "-verdict", "approve", "-key", kf, "-out", out},
		"ticket_non_hex":  {"-cell", "cell-a", "-id", id, "-ticket", strings.Repeat("zz", 16), "-verdict", "approve", "-key", kf, "-out", out},
		"verdict_inconnu": {"-cell", "cell-a", "-id", id, "-ticket", tk, "-verdict", "peut-etre", "-key", kf, "-out", out},
		"id_court":        {"-cell", "cell-a", "-id", "abcd", "-ticket", tk, "-verdict", "approve", "-key", kf, "-out", out},
		"id_non_hex":      {"-cell", "cell-a", "-id", strings.Repeat("zz", 32), "-ticket", tk, "-verdict", "approve", "-key", kf, "-out", out},
		"ttl_court":       {"-cell", "cell-a", "-id", id, "-ticket", tk, "-verdict", "approve", "-ttl", "5", "-key", kf, "-out", out},
		"ttl_long":        {"-cell", "cell-a", "-id", id, "-ticket", tk, "-verdict", "approve", "-ttl", "7200", "-key", kf, "-out", out},
		"sans_cle":        {"-cell", "cell-a", "-id", id, "-ticket", tk, "-verdict", "approve", "-out", out},
		"cle_absente":     {"-cell", "cell-a", "-id", id, "-ticket", tk, "-verdict", "approve", "-key", filepath.Join(dir, "absente"), "-out", out},
	} {
		if err := cmdArbDecide(a); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if err := cmdArbPresence([]string{"-cell", "cell-a", "-out", out}); err == nil {
		t.Error("présence sans clé acceptée")
	}
	if err := cmdArbPresence([]string{"-key", kf, "-out", out}); err == nil {
		t.Error("présence sans cellule acceptée : un battement doit nommer sa cellule")
	}
}

type nopLeaves struct{}

func (nopLeaves) Append(context.Context, registry.Leaf) (uint64, error) { return 0, nil }

func itemOf(subject, intent string) translator.ArbitrationItem {
	return translator.ArbitrationItem{SystemID: subject, Payload: []byte(intent)}
}

// Le geste d'opérateur signe POUR UNE CELLULE : la file d'une autre cellule le refuse.
func TestArbToolsSignForOneCellOnly(t *testing.T) {
	dir := t.TempDir()
	priv, kf := keyFile(t, dir, "op.key", 5)
	qB, err := arbiter.NewQueue(arbiter.Options{
		CellID: "cell-b", Salt: make([]byte, 16), Leaves: nopLeaves{}, OperatorKeys: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	pp := filepath.Join(dir, "presence.json")
	if err := cmdArbPresence([]string{"-cell", "cell-a", "-key", kf, "-out", pp}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(pp)
	var pm map[string]string
	_ = json.Unmarshal(b, &pm)
	at, _ := time.Parse(time.RFC3339, pm["at"])
	sig, _ := hex.DecodeString(pm["signature"])
	if err := qB.Heartbeat(t.Context(), at, sig); err == nil {
		t.Fatal("la cellule B a accepté un battement signé pour la cellule A")
	}
}
