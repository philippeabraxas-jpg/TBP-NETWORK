package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func keyFile(t *testing.T, dir, name string, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = seedByte
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed), p
}

func keyringOf(keys ...ed25519.PrivateKey) map[[16]byte]ed25519.PublicKey {
	kr := map[[16]byte]ed25519.PublicKey{}
	for _, k := range keys {
		pub := k.Public().(ed25519.PublicKey)
		kr[pep.KeyIDFromPublicKey(pub)] = pub
	}
	return kr
}

// La preuve produite par l'outil est acceptée par le VRAI vérificateur des démons —
// et refusée dès qu'on change la condition, la cellule ou le nombre de signataires.
func TestSignedProofIsAcceptedByTheDaemonsVerifier(t *testing.T) {
	dir := t.TempDir()
	k1, f1 := keyFile(t, dir, "k1", 1)
	k2, f2 := keyFile(t, dir, "k2", 2)
	out := filepath.Join(dir, "proof.json")
	const cond, cell = "provisioning-transition-brokerd", "cell-a"

	if err := cmdSign([]string{"-condition", cond, "-cell", cell, "-key", f1, "-key", f2, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions de la preuve = %v", st.Mode().Perm())
	}
	kr := keyringOf(k1, k2)
	if err := pep.VerifyQuorumProofFile(out, cond, cell, kr, 2); err != nil {
		t.Fatalf("preuve valide refusée : %v", err)
	}
	// cas voisins refusés
	if err := pep.VerifyQuorumProofFile(out, "mode-closed", cell, kr, 2); err == nil {
		t.Fatal("la preuve vaut pour une autre condition")
	}
	if err := pep.VerifyQuorumProofFile(out, cond, "cell-b", kr, 2); err == nil {
		t.Fatal("la preuve vaut pour une autre cellule")
	}
	if err := pep.VerifyQuorumProofFile(out, cond, cell, kr, 3); err == nil {
		t.Fatal("2 signatures suffisent pour k = 3")
	}
}

func TestScaleOneAdminAloneIsQuorumOfOne(t *testing.T) {
	dir := t.TempDir()
	admin, f := keyFile(t, dir, "admin", 9)
	out := filepath.Join(dir, "proof.json")
	if err := cmdSign([]string{"-condition", "provisioning-transition-pepd", "-cell", "cell-a", "-key", f, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(out, "provisioning-transition-pepd", "cell-a", keyringOf(admin), 1); err != nil {
		t.Fatalf("l'admin seul (k = 1) refusé : %v", err)
	}
}

func TestSameKeyTwiceIsNotTwoSigners(t *testing.T) {
	dir := t.TempDir()
	_, f := keyFile(t, dir, "k", 3)
	err := cmdSign([]string{"-condition", "c", "-cell", "x", "-key", f, "-key", f, "-out", filepath.Join(dir, "p.json")})
	if err == nil || !strings.Contains(err.Error(), "deux fois") {
		t.Fatalf("même clé comptée deux fois : %v", err)
	}
}

// Le flux HSM : on récupère le message, on signe AILLEURS, on assemble.
func TestMessageThenAssembleMatchesDirectSigning(t *testing.T) {
	dir := t.TempDir()
	k, _ := keyFile(t, dir, "k", 4)
	exp := time.Now().Add(120 * time.Second)
	msg := pep.QuorumMessage("mode-closed", "cell-a", exp)
	kid := pep.KeyIDFromPublicKey(k.Public().(ed25519.PublicKey))
	out := filepath.Join(dir, "proof.json")
	err := cmdAssemble([]string{"-expiry", strconv.FormatInt(exp.Unix(), 10), "-sig", hex.EncodeToString(kid[:]) + "=" + hex.EncodeToString(ed25519.Sign(k, msg)), "-out", out})
	if err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(out, "mode-closed", "cell-a", keyringOf(k), 1); err != nil {
		t.Fatalf("preuve assemblée refusée : %v", err)
	}
}

func TestBadInputsAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("aucune clé acceptée")
	}
	_, f := keyFile(t, dir, "k", 5)
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-ttl", "5", "-key", f, "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("ttl trop court accepté")
	}
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-ttl", "100000", "-key", f, "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("ttl trop long accepté")
	}
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("zz"), 0o600)
	if err := cmdSign([]string{"-condition", "c", "-cell", "x", "-key", bad, "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("clé illisible acceptée")
	}
	if err := cmdAssemble([]string{"-expiry", "12", "-sig", "nokid", "-out", filepath.Join(dir, "p.json")}); err == nil {
		t.Error("signature mal formée acceptée")
	}
}

// keygen produit une clé et un trousseau que le VRAI vérificateur accepte (k = 1),
// n'écrase jamais une clé existante, et complète un trousseau sans le réécrire à l'aveugle.
func TestKeygenBuildsAKeyringTheVerifierAccepts(t *testing.T) {
	dir := t.TempDir()
	keyPath, ringPath := filepath.Join(dir, "admin.key"), filepath.Join(dir, "quorum-keyring.json")
	sink, err := os.Create(filepath.Join(dir, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()

	if err := cmdKeygen([]string{"-key", keyPath, "-keyring", ringPath}, sink); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(keyPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions de la clé = %v", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(ringPath)
	var wire map[string]string
	if err := json.Unmarshal(raw, &wire); err != nil || len(wire) != 1 {
		t.Fatalf("trousseau = %s (%v)", raw, err)
	}
	kr := map[[16]byte]ed25519.PublicKey{}
	for kidHex, pubHex := range wire {
		kid, _ := hex.DecodeString(kidHex)
		pub, _ := hex.DecodeString(pubHex)
		var k [16]byte
		copy(k[:], kid)
		kr[k] = ed25519.PublicKey(pub)
	}
	proof := filepath.Join(dir, "proof.json")
	if err := cmdSign([]string{"-condition", "mode-closed", "-cell", "cell-a", "-key", keyPath, "-out", proof}); err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(proof, "mode-closed", "cell-a", kr, 1); err != nil {
		t.Fatalf("la clé générée n'ouvre pas le trousseau généré : %v", err)
	}

	// jamais d'écrasement d'une clé existante
	if err := cmdKeygen([]string{"-key", keyPath, "-keyring", ringPath}, sink); err == nil {
		t.Fatal("keygen a écrasé une clé existante")
	}
	// une seconde clé complète le trousseau (k-of-n pour les échelles supérieures)
	if err := cmdKeygen([]string{"-key", filepath.Join(dir, "admin2.key"), "-keyring", ringPath}, sink); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(ringPath)
	_ = json.Unmarshal(raw, &wire)
	if len(wire) != 2 {
		t.Fatalf("trousseau après 2 keygen = %d clé(s)", len(wire))
	}
	// un trousseau illisible n'est pas réécrit
	if err := os.WriteFile(ringPath, []byte("pas du json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdKeygen([]string{"-key", filepath.Join(dir, "admin3.key"), "-keyring", ringPath}, sink); err == nil {
		t.Fatal("trousseau corrompu réécrit à l'aveugle")
	}
	if got, _ := os.ReadFile(ringPath); string(got) != "pas du json" {
		t.Fatal("trousseau corrompu modifié")
	}
}

// --- preuves de classe W pour brokerd (wproof / wmessage / wassemble) ------------------

type wLeafSink struct{ n int }

func (w *wLeafSink) Append(_ context.Context, _ registry.Leaf) (uint64, error) {
	w.n++
	return uint64(w.n), nil
}

// wGate : le VRAI QuorumGate de brokerd, 2-sur-3, sur un manifeste dont l'ordre fait les key_id.
func wGate(t *testing.T, dir string, pubs []ed25519.PublicKey, policy [32]byte) (*cluster.QuorumGate, string) {
	t.Helper()
	var hexPubs []string
	ctrls := map[int]ed25519.PublicKey{}
	for i, p := range pubs {
		hexPubs = append(hexPubs, hex.EncodeToString(p))
		ctrls[i+1] = p
	}
	data, _ := json.Marshal(map[string][]string{"pubkeys": hexPubs})
	mf := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mf, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := cluster.NewMemoryProofStore(0)
	if err != nil {
		t.Fatal(err)
	}
	g, err := cluster.NewQuorumGate(cluster.QuorumGateConfig{
		CellID: "cell-a", Salt: make([]byte, 16), Leaves: &wLeafSink{}, Controllers: ctrls, K: 2,
		PolicyID: policy, Consumed: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, mf
}

// La preuve que l'outil fabrique est acceptée par le vrai QuorumGate de brokerd à k = 2, refusée
// à 1 signature, et à usage unique (#206). Le key_id vient de la position dans le manifeste.
func TestWProofIsAcceptedByTheRealQuorumGate(t *testing.T) {
	dir := t.TempDir()
	k1, f1 := keyFile(t, dir, "k1", 1)
	k2, f2 := keyFile(t, dir, "k2", 2)
	k3, _ := keyFile(t, dir, "k3", 3)
	_, fOut := keyFile(t, dir, "intrus", 9)
	var policy [32]byte
	policy[0] = 7
	policyHex := hex.EncodeToString(policy[:])
	// l'ordre du manifeste : k3, k1, k2 → leurs key_id sont 1, 2, 3 et NE sont PAS l'ordre des fichiers
	g, mf := wGate(t, dir, []ed25519.PublicKey{k3.Public().(ed25519.PublicKey), k1.Public().(ed25519.PublicKey), k2.Public().(ed25519.PublicKey)}, policy)
	ctx := context.Background()
	mk := func(out string, files ...string) error {
		args := []string{"-manifest", mf, "-action", "read", "-resource", "doc-1", "-policy", policyHex, "-out", out}
		for _, f := range files {
			args = append(args, "-key", f)
		}
		return cmdWProof(args)
	}
	read := func(p string) []byte {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	one := filepath.Join(dir, "one.json")
	if err := mk(one, f1); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyClassW(ctx, read(one), "read", "doc-1", 0); err == nil {
		t.Fatal("une seule signature acceptée pour k = 2")
	}
	two := filepath.Join(dir, "two.json")
	if err := mk(two, f1, f2); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyClassW(ctx, read(two), "read", "doc-1", 0); err != nil {
		t.Fatalf("preuve à 2 signatures refusée par le vrai gate : %v", err)
	}
	if err := g.VerifyClassW(ctx, read(two), "read", "doc-1", 0); err == nil {
		t.Fatal("la même preuve a servi deux fois (#206)")
	}
	// mauvaise ressource : la liaison la refuse
	three := filepath.Join(dir, "three.json")
	if err := mk(three, f1, f2); err != nil {
		t.Fatal(err)
	}
	if err := g.VerifyClassW(ctx, read(three), "read", "AUTRE", 0); err == nil {
		t.Fatal("preuve acceptée pour une autre ressource")
	}
	// clé hors manifeste, clé en double : l'outil refuse de fabriquer
	if err := mk(filepath.Join(dir, "x.json"), f1, fOut); err == nil {
		t.Fatal("clé hors manifeste acceptée par l'outil")
	}
	if err := mk(filepath.Join(dir, "y.json"), f1, f1); err == nil {
		t.Fatal("contrôleur en double accepté par l'outil")
	}
}

// Le chemin HSM : wmessage écrit la déclaration, les signatures se font ailleurs, wassemble assemble —
// et le résultat est accepté par le vrai gate.
func TestWMessageAndAssembleMatchTheGate(t *testing.T) {
	dir := t.TempDir()
	k1, _ := keyFile(t, dir, "k1", 1)
	k2, _ := keyFile(t, dir, "k2", 2)
	k3, _ := keyFile(t, dir, "k3", 3)
	var policy [32]byte
	policy[1] = 5
	g, _ := wGate(t, dir, []ed25519.PublicKey{k1.Public().(ed25519.PublicKey), k2.Public().(ed25519.PublicKey), k3.Public().(ed25519.PublicKey)}, policy)
	stmt := filepath.Join(dir, "stmt.json")
	if err := cmdWMessage([]string{"-action", "read", "-resource", "doc-1", "-policy", hex.EncodeToString(policy[:]), "-out", stmt}); err != nil {
		t.Fatal(err)
	}
	var st cluster.QuorumStatement
	raw, _ := os.ReadFile(stmt)
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(st)
	proof := filepath.Join(dir, "proof.json")
	err := cmdWAssemble([]string{"-statement", stmt, "-quorum", "2-of-3", "-out", proof,
		"-sig", "1=" + hex.EncodeToString(ed25519.Sign(k1, canonical)),
		"-sig", "3=" + hex.EncodeToString(ed25519.Sign(k3, canonical))})
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := os.ReadFile(proof)
	if err := g.VerifyClassW(context.Background(), pb, "read", "doc-1", 0); err != nil {
		t.Fatalf("preuve assemblée refusée par le vrai gate : %v", err)
	}
	if err := cmdWAssemble([]string{"-statement", stmt, "-out", proof, "-sig", "1=zz"}); err == nil {
		t.Fatal("signature mal formée acceptée")
	}
	if err := cmdWMessage([]string{"-action", "read", "-resource", "doc-1", "-policy", "abc", "-out", stmt}); err == nil {
		t.Fatal("bundle mal formé accepté")
	}
	if err := cmdWMessage([]string{"-action", "read", "-resource", "doc-1", "-policy", hex.EncodeToString(policy[:]), "-ttl", "9999", "-out", stmt}); err == nil {
		t.Fatal("ttl hors bornes accepté")
	}
}

// --- contrat de plan : planapprove / planbind -------------------------------------------

func TestPlanApproveAndBindMatchWhatBrokerdVerifies(t *testing.T) {
	dir := t.TempDir()
	op, fop := keyFile(t, dir, "operator", 4)
	var h [32]byte
	h[0], h[31] = 0xab, 0xcd
	hexHash := hex.EncodeToString(h[:])
	out := filepath.Join(dir, "approve.json")
	if err := cmdPlanApprove([]string{"-plan-hash", hexHash, "-key", fop, "-out", out}); err != nil {
		t.Fatal(err)
	}
	var body struct {
		PlanHash  string `json:"plan_hash"`
		ExpiresAt string `json:"expires_at"`
		Signature string `json:"signature"`
	}
	raw, _ := os.ReadFile(out)
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil || body.PlanHash != hexHash {
		t.Fatalf("corps d'approbation : %+v (%v)", body, err)
	}
	sig, _ := hex.DecodeString(body.Signature)
	if !ed25519.Verify(op.Public().(ed25519.PublicKey), pep.ApprovalMessage(h, exp), sig) {
		t.Fatal("la signature n'est pas celle que brokerd vérifie (ApprovalMessage)")
	}
	if ed25519.Verify(op.Public().(ed25519.PublicKey), pep.ApprovalMessage([32]byte{1}, exp), sig) {
		t.Fatal("signature valable pour un autre plan")
	}
	if err := cmdPlanApprove([]string{"-plan-hash", "zz", "-key", fop, "-out", out}); err == nil {
		t.Fatal("hash mal formé accepté")
	}
	if err := cmdPlanApprove([]string{"-plan-hash", hexHash, "-key", fop, "-ttl", "99999", "-out", out}); err == nil {
		t.Fatal("ttl hors bornes accepté")
	}
	if err := cmdPlanBind([]string{"-plan-hash", hexHash, "-params-hex", "gg"}); err == nil {
		t.Fatal("paramètres mal formés acceptés")
	}
}

// Issue #236 : la condition d'une transition porte l'état de départ et l'état cible ; la
// preuve signée sur la condition annoncée par le démon vaut pour elle, et pour aucune autre paire.
func TestSignedTransitionConditionBindsTheTargetState(t *testing.T) {
	dir := t.TempDir()
	admin, f := keyFile(t, dir, "admin", 9)
	from, to, other := [32]byte{1}, [32]byte{2}, [32]byte{3}
	cond := pep.TransitionCondition("provisioning-transition-pepd", from, to)
	if !strings.Contains(cond, "|from=01") || !strings.Contains(cond, "|to=02") {
		t.Fatalf("condition sans état lié : %q", cond)
	}
	out := filepath.Join(dir, "p.json")
	if err := cmdSign([]string{"-condition", cond, "-cell", "cell-a", "-key", f, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if err := pep.VerifyQuorumProofFile(out, cond, "cell-a", keyringOf(admin), 1); err != nil {
		t.Fatalf("la preuve signée sur la condition annoncée est refusée : %v", err)
	}
	for name, c := range map[string]string{
		"autre cible":       pep.TransitionCondition("provisioning-transition-pepd", from, other),
		"autre départ":      pep.TransitionCondition("provisioning-transition-pepd", other, to),
		"retour (inversée)": pep.TransitionCondition("provisioning-transition-pepd", to, from),
		"sans état":         "provisioning-transition-pepd",
	} {
		if err := pep.VerifyQuorumProofFile(out, c, "cell-a", keyringOf(admin), 1); err == nil {
			t.Fatalf("la preuve vaut aussi pour %s", name)
		}
	}
}

// #244 : planrevoke signe RevocationMessage (« TBPR1 »), pas l'approbation : le corps vérifie
// contre le message de révocation, et la même signature ne vaut pas approbation.
func TestPlanRevokeSignsTheRevocationMessageNotTheApproval(t *testing.T) {
	dir := t.TempDir()
	op, keyPath := keyFile(t, dir, "operator", 7)
	hash := [32]byte{0xab, 0xcd}
	hashHex := hex.EncodeToString(hash[:])
	out := filepath.Join(dir, "revocation.json")
	if err := cmdPlanRevoke([]string{"-plan-hash", hashHex, "-ttl", "120", "-key", keyPath, "-out", out}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		PlanHash  string `json:"plan_hash"`
		ExpiresAt string `json:"expires_at"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil || body.PlanHash != hashHex {
		t.Fatalf("corps mal formé : %+v (%v)", body, err)
	}
	sig, err := hex.DecodeString(body.Signature)
	if err != nil {
		t.Fatal(err)
	}
	pub := op.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, pep.RevocationMessage(hash, exp), sig) {
		t.Fatal("la signature ne vérifie pas contre RevocationMessage")
	}
	if ed25519.Verify(pub, pep.ApprovalMessage(hash, exp), sig) {
		t.Fatal("la signature de révocation vaut aussi approbation (domaines non séparés)")
	}
	// TTL hors bornes et hash mal formé : refusés
	for name, args := range map[string][]string{
		"ttl trop court": {"-plan-hash", hashHex, "-ttl", "1", "-key", keyPath, "-out", out},
		"ttl trop long":  {"-plan-hash", hashHex, "-ttl", "99999", "-key", keyPath, "-out", out},
		"hash invalide":  {"-plan-hash", "zz", "-key", keyPath, "-out", out},
		"sans clé":       {"-plan-hash", hashHex, "-out", out},
	} {
		if err := cmdPlanRevoke(args); err == nil {
			t.Fatalf("%s accepté", name)
		}
	}
}

// ---------------------------------------------------------------------------
// #273 : planhash recalcule le hash d'un plan comme le fait le broker
// ---------------------------------------------------------------------------

type nopSink struct{}

func (nopSink) Append(context.Context, registry.Leaf) (uint64, error) { return 1, nil }

const planJSON = `{"subject":"agent-w","steps":[{"action":"read","resource":"doc-1","params_hex":""},{"action":"write","resource":"doc-2","params_hex":"0a0b"}]}`

func writePlan(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func planHashOf(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := cmdPlanHash(args, &out)
	h := ""
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "plan_hash=") {
			h = strings.TrimPrefix(l, "plan_hash=")
		}
	}
	return h, err
}

// Le hash recalculé par l'outil à partir du plan en clair est EXACTEMENT celui que le vrai
// ContractStore du broker a scellé — et chaque champ du sceau le change.
func TestPlanHashMatchesWhatTheBrokerSeals(t *testing.T) {
	dir := t.TempDir()
	opKey, _ := keyFile(t, dir, "operator", 4)
	policy := [32]byte{9, 8, 7}
	submitted := time.Date(2026, 10, 2, 8, 30, 15, 987_000_000, time.UTC) // sous-secondes : ignorées par le sceau
	store, err := pep.NewContractStore(pep.ContractOptions{
		CellID: "cell-s2", PolicyID: policy, OperatorKeys: []ed25519.PublicKey{opKey.Public().(ed25519.PublicKey)},
		Salt: []byte("sel-de-test-16-octets+"), Leaves: nopSink{}, Now: func() time.Time { return submitted },
	})
	if err != nil {
		t.Fatal(err)
	}
	steps := []pep.PlanStep{
		{Action: "read", Resource: "doc-1", ParamsHash: pep.HashParams(nil)},
		{Action: "write", Resource: "doc-2", ParamsHash: pep.HashParams([]byte{0x0a, 0x0b})},
	}
	sealed, err := store.Submit(context.Background(), "agent-w", steps)
	if err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(sealed[:])
	planPath := writePlan(t, dir, planJSON)
	base := []string{"-cell", "cell-s2", "-policy-id", hex.EncodeToString(policy[:]), "-submitted-at", submitted.Format(time.RFC3339Nano), "-plan", planPath}

	got, err := planHashOf(t, base...)
	if err != nil || got != want {
		t.Fatalf("hash recalculé %q (err=%v), le broker a scellé %q", got, err, want)
	}
	// secondes Unix : même hash ; -expect conforme : succès
	unix := append([]string(nil), base...)
	unix[5] = strconv.FormatInt(submitted.Unix(), 10)
	if got, err := planHashOf(t, append(unix, "-expect", want)...); err != nil || got != want {
		t.Fatalf("secondes Unix + -expect : %q (%v)", got, err)
	}

	// chaque champ du sceau le change (et -expect refuse alors : « ne signez pas »)
	with := func(i int, v string) []string { a := append([]string(nil), base...); a[i] = v; return a }
	otherPolicy := policy
	otherPolicy[0] ^= 1
	variants := map[string][]string{
		"cellule":    with(1, "cell-s3"),
		"politique":  with(3, hex.EncodeToString(otherPolicy[:])),
		"soumission": with(5, submitted.Add(time.Second).Format(time.RFC3339)),
	}
	for name, a := range variants {
		if h, err := planHashOf(t, a...); err != nil || h == want {
			t.Errorf("%s modifié : hash %q (err=%v), doit différer du sceau", name, h, err)
		}
		if _, err := planHashOf(t, append(a, "-expect", want)...); err == nil || !strings.Contains(err.Error(), "DIFFÉRENT") {
			t.Errorf("%s modifié : -expect doit refuser (« DIFFÉRENT »), reçu %v", name, err)
		}
	}
	planVariants := map[string]string{
		"sujet":          strings.Replace(planJSON, "agent-w", "agent-x", 1),
		"action":         strings.Replace(planJSON, `"read"`, `"list"`, 1),
		"ressource":      strings.Replace(planJSON, "doc-1", "doc-9", 1),
		"paramètres":     strings.Replace(planJSON, "0a0b", "0a0c", 1),
		"ordre":          `{"subject":"agent-w","steps":[{"action":"write","resource":"doc-2","params_hex":"0a0b"},{"action":"read","resource":"doc-1","params_hex":""}]}`,
		"étape en moins": `{"subject":"agent-w","steps":[{"action":"read","resource":"doc-1","params_hex":""}]}`,
	}
	for name, body := range planVariants {
		a := with(7, writePlan(t, dir, body))
		if h, err := planHashOf(t, a...); err != nil || h == want {
			t.Errorf("plan avec %s modifié : hash %q (err=%v), doit différer du sceau", name, h, err)
		}
	}
	// la sortie montre tout ce qui entre dans le sceau (« ce qu'on voit est ce qu'on signe »)
	var out strings.Builder
	if err := cmdPlanHash(base, &out); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"cell=cell-s2", "subject=agent-w", "submitted_at=" + strconv.FormatInt(submitted.Unix(), 10), "policy_id=", "step 1: action=read resource=doc-1", "step 2: action=write resource=doc-2"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("sortie sans %q :\n%s", w, out.String())
		}
	}
}

// Le plan est lu STRICTEMENT et borné comme le broker (pep.ValidatePlan) : un plan que le broker
// refuserait n'a pas de hash.
func TestPlanHashRefusesWhatTheBrokerRefuses(t *testing.T) {
	dir := t.TempDir()
	pol := strings.Repeat("02", 32)
	args := func(plan string) []string {
		return []string{"-cell", "cell-s2", "-policy-id", pol, "-submitted-at", "1790000000", "-plan", writePlan(t, dir, plan)}
	}
	if _, err := planHashOf(t, args(planJSON)...); err != nil {
		t.Fatalf("plan valide refusé : %v", err)
	}
	long := strings.Repeat("a", 256)
	manySteps := `{"subject":"a","steps":[` + strings.TrimSuffix(strings.Repeat(`{"action":"r","resource":"x","params_hex":""},`, pep.MaxPlanSteps+1), ",") + `]}`
	for name, body := range map[string]string{
		"champ inconnu":         `{"subject":"a","steps":[{"action":"r","resource":"x","params_hex":"","extra":1}]}`,
		"champ inconnu racine":  `{"subject":"a","evil":1,"steps":[{"action":"r","resource":"x","params_hex":""}]}`,
		"contenu après l'objet": planJSON + `{"x":1}`,
		"JSON invalide":         `{"subject":`,
		"sujet vide":            `{"subject":"","steps":[{"action":"r","resource":"x","params_hex":""}]}`,
		"sujet de 256 octets":   `{"subject":"` + long + `","steps":[{"action":"r","resource":"x","params_hex":""}]}`,
		"aucune étape":          `{"subject":"a","steps":[]}`,
		"trop d'étapes":         manySteps,
		"action vide":           `{"subject":"a","steps":[{"action":"","resource":"x","params_hex":""}]}`,
		"action de 256 octets":  `{"subject":"a","steps":[{"action":"` + long + `","resource":"x","params_hex":""}]}`,
		"ressource vide":        `{"subject":"a","steps":[{"action":"r","resource":"","params_hex":""}]}`,
		"params non hex":        `{"subject":"a","steps":[{"action":"r","resource":"x","params_hex":"zz"}]}`,
	} {
		if h, err := planHashOf(t, args(body)...); err == nil {
			t.Errorf("%s : accepté (hash %q)", name, h)
		}
	}
	// arguments : requis, bornes, formats
	base := args(planJSON)
	for name, bad := range map[string][]string{
		"cellule vide":      {"-cell", "", "-policy-id", pol, "-submitted-at", "1790000000", "-plan", base[7]},
		"cellule de 256":    {"-cell", long, "-policy-id", pol, "-submitted-at", "1790000000", "-plan", base[7]},
		"politique courte":  {"-cell", "c", "-policy-id", "abcd", "-submitted-at", "1790000000", "-plan", base[7]},
		"instant invalide":  {"-cell", "c", "-policy-id", pol, "-submitted-at", "hier", "-plan", base[7]},
		"instant nul":       {"-cell", "c", "-policy-id", pol, "-submitted-at", "0", "-plan", base[7]},
		"plan absent":       {"-cell", "c", "-policy-id", pol, "-submitted-at", "1790000000", "-plan", filepath.Join(dir, "absent.json")},
		"-expect mal formé": append(append([]string(nil), base...), "-expect", "zz"),
	} {
		if _, err := planHashOf(t, bad...); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
