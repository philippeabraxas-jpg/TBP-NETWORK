package main

// plan_submission_test.go — soumetteur ≠ approbateur côté brokerd : à k ≥ 2 la soumission est SIGNÉE (on sait qui soumet), et
// le soumetteur n'approuve pas son propre plan ; la cellule refuse de démarrer quand aucun plan ne pourrait être approuvé ;
// à k = 1 (un seul opérateur fait les deux gestes), la soumission non signée reste ouverte.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func TestSubmissionIsSignedAndTheSubmitterDoesNotApprove(t *testing.T) {
	fx, hc := startQuorumBrokerd(t)
	steps := []planSubmitStepRequest{{Action: "pay", Resource: "invoice-42"}}
	unsigned := `{"subject":"agent-w","steps":[{"action":"pay","resource":"invoice-42","params_hex":""}]}`

	// une cellule à k = 2 refuse la soumission non signée
	if code, out := postBody(t, hc, "/v1/supervision/plan/submit", unsigned); code != http.StatusBadRequest || !strings.Contains(out, "non signée") {
		t.Fatalf("soumission non signée à k = 2 : %d %s", code, out)
	}
	// expires_at sans signature (ou l'inverse) : refusé, pas lu comme une soumission non signée
	half := fmt.Sprintf(`{"subject":"agent-w","steps":[{"action":"pay","resource":"invoice-42","params_hex":""}],"expires_at":%q}`, time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
	if code, _ := postBody(t, hc, "/v1/supervision/plan/submit", half); code != http.StatusBadRequest {
		t.Fatalf("expires_at sans signature : %d", code)
	}
	// une signature d'une clé du trousseau qui n'a pas… ici toutes ont le rôle ; une clé inconnue est refusée
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if code, out := postBody(t, hc, "/v1/supervision/plan/submit", fx.signedSubmitBodyBy(stranger, "agent-w", steps)); code != http.StatusBadRequest || !strings.Contains(out, "signature de soumission") {
		t.Fatalf("soumission signée par un inconnu : %d %s", code, out)
	}
	// voisin : la même soumission, signée par une clé du trousseau
	code, out := postBody(t, hc, "/v1/supervision/plan/submit", fx.signedSubmitBody("agent-w", steps))
	if code != http.StatusOK {
		t.Fatalf("soumission signée : %d %s", code, out)
	}
	hash := strings.Split(strings.Split(out, `"plan_hash":"`)[1], `"`)[0]
	raw, _ := hex.DecodeString(hash)
	var h [32]byte
	copy(h[:], raw)

	expiry := time.Now().Add(10 * time.Minute).UTC()
	approve := func(privs ...ed25519.PrivateKey) (int, string) {
		sigs := make([]string, len(privs))
		for i, p := range privs {
			sigs[i] = fmt.Sprintf("%q", hex.EncodeToString(ed25519.Sign(p, pep.ApprovalMessage(h, expiry))))
		}
		return postBody(t, hc, "/v1/supervision/plan/approve",
			fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signatures":[%s]}`, hash, expiry.Format(time.RFC3339), strings.Join(sigs, ",")))
	}
	// le soumetteur (opPriv3, qui a tous les rôles) complète le quorum : refusé EN ENTIER
	if code, out := approve(fx.opPriv, fx.opPriv3); code != http.StatusBadRequest || !strings.Contains(out, "soumetteur") {
		t.Fatalf("approbation par le soumetteur : %d %s", code, out)
	}
	if !pendingHashes(t, hc)[hash] {
		t.Fatal("le plan a quitté la file malgré le refus")
	}
	// voisin : deux autres opérateurs
	if code, out := approve(fx.opPriv, fx.opPriv2); code != http.StatusOK {
		t.Fatalf("deux opérateurs autres que le soumetteur : %d %s", code, out)
	}
}

// À k = 1 (échelle 1), un seul opérateur soumet et approuve : la soumission non signée reste ouverte.
func TestUnsignedSubmissionStaysOpenAtScaleOne(t *testing.T) {
	_, hc := startQuorumBrokerdWith(t, func(fx *runFixture) { fx.env["TBP_QUORUM_MIN"] = "1" })
	code, out := postBody(t, hc, "/v1/supervision/plan/submit", `{"subject":"agent-i","steps":[{"action":"read","resource":"doc-1","params_hex":""}]}`)
	if code != http.StatusOK {
		t.Fatalf("soumission non signée à k = 1 : %d %s", code, out)
	}
}

func TestCheckSeparatedDuties(t *testing.T) {
	key := func() ed25519.PublicKey {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return pub
	}
	a, b, c := key(), key(), key()
	reg := broker.StaticAgentRegistry{"agent-w": {Class: pep.ClassW}, "agent-i": {Class: pep.ClassI}, "agent-out": {Class: pep.ClassOut}}
	ring := func(submit, approve []ed25519.PublicKey) operatorKeyring {
		return operatorKeyring{Submitters: submit, Approvers: approve}
	}
	for name, c := range map[string]struct {
		k    int
		ring operatorKeyring
		ok   bool
	}{
		"k = 1 : pas de séparation":                               {1, ring(nil, []ed25519.PublicKey{a}), true},
		"personne ne soumet":                                      {2, ring(nil, []ed25519.PublicKey{a, b}), false},
		"soumetteur dédié, deux approbateurs":                     {2, ring([]ed25519.PublicKey{c}, []ed25519.PublicKey{a, b}), true},
		"le soumetteur est l'un des deux seuls approbateurs":      {2, ring([]ed25519.PublicKey{a}, []ed25519.PublicKey{a, b}), false},
		"trois clés qui font tout : le soumetteur en laisse deux": {2, ring([]ed25519.PublicKey{a, b, c}, []ed25519.PublicKey{a, b, c}), true},
		"un soumetteur dédié suffit même si un autre approuve":    {2, ring([]ed25519.PublicKey{a, c}, []ed25519.PublicKey{a, b}), true},
	} {
		err := checkSeparatedDuties(reg, c.k, c.ring)
		if (err == nil) != c.ok {
			t.Errorf("%s : %v", name, err)
		}
	}
	// un registre sans agent exigeant d'approbation (classe Out seule) : rien à séparer, mais il faut quand même un soumetteur
	if err := checkSeparatedDuties(broker.StaticAgentRegistry{"agent-out": {Class: pep.ClassOut}}, 2, ring([]ed25519.PublicKey{a}, []ed25519.PublicKey{a})); err != nil {
		t.Errorf("classe Out seule : %v", err)
	}
}

// Au démarrage : sans clé qui tienne le rôle « submit », ou quand le soumetteur est l'un des deux seuls approbateurs de k = 2,
// aucun plan de classe W ne pourrait être approuvé — brokerd refuse de démarrer et nomme la cause.
func TestBrokerdRefusesToStartWhenDutiesCannotBeSeparated(t *testing.T) {
	start := func(t *testing.T, roles func(fx *runFixture) []map[string]any) error {
		t.Helper()
		sock := filepath.Join(t.TempDir(), "broker.sock")
		fx := newRunFixture(t, sock)
		agents, _ := json.Marshal(map[string]agentRegistryEntry{"agent-w": {Class: classOf(2)}})
		if err := os.WriteFile(fx.agentsFile, agents, 0o600); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(roles(fx))
		if err := os.WriteFile(fx.opsFile, body, 0o600); err != nil {
			t.Fatal(err)
		}
		fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
		return boot(t, fx, sock)
	}
	entry := func(pub ed25519.PublicKey, roles ...string) map[string]any {
		return map[string]any{"key": hex.EncodeToString(pub), "roles": roles}
	}
	// aucune clé ne tient « submit »
	err := start(t, func(fx *runFixture) []map[string]any {
		return []map[string]any{
			entry(fx.opPriv.Public().(ed25519.PublicKey), "approve", "revoke", "arbitrate"),
			entry(fx.opPriv2.Public().(ed25519.PublicKey), "approve"),
		}
	})
	if err == nil || !strings.Contains(err.Error(), "« submit »") {
		t.Fatalf("aucune clé n'a le rôle submit : %v", err)
	}
	// le seul soumetteur est l'un des deux approbateurs de k = 2
	err = start(t, func(fx *runFixture) []map[string]any {
		return []map[string]any{
			entry(fx.opPriv.Public().(ed25519.PublicKey), "submit", "approve", "revoke", "arbitrate"),
			entry(fx.opPriv2.Public().(ed25519.PublicKey), "approve"),
		}
	})
	if err == nil || !strings.Contains(err.Error(), "agent-w") || !strings.Contains(err.Error(), "soumetteur") {
		t.Fatalf("soumetteur = l'un des deux seuls approbateurs : %v", err)
	}
}
