package main

// operators_test.go — les rôles du trousseau d'opérateurs : le chargement (forme historique, forme à rôles, refus) et
// l'effet bout en bout sur le socket d'administration. Approuver ÉLARGIT ce que la cellule autorise, révoquer RESTREINT :
// la clé d'une astreinte de nuit coupe, sans approuver.

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

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func TestLoadOperatorKeyringHistoricalFormGivesEveryRole(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	ring, err := loadOperatorKeyring(writeOps(t, `["`+a+`","`+b+`"]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ring.All) != 2 || len(ring.Approvers) != 2 || len(ring.Revokers) != 2 || len(ring.Arbiters) != 2 {
		t.Fatalf("la forme historique doit donner tous les rôles à chaque clé : %d/%d/%d/%d",
			len(ring.All), len(ring.Approvers), len(ring.Revokers), len(ring.Arbiters))
	}
}

func TestLoadOperatorKeyringWithRoles(t *testing.T) {
	a, b, c := strings.Repeat("ab", 32), strings.Repeat("cd", 32), strings.Repeat("ef", 32)
	ring, err := loadOperatorKeyring(writeOps(t, fmt.Sprintf(`[
		{"key":%q,"roles":["approve"]},
		{"key":%q,"roles":["approve","revoke"]},
		{"key":%q,"roles":["revoke","arbitrate"]}]`, a, b, c)))
	if err != nil {
		t.Fatal(err)
	}
	if len(ring.All) != 3 || len(ring.Approvers) != 2 || len(ring.Revokers) != 2 || len(ring.Arbiters) != 1 {
		t.Fatalf("rôles mal répartis : %d/%d/%d/%d", len(ring.All), len(ring.Approvers), len(ring.Revokers), len(ring.Arbiters))
	}
	// refuser une demande dégradée restreint : ouvert aux arbitres ET à ceux qui tiennent « revoke » (b et c), pas à a
	if len(ring.Refusers) != 2 {
		t.Fatalf("%d clés peuvent refuser, veut 2 (les arbitres et les révocateurs, sans doublon)", len(ring.Refusers))
	}
}

func TestLoadOperatorKeyringRefusals(t *testing.T) {
	a, b := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	all := `"approve","revoke","arbitrate"`
	for name, body := range map[string]string{
		"chaîne égarée dans un fichier à rôles": fmt.Sprintf(`[{"key":%q,"roles":[%s]},%q]`, a, all, b),
		"objet égaré dans une liste de chaînes": fmt.Sprintf(`[%q,{"key":%q,"roles":[%s]}]`, a, b, all),
		"rôle inconnu":  fmt.Sprintf(`[{"key":%q,"roles":["approve","revoke","arbitrate","admin"]}]`, a),
		"rôle répété":   fmt.Sprintf(`[{"key":%q,"roles":["approve","approve","revoke","arbitrate"]}]`, a),
		"rôles absents": fmt.Sprintf(`[{"key":%q}]`, a),
		"rôles vides":   fmt.Sprintf(`[{"key":%q,"roles":[]}]`, a),
		"champ inconnu": fmt.Sprintf(`[{"key":%q,"roles":[%s],"label":"x"}]`, a, all),
		"même clé deux fois, rôles différents": fmt.Sprintf(`[{"key":%q,"roles":["approve"]},{"key":%q,"roles":["revoke","arbitrate"]}]`, a, strings.ToUpper(a)),
		"personne n'approuve":                  fmt.Sprintf(`[{"key":%q,"roles":["revoke","arbitrate"]}]`, a),
		"personne ne révoque":                  fmt.Sprintf(`[{"key":%q,"roles":["approve","arbitrate"]}]`, a),
		"personne n'arbitre":                   fmt.Sprintf(`[{"key":%q,"roles":["approve","revoke"]}]`, a),
		"élément qui n'est ni chaîne ni objet": `[42]`,
	} {
		if _, err := loadOperatorKeyring(writeOps(t, body)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

func writeOps(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ops.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Bout en bout, sur un vrai brokerd : deux approbateurs (k = 2) et une astreinte de nuit qui ne peut que révoquer.
func TestOperatorRolesThroughTheAdminSocket(t *testing.T) {
	_, nightPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nightPub = nightPriv.Public().(ed25519.PublicKey)
	fx, hc := startQuorumBrokerdWith(t, func(fx *runFixture) {
		entry := func(pub ed25519.PublicKey, roles ...string) map[string]any {
			return map[string]any{"key": hex.EncodeToString(pub), "roles": roles}
		}
		body, _ := json.Marshal([]map[string]any{
			entry(fx.opPriv.Public().(ed25519.PublicKey), "approve"),
			entry(fx.opPriv2.Public().(ed25519.PublicKey), "approve"),
			entry(fx.opPriv3.Public().(ed25519.PublicKey), "submit"),
			entry(nightPub, "revoke", "arbitrate"),
		})
		if err := os.WriteFile(fx.opsFile, body, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	expiry := time.Now().Add(10 * time.Minute).UTC()
	ts := expiry.Format(time.RFC3339)
	approve := func(hash string, h [32]byte, privs ...ed25519.PrivateKey) (int, string) {
		sigs := make([]string, len(privs))
		for i, p := range privs {
			sigs[i] = fmt.Sprintf("%q", hex.EncodeToString(ed25519.Sign(p, pep.ApprovalMessage(h, expiry))))
		}
		return postBody(t, hc, "/v1/supervision/plan/approve",
			fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signatures":[%s]}`, hash, ts, strings.Join(sigs, ",")))
	}
	revoke := func(hash string, h [32]byte, priv ed25519.PrivateKey) (int, string) {
		sig := hex.EncodeToString(ed25519.Sign(priv, pep.RevocationMessage(h, expiry)))
		return postBody(t, hc, "/v1/supervision/plan/revoke", fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signature":%q}`, hash, ts, sig))
	}

	// un approbateur n'a pas le rôle de soumission : sa soumission signée est refusée, avec un refus nommé
	if code, out := postBody(t, hc, "/v1/supervision/plan/submit",
		fx.signedSubmitBodyBy(fx.opPriv, "agent-w", []planSubmitStepRequest{{Action: "pay", Resource: "invoice-42"}})); code != http.StatusBadRequest || !strings.Contains(out, "rôle de soumission") {
		t.Fatalf("soumission par une clé qui ne fait qu'approuver : %d %s", code, out)
	}
	hash, h := submitPlanFor(t, fx, hc, "agent-w") // k = 2
	// l'astreinte de nuit ne complète pas un quorum d'approbation
	if code, out := approve(hash, h, fx.opPriv, nightPriv); code != http.StatusBadRequest || !strings.Contains(out, "rôle d'approbation") {
		t.Fatalf("quorum complété par la clé de nuit : %d %s", code, out)
	}
	// un approbateur n'a pas le droit de révoquer : ce rôle est séparé
	if code, out := revoke(hash, h, fx.opPriv); code != http.StatusBadRequest || !strings.Contains(out, "rôle de révocation") {
		t.Fatalf("révocation par un approbateur : %d %s", code, out)
	}
	if !pendingHashes(t, hc)[hash] {
		t.Fatal("le plan a quitté la file malgré les refus de rôle")
	}
	// voisin autorisé : deux approbateurs approuvent, puis l'astreinte coupe
	if code, out := approve(hash, h, fx.opPriv, fx.opPriv2); code != http.StatusOK {
		t.Fatalf("deux approbateurs refusés : %d %s", code, out)
	}
	if code, out := revoke(hash, h, nightPriv); code != http.StatusOK {
		t.Fatalf("l'astreinte de nuit ne peut pas révoquer : %d %s", code, out)
	}
}

// k = 2 avec trois clés dont une seule approuve : brokerd refuse de démarrer, comme pour un trousseau trop court.
func TestBrokerdRefusesToStartWhenTooFewKeysHoldTheApproverRole(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	agents, _ := json.Marshal(map[string]agentRegistryEntry{"agent-w": {Class: classOf(2)}})
	if err := os.WriteFile(fx.agentsFile, agents, 0o600); err != nil {
		t.Fatal(err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	entry := func(pub ed25519.PublicKey, roles ...string) map[string]any {
		return map[string]any{"key": hex.EncodeToString(pub), "roles": roles}
	}
	body, _ := json.Marshal([]map[string]any{
		entry(fx.opPriv.Public().(ed25519.PublicKey), "approve", "revoke", "arbitrate"),
		entry(fx.opPriv2.Public().(ed25519.PublicKey), "revoke"),
		entry(other.Public().(ed25519.PublicKey), "revoke"),
	})
	if err := os.WriteFile(fx.opsFile, body, 0o600); err != nil {
		t.Fatal(err)
	}
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	err := boot(t, fx, sock)
	if err == nil || !strings.Contains(err.Error(), "agent-w") {
		t.Fatalf("un seul approbateur pour k = 2 doit refuser de démarrer et nommer l'agent : %v", err)
	}
}
