package main

// plan_approvals_test.go — issue #196 côté brokerd : combien d'opérateurs approuvent un plan, selon la
// classe de l'agent (F et W : k ; I : 1), et refus de démarrer quand ce quorum serait inatteignable.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func TestPlanApprovalsRequiredFollowsTheClass(t *testing.T) {
	reg := broker.StaticAgentRegistry{
		"agent-f": {Class: pep.ClassF}, "agent-i": {Class: pep.ClassI},
		"agent-w": {Class: pep.ClassW}, "agent-out": {Class: pep.ClassOut},
	}
	for k := 1; k <= 3; k++ {
		fn := planApprovalsRequired(reg, k)
		for subject, want := range map[string]int{"agent-f": k, "agent-w": k, "agent-i": 1, "agent-out": 1, "inconnu": 1} {
			if got := fn(subject); got != want {
				t.Errorf("k = %d, %s : %d approbations exigées, veut %d", k, subject, got, want)
			}
		}
	}
}

func TestCheckOperatorQuorum(t *testing.T) {
	withW := broker.StaticAgentRegistry{"agent-w": {Class: pep.ClassW}, "agent-i": {Class: pep.ClassI}}
	onlyI := broker.StaticAgentRegistry{"agent-i": {Class: pep.ClassI}, "agent-out": {Class: pep.ClassOut}}
	// refusé : un agent W existe, k = 2, une seule clé distincte
	if err := checkOperatorQuorum(withW, 2, 1); err == nil || !strings.Contains(err.Error(), "agent-w") {
		t.Fatalf("quorum d'approbation impossible accepté : %v", err)
	}
	// voisins acceptés
	for name, c := range map[string]struct {
		reg    broker.StaticAgentRegistry
		k, ops int
	}{
		"assez de clés":          {withW, 2, 2},
		"k = 1 (échelle 1)":      {withW, 1, 1},
		"aucun agent F ou W":     {onlyI, 2, 1},
		"plus de clés que de k":  {withW, 2, 3},
		"registre vide, k élevé": {broker.StaticAgentRegistry{}, 3, 1},
	} {
		if err := checkOperatorQuorum(c.reg, c.k, c.ops); err != nil {
			t.Errorf("%s : %v", name, err)
		}
	}
}

// startQuorumBrokerd démarre un vrai brokerd dont le registre porte des agents F, I et W (k = 2, deux
// opérateurs) et rend le client du socket d'administration.
func startQuorumBrokerd(t *testing.T) (*runFixture, *http.Client) {
	t.Helper()
	return startQuorumBrokerdWith(t, nil)
}

// startQuorumBrokerdWith : comme startQuorumBrokerd, avec une chance d'adapter la configuration (le fichier des
// opérateurs, par exemple) avant le démarrage.
func startQuorumBrokerdWith(t *testing.T, adapt func(*runFixture)) (*runFixture, *http.Client) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	if adapt != nil {
		adapt(fx)
	}
	agents, _ := json.Marshal(map[string]agentRegistryEntry{
		"agent-f": {Class: classOf(0)}, "agent-i": {Class: classOf(1)}, "agent-w": {Class: classOf(2)},
	})
	if err := os.WriteFile(fx.agentsFile, agents, 0o600); err != nil {
		t.Fatal(err)
	}
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			fmt.Fprintf(w, `{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":%q}}}}`, fx.env["TBP_POLICY_ID"])
			return
		}
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(opa.Close)
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runErr:
		case <-time.After(10 * time.Second):
		}
	})
	waitSocket(t, sock)
	waitSocket(t, fx.adminSock)
	return fx, unixClient(t, fx.adminSock)
}

// signedSubmitBody rend le corps d'une soumission SIGNÉE par la clé qui soumet (opPriv3) : une cellule à k ≥ 2 sépare les
// tâches et refuse la soumission non signée.
func (fx *runFixture) signedSubmitBody(subject string, steps []planSubmitStepRequest) string {
	return fx.signedSubmitBodyBy(fx.opPriv3, subject, steps)
}

func (fx *runFixture) signedSubmitBodyBy(priv ed25519.PrivateKey, subject string, steps []planSubmitStepRequest) string {
	planSteps := make([]pep.PlanStep, 0, len(steps))
	for _, s := range steps {
		params, _ := hex.DecodeString(s.ParamsHex)
		planSteps = append(planSteps, pep.PlanStep{Action: s.Action, Resource: s.Resource, ParamsHash: pep.HashParams(params)})
	}
	exp := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	sig := ed25519.Sign(priv, pep.SubmissionMessage(fx.env["TBP_CELL_ID"], subject, planSteps, exp))
	raw, _ := json.Marshal(map[string]any{"subject": subject, "steps": steps, "expires_at": exp.Format(time.RFC3339), "signature": hex.EncodeToString(sig)})
	return string(raw)
}

func submitPlanFor(t *testing.T, fx *runFixture, hc *http.Client, subject string) (string, [32]byte) {
	t.Helper()
	body := fx.signedSubmitBody(subject, []planSubmitStepRequest{{Action: "pay", Resource: "invoice-42"}})
	code, out := postBody(t, hc, "/v1/supervision/plan/submit", body)
	if code != http.StatusOK {
		t.Fatalf("soumission pour %s : %d %s", subject, code, out)
	}
	hash := strings.Split(strings.Split(out, `"plan_hash":"`)[1], `"`)[0]
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != 32 {
		t.Fatalf("hash %q", hash)
	}
	var h [32]byte
	copy(h[:], raw)
	return hash, h
}

func TestPlanApprovalQuorumThroughTheAdminSocket(t *testing.T) {
	fx, hc := startQuorumBrokerd(t)
	expiry := time.Now().Add(10 * time.Minute).UTC()
	ts := expiry.Format(time.RFC3339)
	sig := func(priv ed25519.PrivateKey, h [32]byte) string {
		return hex.EncodeToString(ed25519.Sign(priv, pep.ApprovalMessage(h, expiry)))
	}
	one := func(hash, s string) string {
		return fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signature":%q}`, hash, ts, s)
	}
	many := func(hash string, sigs ...string) string {
		q := make([]string, len(sigs))
		for i, s := range sigs {
			q[i] = fmt.Sprintf("%q", s)
		}
		return fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signatures":[%s]}`, hash, ts, strings.Join(q, ","))
	}

	for _, subject := range []string{"agent-w", "agent-f"} {
		hash, h := submitPlanFor(t, fx, hc, subject)
		s1, s2 := sig(fx.opPriv, h), sig(fx.opPriv2, h)

		// une seule signature : refusé, le plan reste en attente (k = 2)
		if code, out := postBody(t, hc, "/v1/supervision/plan/approve", one(hash, s1)); code != http.StatusBadRequest || !strings.Contains(out, "insuffisante") {
			t.Fatalf("%s : une signature sur 2 : %d %s", subject, code, out)
		}
		// la même clé deux fois : refusé
		if code, out := postBody(t, hc, "/v1/supervision/plan/approve", many(hash, s1, s1)); code != http.StatusBadRequest || !strings.Contains(out, "même clé") {
			t.Fatalf("%s : deux fois la même clé : %d %s", subject, code, out)
		}
		// « signature » ET « signatures » : refusé
		both := fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q,"signature":%q,"signatures":[%q]}`, hash, ts, s1, s2)
		if code, _ := postBody(t, hc, "/v1/supervision/plan/approve", both); code != http.StatusBadRequest {
			t.Fatalf("%s : les deux formes à la fois acceptées (%d)", subject, code)
		}
		// ni l'une ni l'autre : refusé
		none := fmt.Sprintf(`{"plan_hash":%q,"expires_at":%q}`, hash, ts)
		if code, _ := postBody(t, hc, "/v1/supervision/plan/approve", none); code != http.StatusBadRequest {
			t.Fatalf("%s : aucune signature acceptée (%d)", subject, code)
		}
		if !pendingHashes(t, hc)[hash] {
			t.Fatalf("%s : le plan a quitté la file malgré les refus", subject)
		}
		// cas voisin : deux clés distinctes ⇒ approuvé
		if code, out := postBody(t, hc, "/v1/supervision/plan/approve", many(hash, s1, s2)); code != http.StatusOK {
			t.Fatalf("%s : deux opérateurs distincts refusés : %d %s", subject, code, out)
		}
		if pendingHashes(t, hc)[hash] {
			t.Fatalf("%s : plan approuvé toujours en attente", subject)
		}
	}

	// classe I : une signature suffit, sous la forme historique
	hash, h := submitPlanFor(t, fx, hc, "agent-i")
	if code, out := postBody(t, hc, "/v1/supervision/plan/approve", one(hash, sig(fx.opPriv, h))); code != http.StatusOK {
		t.Fatalf("classe I à une signature refusée : %d %s", code, out)
	}
}

// Un trousseau d'une seule clé avec un agent W et k = 2 : brokerd refuse de démarrer, et nomme l'agent.
// Cas voisin : à k = 1 (échelle 1), la même configuration démarre. Deux cellules distinctes : abaisser k sur
// une cellule qui a déjà un témoin est une transition de quorum (#224), pas le sujet de ce test.
func TestBrokerdRefusesToStartWhenPlanApprovalQuorumIsUnreachable(t *testing.T) {
	oneOperator := func(t *testing.T, k string) (*runFixture, string) {
		t.Helper()
		sock := filepath.Join(t.TempDir(), "broker.sock")
		fx := newRunFixture(t, sock)
		agents, _ := json.Marshal(map[string]agentRegistryEntry{"agent-w": {Class: classOf(2)}})
		if err := os.WriteFile(fx.agentsFile, agents, 0o600); err != nil {
			t.Fatal(err)
		}
		pub := fx.opPriv.Public().(ed25519.PublicKey)
		one, _ := json.Marshal([]string{hex.EncodeToString(pub)})
		if err := os.WriteFile(fx.opsFile, one, 0o600); err != nil {
			t.Fatal(err)
		}
		fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
		if k != "" {
			fx.env["TBP_QUORUM_MIN"] = k
		}
		return fx, sock
	}
	fx, sock := oneOperator(t, "")
	err := boot(t, fx, sock)
	if err == nil || !strings.Contains(err.Error(), "agent-w") || !strings.Contains(err.Error(), "signatures distinctes") {
		t.Fatalf("quorum d'approbation inatteignable accepté ou mal expliqué : %v", err)
	}
	fx1, sock1 := oneOperator(t, "1")
	if err := boot(t, fx1, sock1); err != nil {
		t.Fatalf("échelle 1 (k = 1) avec une clé d'opérateur refusée : %v", err)
	}
}
