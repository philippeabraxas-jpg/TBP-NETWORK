package broker

// agent_registry_test.go — revue de sécurité #125. Preuves NON VACUES que
// l'identité/classe/quota viennent désormais du registre, jamais de la
// déclaration de l'agent :
//   - subject absent du registre ⇒ refus AVANT même la traduction ;
//   - un agent qui SE DÉCLARE une classe plus favorable que celle du
//     registre voit sa déclaration IGNORÉE — la classe évaluée par OPA et
//     portée par le jeton émis est celle du registre ;
//   - un agent qui se déclare une classe MOINS coûteuse (pour éviter le
//     quorum classe W) est toujours jugé sur sa vraie classe résolue ;
//   - un agent sans politique de quota, ou demandant au-delà de son
//     plafond résolu, est refusé — jamais silencieusement plafonné.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// newAgentTestBroker assemble un broker de test complet (OPA, enveloppe,
// ledger, émetteur, époque fixe) avec un AgentRegistry EXPLICITE — à la
// différence de newTestBroker (permissiveAgentRegistry{}), ces tests
// veulent contrôler précisément ce que le registre résout. lastOPAInput,
// si non nil, reçoit l'entrée OPA de la DERNIÈRE évaluation (classe
// réellement jugée) — le témoin direct que tr.Class ne l'influence plus.
func newAgentTestBroker(t *testing.T, reg AgentRegistry, lastOPAInput *map[string]any) (*Broker, *leafRecorder) {
	t.Helper()
	leaves := &leafRecorder{}
	var mu sync.Mutex

	decisionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input map[string]any `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if lastOPAInput != nil {
			mu.Lock()
			*lastOPAInput = body.Input
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	t.Cleanup(decisionSrv.Close)

	envelopeSrv := opaServer(t, func(map[string]any) bool { return true }, 0)
	t.Cleanup(envelopeSrv.Close)

	signer, err := NewDevSigner(testSeed)
	if err != nil {
		t.Fatalf("NewDevSigner: %v", err)
	}
	issuer, err := NewIssuer(IssuerOptions{CellID: "tbp/registry/cell-test-01", Signer: signer, PolicyID: testPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	opa, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint: decisionSrv.URL, Timeout: 500 * time.Millisecond,
		CellID: "tbp/registry/cell-test-01", Salt: testSalt, Leaves: leaves,
	})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	env, err := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: envelopeSrv.URL, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewHTTPEnvelopeEvaluator: %v", err)
	}
	ledger, err := NewEnvelopeLedger(16, nil)
	if err != nil {
		t.Fatalf("NewEnvelopeLedger: %v", err)
	}
	b, err := NewBroker(BrokerOptions{
		CellID: "tbp/registry/cell-test-01", Salt: testSalt, Leaves: leaves,
		OPA: opa, Translator: StructuredTranslator{}, Issuer: issuer,
		Epochs: StaticEpoch(7), Registry: reg,
		Envelope: env, Ledger: ledger,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return b, leaves
}

// ---------------------------------------------------------------------------
// Identité : un subject absent du registre est un refus, jamais un défaut.
// ---------------------------------------------------------------------------

func TestAgentUnknownDeniesBeforeTranslation(t *testing.T) {
	leaves := &leafRecorder{}
	tr := &countingTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: mustTestOPA(t, leaves),
		Translator: tr, Issuer: mustTestIssuer(t), Epochs: StaticEpoch(1),
		Registry: StaticAgentRegistry{}, // registre VIDE — personne n'est connu
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	res := b.HandleAction(context.Background(), "ghost-agent", `{"action":"a","resource":"r"}`)
	if res.Allow || res.Reason != ReasonAgentUnknown {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonAgentUnknown)
	}
	if tr.calls != 0 {
		t.Fatalf("traducteur appelé %d fois pour une identité inconnue — le refus doit précéder la traduction (§125)", tr.calls)
	}
	if st := statsOf(t, b); st.AgentDenies != 1 {
		t.Fatalf("AgentDenies=%d, veut 1", st.AgentDenies)
	}
}

// ---------------------------------------------------------------------------
// Classe : la déclaration de l'agent dans l'intention est IGNORÉE — la
// classe jugée par OPA, et portée par le jeton, est celle du registre.
// ---------------------------------------------------------------------------

// TestAgentClassOverridesFavorableSelfDeclaration : un agent enregistré en
// classe F (aucun quorum requis) se déclare lui-même classe W (2) dans son
// intention structurée, SANS fournir de preuve de quorum. Avant #125, la
// déclaration self-reported aurait été jugée — ici la demande doit malgré
// tout ABOUTIR (classe réelle F), et l'entrée OPA capturée doit porter
// class=0, jamais 2.
func TestAgentClassOverridesFavorableSelfDeclaration(t *testing.T) {
	var lastInput map[string]any
	reg := StaticAgentRegistry{"agent-f": {Class: pep.ClassF}}
	b, _ := newAgentTestBroker(t, reg, &lastInput)

	intent := `{"action":"read","resource":"doc-1","class":2}` // déclaration : W, mais AUCUNE preuve de quorum
	res := b.HandleAction(context.Background(), "agent-f", intent)
	if !res.Allow {
		t.Fatalf("classe registre (F) ignorée au profit de la déclaration (W) : allow=%v reason=%q", res.Allow, res.Reason)
	}
	gotClass, _ := lastInput["class"].(float64)
	if int(gotClass) != int(pep.ClassF) {
		t.Fatalf("classe évaluée par OPA = %v, veut %d (registre) — la déclaration de l'agent (2) a fuité dans la décision (§125)", lastInput["class"], pep.ClassF)
	}
}

// TestAgentClassOverridesUnfavorableSelfDeclaration : un agent enregistré
// en classe W (quorum requis) se déclare lui-même classe F (0) — la
// tentative classique d'un agent compromis pour éviter le quorum. Sans
// preuve de quorum, la demande doit être REFUSÉE quorum-required, quelle
// que soit la déclaration.
func TestAgentClassOverridesUnfavorableSelfDeclaration(t *testing.T) {
	reg := StaticAgentRegistry{"agent-w": {Class: pep.ClassW}}
	b, _ := newAgentTestBroker(t, reg, nil)

	intent := `{"action":"read","resource":"doc-1","class":0}` // déclaration : F, sans preuve
	res := b.HandleAction(context.Background(), "agent-w", intent)
	if res.Allow || res.Reason != ReasonQuorumRequired {
		t.Fatalf("allow=%v reason=%q, veut deny/%q — une classe auto-déclarée plus favorable ne doit jamais dispenser du quorum (§125)", res.Allow, res.Reason, ReasonQuorumRequired)
	}
}

// ---------------------------------------------------------------------------
// Quota : plafond résolu par le registre, jamais la valeur demandée.
// ---------------------------------------------------------------------------

func TestAgentQuotaForbiddenWithoutPolicy(t *testing.T) {
	reg := StaticAgentRegistry{"agent-f": {Class: pep.ClassF}} // Quota nil : aucun passeport permis
	b, _ := newAgentTestBroker(t, reg, nil)

	intent := `{"action":"http.send","resource":"https://x","quota":{"resource":"https://x","operation":"POST","volume_max":10,"window_s":60}}`
	res := b.HandleAction(context.Background(), "agent-f", intent)
	if res.Allow || res.Reason != ReasonAgentQuotaForbidden {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonAgentQuotaForbidden)
	}
	if st := statsOf(t, b); st.EnvelopeEvals != 0 {
		t.Fatalf("EnvelopeEvals=%d, veut 0 — un refus de plafond ne doit consommer aucune réservation", st.EnvelopeEvals)
	}
}

func TestAgentQuotaExceedsCeiling(t *testing.T) {
	reg := StaticAgentRegistry{"agent-f": {Class: pep.ClassF, Quota: &AgentQuotaPolicy{MaxVolume: 100, MaxWindowS: 3600}}}
	b, _ := newAgentTestBroker(t, reg, nil)

	// Volume demandé (1000) très au-delà du plafond résolu (100).
	intent := `{"action":"http.send","resource":"https://x","quota":{"resource":"https://x","operation":"POST","volume_max":1000,"window_s":60}}`
	res := b.HandleAction(context.Background(), "agent-f", intent)
	if res.Allow || res.Reason != ReasonAgentQuotaExceeded {
		t.Fatalf("allow=%v reason=%q, veut deny/%q — une demande au-delà du plafond résolu ne doit jamais être accordée telle quelle", res.Allow, res.Reason, ReasonAgentQuotaExceeded)
	}
	if st := statsOf(t, b); st.EnvelopeEvals != 0 {
		t.Fatalf("EnvelopeEvals=%d, veut 0", st.EnvelopeEvals)
	}
}

func TestAgentQuotaWithinCeilingAllowed(t *testing.T) {
	reg := StaticAgentRegistry{"agent-f": {Class: pep.ClassF, Quota: &AgentQuotaPolicy{MaxVolume: 1000, MaxWindowS: 120}}}
	b, _ := newAgentTestBroker(t, reg, nil)

	intent := `{"action":"http.send","resource":"https://x","quota":{"resource":"https://x","operation":"POST","volume_max":500,"window_s":60}}`
	res := b.HandleAction(context.Background(), "agent-f", intent)
	if !res.Allow {
		t.Fatalf("demande dans le plafond résolu refusée : allow=%v reason=%q", res.Allow, res.Reason)
	}
	if res.Token == nil {
		t.Fatal("passeport dans le plafond résolu sans jeton émis")
	}
}

// ---------------------------------------------------------------------------
// StaticAgentRegistry — table fixe, aucune identité fantôme.
// ---------------------------------------------------------------------------

func TestStaticAgentRegistryResolve(t *testing.T) {
	reg := StaticAgentRegistry{"known": {Class: pep.ClassI}}
	if _, ok := reg.Resolve("unknown"); ok {
		t.Fatal("subject absent de la table résolu quand même")
	}
	rec, ok := reg.Resolve("known")
	if !ok || rec.Class != pep.ClassI {
		t.Fatalf("Resolve(known) = %+v, %v", rec, ok)
	}
}

// mustTestOPA/mustTestIssuer : couture minimale pour les tests d'identité
// qui n'ont pas besoin d'enveloppe/quorum — allow inconditionnel.
func mustTestOPA(t *testing.T, leaves *leafRecorder) *pep.OPAClient {
	t.Helper()
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	t.Cleanup(srv.Close)
	opa, err := pep.NewOPAClient(pep.OPAOptions{Endpoint: srv.URL, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	return opa
}

func mustTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	signer, err := NewDevSigner(testSeed)
	if err != nil {
		t.Fatalf("NewDevSigner: %v", err)
	}
	issuer, err := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}
