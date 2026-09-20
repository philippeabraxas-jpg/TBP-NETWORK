package broker

// plan_contract_test.go — tests du câblage broker du contrat de plan
// (§4.2, T30 — étape 7 de la chaîne, entre quorum et enveloppe).
//
// Couverture :
//   - la couture ContractGate est bien implémentée par pep.ContractStore
//     (assertion de compilation) ;
//   - binding présent sans gate câblé ⇒ plan-unverified (fail-closed,
//     même doctrine qu'envelope-unverified) ;
//   - exécution conforme ⇒ jeton v2 scellé (claim −8 = hash du plan),
//     vérifié en croisé par le validateur T9 ;
//   - déviation refusée MÊME si OPA autorise l'action isolément
//     (critère d'acceptation 3 de #31, niveau broker) ;
//   - plan inconnu / en attente ⇒ refus dédié ;
//   - faute du store (feuille de consommation impossible) ⇒ faute
//     système alarmée plan-store-fault, jamais un allow ;
//   - bornes du champ plan_binding du traducteur structuré ;
//   - empilement avec le quorum (§7.5) : un mauvais quorum refuse AVANT
//     la consommation — le curseur du plan n'est pas avancé.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Assertion de compilation : le store T30 implémente la couture broker.
var _ ContractGate = (*pep.ContractStore)(nil)

// testOperatorSeed : seed Ed25519 de test (RFC 8032, clé 3) — aucune valeur,
// jamais utilisée hors tests. L'opérateur est DISTINCT de l'émetteur.
var testOperatorSeed, _ = hex.DecodeString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458d7")

func testOperatorKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(testOperatorSeed) }

// newContractBroker assemble un broker de test AVEC gate de contrat câblé —
// newTestBroker, plus la couture Contract (T30).
func newContractBroker(t *testing.T, opaURL string, tr Translator, gate ContractGate) (*Broker, *Issuer, *leafRecorder, *tripRecorder) {
	t.Helper()
	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	signer, err := NewDevSigner(testSeed)
	if err != nil {
		t.Fatalf("NewDevSigner: %v", err)
	}
	issuer, err := NewIssuer(IssuerOptions{
		CellID:   "tbp/registry/cell-test-01",
		Signer:   signer,
		PolicyID: testPolicyID,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	opa, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint: opaURL,
		Timeout:  500 * time.Millisecond,
		CellID:   "tbp/registry/cell-test-01",
		Salt:     testSalt,
		Leaves:   leaves,
		OnTrip:   trips.trip,
	})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	// Même convention que newTestBroker : les traducteurs fixes sans classe
	// explicite empruntent le chemin classe W — preuve de quorum valide
	// attachée pour rester sur le chemin nominal.
	if st, ok := tr.(staticTranslator); ok && st.err == nil && st.tr.Class == nil && len(st.tr.QuorumProof) == 0 {
		st.tr.QuorumProof = mintTestProof(t, st.tr.Action, st.tr.Resource, 7)
		tr = st
	}
	b, err := NewBroker(BrokerOptions{
		CellID:     "tbp/registry/cell-test-01",
		Salt:       testSalt,
		Leaves:     leaves,
		OPA:        opa,
		Translator: tr,
		Issuer:     issuer,
		Epochs:     StaticEpoch(7),
		Quorum:     newTestQuorumGate(t, leaves),
		Contract:   gate,
		OnTrip:     trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return b, issuer, leaves, trips
}

// newContractStore assemble le store T30 de test (mêmes cellID/sel/policyID
// que le broker) avec son propre enregistreur de feuilles KindContract.
func newContractStore(t *testing.T, sink *leafRecorder, onTrip func(string)) *pep.ContractStore {
	t.Helper()
	store, err := pep.NewContractStore(pep.ContractOptions{
		CellID:       "tbp/registry/cell-test-01",
		PolicyID:     testPolicyID,
		OperatorKeys: []ed25519.PublicKey{testOperatorKey().Public().(ed25519.PublicKey)},
		Salt:         testSalt,
		Leaves:       sink,
		OnTrip:       onTrip,
	})
	if err != nil {
		t.Fatalf("NewContractStore: %v", err)
	}
	return store
}

// approvePlan soumet puis approuve un plan (signature opérateur valide,
// expiry 30 min) et rend le hash du plan scellé.
func approvePlan(t *testing.T, store *pep.ContractStore, steps []pep.PlanStep) [32]byte {
	t.Helper()
	ctx := context.Background()
	planHash, err := store.Submit(ctx, steps)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	expiry := time.Now().Add(30 * time.Minute)
	sig := ed25519.Sign(testOperatorKey(), pep.ApprovalMessage(planHash, expiry))
	if err := store.Approve(ctx, planHash, expiry, sig); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return planHash
}

// contractStep est l'étape nominale des tests broker.
func contractStep(params []byte) pep.PlanStep {
	return pep.PlanStep{
		Action:     "http.send",
		Resource:   "https://api.example.com/v1/messages",
		ParamsHash: pep.HashParams(params),
	}
}

// TestPlanBindingWithoutGateDenied : une demande portant un binding alors
// qu'AUCUN gate n'est câblé est refusée plan-unverified — jamais ignorée
// (même doctrine qu'envelope-unverified, T33, et quota-unverified, T9).
func TestPlanBindingWithoutGateDenied(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	binding, err := pep.BuildBinding([32]byte{0x42}, []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("BuildBinding: %v", err)
	}
	tr := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: binding,
	}}
	b, _, _, _ := newTestBroker(t, srv.URL, tr)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if res.Allow || res.Reason != ReasonPlanUnverified {
		t.Fatalf("allow=%v reason=%q, veut deny/plan-unverified", res.Allow, res.Reason)
	}
	if len(res.Token) != 0 {
		t.Fatal("un jeton a été émis sans vérification de contrat")
	}
	if got := b.Stats().PlanDenies; got != 1 {
		t.Fatalf("PlanDenies=%d, veut 1", got)
	}
}

// TestPlanConformantExecutionIssuesSealedToken : une étape conforme au plan
// approuvé reçoit un jeton v2 dont le claim −8 porte le hash du plan —
// vérifié en croisé par le validateur T9 (critères 1 et 2 de #31).
func TestPlanConformantExecutionIssuesSealedToken(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	params := []byte(`{"to":"ops@example.com","n":3}`)
	storeSink := &leafRecorder{}
	store := newContractStore(t, storeSink, nil)
	planHash := approvePlan(t, store, []pep.PlanStep{contractStep(params)})
	binding, err := pep.BuildBinding(planHash, params)
	if err != nil {
		t.Fatalf("BuildBinding: %v", err)
	}

	tr := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: binding,
	}}
	b, issuer, leaves, _ := newContractBroker(t, srv.URL, tr, store)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if !res.Allow || res.Reason != pep.ReasonOK {
		t.Fatalf("exécution conforme refusée : %q", res.Reason)
	}
	if len(res.Token) == 0 || len(res.Token) > 1024 {
		t.Fatalf("jeton fil de %d octets — bornes (0, 1024]", len(res.Token))
	}

	// Test croisé : le validateur T9 accepte le jeton v2 et retrouve le
	// sceau du plan dans le claim −8 — l'objet signé est opposable (§7.6).
	signer, _ := NewDevSigner(testSeed)
	v := newTestValidator(t, issuer, signer, leaves, nil)
	d := v.Validate(context.Background(), res.Token, pep.Request{
		Action:   "http.send",
		Resource: "https://api.example.com/v1/messages",
		Epoch:    7,
	})
	if !d.Allow {
		t.Fatalf("T9 refuse le jeton scellé du broker : %q", d.Reason)
	}
	if d.Token == nil || d.Token.PlanSeal == nil {
		t.Fatal("claim −8 absent du jeton émis")
	}
	if *d.Token.PlanSeal != planHash {
		t.Fatalf("plan_seal=%x, veut %x (hash du plan approuvé)", *d.Token.PlanSeal, planHash)
	}

	// Le store a tracé soumission + approbation + consommation (§4.1).
	var kinds []registry.Leaf
	for _, l := range storeSink.all() {
		kinds = append(kinds, l)
	}
	if len(kinds) != 3 {
		t.Fatalf("feuilles de contrat=%d, veut 3 (submit, approve, consume)", len(kinds))
	}
	for _, l := range kinds {
		if l.Kind != registry.KindContract {
			t.Fatalf("kind=%v, veut KindContract", l.Kind)
		}
	}
}

// TestPlanDeviationDeniedThoughOPAAllows : OPA autorise l'action isolément,
// mais les paramètres dévient du plan scellé ⇒ plan-deviation, sans jeton
// (critère d'acceptation 3 de #31 : « déviation = refus »).
func TestPlanDeviationDeniedThoughOPAAllows(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	params := []byte(`{"to":"ops@example.com","n":3}`)
	store := newContractStore(t, &leafRecorder{}, nil)
	planHash := approvePlan(t, store, []pep.PlanStep{contractStep(params)})
	// Mêmes action/ressource, paramètres DIFFÉRENTS : la déviation fine.
	deviant, err := pep.BuildBinding(planHash, []byte(`{"to":"attacker@example.com","n":3}`))
	if err != nil {
		t.Fatalf("BuildBinding: %v", err)
	}

	tr := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: deviant,
	}}
	b, _, _, _ := newContractBroker(t, srv.URL, tr, store)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if res.Allow || res.Reason != ReasonPlanDeviation {
		t.Fatalf("allow=%v reason=%q, veut deny/plan-deviation", res.Allow, res.Reason)
	}
	if len(res.Token) != 0 {
		t.Fatal("un jeton a été émis sur une déviation")
	}
	if got := b.Stats().PlanDenies; got != 1 {
		t.Fatalf("PlanDenies=%d, veut 1", got)
	}

	// Le plan survit à la déviation : l'étape conforme reste exigible.
	conform, _ := pep.BuildBinding(planHash, params)
	b2, _, _, _ := newContractBroker(t, srv.URL, staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: conform,
	}}, store)
	res2 := b2.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if !res2.Allow {
		t.Fatalf("étape conforme après déviation refusée : %q", res2.Reason)
	}
}

// TestPlanPendingDenied : un plan soumis mais non approuvé n'exécute rien —
// « l'arbitrage est une signature, pas une lecture » (§4.2).
func TestPlanPendingDenied(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	params := []byte(`{"n":1}`)
	store := newContractStore(t, &leafRecorder{}, nil)
	planHash, err := store.Submit(context.Background(), []pep.PlanStep{contractStep(params)})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	binding, _ := pep.BuildBinding(planHash, params)
	tr := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: binding,
	}}
	b, _, _, _ := newContractBroker(t, srv.URL, tr, store)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if res.Allow || res.Reason != ReasonPlanPending {
		t.Fatalf("allow=%v reason=%q, veut deny/plan-pending", res.Allow, res.Reason)
	}
}

// TestPlanUnknownDenied : un binding vers un plan jamais soumis est refusé
// plan-unknown (default-deny §1 : l'inconnu n'est jamais autorisé).
func TestPlanUnknownDenied(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	store := newContractStore(t, &leafRecorder{}, nil)
	binding, err := pep.BuildBinding([32]byte{0xde, 0xad}, []byte(`{"n":1}`))
	if err != nil {
		t.Fatalf("BuildBinding: %v", err)
	}
	tr := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: binding,
	}}
	b, _, _, _ := newContractBroker(t, srv.URL, tr, store)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if res.Allow || res.Reason != ReasonPlanUnknown {
		t.Fatalf("allow=%v reason=%q, veut deny/plan-unknown", res.Allow, res.Reason)
	}
	if got := b.Stats().PlanDenies; got != 1 {
		t.Fatalf("PlanDenies=%d, veut 1", got)
	}
}

// TestPlanStoreFaultAlarms : la feuille de CONSOMMATION est impossible
// (registre en faute) ⇒ faute système plan-store-fault, alarmée — jamais
// un allow sans preuve (§4.1, même doctrine que leaf-write-failed).
func TestPlanStoreFaultAlarms(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	params := []byte(`{"n":1}`)
	// Sink dédié au store : submit (appel 1) et approve (appel 2) réussissent,
	// la feuille de consommation (appel 3) échoue.
	storeSink := &leafRecorder{failFromCall: 3}
	trips := &tripRecorder{}
	store := newContractStore(t, storeSink, trips.trip)
	planHash := approvePlan(t, store, []pep.PlanStep{contractStep(params)})
	binding, _ := pep.BuildBinding(planHash, params)
	tr := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: binding,
	}}
	b, _, _, brokerTrips := newContractBroker(t, srv.URL, tr, store)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if res.Allow || res.Reason != ReasonPlanStoreFault {
		t.Fatalf("allow=%v reason=%q, veut deny/plan-store-fault", res.Allow, res.Reason)
	}
	if len(res.Token) != 0 {
		t.Fatal("un jeton a été émis sans feuille de consommation")
	}
	// L'alarme est levée — par le store ET par le broker (faute système).
	var alarms []string
	alarms = append(alarms, trips.all()...)
	alarms = append(alarms, brokerTrips.all()...)
	found := false
	for _, r := range alarms {
		if r == ReasonPlanStoreFault {
			found = true
		}
	}
	if !found {
		t.Fatalf("aucune alarme plan-store-fault parmi %v", alarms)
	}

	// Le curseur N'A PAS été avancé : registre guéri, l'étape est exigible.
	storeSink.mu.Lock()
	storeSink.failFromCall = 0
	storeSink.mu.Unlock()
	res2 := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if !res2.Allow {
		t.Fatalf("étape après guérison refusée : %q (le curseur a été avancé sans preuve)", res2.Reason)
	}
}

// TestStructuredTranslatorPlanBindingBounds : le champ plan_binding du mode
// structuré est un blob hex opaque — relayé borné, jamais interprété (no-DPI).
func TestStructuredTranslatorPlanBindingBounds(t *testing.T) {
	tr := StructuredTranslator{}
	ctx := context.Background()

	binding, err := pep.BuildBinding([32]byte{0x42}, []byte(`{"x":1}`))
	if err != nil {
		t.Fatalf("BuildBinding: %v", err)
	}
	hexBinding := hex.EncodeToString(binding)
	out, err := tr.Translate(ctx, "agent-1",
		fmt.Sprintf(`{"action":"a","resource":"r","plan_binding":%q}`, hexBinding))
	if err != nil {
		t.Fatalf("binding nominal : %v", err)
	}
	if string(out.PlanBinding) != string(binding) {
		t.Fatal("plan_binding altéré par la traduction (le blob doit rester opaque)")
	}
	// Non-hex ⇒ « je ne sais pas traduire ».
	if _, err = tr.Translate(ctx, "agent-1", `{"action":"a","resource":"r","plan_binding":"zz"}`); err == nil {
		t.Fatal("plan_binding non hex accepté")
	}
	// Hors bornes ⇒ refus (§4.3 : état et messages bornés).
	oversized := strings.Repeat("ab", maxPlanBindingBytes+1)
	if _, err = tr.Translate(ctx, "agent-1",
		`{"action":"a","resource":"r","plan_binding":"`+oversized+`"}`); err == nil {
		t.Fatal("plan_binding hors bornes accepté")
	}
}

// TestPlanContractStacksWithQuorum : le contrat de plan s'empile avec le
// quorum de classe W (§7.5 + §4.2) — un mauvais quorum refuse AVANT la
// consommation : le curseur du plan n'est pas avancé par un refus amont.
func TestPlanContractStacksWithQuorum(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	params := []byte(`{"n":1}`)
	store := newContractStore(t, &leafRecorder{}, nil)
	planHash := approvePlan(t, store, []pep.PlanStep{contractStep(params)})
	binding, _ := pep.BuildBinding(planHash, params)

	// Mauvaise preuve de quorum : refus amont, AVANT l'étape 7.
	badProof := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		QuorumProof: []byte("preuve-forgée"),
		PlanBinding: binding,
	}}
	b, _, _, _ := newContractBroker(t, srv.URL, badProof, store)
	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if res.Allow || res.Reason != ReasonQuorumInsufficient {
		t.Fatalf("allow=%v reason=%q, veut deny/quorum-insufficient", res.Allow, res.Reason)
	}

	// Le refus amont n'a PAS consommé l'étape : bonne preuve ⇒ allow.
	goodProof := staticTranslator{tr: Translation{
		Action:      "http.send",
		Resource:    "https://api.example.com/v1/messages",
		PlanBinding: binding,
	}}
	b2, _, _, _ := newContractBroker(t, srv.URL, goodProof, store)
	res2 := b2.HandleAction(context.Background(), "spiffe://tbp.example/agent/test",
		simpleIntent(t, "http.send", "https://api.example.com/v1/messages"))
	if !res2.Allow {
		t.Fatalf("étape après refus de quorum refusée : %q (curseur consommé par un refus amont)", res2.Reason)
	}
}
