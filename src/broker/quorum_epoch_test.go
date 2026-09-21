package broker

// Tests du câblage T29 (§7.2/§7.5) : époque fail-closed AVANT traduction,
// quorum k-of-n classe W obligatoire (revue #30 : « une cellule seule ne
// peut jamais autoriser le maximal irréversible » — invariant dur, pas
// une option). Doctrine non-vacuole : chaque test échoue si le câblage
// qu'il verrouille est retiré (p.ex. supprimer l'étape 3 rend
// TestEpochUnavailableDeniesBeforeTranslation rouge).

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// errEpoch est un EpochProvider en faute — le fencing (T29) sans autorité
// valide : « seul le détenteur sert », personne ne détient ⇒ erreur.
type errEpoch struct{ err error }

func (e errEpoch) CurrentEpoch() (uint64, error) { return 0, e.err }

// countingTranslator compte ses appels — pour prouver que le refus
// d'époque précède la traduction.
type countingTranslator struct {
	calls int
	tr    Translation
}

func (c *countingTranslator) Translate(_ context.Context, _, _ string) (Translation, error) {
	c.calls++
	return c.tr, nil
}

// newQuorumTestBroker assemble un broker de test avec choix explicite des
// coutures époque/quorum (les autres coutures sont celles de newTestBroker).
func newQuorumTestBroker(t *testing.T, opaURL string, tr Translator, epochs EpochProvider, quorum QuorumGate) (*Broker, *leafRecorder, *tripRecorder) {
	t.Helper()
	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	signer, err := NewDevSigner(testSeed)
	if err != nil {
		t.Fatalf("NewDevSigner: %v", err)
	}
	issuer, err := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	opa, err := pep.NewOPAClient(pep.OPAOptions{Endpoint: opaURL, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: tr, Issuer: issuer, Epochs: epochs, Quorum: quorum,
		OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return b, leaves, trips
}

// TestEpochUnavailableDeniesBeforeTranslation : sans époque valide (pas
// d'autorité — fencing down, expiration, quarantaine), la demande est
// refusée epoch-unavailable AVANT d'atteindre le traducteur, avec feuille
// et alarme (revue #30 : jamais d'émission sur une époque périmée servie
// en silence).
func TestEpochUnavailableDeniesBeforeTranslation(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	ct := &countingTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, leaves, trips := newQuorumTestBroker(t, srv.URL, ct, errEpoch{err: cluster.ErrNoEpoch}, nil)

	res := b.HandleAction(context.Background(), "agent-1", `{"action":"a","resource":"r"}`)
	if res.Allow || res.Reason != ReasonEpochUnavailable {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonEpochUnavailable)
	}
	if ct.calls != 0 {
		t.Fatalf("traducteur appelé %d fois — le refus d'époque doit PRÉCÉDER la traduction", ct.calls)
	}
	if len(res.Token) != 0 {
		t.Fatal("un refus d'époque ne doit JAMAIS porter un jeton")
	}
	if !res.LeafWritten {
		t.Fatal("le refus epoch-unavailable laisse sa feuille (§4.1)")
	}
	found := false
	for _, r := range trips.all() {
		if r == ReasonEpochUnavailable {
			found = true
		}
	}
	if !found {
		t.Fatalf("alarmes %v — une faute d'époque alarme (T14)", trips.all())
	}
	if got := statsOf(t, b).Denies; got != 1 {
		t.Fatalf("Denies=%d, veut 1", got)
	}
	if n := len(leaves.all()); n != 1 {
		t.Fatalf("%d feuilles, veut 1 (le refus, avant OPA)", n)
	}
}

// TestClassWWithoutGateDenied : gate absent + demande classée W (défaut,
// claim −4 absent) ⇒ quorum-required. C'est le trou que la revue #30 a
// ordonné de fermer : sans ce refus, le broker émet un jeton W avec la
// seule autorité d'une cellule.
func TestClassWWithoutGateDenied(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	b, leaves, _ := newQuorumTestBroker(t, srv.URL, StructuredTranslator{}, StaticEpoch(7), nil)

	res := b.HandleAction(context.Background(), "agent-1", `{"action":"a","resource":"r"}`)
	if res.Allow || res.Reason != ReasonQuorumRequired {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonQuorumRequired)
	}
	if len(res.Token) != 0 {
		t.Fatal("un refus de quorum ne doit JAMAIS porter un jeton")
	}
	if got := statsOf(t, b).QuorumDenies; got != 1 {
		t.Fatalf("QuorumDenies=%d, veut 1", got)
	}
	// Feuilles : décision OPA (allow — l'action est légale en soi) + refus
	// final du broker. AUCUNE feuille KindQuorum : pas de gate, pas de
	// décision de quorum à tracer.
	var kinds []byte
	for _, l := range leaves.all() {
		kinds = append(kinds, l.Kind)
		if l.Kind == registry.KindQuorum {
			t.Fatal("feuille KindQuorum écrite sans gate")
		}
	}
	if len(kinds) != 2 {
		t.Fatalf("feuilles kinds=%v, veut 2 (OPA + refus broker)", kinds)
	}
}

// TestClassWWithoutProofDenied : gate présent mais demande sans preuve ⇒
// quorum-required (§7.5 : la classe W exige la co-signature, pas seulement
// un gate configuré).
func TestClassWWithoutProofDenied(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	leaves := &leafRecorder{}
	gate := newTestQuorumGate(t, leaves)
	b, _, _ := newQuorumTestBroker(t, srv.URL, StructuredTranslator{}, StaticEpoch(7), gate)

	res := b.HandleAction(context.Background(), "agent-1", `{"action":"a","resource":"r"}`)
	if res.Allow || res.Reason != ReasonQuorumRequired {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonQuorumRequired)
	}
	if got := statsOf(t, b).QuorumDenies; got != 1 {
		t.Fatalf("QuorumDenies=%d, veut 1", got)
	}
}

// TestQuorumInsufficientProof : preuves présentes mais insuffisantes ou
// mal liées ⇒ quorum-insufficient (le gate trace KindQuorum verdict deny).
func TestQuorumInsufficientProof(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	leaves := &leafRecorder{}
	gate := newTestQuorumGate(t, leaves)
	b, _, _ := newQuorumTestBroker(t, srv.URL, StructuredTranslator{}, StaticEpoch(7), gate)

	cases := map[string]string{
		// Une seule signature (1-of-3 < k=2).
		"quorum k-1": proofIntent(t, "a", "r", 7, 1),
		// Preuve liée à une AUTRE action.
		"liaison action": proofIntent(t, "autre-action", "r", 7, 1, 2),
		// Preuve liée à une AUTRE époque (rejeu post-bascule, §7.3).
		"liaison époque": proofIntent(t, "a", "r", 6, 1, 2),
	}
	for name, intent := range cases {
		res := b.HandleAction(context.Background(), "agent-1", intent)
		if res.Allow || res.Reason != ReasonQuorumInsufficient {
			t.Fatalf("%s : allow=%v reason=%q, veut deny/%q", name, res.Allow, res.Reason, ReasonQuorumInsufficient)
		}
		if len(res.Token) != 0 {
			t.Fatalf("%s : jeton émis sur quorum insuffisant", name)
		}
	}
	if got := statsOf(t, b).QuorumDenies; got != 3 {
		t.Fatalf("QuorumDenies=%d, veut 3", got)
	}
	// Le gate a tracé chaque refus en KindQuorum (§4.1).
	n := 0
	for _, l := range leaves.all() {
		if l.Kind == registry.KindQuorum {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%d feuilles KindQuorum, veut 3 (chaque décision de quorum laisse une feuille)", n)
	}
}

// proofIntent assemble une intention structurée {"action":"a","resource":"r"}
// portant une preuve frappée pour (proofAction, proofResource, proofEpoch)
// par les signataires donnés — la liaison preuve ↔ demande est le test.
func proofIntent(t *testing.T, proofAction, proofResource string, proofEpoch uint64, signers ...int) string {
	t.Helper()
	proof := mintTestProof(t, proofAction, proofResource, proofEpoch, signers...)
	return `{"action":"a","resource":"r","quorum_proof":"` + hex.EncodeToString(proof) + `"}`
}

// TestQuorumAllowLeavesKindQuorum : chemin allow classe W — le gate trace
// sa feuille KindQuorum EN PLUS des feuilles de décision (§4.1 : chaque
// décision laisse une feuille, quorum compris).
func TestQuorumAllowLeavesKindQuorum(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, leaves, _ := newTestBroker(t, srv.URL, tr)

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent(t, "a", "r"))
	if !res.Allow {
		t.Fatalf("allow refusé : %q", res.Reason)
	}
	var quorumLeaves, decisionLeaves int
	for _, l := range leaves.all() {
		switch l.Kind {
		case registry.KindQuorum:
			quorumLeaves++
		case registry.KindDecision:
			decisionLeaves++
		}
	}
	if quorumLeaves != 1 {
		t.Fatalf("%d feuilles KindQuorum, veut 1 (admission tracée)", quorumLeaves)
	}
	if decisionLeaves != 2 {
		t.Fatalf("%d feuilles KindDecision, veut 2 (OPA + émission broker)", decisionLeaves)
	}
}

// TestErrQuorumProofRequiredSurface : la preuve vide côté gate rend
// ErrQuorumProofRequired — le code machine que le broker mappe en
// quorum-required (cohérence des contrats broker ↔ cluster).
func TestErrQuorumProofRequiredSurface(t *testing.T) {
	leaves := &leafRecorder{}
	gate := newTestQuorumGate(t, leaves)
	err := gate.VerifyClassW(context.Background(), nil, "a", "r", 7)
	if !errors.Is(err, cluster.ErrQuorumProofRequired) {
		t.Fatalf("err=%v, veut ErrQuorumProofRequired", err)
	}
}
