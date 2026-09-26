package broker

// skill_registry_test.go — catalogue de conformité #142-#161. Preuves NON
// VACUES que le registre de skills, une fois configuré, referme le trou
// structurel confirmé sept fois par des référentiels indépendants
// (« TBP n'a aucune notion de skill installable ») :
//   - une action sans skill correspondant est refusée AVANT l'évaluation
//     OPA — jamais un passage silencieux à la règle générique ;
//   - une action dont le skill est connu, mais dont la ressource est hors
//     du périmètre déclaré, est refusée de la même manière ;
//   - un déploiement qui NE CONFIGURE PAS de registre garde son
//     comportement historique exact — pas de régression.

import (
	"context"
	"sync/atomic"
	"testing"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// newSkillTestBroker assemble un broker de test minimal (OPA toujours allow,
// agent de classe F — hors quorum, pour isoler le comportement du registre
// de skills lui-même) avec un SkillRegistry EXPLICITE (nil accepté : « pas
// configuré », le cas historique). opaCalls, si non nil, compte les
// évaluations OPA RÉELLEMENT atteintes — le témoin direct qu'un refus de
// skill précède l'appel OPA, pas une coïncidence de raison retournée.
func newSkillTestBroker(t *testing.T, skills SkillRegistry, opaCalls *atomic.Int64) (*Broker, *leafRecorder) {
	t.Helper()
	leaves := &leafRecorder{}
	srv := opaServer(t, func(map[string]any) bool {
		if opaCalls != nil {
			opaCalls.Add(1)
		}
		return true
	}, 0)
	t.Cleanup(srv.Close)
	opa, err := pep.NewOPAClient(pep.OPAOptions{Endpoint: srv.URL, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: mustTestIssuer(t),
		Epochs:   StaticEpoch(7),
		Registry: StaticAgentRegistry{"agent-1": {Class: pep.ClassF}}, // ClassF : hors quorum, isole le test
		Skills:   skills,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return b, leaves
}

func TestSkillUnknownDeniesBeforeOPA(t *testing.T) {
	var opaCalls atomic.Int64
	b, _ := newSkillTestBroker(t, StaticSkillRegistry{}, &opaCalls) // registre VIDE — aucun skill connu

	res := b.HandleAction(context.Background(), "agent-1", `{"action":"unregistered.skill","resource":"doc-1"}`)
	if res.Allow || res.Reason != ReasonSkillUnknown {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonSkillUnknown)
	}
	if got := opaCalls.Load(); got != 0 {
		t.Fatalf("OPA appelé %d fois pour un skill inconnu — le refus doit précéder l'évaluation OPA (catalogue #142-#161)", got)
	}
	if st := statsOf(t, b); st.SkillDenies != 1 {
		t.Fatalf("SkillDenies=%d, veut 1", st.SkillDenies)
	}
}

func TestSkillScopeViolationDeniesBeforeOPA(t *testing.T) {
	var opaCalls atomic.Int64
	reg := StaticSkillRegistry{
		"read.doc": {Provenance: "vendor-x", Scope: []string{"doc-1", "doc-2"}},
	}
	b, _ := newSkillTestBroker(t, reg, &opaCalls)

	// Le skill EST connu, mais la ressource ciblée ("doc-999") n'est PAS
	// dans son périmètre déclaré.
	res := b.HandleAction(context.Background(), "agent-1", `{"action":"read.doc","resource":"doc-999"}`)
	if res.Allow || res.Reason != ReasonSkillScopeViolation {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonSkillScopeViolation)
	}
	if got := opaCalls.Load(); got != 0 {
		t.Fatalf("OPA appelé %d fois pour une ressource hors périmètre — le refus doit précéder l'évaluation OPA", got)
	}
	if st := statsOf(t, b); st.SkillDenies != 1 {
		t.Fatalf("SkillDenies=%d, veut 1", st.SkillDenies)
	}
}

func TestSkillWithinScopeReachesOPAAndIsAllowed(t *testing.T) {
	var opaCalls atomic.Int64
	reg := StaticSkillRegistry{
		"read.doc": {Provenance: "vendor-x", Scope: []string{"doc-1", "doc-2"}},
	}
	b, _ := newSkillTestBroker(t, reg, &opaCalls)

	res := b.HandleAction(context.Background(), "agent-1", `{"action":"read.doc","resource":"doc-1"}`)
	if !res.Allow {
		t.Fatalf("action dans le périmètre déclaré refusée : allow=%v reason=%q", res.Allow, res.Reason)
	}
	if got := opaCalls.Load(); got != 1 {
		t.Fatalf("OPA appelé %d fois, veut exactement 1 — une action dans le périmètre doit atteindre OPA normalement", got)
	}
}

func TestNoSkillRegistryConfiguredPreservesHistoricalBehavior(t *testing.T) {
	var opaCalls atomic.Int64
	// Skills nil (interface, pas de type concret StaticSkillRegistry(nil)) —
	// AUCUNE configuration, exactement le cas d'un déploiement qui n'a pas
	// encore adopté le registre de skills : le comportement doit rester
	// celui d'avant cette couture, quelle que soit l'action déclarée.
	b, _ := newSkillTestBroker(t, nil, &opaCalls)

	res := b.HandleAction(context.Background(), "agent-1", `{"action":"anything.at.all","resource":"anything"}`)
	if !res.Allow {
		t.Fatalf("sans registre de skills configuré, une action arbitraire doit atteindre OPA normalement : allow=%v reason=%q", res.Allow, res.Reason)
	}
	if got := opaCalls.Load(); got != 1 {
		t.Fatalf("OPA appelé %d fois, veut exactement 1", got)
	}
}

// ---------------------------------------------------------------------------
// StaticSkillRegistry / SkillRecord — unités.
// ---------------------------------------------------------------------------

func TestStaticSkillRegistryResolve(t *testing.T) {
	reg := StaticSkillRegistry{"known": {Provenance: "vendor-x", Scope: []string{"r1"}}}
	if _, ok := reg.Resolve("unknown"); ok {
		t.Fatal("action absente de la table résolue quand même")
	}
	rec, ok := reg.Resolve("known")
	if !ok || rec.Provenance != "vendor-x" {
		t.Fatalf("Resolve(known) = %+v, %v", rec, ok)
	}
}

func TestSkillRecordAllowsIsExactNeverPrefix(t *testing.T) {
	rec := SkillRecord{Scope: []string{"doc-1"}}
	if rec.allows("doc-1-admin") {
		t.Fatal("« doc-1 » a couvert « doc-1-admin » — comparaison de préfixe, pas exacte (même confusion que #107/#108)")
	}
	if !rec.allows("doc-1") {
		t.Fatal("« doc-1 » exact refusé")
	}
	if rec.allows("doc-2") {
		t.Fatal("ressource absente du scope autorisée quand même")
	}
}

func TestSkillRecordEmptyScopeAllowsNothing(t *testing.T) {
	rec := SkillRecord{Provenance: "vendor-x"} // Scope nil
	if rec.allows("anything") {
		t.Fatal("scope vide a autorisé une ressource — devrait tout refuser (§1)")
	}
}
