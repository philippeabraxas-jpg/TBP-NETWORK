package pep

// Tests du contrat de plan (T30, §4.2 — issue #31). Doctrine : scénarios
// d'acceptation de l'issue mappés un à un, tests NON vacuoles (les
// mutations M1–M5 du plan sont vérifiées échouer), aucune clé de
// production (seeds RFC 8032 / fixtures de test uniquement).

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// Seeds Ed25519 de test — RFC 8032 §7.1, clés 2 et 3 (publiques par
// construction, aucune valeur de production).
var (
	contractOpSeed1 = mustHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	contractOpSeed2 = mustHex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
	contractSalt    = []byte("t30-contract-salt-0123456789")
	contractEpochT0 = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
)

func opKey1() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(contractOpSeed1) }
func opKey2() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(contractOpSeed2) }

// contractClock est l'horloge manuelle injectée (couture Now).
type contractClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *contractClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *contractClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// contractTrips collecte les alarmes (couture OnTrip vers T14).
type contractTrips struct {
	mu      sync.Mutex
	reasons []string
}

func (r *contractTrips) trip(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
}

func (r *contractTrips) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reasons)
}

// newContractStore assemble un store nominal : une clé d'opérateur épinglée,
// horloge figée à t0, sink et alarme de test.
func newContractStore(t *testing.T, sink *stubSink, clock *contractClock, trips *contractTrips, mut func(*ContractOptions)) *ContractStore {
	t.Helper()
	opts := ContractOptions{
		CellID:       "cell-alpha-01",
		PolicyID:     arr32(policyV1),
		OperatorKeys: []ed25519.PublicKey{opKey1().Public().(ed25519.PublicKey)},
		Salt:         contractSalt,
		Leaves:       sink,
		OnTrip:       trips.trip,
		Now:          clock.now,
	}
	if mut != nil {
		mut(&opts)
	}
	s, err := NewContractStore(opts)
	if err != nil {
		t.Fatalf("NewContractStore: %v", err)
	}
	return s
}

func stepOf(action, resource string, params []byte) PlanStep {
	return PlanStep{Action: action, Resource: resource, ParamsHash: HashParams(params)}
}

// signApproval produit la signature d'approbation opérateur (D59).
func signApproval(priv ed25519.PrivateKey, planHash [32]byte, expiry time.Time) []byte {
	return ed25519.Sign(priv, ApprovalMessage(planHash, expiry))
}

// approveNominal approuve le plan avec la clé 1 et une fenêtre de 30 min.
func approveNominal(t *testing.T, s *ContractStore, clock *contractClock, planHash [32]byte) {
	t.Helper()
	expiry := clock.now().Add(30 * time.Minute)
	if err := s.Approve(context.Background(), planHash, expiry, signApproval(opKey1(), planHash, expiry)); err != nil {
		t.Fatalf("Approve nominal: %v", err)
	}
}

// bindingOf construit le blob opaque présenté au gate (D62).
func bindingOf(t *testing.T, planHash [32]byte, params []byte) []byte {
	t.Helper()
	b, err := BuildBinding(planHash, params)
	if err != nil {
		t.Fatalf("BuildBinding: %v", err)
	}
	return b
}

// contractLeaves filtre les feuilles KindContract du sink (défensif : le
// store est ici le seul écrivain, mais le filtre verrouille le kind).
func contractLeaves(sink *stubSink) []registry.Leaf {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	var out []registry.Leaf
	for _, l := range sink.leaves {
		if l.Kind == registry.KindContract {
			out = append(out, l)
		}
	}
	return out
}

// contractRecord reconstitue le record « TBPL1 » attendu (D64) — le test
// compare le hash salé, ce qui verrouille le format octet par octet.
func contractRecord(event byte, planHash [32]byte, step uint16, verdict byte, reason string) []byte {
	r := make([]byte, 0, 5+1+32+2+1+1+len(reason))
	r = append(r, "TBPL1"...)
	r = append(r, event)
	r = append(r, planHash[:]...)
	r = binary.BigEndian.AppendUint16(r, step)
	r = append(r, verdict, byte(len(reason)))
	return append(r, reason...)
}

func expectLeafHash(t *testing.T, l registry.Leaf, event byte, planHash [32]byte, step uint16, verdict byte, reason string) {
	t.Helper()
	want := registry.HashPayload(contractSalt, contractRecord(event, planHash, step, verdict, reason))
	if l.PayloadHash != want {
		t.Fatalf("feuille KindContract : hash inattendu (event %d)", event)
	}
}

// ---------------------------------------------------------------------------
// Configuration fail-closed
// ---------------------------------------------------------------------------

func TestContractStoreConfigFailClosed(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	nominal := func() ContractOptions {
		return ContractOptions{
			CellID:       "cell-alpha-01",
			PolicyID:     arr32(policyV1),
			OperatorKeys: []ed25519.PublicKey{opKey1().Public().(ed25519.PublicKey)},
			Salt:         contractSalt,
			Leaves:       sink,
			Now:          clock.now,
		}
	}
	cases := []struct {
		name string
		mut  func(*ContractOptions)
	}{
		{"cellID vide", func(o *ContractOptions) { o.CellID = "" }},
		{"cellID trop long", func(o *ContractOptions) { o.CellID = string(bytesOf(0x63, 256)) }},
		{"sans clé opérateur", func(o *ContractOptions) { o.OperatorKeys = nil }},
		{"clé opérateur tronquée", func(o *ContractOptions) {
			o.OperatorKeys = []ed25519.PublicKey{ed25519.PublicKey(bytesOf(0x07, 31))}
		}},
		{"sel trop court", func(o *ContractOptions) { o.Salt = bytesOf(0x51, 15) }},
		{"sans feuilles", func(o *ContractOptions) { o.Leaves = nil }},
		{"MaxPending négatif", func(o *ContractOptions) { o.MaxPending = -1 }},
		{"MaxApproved négatif", func(o *ContractOptions) { o.MaxApproved = -1 }},
		{"ApprovalTTL < 60 s", func(o *ContractOptions) { o.ApprovalTTL = 59 * time.Second }},
		{"ApprovalTTL > 24 h", func(o *ContractOptions) { o.ApprovalTTL = 25 * time.Hour }},
		{"PendingTTL < 60 s", func(o *ContractOptions) { o.PendingTTL = 30 * time.Second }},
		{"PendingTTL > 24 h", func(o *ContractOptions) { o.PendingTTL = 48 * time.Hour }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := nominal()
			c.mut(&o)
			if _, err := NewContractStore(o); err == nil {
				t.Fatalf("config invalide acceptée (%s)", c.name)
			}
		})
	}
	// Et la configuration nominale passe (un store sans alarme est valide).
	if _, err := NewContractStore(nominal()); err != nil {
		t.Fatalf("config nominale refusée : %v", err)
	}
}

// ---------------------------------------------------------------------------
// Soumission : scellement du hash (critère 1 de #31)
// ---------------------------------------------------------------------------

func TestSubmitSealsPlanHash(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, nil)

	steps := []PlanStep{
		stepOf("read.list", "registry/docs/42", []byte(`{"limit":10}`)),
		stepOf("http.send", "https://api.example.com/v1/messages", nil),
	}
	hash, err := s.Submit(context.Background(), steps)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// Le sceau est exactement HashPlan à l'instant de soumission (D58).
	want := HashPlan("cell-alpha-01", contractEpochT0, arr32(policyV1), steps)
	if hash != want {
		t.Fatalf("sceau ≠ HashPlan attendu")
	}
	leaves := contractLeaves(sink)
	if len(leaves) != 1 {
		t.Fatalf("soumission : %d feuilles, attendu 1", len(leaves))
	}
	expectLeafHash(t, leaves[0], planEventSubmit, hash, 2, 1, "ok")

	// Soumission en double au même instant : idempotente (même sceau,
	// aucun second plan) mais tracée (chaque événement laisse une feuille).
	hash2, err := s.Submit(context.Background(), steps)
	if err != nil {
		t.Fatalf("Submit doublon: %v", err)
	}
	if hash2 != hash {
		t.Fatalf("soumission en double : sceau différent")
	}
	if n := len(contractLeaves(sink)); n != 2 {
		t.Fatalf("doublon : %d feuilles, attendu 2 (tracé)", n)
	}

	// Un instant plus tard, les mêmes étapes forment un NOUVEAU contrat
	// (submittedAt entre dans le sceau).
	clock.advance(time.Second)
	hash3, err := s.Submit(context.Background(), steps)
	if err != nil {
		t.Fatalf("Submit nouvel instant: %v", err)
	}
	if hash3 == hash {
		t.Fatalf("submittedAt hors du sceau : deux soumissions partagent le hash")
	}

	// Plans invalides : bornes D57.
	for _, bad := range [][]PlanStep{
		{}, // 0 étape
		make([]PlanStep, MaxPlanSteps+1),
		{stepOf("", "r", nil)},
		{stepOf("a", "", nil)},
		{stepOf(string(bytesOf(0x61, 256)), "r", nil)},
		{stepOf("a", string(bytesOf(0x72, 1025)), nil)},
	} {
		if _, err := s.Submit(context.Background(), bad); !errors.Is(err, ErrPlanSubmissionInvalid) {
			t.Fatalf("plan invalide accepté : %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Approbation : signature Ed25519, expiry bornée (D59)
// ---------------------------------------------------------------------------

func TestApproveRequiresOperatorSignature(t *testing.T) {
	newPending := func(t *testing.T) (*ContractStore, *contractClock, *stubSink, [32]byte) {
		sink := &stubSink{}
		clock := &contractClock{t: contractEpochT0}
		s := newContractStore(t, sink, clock, &contractTrips{}, nil)
		hash, err := s.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		return s, clock, sink, hash
	}
	expiry30 := func(c *contractClock) time.Time { return c.now().Add(30 * time.Minute) }

	t.Run("signature forgée", func(t *testing.T) {
		s, clock, sink, hash := newPending(t)
		sig := signApproval(opKey1(), hash, expiry30(clock))
		sig[0] ^= 0x01
		if err := s.Approve(context.Background(), hash, expiry30(clock), sig); !errors.Is(err, ErrPlanApprovalSignature) {
			t.Fatalf("signature forgée acceptée : %v", err)
		}
		// La tentative laisse une feuille de refus d'approbation.
		leaves := contractLeaves(sink)
		expectLeafHash(t, leaves[len(leaves)-1], planEventApprove, hash, planStepNA, 0, "plan-approval-signature-invalid")
	})

	t.Run("clé hors trousseau", func(t *testing.T) {
		s, clock, _, hash := newPending(t)
		// opKey2 n'est PAS dans le trousseau épinglé de ce store.
		err := s.Approve(context.Background(), hash, expiry30(clock), signApproval(opKey2(), hash, expiry30(clock)))
		if !errors.Is(err, ErrPlanApprovalSignature) {
			t.Fatalf("signature hors trousseau acceptée : %v", err)
		}
	})

	t.Run("signature sur autre expiry", func(t *testing.T) {
		s, clock, _, hash := newPending(t)
		sig := signApproval(opKey1(), hash, expiry30(clock).Add(time.Hour))
		if err := s.Approve(context.Background(), hash, expiry30(clock), sig); !errors.Is(err, ErrPlanApprovalSignature) {
			t.Fatalf("l'expiry n'est pas liée par la signature : %v", err)
		}
	})

	t.Run("expiry trop courte", func(t *testing.T) {
		s, clock, _, hash := newPending(t)
		exp := clock.now().Add(59 * time.Second)
		if err := s.Approve(context.Background(), hash, exp, signApproval(opKey1(), hash, exp)); !errors.Is(err, ErrPlanApprovalExpiryInvalid) {
			t.Fatalf("expiry 59 s acceptée : %v", err)
		}
	})

	t.Run("expiry au-delà du TTL configuré", func(t *testing.T) {
		s, clock, _, hash := newPending(t)
		exp := clock.now().Add(2 * time.Hour) // ApprovalTTL défaut 1 h
		if err := s.Approve(context.Background(), hash, exp, signApproval(opKey1(), hash, exp)); !errors.Is(err, ErrPlanApprovalExpiryInvalid) {
			t.Fatalf("expiry 2 h acceptée avec TTL 1 h : %v", err)
		}
	})

	t.Run("plan inconnu", func(t *testing.T) {
		s, clock, _, _ := newPending(t)
		unknown := arr32(bytesOf(0x99, 32))
		err := s.Approve(context.Background(), unknown, expiry30(clock), signApproval(opKey1(), unknown, expiry30(clock)))
		if !errors.Is(err, ErrPlanUnknown) {
			t.Fatalf("approbation d'un plan inconnu : %v", err)
		}
	})

	t.Run("double approbation refusée", func(t *testing.T) {
		s, clock, _, hash := newPending(t)
		approveNominal(t, s, clock, hash)
		exp := expiry30(clock)
		if err := s.Approve(context.Background(), hash, exp, signApproval(opKey1(), hash, exp)); !errors.Is(err, ErrPlanUnknown) {
			t.Fatalf("double approbation : %v", err)
		}
	})

	t.Run("soumission expirée inapprovable", func(t *testing.T) {
		sink := &stubSink{}
		clock := &contractClock{t: contractEpochT0}
		s := newContractStore(t, sink, clock, &contractTrips{}, func(o *ContractOptions) { o.PendingTTL = time.Minute })
		hash, err := s.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		clock.advance(2 * time.Minute) // PendingTTL dépassé
		exp := clock.now().Add(30 * time.Minute)
		if err := s.Approve(context.Background(), hash, exp, signApproval(opKey1(), hash, exp)); !errors.Is(err, ErrPlanExpired) {
			t.Fatalf("soumission expirée approuvée : %v", err)
		}
	})

	t.Run("plusieurs clés opérateur : une suffit", func(t *testing.T) {
		sink := &stubSink{}
		clock := &contractClock{t: contractEpochT0}
		s := newContractStore(t, sink, clock, &contractTrips{}, func(o *ContractOptions) {
			o.OperatorKeys = []ed25519.PublicKey{
				opKey1().Public().(ed25519.PublicKey),
				opKey2().Public().(ed25519.PublicKey),
			}
		})
		hash, err := s.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		exp := expiry30(clock)
		if err := s.Approve(context.Background(), hash, exp, signApproval(opKey2(), hash, exp)); err != nil {
			t.Fatalf("approbation par la 2e clé du trousseau refusée : %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Exécution conforme (critère 2 de #31)
// ---------------------------------------------------------------------------

func TestConformantExecutionConsumesSteps(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, nil)

	steps := []PlanStep{
		stepOf("read.list", "registry/docs/42", []byte(`{"limit":10}`)),
		stepOf("http.send", "https://api.example.com/v1/messages", nil),
		stepOf("storage.append", "storage/artifacts/report.pdf", []byte("blob-bytes")),
	}
	hash, err := s.Submit(context.Background(), steps)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approveNominal(t, s, clock, hash)

	// Chaque étape conforme, dans l'ordre : acceptée, sceau rendu, curseur avancé.
	for i, st := range steps {
		params := [][]byte{[]byte(`{"limit":10}`), nil, []byte("blob-bytes")}[i]
		seal, err := s.VerifyStep(context.Background(), bindingOf(t, hash, params), st.Action, st.Resource)
		if err != nil {
			t.Fatalf("étape %d conforme refusée : %v", i, err)
		}
		if seal != hash {
			t.Fatalf("étape %d : sceau rendu ≠ hash du plan", i)
		}
	}
	// Le plan épuisé refuse toute étape supplémentaire (déviation).
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "read.list", "registry/docs/42"); !errors.Is(err, ErrPlanDeviation) {
		t.Fatalf("plan épuisé : étape supplémentaire acceptée : %v", err)
	}
	// Feuilles : 1 submit + 1 approve + 3 consume + 1 refuse.
	leaves := contractLeaves(sink)
	if len(leaves) != 6 {
		t.Fatalf("%d feuilles, attendu 6", len(leaves))
	}
	expectLeafHash(t, leaves[1], planEventApprove, hash, planStepNA, 1, "ok")
	for i := range steps {
		expectLeafHash(t, leaves[2+i], planEventConsume, hash, uint16(i), 1, "ok")
	}
	expectLeafHash(t, leaves[5], planEventRefuse, hash, planStepNA, 0, "plan-deviation")
	if trips.count() != 0 {
		t.Fatalf("alarmes inattendues : %v", trips.reasons)
	}
}

// ---------------------------------------------------------------------------
// Déviation refusée (critère 3 de #31)
// ---------------------------------------------------------------------------

func TestPlanDeviationRefused(t *testing.T) {
	setup := func(t *testing.T) (*ContractStore, *stubSink, [32]byte) {
		sink := &stubSink{}
		clock := &contractClock{t: contractEpochT0}
		s := newContractStore(t, sink, clock, &contractTrips{}, nil)
		steps := []PlanStep{
			stepOf("read.list", "registry/docs/42", []byte(`{"limit":10}`)),
			stepOf("http.send", "https://api.example.com/v1/messages", nil),
		}
		hash, err := s.Submit(context.Background(), steps)
		if err != nil {
			t.Fatalf("Submit: %v", err)
		}
		approveNominal(t, s, clock, hash)
		return s, sink, hash
	}

	t.Run("action différente", func(t *testing.T) {
		s, _, hash := setup(t)
		_, err := s.VerifyStep(context.Background(), bindingOf(t, hash, []byte(`{"limit":10}`)), "storage.delete", "registry/docs/42")
		if !errors.Is(err, ErrPlanDeviation) {
			t.Fatalf("action déviante acceptée : %v", err)
		}
	})
	t.Run("ressource différente", func(t *testing.T) {
		s, _, hash := setup(t)
		_, err := s.VerifyStep(context.Background(), bindingOf(t, hash, []byte(`{"limit":10}`)), "read.list", "registry/docs/1337")
		if !errors.Is(err, ErrPlanDeviation) {
			t.Fatalf("ressource déviante acceptée : %v", err)
		}
	})
	t.Run("paramètre différent", func(t *testing.T) {
		s, _, hash := setup(t)
		// Même action, même ressource, params reformattés (espace en plus) :
		// le sceau lie les OCTETS BRUTS — même une dérive cosmétique refuse.
		_, err := s.VerifyStep(context.Background(), bindingOf(t, hash, []byte(`{"limit": 10}`)), "read.list", "registry/docs/42")
		if !errors.Is(err, ErrPlanDeviation) {
			t.Fatalf("paramètres déviants acceptés : %v", err)
		}
	})
	t.Run("ordre différent (étape 2 d'abord)", func(t *testing.T) {
		s, _, hash := setup(t)
		_, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "http.send", "https://api.example.com/v1/messages")
		if !errors.Is(err, ErrPlanDeviation) {
			t.Fatalf("exécution hors ordre acceptée : %v", err)
		}
	})
	t.Run("rejeu d'étape consommée", func(t *testing.T) {
		s, _, hash := setup(t)
		if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, []byte(`{"limit":10}`)), "read.list", "registry/docs/42"); err != nil {
			t.Fatalf("étape 1 nominale : %v", err)
		}
		_, err := s.VerifyStep(context.Background(), bindingOf(t, hash, []byte(`{"limit":10}`)), "read.list", "registry/docs/42")
		if !errors.Is(err, ErrPlanDeviation) {
			t.Fatalf("rejeu d'étape accepté : %v", err)
		}
	})
	t.Run("chaque refus laisse sa feuille", func(t *testing.T) {
		s, sink, hash := setup(t)
		before := len(contractLeaves(sink)) // submit + approve
		_, _ = s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "storage.delete", "registry/docs/42")
		leaves := contractLeaves(sink)
		if len(leaves) != before+1 {
			t.Fatalf("refus sans feuille : %d → %d", before, len(leaves))
		}
		expectLeafHash(t, leaves[len(leaves)-1], planEventRefuse, hash, 0, 0, "plan-deviation")
	})
}

// ---------------------------------------------------------------------------
// Scénario P2 « plan mensonger » (§13, critère 4 de #31)
// ---------------------------------------------------------------------------

func TestLyingPlanP2(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, nil)

	// L'agent présente un plan d'apparence bénigne ; l'opérateur le signe.
	benign := []PlanStep{
		stepOf("read.list", "registry/docs/42", nil),
		stepOf("http.send", "https://api.example.com/v1/messages", []byte(`{"to":"ops@example.com"}`)),
	}
	hash, err := s.Submit(context.Background(), benign)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approveNominal(t, s, clock, hash)

	// Première étape conforme : exécutée.
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "read.list", "registry/docs/42"); err != nil {
		t.Fatalf("étape 1 conforme : %v", err)
	}

	// Le plan mentait : à mi-chemin, l'agent tente l'action destructive —
	// jamais montrée à l'opérateur. REFUS, alors que l'action isolée aurait
	// pu être autorisée par la politique (c'est le contrat qui refuse, pas
	// OPA — le test croisé broker le démontre avec un OPA qui permet tout).
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "storage.delete", "storage/artifacts"); !errors.Is(err, ErrPlanDeviation) {
		t.Fatalf("P2 : action destructive hors plan acceptée : %v", err)
	}

	// Variante : l'agent soumet SON propre plan destructeur sans jamais
	// obtenir la signature de l'opérateur — l'exécution refuse « pending ».
	evil := []PlanStep{stepOf("storage.delete", "storage/artifacts", nil)}
	evilHash, err := s.Submit(context.Background(), evil)
	if err != nil {
		t.Fatalf("Submit plan adverse: %v", err)
	}
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, evilHash, nil), "storage.delete", "storage/artifacts"); !errors.Is(err, ErrPlanPending) {
		t.Fatalf("P2 : plan adverse non approuvé exécutable : %v", err)
	}

	// Variante : l'agent forge une approbation de SA propre clé — le
	// trousseau épinglé refuse (jamais par nom, toujours par signature §12).
	exp := clock.now().Add(30 * time.Minute)
	forged := ed25519.Sign(ed25519.NewKeyFromSeed(bytesOf(0x42, 32)), ApprovalMessage(evilHash, exp))
	if err := s.Approve(context.Background(), evilHash, exp, forged); !errors.Is(err, ErrPlanApprovalSignature) {
		t.Fatalf("P2 : approbation forgée acceptée : %v", err)
	}

	// Et le plan bénin approuvé, lui, continue son cours exact après la
	// tentative de déviation (le curseur n'a pas bougé).
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, []byte(`{"to":"ops@example.com"}`)), "http.send", "https://api.example.com/v1/messages"); err != nil {
		t.Fatalf("plan bénin bloqué par la déviation adverse : %v", err)
	}
}

// ---------------------------------------------------------------------------
// Expiration, révocation, saturation, fautes
// ---------------------------------------------------------------------------

func TestApprovedPlanExpiryRefuses(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	s := newContractStore(t, sink, clock, &contractTrips{}, nil)
	hash, err := s.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	exp := clock.now().Add(MinApprovalTTL)
	if err := s.Approve(context.Background(), hash, exp, signApproval(opKey1(), hash, exp)); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// À l'instant d'expiry exact, le contrat tient encore (convention
	// inclusive, comme exp des jetons) ; une seconde après, il est mort.
	clock.advance(MinApprovalTTL)
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "read.list", "registry/docs/42"); err != nil {
		t.Fatalf("à l'instant expiry, le plan devrait encore servir : %v", err)
	}
	// (L'étape a été consommée — plan d'une étape épuisé : on re-soumet
	// pour tester l'expiration elle-même.)
	clock2 := &contractClock{t: contractEpochT0}
	sink2 := &stubSink{}
	s2 := newContractStore(t, sink2, clock2, &contractTrips{}, nil)
	hash2, err := s2.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
	if err != nil {
		t.Fatalf("Submit 2: %v", err)
	}
	exp2 := clock2.now().Add(MinApprovalTTL)
	if err := s2.Approve(context.Background(), hash2, exp2, signApproval(opKey1(), hash2, exp2)); err != nil {
		t.Fatalf("Approve 2: %v", err)
	}
	clock2.advance(MinApprovalTTL + time.Second)
	if _, err := s2.VerifyStep(context.Background(), bindingOf(t, hash2, nil), "read.list", "registry/docs/42"); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("plan expiré accepté : %v", err)
	}
	// Feuille d'expiration écrite UNE fois, puis chaque tentative = refus tracé.
	leaves := contractLeaves(sink2)
	expireCount := 0
	for _, l := range leaves {
		if l.PayloadHash == registry.HashPayload(contractSalt, contractRecord(planEventExpire, hash2, planStepNA, 1, "ok")) {
			expireCount++
		}
	}
	if expireCount != 1 {
		t.Fatalf("feuilles d'expiration : %d, attendu 1", expireCount)
	}
	if _, err := s2.VerifyStep(context.Background(), bindingOf(t, hash2, nil), "read.list", "registry/docs/42"); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("seconde tentative sur plan expiré : %v", err)
	}
	leaves = contractLeaves(sink2)
	expireCount = 0
	for _, l := range leaves {
		if l.PayloadHash == registry.HashPayload(contractSalt, contractRecord(planEventExpire, hash2, planStepNA, 1, "ok")) {
			expireCount++
		}
	}
	if expireCount != 1 {
		t.Fatalf("feuille d'expiration dupliquée : %d", expireCount)
	}
}

func TestRevocationRefuses(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	s := newContractStore(t, sink, clock, &contractTrips{}, nil)
	hash, err := s.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approveNominal(t, s, clock, hash)
	if err := s.Revoke(context.Background(), hash); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "read.list", "registry/docs/42"); !errors.Is(err, ErrPlanRevoked) {
		t.Fatalf("plan révoqué exécutable : %v", err)
	}
	// Révocation d'un inconnu et double révocation : refusées, tracées.
	if err := s.Revoke(context.Background(), arr32(bytesOf(0x77, 32))); !errors.Is(err, ErrPlanUnknown) {
		t.Fatalf("révocation d'un inconnu : %v", err)
	}
	if err := s.Revoke(context.Background(), hash); !errors.Is(err, ErrPlanUnknown) {
		t.Fatalf("double révocation : %v", err)
	}
	leaves := contractLeaves(sink)
	found := false
	for _, l := range leaves {
		if l.PayloadHash == registry.HashPayload(contractSalt, contractRecord(planEventRevoke, hash, planStepNA, 1, "ok")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("révocation sans feuille")
	}
}

func TestContractStoreSaturation(t *testing.T) {
	t.Run("soumissions saturées", func(t *testing.T) {
		sink := &stubSink{}
		clock := &contractClock{t: contractEpochT0}
		trips := &contractTrips{}
		s := newContractStore(t, sink, clock, trips, func(o *ContractOptions) { o.MaxPending = 1 })
		if _, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r1", nil)}); err != nil {
			t.Fatalf("Submit 1: %v", err)
		}
		clock.advance(time.Second) // sceau distinct
		if _, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r2", nil)}); !errors.Is(err, ErrPlanStoreSaturated) {
			t.Fatalf("saturation pending non refusée : %v", err)
		}
		if trips.count() != 1 {
			t.Fatalf("saturation sans alarme : %d", trips.count())
		}
	})
	t.Run("approbations saturées", func(t *testing.T) {
		sink := &stubSink{}
		clock := &contractClock{t: contractEpochT0}
		trips := &contractTrips{}
		s := newContractStore(t, sink, clock, trips, func(o *ContractOptions) { o.MaxApproved = 1 })
		h1, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r1", nil)})
		if err != nil {
			t.Fatalf("Submit 1: %v", err)
		}
		clock.advance(time.Second)
		h2, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r2", nil)})
		if err != nil {
			t.Fatalf("Submit 2: %v", err)
		}
		approveNominal(t, s, clock, h1)
		exp := clock.now().Add(30 * time.Minute)
		if err := s.Approve(context.Background(), h2, exp, signApproval(opKey1(), h2, exp)); !errors.Is(err, ErrPlanStoreSaturated) {
			t.Fatalf("saturation approved non refusée : %v", err)
		}
		if trips.count() != 1 {
			t.Fatalf("saturation sans alarme : %d", trips.count())
		}
	})
}

// TestConsumeWithoutLeafFailsClosed est l'ancre de la mutation M5 : un
// allow de gate sans feuille est une ERREUR, et le curseur n'a pas avancé
// (pas de preuve, pas de progression — doctrine T9/T11/T29).
func TestConsumeWithoutLeafFailsClosed(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, nil)
	hash, err := s.Submit(context.Background(), []PlanStep{stepOf("read.list", "registry/docs/42", nil)})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	approveNominal(t, s, clock, hash)

	sink.err = errors.New("registre indisponible")
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "read.list", "registry/docs/42"); !errors.Is(err, ErrPlanStoreFault) {
		t.Fatalf("consommation sans feuille acceptée : %v", err)
	}
	if trips.count() != 1 {
		t.Fatalf("faute de store sans alarme : %d", trips.count())
	}
	// Le curseur n'a PAS avancé : une fois le registre rétabli, la même
	// étape est toujours l'exigible — aucune consommation clandestine.
	sink.err = nil
	if _, err := s.VerifyStep(context.Background(), bindingOf(t, hash, nil), "read.list", "registry/docs/42"); err != nil {
		t.Fatalf("reprise après faute : %v (le curseur aurait avancé sans preuve)", err)
	}
}

func TestSubmitWithoutLeafFailsClosed(t *testing.T) {
	sink := &stubSink{err: errors.New("registre indisponible")}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, nil)
	if _, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r", nil)}); !errors.Is(err, ErrPlanStoreFault) {
		t.Fatalf("soumission sans feuille acceptée : %v", err)
	}
	if trips.count() != 1 {
		t.Fatalf("faute sans alarme : %d", trips.count())
	}
	// Rien n'a été stocké : la re-soumission après rétablissement fonctionne.
	sink.err = nil
	if _, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r", nil)}); err != nil {
		t.Fatalf("reprise après faute : %v", err)
	}
}

func TestBindingMalformed(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	s := newContractStore(t, sink, clock, &contractTrips{}, nil)
	good := bindingOf(t, arr32(bytesOf(0x11, 32)), []byte("p"))
	cases := []struct {
		name string
		b    []byte
	}{
		{"vide", nil},
		{"trop court", good[:20]},
		{"préfixe faux", append([]byte("XXXXX"), good[5:]...)},
		{"paramsLen trop grand", append(good, 0x00)},
		{"paramsLen trop petit", good[:len(good)-1]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := s.VerifyStep(context.Background(), c.b, "a", "r"); !errors.Is(err, ErrPlanBindingInvalid) {
				t.Fatalf("binding mal formé accepté : %v", err)
			}
		})
	}
	if n := len(contractLeaves(sink)); n != len(cases) {
		t.Fatalf("bindings mal formés : %d feuilles, attendu %d", n, len(cases))
	}
}

// TestTombstonesAreBounded vérifie que les plans expirés ou révoqués ne
// font pas grossir la carte du store sans fin (§4.3). Trouvé en revue de
// #66 : MaxPending/MaxApproved ne bornent que les plans VIVANTS
// (countStatusLocked exclut tout ce qui est expiré ou révoqué) — sans
// purge séparée, chaque nouveau plan expiré ou révoqué laissait une
// entrée permanente dans store.plans, jamais retirée, pour toute la durée
// de vie de la cellule. Beaucoup plus de plans que MaxTombstones sont
// soumis puis expirés ; la taille de la carte doit rester bornée.
func TestTombstonesAreBounded(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	const maxTombstones = 5
	s := newContractStore(t, sink, clock, &contractTrips{}, func(o *ContractOptions) {
		o.MaxTombstones = maxTombstones
		o.PendingTTL = MinApprovalTTL // expire vite pour ce test
	})

	const rounds = 200 // très au-delà de maxTombstones
	for i := 0; i < rounds; i++ {
		steps := []PlanStep{stepOf("a", "r", []byte{byte(i), byte(i >> 8)})}
		if _, err := s.Submit(context.Background(), steps); err != nil {
			t.Fatalf("submit %d : %v (le quota VIVANT ne doit jamais saturer ici — chaque plan expire avant le suivant)", i, err)
		}
		clock.advance(MinApprovalTTL + time.Second)
	}
	// Un dernier toucher pour que le dernier lot expiré soit purgé au tour
	// suivant (expireLocked tourne en tête de chaque appel public).
	if _, err := s.Submit(context.Background(), []PlanStep{stepOf("a", "r", []byte("flush"))}); err != nil {
		t.Fatalf("submit de purge : %v", err)
	}

	s.mu.Lock()
	n := len(s.plans)
	s.mu.Unlock()

	// Borne : au plus maxTombstones tombes + 1 entrée vivante (la toute
	// dernière soumission, pas encore expirée à cet instant).
	if n > maxTombstones+1 {
		t.Fatalf("store.plans contient %d entrées après %d soumissions expirées — attendu ≤ %d (MaxTombstones=%d), la carte grossit sans borne", n, rounds, maxTombstones+1, maxTombstones)
	}
}

// TestContractStoreSnapshot couvre la couture T34c (D81) : la console
// affiche la file d'arbitrage — pending vivants seuls, triés par
// submittedAt, avec hash scellé et bornes temporelles ; un plan approuvé
// ou expiré disparaît ; la lecture ne mute rien (aucune feuille).
func TestContractStoreSnapshot(t *testing.T) {
	sink := &stubSink{}
	clock := &contractClock{t: contractEpochT0}
	trips := &contractTrips{}
	s := newContractStore(t, sink, clock, trips, nil)

	if got := s.Snapshot(); len(got) != 0 {
		t.Fatalf("snapshot initial non vide : %d plans", len(got))
	}
	if got := s.PolicyID(); got != arr32(policyV1) {
		t.Fatalf("PolicyID : %x — attendu %x (claim −1)", got, arr32(policyV1))
	}

	steps1 := []PlanStep{stepOf("db.write", "users", []byte("p1")), stepOf("db.read", "audit", []byte("p2"))}
	h1, err := s.Submit(context.Background(), steps1)
	if err != nil {
		t.Fatalf("submit 1 : %v", err)
	}
	submitted1 := clock.now()
	clock.advance(time.Minute) // ordre d'arrivée distinct
	steps2 := []PlanStep{stepOf("fs.delete", "/tmp/x", []byte("p3"))}
	h2, err := s.Submit(context.Background(), steps2)
	if err != nil {
		t.Fatalf("submit 2 : %v", err)
	}
	submitted2 := clock.now()

	got := s.Snapshot()
	if len(got) != 2 {
		t.Fatalf("snapshot : %d plans — attendu 2", len(got))
	}
	// Tri par submittedAt : h1 (plus ancien) en tête.
	if got[0].Hash != h1 || got[1].Hash != h2 {
		t.Fatalf("ordre de la file : [%x %x] — attendu [%x %x] (ordre d'arrivée = ordre d'arbitrage)",
			got[0].Hash[:4], got[1].Hash[:4], h1[:4], h2[:4])
	}
	if got[0].Steps != 2 || got[1].Steps != 1 {
		t.Fatalf("nombre d'étapes : %d et %d — attendu 2 et 1", got[0].Steps, got[1].Steps)
	}
	if !got[0].SubmittedAt.Equal(submitted1) || !got[1].SubmittedAt.Equal(submitted2) {
		t.Fatalf("submittedAt : %v / %v — attendu %v / %v", got[0].SubmittedAt, got[1].SubmittedAt, submitted1, submitted2)
	}
	wantExpiry := submitted1.Add(DefaultPendingTTL)
	if !got[0].ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expiresAt : %v — attendu %v (submittedAt + PendingTTL)", got[0].ExpiresAt, wantExpiry)
	}

	// La lecture est pure : aucune feuille, aucune mutation, résultat
	// stable à l'appel répété.
	leavesBefore := len(sink.leaves)
	if again := s.Snapshot(); len(again) != 2 || again[0].Hash != h1 || again[1].Hash != h2 {
		t.Fatalf("snapshot répété instable : %+v", again)
	}
	if len(sink.leaves) != leavesBefore {
		t.Fatalf("Snapshot a écrit %d feuille(s) — une lecture ne produit aucun événement", len(sink.leaves)-leavesBefore)
	}

	// Un plan approuvé sort de la file d'arbitrage.
	approveNominal(t, s, clock, h1)
	if got := s.Snapshot(); len(got) != 1 || got[0].Hash != h2 {
		t.Fatalf("snapshot après approbation : %+v — attendu [h2] seul", got)
	}

	// Un plan dont la vie est passée n'apparaît plus, MÊME si la feuille
	// d'expiration n'est pas encore écrite (filtre horloge, D81 : la
	// console ne montre jamais un plan déjà mort).
	clock.advance(DefaultPendingTTL) // submitted2 + 15 min pile
	if got := s.Snapshot(); len(got) != 0 {
		t.Fatalf("snapshot après expiration : %d plans — attendu 0 (expiresAt atteint)", len(got))
	}
}
