package pep

import (
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures T14
// ---------------------------------------------------------------------------

func newTestFailClosed(t *testing.T, sink *stubSink, alarm *tripRecorder) *FailClosed {
	t.Helper()
	opts := FailClosedOptions{
		CellID: opaTestCellID,
		Salt:   testSalt,
		Leaves: sink,
		Now:    func() time.Time { return time.Unix(testIAT+30, 0) },
	}
	if alarm != nil {
		opts.OnAlarm = alarm.trip
	}
	fc, err := NewFailClosed(opts)
	if err != nil {
		t.Fatalf("NewFailClosed: %v", err)
	}
	return fc
}

// tripLeafHash re-compute le hash attendu d'une feuille trip/clear.
func tripLeafHash(action byte, name, detail string) [32]byte {
	return registry.HashPayload(testSalt, failClosedRecord(action, name, detail))
}

// knownConditions est le catalogue des conditions de défaillance de l'issue
// #16 : OPA (T11), horloge (T13), ancrage (T6), cache jti (T10), quota (T12),
// disque registre (T5).
var knownConditions = []struct {
	name  string
	class Class
}{
	{ReasonOPATimeout, ClassI},
	{ReasonOPAUnreachable, ClassI},
	{ReasonOPAError, ClassI},
	{ReasonOPABadResponse, ClassI},
	{ReasonClockSkew, ClassI},
	{TripReasonJTISaturated, ClassI},
	{TripReasonQuotaSaturated, ClassI},
	{CondRegistryDiskHigh, ClassI},
	{CondAnchorLag, ClassW}, // fencing §6.2 : levée gouvernée
}

// ---------------------------------------------------------------------------
// Portillon propre : aucune condition ⇒ Gate laisse passer, rien n'est tracé.
// ---------------------------------------------------------------------------

func TestGateCleanPasses(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(t, sink, alarm)

	if ref := fc.Gate(); ref != nil {
		t.Fatalf("refus=%v sur portillon propre", ref)
	}
	if sink.count() != 0 || alarm.count() != 0 {
		t.Fatalf("tracé intempestif: feuilles=%d alarmes=%d", sink.count(), alarm.count())
	}
}

// ---------------------------------------------------------------------------
// Critère d'acceptation central : CHAQUE condition de défaillance est testée
// individuellement et le refus passe par LE MÊME chemin de code — Gate() —
// avec feuille et alarme.
// ---------------------------------------------------------------------------

func TestEachConditionSameGatePath(t *testing.T) {
	for _, cond := range knownConditions {
		t.Run(cond.name, func(t *testing.T) {
			sink := &stubSink{}
			alarm := &tripRecorder{}
			fc := newTestFailClosed(t, sink, alarm)
			if err := fc.Register(cond.name, cond.class); err != nil {
				t.Fatalf("Register: %v", err)
			}

			fc.Trip(cond.name, "détecteur de test")

			// LE point unique de décision : Gate().
			ref := fc.Gate()
			if ref == nil {
				t.Fatalf("Gate() ne refuse pas après Trip(%s)", cond.name)
			}
			if ref.Reason != cond.name {
				t.Fatalf("raison=%q, veut %q (refus motivé)", ref.Reason, cond.name)
			}
			if ref.Detail != "détecteur de test" {
				t.Fatalf("detail=%q", ref.Detail)
			}
			var err error = ref
			if err == nil || !strings.Contains(err.Error(), cond.name) {
				t.Fatalf("Refusal doit être une error motivée: %v", err)
			}
			// Bascule tracée (feuille) et alarmée — jamais silencieuse.
			if sink.count() != 1 {
				t.Fatalf("feuilles=%d, veut 1 (bascule tracée)", sink.count())
			}
			if leaf := sink.leaves[0]; leaf.Kind != registry.KindTelemetry {
				t.Fatalf("kind=%d, veut KindTelemetry", leaf.Kind)
			}
			if alarm.count() != 1 || lastReason(alarm) != cond.name {
				t.Fatalf("alarmes=%v, veut 1 × %s", alarm.reasons, cond.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// La bascule est tracée hash-only : le registre ne voit que l'engagement.
// ---------------------------------------------------------------------------

func TestTripTracedHashOnly(t *testing.T) {
	sink := &stubSink{}
	fc := newTestFailClosed(t, sink, nil)
	if err := fc.Register(ReasonOPAUnreachable, ClassI); err != nil {
		t.Fatalf("Register: %v", err)
	}
	fc.Trip(ReasonOPAUnreachable, "sidecar injoignable")

	leaf := sink.leaves[0]
	if got := leaf.PayloadHash; got != tripLeafHash(failClosedActionTrip, ReasonOPAUnreachable, "sidecar injoignable") {
		t.Fatalf("hash=%x, veut engagement trip(%s)", got, ReasonOPAUnreachable)
	}
	if leaf.CellID != opaTestCellID {
		t.Fatalf("cellID=%q", leaf.CellID)
	}
	if leaf.Timestamp != time.Unix(testIAT+30, 0).UnixNano() {
		t.Fatalf("timestamp=%d", leaf.Timestamp)
	}
	// Condition observable (couture forensique).
	c, ok := fc.Condition(ReasonOPAUnreachable)
	if !ok || !c.Tripped || c.Detail != "sidecar injoignable" || c.Class != ClassI {
		t.Fatalf("condition=%+v ok=%v", c, ok)
	}
	if c.Since != time.Unix(testIAT+30, 0) {
		t.Fatalf("since=%v", c.Since)
	}
}

// ---------------------------------------------------------------------------
// Re-trip d'une condition déjà basculée : pas de feuille ni d'alarme en
// double (la bascule est un événement, pas un état répété).
// ---------------------------------------------------------------------------

func TestTripIdempotentNoDuplicate(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(t, sink, alarm)
	if err := fc.Register(ReasonOPATimeout, ClassI); err != nil {
		t.Fatalf("Register: %v", err)
	}
	fc.Trip(ReasonOPATimeout, "premier")
	fc.Trip(ReasonOPATimeout, "second")

	if sink.count() != 1 || alarm.count() != 1 {
		t.Fatalf("feuilles=%d alarmes=%d, veut 1/1 (pas de doublon)", sink.count(), alarm.count())
	}
	c, _ := fc.Condition(ReasonOPATimeout)
	if c.Detail != "premier" {
		t.Fatalf("detail=%q, veut %q (le premier diagnostic reste)", c.Detail, "premier")
	}
}

// ---------------------------------------------------------------------------
// Plusieurs conditions basculées : le refus est DÉTERMINISTE (tri par nom) —
// deux appels à Gate() donnent toujours la même raison.
// ---------------------------------------------------------------------------

func TestGateDeterministicOrder(t *testing.T) {
	sink := &stubSink{}
	fc := newTestFailClosed(t, sink, nil)
	for _, name := range []string{ReasonOPAUnreachable, ReasonClockSkew, TripReasonJTISaturated} {
		if err := fc.Register(name, ClassI); err != nil {
			t.Fatalf("Register: %v", err)
		}
		fc.Trip(name, "")
	}
	first := fc.Gate()
	if first == nil {
		t.Fatal("Gate() ne refuse pas")
	}
	for i := 0; i < 16; i++ {
		if ref := fc.Gate(); ref == nil || ref.Reason != first.Reason {
			t.Fatalf("raison instable: %v puis %v", first.Reason, ref)
		}
	}
	// clock-skew < jti-cache-saturated < opa-unreachable (ordre lexicographique).
	if first.Reason != ReasonClockSkew {
		t.Fatalf("raison=%q, veut %q (ordre déterministe)", first.Reason, ReasonClockSkew)
	}
}

// ---------------------------------------------------------------------------
// Levée de condition (classes F/I) : action tracée, le portillon rouvre.
// ---------------------------------------------------------------------------

func TestClearTraced(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(t, sink, alarm)
	if err := fc.Register(CondRegistryDiskHigh, ClassI); err != nil {
		t.Fatalf("Register: %v", err)
	}
	fc.Trip(CondRegistryDiskHigh, "disque à 83 %")
	if fc.Gate() == nil {
		t.Fatal("Gate() ne refuse pas après Trip")
	}

	if err := fc.Clear(CondRegistryDiskHigh, QuorumProof{}); err != nil {
		t.Fatalf("Clear classe I: %v", err)
	}
	if ref := fc.Gate(); ref != nil {
		t.Fatalf("refus=%v après Clear", ref)
	}
	if sink.count() != 2 {
		t.Fatalf("feuilles=%d, veut 2 (trip + clear tracé)", sink.count())
	}
	if got := sink.leaves[1].PayloadHash; got != tripLeafHash(failClosedActionClear, CondRegistryDiskHigh, "") {
		t.Fatalf("2e feuille hash=%x, veut clear(%s)", got, CondRegistryDiskHigh)
	}
	c, _ := fc.Condition(CondRegistryDiskHigh)
	if c.Tripped {
		t.Fatal("condition encore basculée après Clear")
	}
}

// ---------------------------------------------------------------------------
// Classe W (§5.3) : la levée EXIGE un quorum — nil vérifieur ou preuve
// invalide ⇒ refus fail-closed, la condition reste basculée.
// ---------------------------------------------------------------------------

func TestClearClassWRequiresQuorum(t *testing.T) {
	sink := &stubSink{}
	fc := newTestFailClosed(t, sink, nil)
	if err := fc.Register(CondAnchorLag, ClassW); err != nil {
		t.Fatalf("Register: %v", err)
	}
	fc.Trip(CondAnchorLag, "ancrage en retard de 3 fenêtres")

	// Pas de vérifieur de quorum configuré : la levée W est impossible.
	if err := fc.Clear(CondAnchorLag, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err == nil {
		t.Fatal("classe W levée sans vérifieur de quorum (fail-closed violé)")
	}
	if fc.Gate() == nil {
		t.Fatal("condition W levée malgré le refus de quorum")
	}

	// Vérifieur qui rejette : toujours basculé.
	fc2 := newTestFailClosed(t, sink, nil)
	fc2.SetQuorumVerifier(func(condition string, proof QuorumProof) bool { return false })
	if err := fc2.Register(CondAnchorLag, ClassW); err != nil {
		t.Fatalf("Register: %v", err)
	}
	fc2.Trip(CondAnchorLag, "")
	if err := fc2.Clear(CondAnchorLag, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err == nil {
		t.Fatal("classe W levée avec preuve rejetée")
	}
	if fc2.Gate() == nil {
		t.Fatal("condition W levée malgré la preuve rejetée")
	}

	// Vérifieur qui accepte : levée tracée.
	fc2.SetQuorumVerifier(func(condition string, proof QuorumProof) bool {
		return condition == CondAnchorLag && len(proof.Signatures) >= 2
	})
	fc2.SetQuorumState(acceptQuorumState{})
	if err := fc2.Clear(CondAnchorLag, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}, {KeyID: [16]byte{2}}}}); err != nil {
		t.Fatalf("Clear classe W avec quorum: %v", err)
	}
	if ref := fc2.Gate(); ref != nil {
		t.Fatalf("refus=%v après levée quorée", ref)
	}
}

// ---------------------------------------------------------------------------
// Erreurs de levée : condition inconnue ou non basculée.
// ---------------------------------------------------------------------------

func TestClearErrors(t *testing.T) {
	sink := &stubSink{}
	fc := newTestFailClosed(t, sink, nil)
	if err := fc.Clear("jamais-vu", QuorumProof{}); err == nil {
		t.Fatal("levée d'une condition inconnue acceptée")
	}
	if err := fc.Register(ReasonOPAError, ClassI); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := fc.Clear(ReasonOPAError, QuorumProof{}); err == nil {
		t.Fatal("levée d'une condition non basculée acceptée")
	}
	if sink.count() != 0 {
		t.Fatalf("feuilles=%d, veut 0 (rien à tracer)", sink.count())
	}
}

// ---------------------------------------------------------------------------
// Fail-closed sur condition INCONNUE : un détecteur qui bascule une raison
// non enregistrée refuse quand même — et la condition hérite de la classe
// la plus dure à lever (W, défaut §5.3) : quorum requis.
// ---------------------------------------------------------------------------

func TestUnknownTripStillRefuses(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(t, sink, alarm)

	fc.Trip("panne-inconnue", "détecteur futur")

	ref := fc.Gate()
	if ref == nil || ref.Reason != "panne-inconnue" {
		t.Fatalf("Gate()=%v, veut refus panne-inconnue", ref)
	}
	c, ok := fc.Condition("panne-inconnue")
	if !ok || c.Class != ClassW {
		t.Fatalf("classe=%v, veut W (défaut §5.3 : la plus dure à lever)", c.Class)
	}
	if err := fc.Clear("panne-inconnue", QuorumProof{}); err == nil {
		t.Fatal("condition inconnue levée sans quorum")
	}
}

// ---------------------------------------------------------------------------
// Soudure T13→T14 : l'adaptateur OnTrip() câble les détecteurs existants
// (func(reason string)) sur le point unique — ici le vrai ClockWatchdog :
// skew ⇒ le portillon T14 refuse avec la MÊME raison.
// ---------------------------------------------------------------------------

func TestOnTripAdapterWiresClockWatchdog(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(t, sink, alarm)

	p := &stubProbe{}
	p.set(ClockSample{Unsync: false, EstError: 60 * time.Millisecond}, nil)
	w, err := NewClockWatchdog(ClockOptions{
		Probe:       p.probe,
		LocalIssuer: localTestIssuer,
		CellID:      opaTestCellID,
		Salt:        testSalt,
		Leaves:      sink,
		OnTrip:      fc.OnTrip(), // couture T13 → point unique T14
		Now:         func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewClockWatchdog: %v", err)
	}

	if ref := fc.Gate(); ref != nil {
		t.Fatalf("refus=%v avant la détection", ref)
	}
	w.Check()
	ref := fc.Gate()
	if ref == nil || ref.Reason != ReasonClockSkew {
		t.Fatalf("Gate()=%v, veut refus %s", ref, ReasonClockSkew)
	}
	if alarm.count() != 1 || lastReason(alarm) != ReasonClockSkew {
		t.Fatalf("alarmes=%v, veut 1 × %s", alarm.reasons, ReasonClockSkew)
	}
}

// ---------------------------------------------------------------------------
// Soudure T9↔T14 : le validateur interroge le portillon AVANT toute la
// chaîne — refus motivé, feuille de décision, anti-rejeu NON consommé (le
// même jeton passe une fois la condition levée).
// ---------------------------------------------------------------------------

func TestValidatorGatedBeforeChain(t *testing.T) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(t, sink, alarm)

	ar, err := NewAntiReplay(AntiReplayOptions{
		Capacity: 16,
		Now:      func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	v, err := NewValidator(ValidatorOptions{
		CellID:     opaTestCellID,
		Keyring:    map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)},
		PolicyID:   arr32(policyV1),
		Salt:       testSalt,
		Leaves:     sink,
		AntiReplay: ar,
		Gate:       fc,
		Now:        func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	tok := mintToken(t, nominalClaims())

	// Portillon propre : la chaîne suit son cours normal.
	if d := v.Validate(t.Context(), tok, nominalRequest()); !d.Allow {
		t.Fatalf("jeton nominal refusé portillon propre: %s", d.Reason)
	}

	// OPA injoignable détecté (T11) ⇒ le validateur refuse AVANT la chaîne.
	if err := fc.Register(ReasonOPAUnreachable, ClassI); err != nil {
		t.Fatalf("Register: %v", err)
	}
	fc.Trip(ReasonOPAUnreachable, "sidecar down")
	claims2 := nominalClaims()
	j2 := jtiOf(0x77)
	claims2.jti = j2[:] // jti distinct : tok a déjà consommé le sien
	tok2 := mintToken(t, claims2)
	d := v.Validate(t.Context(), tok2, nominalRequest())
	if d.Allow {
		t.Fatal("allow malgré le portillon basculé (§4.1 violé)")
	}
	if d.Reason != ReasonOPAUnreachable {
		t.Fatalf("raison=%q, veut %q (refus motivé par la condition)", d.Reason, ReasonOPAUnreachable)
	}
	if !d.LeafWritten {
		t.Fatal("refus de portillon sans feuille de décision (§4.1)")
	}

	// L'anti-rejeu n'a PAS consommé le jti de tok2 : condition levée, le
	// MÊME jeton passe — preuve que le portillon court-circuite avant
	// toute mutation.
	if err := fc.Clear(ReasonOPAUnreachable, QuorumProof{}); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if d := v.Validate(t.Context(), tok2, nominalRequest()); !d.Allow {
		t.Fatalf("jeton refusé après levée (anti-rejeu consommé trop tôt ?): %s", d.Reason)
	}
}

// ---------------------------------------------------------------------------
// Critère « revue + linter » : AUCUN composant ne construit son propre refus
// parallèle — le type Refusal n'est instancié que dans failclosed.go.
// ---------------------------------------------------------------------------

func TestNoParallelRefusalLinter(t *testing.T) {
	// Refusal a des champs exportés : n'importe quel package qui importe
	// pep peut en construire un directement, contournant entièrement
	// FailClosed.Trip()/Gate() — un scan limité au répertoire courant
	// (os.ReadDir(".") non récursif) ne verrait donc JAMAIS une
	// construction parallèle logée ailleurs (un sous-répertoire comme
	// src/pep/postgres-extension, ou tout futur package qui importe pep).
	// Le linter doit donc couvrir tout le module, pas seulement le paquet
	// pep lui-même — c'est exactement le genre de dérive que ce test
	// existe pour empêcher (« un seul endroit qui décide »).
	root := moduleRoot(t)
	wantOnly := filepath.Join(root, "src", "pep", "failclosed.go")

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "tbp4.2.1":
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if path == wantOnly {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "Refusal{") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir(%s): %v", root, err)
	}
	if len(offenders) > 0 {
		t.Fatalf("construction(s) de Refusal{} hors %s : %v — le seul point de décision « refuser maintenant » est failclosed.go", wantOnly, offenders)
	}
}

// moduleRoot localise la racine du module (le répertoire portant go.mod)
// en remontant depuis le répertoire du paquet — le test tourne avec pour
// CWD le répertoire du paquet (src/pep), pas la racine du dépôt.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod introuvable en remontant depuis le répertoire du paquet")
		}
		dir = parent
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration.
// ---------------------------------------------------------------------------

func TestNewFailClosedConfig(t *testing.T) {
	base := FailClosedOptions{
		CellID: opaTestCellID,
		Salt:   testSalt,
		Leaves: &stubSink{},
	}
	if _, err := NewFailClosed(base); err != nil {
		t.Fatalf("config nominale refusée: %v", err)
	}
	bad := base
	bad.CellID = ""
	if _, err := NewFailClosed(bad); err == nil {
		t.Fatal("CellID vide accepté")
	}
	bad = base
	bad.Salt = []byte("court")
	if _, err := NewFailClosed(bad); err == nil {
		t.Fatal("sel < 16 o accepté (§6.2)")
	}
	bad = base
	bad.Leaves = nil
	if _, err := NewFailClosed(bad); err == nil {
		t.Fatal("Leaves nil accepté (la bascule doit être tracée)")
	}
}

// ---------------------------------------------------------------------------
// Concurrence : Trip/Gate/Clear simultanés (sous -race).
// ---------------------------------------------------------------------------

func TestFailClosedConcurrent(t *testing.T) {
	sink := &stubSink{}
	fc := newTestFailClosed(t, sink, nil)
	for _, cond := range knownConditions {
		if err := fc.Register(cond.name, cond.class); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	var wg sync.WaitGroup
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			cond := knownConditions[g%len(knownConditions)]
			for i := 0; i < 64; i++ {
				fc.Trip(cond.name, "concurrent")
				_ = fc.Gate()
				_, _ = fc.Condition(cond.name)
			}
		}(g)
	}
	wg.Wait()
	if ref := fc.Gate(); ref == nil {
		t.Fatal("Gate() propre après 64×64 trips")
	}
}

// ---------------------------------------------------------------------------

func BenchmarkFailClosedGate(b *testing.B) {
	sink := &stubSink{}
	alarm := &tripRecorder{}
	fc := newTestFailClosed(&testing.T{}, sink, alarm)
	b.Run("clean", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = fc.Gate()
		}
	})
	if err := fc.Register(ReasonOPATimeout, ClassI); err != nil {
		b.Fatalf("Register: %v", err)
	}
	fc.Trip(ReasonOPATimeout, "")
	b.Run("tripped", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = fc.Gate()
		}
	})
}
