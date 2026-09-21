package pep

// dryrun_test.go — T36 (issue #62) : batterie du dry-run §4.4(1) (D104)
// et de sa soumission à OPA. Chaque témoin est une faute précise qui DOIT
// être prise (D106) — un contrôle qui passerait sans la faute est
// non-vacuole.
//
// Couverture :
//   - canonisation : tri, non-mutation, bornes et conventions de kind ;
//   - hash de diff : vecteur doré « TBPF1 » (provenance : deux
//     implémentations indépendantes, Go + Python hashlib, figées) ;
//   - porte : configuration fail-closed, exécution (succès / erreur
//     composant / diff mal formé / timeout), feuilles dans tous les cas ;
//   - listener : dry-run AVANT passeport (un refus dry-run n'ouvre pas de
//     compteur), veto OPA sur le diff avec scope par ailleurs valide,
//     available=false sans porte, et D105 — hors F/I/W, le runner n'est
//     JAMAIS appelé et l'entrée OPA ne porte pas dry_run ;
//   - intégration RÉELLE : un vrai binaire OPA sur
//     policies/testdata/rule_dryrun.rego refuse sur la base du diff
//     (critère d'acceptation 1 de l'issue).

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Canonisation et hash de diff
// ---------------------------------------------------------------------------

func diffHashOf(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// goldenDiffTBPF1 : hash « TBPF1 » de cellID="cell-a",
// entries {account/42,balance,update,sha256("old-value-100"),sha256("new-value-150")},
// {account/42,owner,create,0×32,sha256("agent-007")}.
const goldenDiffTBPF1 = "433f80a5fdfd75821cd123bd3845e203ab8a9bee3725547f391cd59bc185d598"

func nominalDiff() StateDiff {
	return StateDiff{Entries: []DiffEntry{
		{Object: "account/42", Field: "balance", Kind: DiffUpdate,
			BeforeHash: diffHashOf("old-value-100"), AfterHash: diffHashOf("new-value-150")},
		{Object: "account/42", Field: "owner", Kind: DiffCreate,
			AfterHash: diffHashOf("agent-007")},
	}}
}

func TestCanonicalizeDiffTriEtNonMutation(t *testing.T) {
	d := nominalDiff()
	c, err := CanonicalizeDiff(d)
	if err != nil {
		t.Fatal(err)
	}
	// balance < owner : l'entrée balance doit passer devant.
	if c.Entries[0].Field != "balance" || c.Entries[1].Field != "owner" {
		t.Fatalf("tri canonique absent: %+v", c.Entries)
	}
	// L'entrée appelant n'est PAS mutée.
	if d.Entries[0].Field != "balance" || d.Entries[1].Field != "owner" {
		t.Fatal("CanonicalizeDiff a muté l'entrée de l'appelant")
	}
	// Déjà trié ou non : même résultat.
	rev := StateDiff{Entries: []DiffEntry{d.Entries[1], d.Entries[0]}}
	c2, _ := CanonicalizeDiff(rev)
	if fmt.Sprintf("%v", c) != fmt.Sprintf("%v", c2) {
		t.Fatal("l'ordre de fourniture ne doit pas changer la canonisation")
	}
}

func TestCanonicalizeDiffBornes(t *testing.T) {
	long := func(n int) string { return string(make([]byte, n)) }
	good := DiffEntry{Object: "o", Field: "f", Kind: DiffUpdate,
		BeforeHash: diffHashOf("a"), AfterHash: diffHashOf("b")}
	cases := []struct {
		name string
		diff StateDiff
	}{
		{"object vide", StateDiff{Entries: []DiffEntry{{Object: "", Field: "f", Kind: DiffUpdate}}}},
		{"object trop long", StateDiff{Entries: []DiffEntry{{Object: long(MaxSealObjectLen + 1), Field: "f", Kind: DiffUpdate}}}},
		{"field vide", StateDiff{Entries: []DiffEntry{{Object: "o", Field: "", Kind: DiffUpdate}}}},
		{"field trop long", StateDiff{Entries: []DiffEntry{{Object: "o", Field: long(MaxSealFieldLen + 1), Kind: DiffUpdate}}}},
		{"kind inconnu", StateDiff{Entries: []DiffEntry{{Object: "o", Field: "f", Kind: DiffKind(9)}}}},
		{"create avec before non nul", StateDiff{Entries: []DiffEntry{{Object: "o", Field: "f", Kind: DiffCreate, BeforeHash: diffHashOf("x"), AfterHash: diffHashOf("y")}}}},
		{"delete avec after non nul", StateDiff{Entries: []DiffEntry{{Object: "o", Field: "f", Kind: DiffDelete, BeforeHash: diffHashOf("x"), AfterHash: diffHashOf("y")}}}},
		{"trop d'entrées", StateDiff{Entries: make([]DiffEntry, MaxDiffEntries+1)}},
	}
	for _, tc := range cases {
		if tc.name == "trop d'entrées" {
			for i := range tc.diff.Entries {
				tc.diff.Entries[i] = good
			}
		}
		if _, err := CanonicalizeDiff(tc.diff); !errors.Is(err, ErrDiffBounds) {
			t.Errorf("%s : err=%v, veut ErrDiffBounds", tc.name, err)
		}
	}
}

func TestHashDiffGolden(t *testing.T) {
	digest, err := HashDiff("cell-a", nominalDiff())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest[:]); got != goldenDiffTBPF1 {
		t.Fatalf("diff_hash=%s, veut le vecteur doré %s", got, goldenDiffTBPF1)
	}
	// cellID lie l'engagement.
	d2, _ := HashDiff("cell-b", nominalDiff())
	if digest == d2 {
		t.Fatal("cellID doit lier le hash de diff")
	}
}

// ---------------------------------------------------------------------------
// Porte dry-run : configuration et exécution
// ---------------------------------------------------------------------------

type stubRunner struct {
	diff    StateDiff
	err     error
	delay   time.Duration
	calls   atomic.Int32
	lastAct string
}

func (s *stubRunner) DryRun(ctx context.Context, action, _ string) (StateDiff, error) {
	s.calls.Add(1)
	s.lastAct = action
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return StateDiff{}, ctx.Err()
		}
	}
	return s.diff, s.err
}

type panicRunner struct{}

func (p *panicRunner) DryRun(context.Context, string, string) (StateDiff, error) {
	panic("DryRun appelé sur une action HORS classes F/I/W — D105 violé")
}

func TestDryRunGateConfigFailClosed(t *testing.T) {
	sink := &stubSink{}
	ok := DryRunGateOptions{
		Runner: &stubRunner{}, CellID: "cell-a", Salt: testSalt, Leaves: sink,
	}
	if _, err := NewDryRunGate(ok); err != nil {
		t.Fatalf("config nominale: %v", err)
	}
	cases := []struct {
		name  string
		mut   func(*DryRunGateOptions)
	}{
		{"runner nil", func(o *DryRunGateOptions) { o.Runner = nil }},
		{"cellID vide", func(o *DryRunGateOptions) { o.CellID = "" }},
		{"sel court", func(o *DryRunGateOptions) { o.Salt = testSalt[:8] }},
		{"leaves nil", func(o *DryRunGateOptions) { o.Leaves = nil }},
		{"timeout hors plafond", func(o *DryRunGateOptions) { o.Timeout = MaxDryRunTimeout + time.Second }},
	}
	for _, tc := range cases {
		o := ok
		tc.mut(&o)
		if _, err := NewDryRunGate(o); err == nil {
			t.Errorf("%s : configuration acceptée, veut refus fail-closed", tc.name)
		}
	}
}

func newGate(t *testing.T, runner DryRunner, sink *stubSink) *DryRunGate {
	t.Helper()
	g, err := NewDryRunGate(DryRunGateOptions{
		Runner: runner, CellID: "cell-a", Salt: testSalt, Leaves: sink,
	})
	if err != nil {
		t.Fatalf("NewDryRunGate: %v", err)
	}
	return g
}

// sinkKinds rend les kinds des feuilles capturées, dans l'ordre.
func sinkKinds(s *stubSink) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, len(s.leaves))
	for i, l := range s.leaves {
		out[i] = l.Kind
	}
	return out
}

func TestDryRunGateExecuteSucces(t *testing.T) {
	sink := &stubSink{}
	runner := &stubRunner{diff: nominalDiff()}
	g := newGate(t, runner, sink)

	jti := [16]byte{1, 2, 3}
	in, reason := g.Execute(context.Background(), jti, "transfer", "account/42")
	if reason != "" {
		t.Fatalf("reason=%q, veut succès", reason)
	}
	if !in.Available || in.EntryCount != 2 || len(in.Entries) != 2 {
		t.Fatalf("entrée OPA: %+v", in)
	}
	if in.DiffHash != goldenDiffTBPF1 {
		t.Errorf("diff_hash=%q, veut le vecteur doré", in.DiffHash)
	}
	// Vue OPA : structure SEULE — kinds lisibles, jamais de hash de valeur.
	if in.Entries[0] != (DryRunEntry{Object: "account/42", Field: "balance", Kind: "update"}) {
		t.Errorf("entrée[0]=%+v", in.Entries[0])
	}
	if in.Entries[1].Kind != "create" {
		t.Errorf("entrée[1].Kind=%q, veut create", in.Entries[1].Kind)
	}
	// Feuilles : une télémétrie, AUCUNE décision (pas de refus).
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1 (télémétrie seule)", sink.count())
	}
	if got := sinkKinds(sink)[0]; got != registry.KindTelemetry {
		t.Fatalf("kind=%d, veut KindTelemetry", got)
	}
}

func TestDryRunGateErreurComposant(t *testing.T) {
	sink := &stubSink{}
	runner := &stubRunner{err: errors.New("composant en panne")}
	g := newGate(t, runner, sink)

	in, reason := g.Execute(context.Background(), [16]byte{}, "transfer", "account/42")
	if in != nil || reason != ReasonDryRunFailed {
		t.Fatalf("in=%v reason=%q, veut nil/%s", in, reason, ReasonDryRunFailed)
	}
	// Télémétrie (mesure de l'échec) + feuille de REFUS (§4.1).
	kinds := sinkKinds(sink)
	if len(kinds) != 2 || kinds[0] != registry.KindTelemetry || kinds[1] != registry.KindDecision {
		t.Fatalf("feuilles=%v, veut [télémétrie, décision]", kinds)
	}
}

func TestDryRunGateDiffMalForme(t *testing.T) {
	sink := &stubSink{}
	runner := &stubRunner{diff: StateDiff{Entries: []DiffEntry{
		{Object: "o", Field: "f", Kind: DiffKind(42)}, // kind inconnu
	}}}
	g := newGate(t, runner, sink)
	if _, reason := g.Execute(context.Background(), [16]byte{}, "a", "r"); reason != ReasonDryRunFailed {
		t.Fatalf("reason=%q, veut %s — un diff mal formé ne passe JAMAIS", reason, ReasonDryRunFailed)
	}
}

func TestDryRunGateTimeout(t *testing.T) {
	sink := &stubSink{}
	runner := &stubRunner{diff: nominalDiff(), delay: 300 * time.Millisecond}
	g, err := NewDryRunGate(DryRunGateOptions{
		Runner: runner, Timeout: 50 * time.Millisecond,
		CellID: "cell-a", Salt: testSalt, Leaves: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, reason := g.Execute(context.Background(), [16]byte{}, "transfer", "account/42")
	if reason != ReasonDryRunTimeout {
		t.Fatalf("reason=%q, veut %s", reason, ReasonDryRunTimeout)
	}
}

// ---------------------------------------------------------------------------
// Listener : orchestration D104 (avant passeport) et D105 (hors-classes)
// ---------------------------------------------------------------------------

// opaCapture est un stub OPA qui ENREGISTRE l'entrée reçue et applique un
// verdict scripté sur le diff — la preuve que l'entrée dry_run arrive
// bien au moteur de politique.
type opaCapture struct {
	t        *testing.T
	lastIn   atomic.Value // map[string]any
	denyFunc func(in map[string]any) bool
}

func (o *opaCapture) handler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Input map[string]any `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		o.t.Fatalf("corps OPA illisible: %v", err)
	}
	o.lastIn.Store(body.Input)
	allow := true
	if o.denyFunc != nil && o.denyFunc(body.Input) {
		allow = false
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"result":{"allow":%v}}`, allow)
}

func (o *opaCapture) input() map[string]any {
	v := o.lastIn.Load()
	if v == nil {
		return nil
	}
	return v.(map[string]any)
}

// dryRunFixture : pile complète listener + OPA stub + porte dry-run.
type dryRunFixture struct {
	sink   *stubSink
	ledger *QuotaLedger
	l      *Listener
	srv    *httptest.Server
	opa    *opaCapture
	opaSrv *httptest.Server
}

func newDryRunFixture(t *testing.T, gate *DryRunGate, denyFunc func(map[string]any) bool) *dryRunFixture {
	t.Helper()
	opa := &opaCapture{t: t, denyFunc: denyFunc}
	opaSrv := httptest.NewServer(http.HandlerFunc(opa.handler))
	t.Cleanup(opaSrv.Close)
	f := newDryRunFixtureEndpoint(t, gate, opaSrv.URL+"/v1/data/tbp/test/dryrun")
	f.opa = opa
	f.opaSrv = opaSrv
	return f
}

// newDryRunFixtureEndpoint : même pile, mais pointée vers n'importe quel
// endpoint OPA (stub ou vrai binaire).
func newDryRunFixtureEndpoint(t *testing.T, gate *DryRunGate, opaEndpoint string) *dryRunFixture {
	t.Helper()
	sink := &stubSink{}
	now := func() time.Time { return time.Unix(testIAT+30, 0) }

	fc, err := NewFailClosed(FailClosedOptions{CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Now: now})
	if err != nil {
		t.Fatalf("NewFailClosed: %v", err)
	}
	mc, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: sink, VerifyQuorum: acceptQuorum, Now: now,
	})
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}
	ar, err := NewAntiReplay(AntiReplayOptions{Capacity: 256, Now: now})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	ledger, err := NewQuotaLedger(QuotaLedgerOptions{
		MaxPassports: 64, CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Now: now,
	})
	if err != nil {
		t.Fatalf("NewQuotaLedger: %v", err)
	}
	v, err := NewValidator(ValidatorOptions{
		CellID:     opaTestCellID,
		Keyring:    map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)},
		PolicyID:   arr32(policyV1),
		Salt:       testSalt,
		Leaves:     sink,
		AntiReplay: ar,
		Quota:      ledger,
		Gate:       fc,
		Now:        now,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}

	opa := &opaCapture{t: t}
	oc, err := NewOPAClient(OPAOptions{
		Endpoint: opaEndpoint,
		CellID:   opaTestCellID, Salt: testSalt, Leaves: sink, Now: now,
	})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}

	l, err := NewListener(ListenerOptions{Validator: v, Mode: mc, Ledger: ledger, OPA: oc, DryRun: gate})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	srv := httptest.NewServer(l.Handler())
	t.Cleanup(srv.Close)
	return &dryRunFixture{sink: sink, ledger: ledger, l: l, srv: srv, opa: opa}
}

// newDryRunFixtureRealOPA : pile pointée vers le vrai binaire OPA.
func newDryRunFixtureRealOPA(t *testing.T, gate *DryRunGate, endpoint string) *dryRunFixture {
	t.Helper()
	return newDryRunFixtureEndpoint(t, gate, endpoint)
}

// transferClaims : action classe F avec quota — le passeport rend visible
// l'ordonnancement dry-run AVANT ouverture (revue #62).
func transferClaims() testClaims {
	c := nominalClaims()
	c.action = "transfer"
	c.resource = "account/42"
	c.class = intPtr(0) // ClassF
	c.quota = map[int]any{1: "bank.accounts", 2: "transfer", 3: 1000000, 4: 60}
	return c
}

func evaluateTransfer(t *testing.T, f *dryRunFixture, tok []byte) EvaluateResponse {
	t.Helper()
	body, _ := json.Marshal(EvaluateRequest{
		Token:    base64.StdEncoding.EncodeToString(tok),
		Action:   "transfer",
		Resource: "account/42",
		Epoch:    0,
	})
	status, data := postJSON(t, f.srv.URL+"/v1/evaluate", body)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, data)
	}
	var out EvaluateResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// Critère d'acceptation 1 : OPA refuse SUR LA BASE DU DIFF, scope par
// ailleurs valide — et le refus dry-run/OPA n'ouvre pas de passeport en
// amont (dry-run avant passeport) quand la faute vient du dry-run lui-
// même.
func TestListenerVetoOPASurDiff(t *testing.T) {
	sink := &stubSink{}
	gate := newGate(t, &stubRunner{diff: nominalDiff()}, sink)
	// Politique stub : deny si le diff touche "balance" — le scope
	// (transfer account/42) est par ailleurs VALIDE et le jeton T9 passe.
	f := newDryRunFixture(t, gate, func(in map[string]any) bool {
		dr, _ := in["dry_run"].(map[string]any)
		if dr == nil {
			return false
		}
		entries, _ := dr["entries"].([]any)
		for _, e := range entries {
			if m, _ := e.(map[string]any); m != nil && m["field"] == "balance" {
				return true
			}
		}
		return false
	})

	out := evaluateTransfer(t, f, mintToken(t, transferClaims()))
	if out.Allow || out.Reason != ReasonOPADeny {
		t.Fatalf("verdict=%+v, veut deny/%s — OPA doit pouvoir refuser sur le diff", out, ReasonOPADeny)
	}
	// L'entrée reçue par OPA portait le diff structurel (hash-only).
	in := f.opa.input()
	dr, _ := in["dry_run"].(map[string]any)
	if dr == nil || dr["available"] != true {
		t.Fatalf("input.dry_run=%v, veut available=true", dr)
	}
	if dr["diff_hash"] != goldenDiffTBPF1 {
		t.Errorf("diff_hash=%v, veut le vecteur doré", dr["diff_hash"])
	}
	// Le passeport n'a JAMAIS été ouvert (dry-run + veto avant/consommé) :
	// ici le veto est OPA, postérieur — le cas dry-run-refus est couvert
	// par TestListenerDryRunRefusAvantPasseport ci-dessous.
}

func TestListenerDryRunAllowPasseportOuvert(t *testing.T) {
	sink := &stubSink{}
	// Diff BÉNIN (pas de champ interdit) → la politique stub laisse passer.
	benign := StateDiff{Entries: []DiffEntry{
		{Object: "account/42", Field: "memo", Kind: DiffUpdate,
			BeforeHash: diffHashOf("x"), AfterHash: diffHashOf("y")},
	}}
	gate := newGate(t, &stubRunner{diff: benign}, sink)
	f := newDryRunFixture(t, gate, func(in map[string]any) bool {
		dr, _ := in["dry_run"].(map[string]any)
		entries, _ := dr["entries"].([]any)
		for _, e := range entries {
			if m, _ := e.(map[string]any); m != nil && m["field"] == "balance" {
				return true
			}
		}
		return false
	})

	out := evaluateTransfer(t, f, mintToken(t, transferClaims()))
	if !out.Allow || !out.PassportOpened {
		t.Fatalf("verdict=%+v, veut allow + passeport ouvert", out)
	}
}

func TestListenerDryRunRefusAvantPasseport(t *testing.T) {
	sink := &stubSink{}
	runner := &stubRunner{err: errors.New("dry-run impossible")}
	gate := newGate(t, runner, sink)
	f := newDryRunFixture(t, gate, nil) // OPA laisserait tout passer

	out := evaluateTransfer(t, f, mintToken(t, transferClaims()))
	if out.Allow || out.Reason != ReasonDryRunFailed {
		t.Fatalf("verdict=%+v, veut deny/%s", out, ReasonDryRunFailed)
	}
	if out.PassportOpened {
		t.Fatal("un refus dry-run ne doit JAMAIS ouvrir de passeport (revue #62)")
	}
}

func TestListenerSansGateAvailableFalse(t *testing.T) {
	// Pas de porte : la politique est informée (available=false) — ici le
	// stub EXIGE le dry-run et refuse (la politique tranche).
	f := newDryRunFixture(t, nil, func(in map[string]any) bool {
		dr, _ := in["dry_run"].(map[string]any)
		return dr == nil || dr["available"] != true
	})
	out := evaluateTransfer(t, f, mintToken(t, transferClaims()))
	if out.Allow || out.Reason != ReasonOPADeny {
		t.Fatalf("verdict=%+v, veut deny/%s (available=false + politique exigeante)", out, ReasonOPADeny)
	}
	dr, _ := f.opa.input()["dry_run"].(map[string]any)
	if dr == nil || dr["available"] != false {
		t.Fatalf("input.dry_run=%v, veut available=false explicite", dr)
	}
}

// D105 — mitigation bornée : hors classes F/I/W, le runner n'est JAMAIS
// appelé (panic-guard) et l'entrée OPA ne porte AUCUNE clé dry_run —
// coût de latence nul, chemin strictement inchangé.
func TestListenerHorsClassesCoutNul(t *testing.T) {
	sink := &stubSink{}
	gate := newGate(t, &panicRunner{}, sink)
	f := newDryRunFixture(t, gate, nil)

	c := transferClaims() // scope transfer/account/42 conforme à la requête
	c.class = intPtr(3)   // ClassOut
	out := evaluateTransfer(t, f, mintToken(t, c))
	if !out.Allow {
		t.Fatalf("verdict=%+v, veut allow (hors classes, chemin inchangé)", out)
	}
	if _, present := f.opa.input()["dry_run"]; present {
		t.Fatal("input ne doit PAS porter dry_run hors classes F/I/W (D105)")
	}
}

// ---------------------------------------------------------------------------
// Intégration RÉELLE : vrai OPA sur policies/testdata/rule_dryrun.rego
// ---------------------------------------------------------------------------

// TestDryRunRealOPAVetoSurDiff prouve le critère d'acceptation 1 de
// l'issue avec le vrai moteur : une action F dont le scope est valide est
// REFUSÉE par OPA parce que le diff touche un champ interdit, et admise
// avec un diff bénin. Binaire opa requis (explicite — pas de skip
// silencieux : le test le dit).
func TestDryRunRealOPAVetoSurDiff(t *testing.T) {
	opaBin, err := exec.LookPath("opa")
	if err != nil {
		t.Skipf("binaire opa absent — intégration réelle non exécutable ici (le stub opaCapture couvre le chemin)")
	}

	// Port libre via un listener éphémère.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	// Vrai OPA sur la politique de test (working dir = src/pep).
	cmd := exec.Command(opaBin, "run", "--server", "--addr", fmt.Sprintf("127.0.0.1:%d", port),
		"../../policies/testdata/rule_dryrun.rego")
	var opaLog strings.Builder
	cmd.Stdout, cmd.Stderr = &opaLog, &opaLog
	if err := cmd.Start(); err != nil {
		t.Fatalf("opa run: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	// Sonde de démarrage.
	health := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	deadline := time.Now().Add(15 * time.Second)
	up := false
	for time.Now().Before(deadline) {
		resp, err := http.Get(health) //nolint:noctx — sonde locale bornée
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				up = true
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !up {
		t.Fatalf("opa injoignable après 15 s — %s", opaLog.String())
	}

	sink := &stubSink{}
	gate := newGate(t, &stubRunner{diff: nominalDiff()}, sink) // diff avec "balance"
	f := newDryRunFixtureRealOPA(t, gate, fmt.Sprintf("http://127.0.0.1:%d/v1/data/tbp/test/dryrun", port))

	// Scope valide, jeton valide, diff touche "balance" → REFUS sur le diff.
	out := evaluateTransfer(t, f, mintToken(t, transferClaims()))
	if out.Allow || out.Reason != ReasonOPADeny {
		t.Fatalf("diff interdit: verdict=%+v, veut deny/%s — le vrai OPA doit refuser sur la base du diff", out, ReasonOPADeny)
	}

	// Diff bénin → allow. Nouvelle fixture (jti consommé, passeport ouvert).
	sink2 := &stubSink{}
	benign := StateDiff{Entries: []DiffEntry{
		{Object: "account/42", Field: "memo", Kind: DiffUpdate,
			BeforeHash: diffHashOf("x"), AfterHash: diffHashOf("y")},
	}}
	gate2 := newGate(t, &stubRunner{diff: benign}, sink2)
	f2 := newDryRunFixtureRealOPA(t, gate2, fmt.Sprintf("http://127.0.0.1:%d/v1/data/tbp/test/dryrun", port))
	out2 := evaluateTransfer(t, f2, mintToken(t, transferClaims()))
	if !out2.Allow {
		t.Fatalf("diff bénin: verdict=%+v, veut allow", out2)
	}
}
