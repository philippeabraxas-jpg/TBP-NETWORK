package pep

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures T15 (listener) : la pile complète — FailClosed (T14) + Mode (T15)
// + AntiReplay (T10) + Validator (T9) [+ QuotaLedger (T12)] + Listener.
// ---------------------------------------------------------------------------

type listenerFixture struct {
	sink     *stubSink
	fc       *FailClosed
	mc       *ModeController
	ledger   *QuotaLedger
	l        *Listener
	srv      *httptest.Server // plan de données : /v1/evaluate, /v1/passport/consume
	adminSrv *httptest.Server // plan d'administration (revue #95) : /v1/mode, /healthz
}

func newListenerFixture(t *testing.T, withLedger bool) *listenerFixture {
	t.Helper()
	sink := &stubSink{}
	now := func() time.Time { return time.Unix(testIAT+30, 0) }

	fc, err := NewFailClosed(FailClosedOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Now: now,
	})
	if err != nil {
		t.Fatalf("NewFailClosed: %v", err)
	}
	mc, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: sink,
		VerifyQuorum: acceptQuorum, Now: now,
	})
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}
	ar, err := NewAntiReplay(AntiReplayOptions{Capacity: 256, Now: now})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	var ledger *QuotaLedger
	var qc QuotaChecker
	if withLedger {
		ledger, err = NewQuotaLedger(QuotaLedgerOptions{
			MaxPassports: 64, CellID: opaTestCellID, Salt: testSalt, Leaves: sink, Now: now,
		})
		if err != nil {
			t.Fatalf("NewQuotaLedger: %v", err)
		}
		qc = ledger
	}
	v, err := NewValidator(ValidatorOptions{
		CellID:     opaTestCellID,
		Keyring:    map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)},
		PolicyID:   arr32(policyV1),
		Salt:       testSalt,
		Leaves:     sink,
		AntiReplay: ar,
		Quota:      qc,
		Gate:       fc,
		Now:        now,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	l, err := NewListener(ListenerOptions{Validator: v, Mode: mc, Ledger: ledger})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	srv := httptest.NewServer(l.Handler())
	t.Cleanup(srv.Close)
	adminSrv := httptest.NewServer(l.AdminHandler())
	t.Cleanup(adminSrv.Close)
	return &listenerFixture{sink: sink, fc: fc, mc: mc, ledger: ledger, l: l, srv: srv, adminSrv: adminSrv}
}

func evalBody(t *testing.T, tok []byte) []byte {
	t.Helper()
	body, err := json.Marshal(EvaluateRequest{
		Token:    base64.StdEncoding.EncodeToString(tok),
		Action:   "read.list",
		Resource: "registry/docs/42",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

func postJSON(t *testing.T, url string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, buf.Bytes()
}

func evaluate(t *testing.T, f *listenerFixture, tok []byte) EvaluateResponse {
	t.Helper()
	status, data := postJSON(t, f.srv.URL+"/v1/evaluate", evalBody(t, tok))
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, data)
	}
	var out EvaluateResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, data)
	}
	return out
}

// ---------------------------------------------------------------------------
// Mode monitor (défaut doctrinal §5.3) : verdicts journalisés (feuille),
// RIEN bloqué — un deny est « would-deny », le flux est forwardé.
// ---------------------------------------------------------------------------

func TestListenerMonitorNominal(t *testing.T) {
	f := newListenerFixture(t, false)
	out := evaluate(t, f, mintToken(t, nominalClaims()))

	if !out.Allow || out.Reason != ReasonOK {
		t.Fatalf("verdict=%+v, veut allow", out)
	}
	if !out.Forwarded {
		t.Fatal("flux non forwardé en monitor sur allow")
	}
	if out.Mode != "monitor" {
		t.Fatalf("mode=%q, veut monitor", out.Mode)
	}
	if !out.LeafWritten {
		t.Fatal("feuille de décision non écrite (§4.1 : monitor comme closed, on trace)")
	}
	if out.ElapsedUs < 0 {
		t.Fatalf("elapsed=%d", out.ElapsedUs)
	}
	st := f.l.Stats()
	if st.Evaluations != 1 || st.Forwarded != 1 || st.Denied != 0 || st.WouldDeny != 0 {
		t.Fatalf("stats=%+v", st)
	}
}

func TestListenerMonitorWouldDeny(t *testing.T) {
	f := newListenerFixture(t, false)
	claims := nominalClaims()
	claims.action = "write.delete" // portée invalide ⇒ deny scope-mismatch
	out := evaluate(t, f, mintToken(t, claims))

	if out.Allow {
		t.Fatal("allow sur portée invalide")
	}
	if out.Reason != ReasonScopeMismatch {
		t.Fatalf("raison=%q, veut %q", out.Reason, ReasonScopeMismatch)
	}
	if !out.Forwarded {
		t.Fatal("monitor a BLOQUÉ un deny (doctrine §5.3 : log, aucun blocage)")
	}
	if !out.LeafWritten {
		t.Fatal("deny monitor sans feuille")
	}
	st := f.l.Stats()
	if st.WouldDeny != 1 || st.Denied != 0 {
		t.Fatalf("stats=%+v, veut WouldDeny=1 Denied=0 (monitor ne compte pas de blocage)", st)
	}
}

// ---------------------------------------------------------------------------
// Bascule closed (gouvernée) : le verdict S'APPLIQUE — deny ⇒ non forwardé.
// ---------------------------------------------------------------------------

func TestListenerClosedAppliesVerdict(t *testing.T) {
	f := newListenerFixture(t, false)

	// Bascule gouvernée monitor → closed via l'endpoint HTTP.
	body, _ := json.Marshal(ModeChangeRequest{Mode: "closed"})
	status, data := postJSON(t, f.adminSrv.URL+"/v1/mode", body)
	if status != http.StatusOK {
		t.Fatalf("bascule closed: status=%d body=%s", status, data)
	}
	var mr ModeResponse
	if err := json.Unmarshal(data, &mr); err != nil || mr.Mode != "closed" {
		t.Fatalf("mode=%q err=%v", mr.Mode, err)
	}

	// Allow : toujours forwardé en closed.
	out := evaluate(t, f, mintToken(t, nominalClaims()))
	if !out.Allow || !out.Forwarded {
		t.Fatalf("allow non forwardé en closed: %+v", out)
	}

	// Deny : BLOQUÉ en closed.
	claims := nominalClaims()
	j := jtiOf(0x41)
	claims.jti = j[:]
	claims.action = "write.delete"
	out = evaluate(t, f, mintToken(t, claims))
	if out.Allow || out.Forwarded {
		t.Fatalf("deny forwardé en closed: %+v", out)
	}
	if out.Mode != "closed" {
		t.Fatalf("mode=%q", out.Mode)
	}
	st := f.l.Stats()
	if st.Denied != 1 || st.WouldDeny != 0 {
		t.Fatalf("stats=%+v, veut Denied=1", st)
	}
}

// ---------------------------------------------------------------------------
// Portillon T14 : une condition basculée refuse en closed… et reste
// « log seulement » en monitor (le refus est journalisé, pas appliqué).
// ---------------------------------------------------------------------------

func TestListenerGateTripMonitorVsClosed(t *testing.T) {
	f := newListenerFixture(t, false)
	if err := f.fc.Register(ReasonOPAUnreachable, ClassI); err != nil {
		t.Fatalf("Register: %v", err)
	}
	f.fc.Trip(ReasonOPAUnreachable, "sidecar down")

	// Monitor : le refus du portillon est journalisé, pas appliqué.
	out := evaluate(t, f, mintToken(t, nominalClaims()))
	if out.Allow || out.Reason != ReasonOPAUnreachable {
		t.Fatalf("verdict=%+v, veut deny %s", out, ReasonOPAUnreachable)
	}
	if !out.Forwarded {
		t.Fatal("monitor a appliqué le refus du portillon (log only attendu)")
	}

	// Closed : le refus du portillon bloque.
	if err := f.mc.SetMode(ModeClosed, QuorumProof{Signatures: []QuorumSignature{{KeyID: [16]byte{1}}}}); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	claims := nominalClaims()
	j := jtiOf(0x42)
	claims.jti = j[:]
	out = evaluate(t, f, mintToken(t, claims))
	if out.Allow || out.Forwarded {
		t.Fatalf("closed n'a pas appliqué le refus du portillon: %+v", out)
	}
	if out.Reason != ReasonOPAUnreachable {
		t.Fatalf("raison=%q, veut %q", out.Reason, ReasonOPAUnreachable)
	}
}

// ---------------------------------------------------------------------------
// Passeport de quota (§4.1-bis) : ouvert à l'allow, décrémenté via
// l'endpoint d'exécution ; dépassement ⇒ coupure nette + refus tracé ;
// le jeton suivant (même jti) est refusé quota-exhausted AVANT le rejeu.
// ---------------------------------------------------------------------------

func quotaClaims(volumeMax, windowS uint64) testClaims {
	claims := nominalClaims()
	claims.quota = map[int]any{1: "storage.artifacts", 2: "append", 3: volumeMax, 4: windowS}
	return claims
}

// consume présente le JETON signé (revue de sécurité #90, point 3 : le
// jti n'est plus déclaré nu — il est extrait du jeton après vérification
// de possession) et décrémente le passeport de son jti.
func consume(t *testing.T, f *listenerFixture, tok []byte, n uint64) (int, ConsumeResponse) {
	t.Helper()
	body, _ := json.Marshal(ConsumeRequest{Token: base64.StdEncoding.EncodeToString(tok), N: n})
	status, data := postJSON(t, f.srv.URL+"/v1/passport/consume", body)
	var out ConsumeResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, data)
	}
	return status, out
}

func TestListenerPassportFlow(t *testing.T) {
	f := newListenerFixture(t, true)
	tok := mintToken(t, quotaClaims(100, 60))

	out := evaluate(t, f, tok)
	if !out.Allow || !out.PassportOpened {
		t.Fatalf("verdict=%+v, veut allow + passeport ouvert", out)
	}

	// Décrément à l'exécution : 100 puis dépassement net.
	status, c := consume(t, f, tok, 100)
	if status != http.StatusOK || !c.OK || c.Remaining != 0 {
		t.Fatalf("consume(100): status=%d %+v", status, c)
	}
	_, c = consume(t, f, tok, 1)
	if c.OK || c.Err != ReasonQuotaExceeded || !c.Closed {
		t.Fatalf("consume(1) au-delà: %+v, veut coupure nette %s", c, ReasonQuotaExceeded)
	}

	// §8 : le jeton suivant portant ce jti est refusé quota-exhausted
	// AVANT le verdict de rejeu (étape quota avant anti-rejeu, T9).
	out = evaluate(t, f, tok)
	if out.Allow || out.Reason != ReasonQuotaExhausted {
		t.Fatalf("verdict=%+v, veut deny %s", out, ReasonQuotaExhausted)
	}
}

func TestListenerConsumeUnknownPassport(t *testing.T) {
	f := newListenerFixture(t, true)
	// Jeton valide (preuve de possession admise) mais dont le jti n'a
	// JAMAIS ouvert de compteur — distinct du témoin de possession refusée
	// (TestListenerConsumeForgedProofRejected, ci-dessous).
	claims := nominalClaims()
	j := jtiOf(0x99)
	claims.jti = j[:]
	tok := mintToken(t, claims)
	_, c := consume(t, f, tok, 1)
	if c.OK || c.Err == "" {
		t.Fatalf("consume passeport inconnu: %+v, veut erreur", c)
	}
}

// TestListenerConsumeForgedProofRejected : revue de sécurité #90, point 3
// — présenter un jti nu (ancien format), ou n'importe quel octet ne
// formant pas un jeton signé valide, est refusé AVANT même de chercher un
// compteur. C'est exactement l'attaque qu'un attaquant ayant seulement
// observé ou deviné le jti d'un AUTRE agent aurait pu monter sous l'ancien
// contrat (déni de service coopératif sur son passeport).
func TestListenerConsumeForgedProofRejected(t *testing.T) {
	f := newListenerFixture(t, true)

	// Attaque historique exacte : jti nu, aucun jeton signé présenté.
	legacyBody, _ := json.Marshal(map[string]any{"jti": hex.EncodeToString(testJTI[:]), "n": 1})
	status, data := postJSON(t, f.srv.URL+"/v1/passport/consume", legacyBody)
	var legacy ConsumeResponse
	_ = json.Unmarshal(data, &legacy)
	if status != http.StatusForbidden {
		t.Fatalf("jti nu (attaque #90.3 historique) : status=%d, veut 403 (aucun champ token ⇒ preuve de possession vide)", status)
	}

	// Octets aléatoires en Token : pas un COSE_Sign1 valide — possession
	// refusée AVANT toute recherche de compteur (aucun jti n'est même
	// extrait), exactement le contrôle qui manquait §90.3.
	status, out := consume(t, f, []byte("pas-un-jeton-cose-sign1"), 1)
	if status != http.StatusForbidden || out.OK {
		t.Fatalf("token forgé : status=%d out=%+v, veut 403", status, out)
	}
}

// TestListenerQuotaSaturationTracesDeny : le validateur (T9) écrit sa
// feuille allow AVANT que l'ouverture du passeport (T12) échoue par
// saturation du registre — sans feuille supplémentaire, le refus
// réellement rendu à l'appelant ne laisserait AUCUNE trace au registre
// (seule la feuille allow, déjà obsolète, resterait). §4.1 : chaque
// décision — allow comme deny — doit porter une feuille correspondant au
// verdict réel.
func TestListenerQuotaSaturationTracesDeny(t *testing.T) {
	f := newListenerFixture(t, true) // MaxPassports: 64

	for i := 0; i < 64; i++ {
		dummy := passportToken(jtiNum(9000+i), testIAT+3600, 100, 60)
		if _, err := f.ledger.Open(dummy); err != nil {
			t.Fatalf("dummy Open #%d: %v", i, err)
		}
	}

	leavesBefore := f.sink.count()
	tok := mintToken(t, quotaClaims(100, 60))
	out := evaluate(t, f, tok)

	if out.Allow || out.Reason != TripReasonQuotaSaturated {
		t.Fatalf("verdict=%+v, veut deny %s (registre de quotas saturé à l'admission)", out, TripReasonQuotaSaturated)
	}

	wantHash := registry.HashPayload(testSalt, decisionLeafRecord(testJTI, false, TripReasonQuotaSaturated))
	found := false
	for _, leaf := range f.sink.leaves[leavesBefore:] {
		if leaf.PayloadHash == wantHash {
			found = true
		}
	}
	if !found {
		t.Fatalf("aucune feuille deny pour le verdict réel (%s) — seule la feuille allow du validateur, déjà obsolète, est au registre", TripReasonQuotaSaturated)
	}
}

// ---------------------------------------------------------------------------
// Arbitrage OPA (T11) après validation : deny OPA ⇒ verdict deny.
// ---------------------------------------------------------------------------

func TestListenerOPAConsulted(t *testing.T) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"allow":false}}`)
	}))
	defer opaSrv.Close()

	f := newListenerFixture(t, false)
	sink := &stubSink{}
	opa, err := NewOPAClient(OPAOptions{
		Endpoint: opaSrv.URL,
		Timeout:  2 * time.Second, // voir TestOPAConcurrent : 5 ms sous -race
		CellID:   opaTestCellID,
		Salt:     testSalt,
		Leaves:   sink,
	})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	l, err := NewListener(ListenerOptions{Validator: f.l.validator, Mode: f.mc, OPA: opa})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	srv := httptest.NewServer(l.Handler())
	defer srv.Close()

	status, data := postJSON(t, srv.URL+"/v1/evaluate", evalBody(t, mintToken(t, nominalClaims())))
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	var out EvaluateResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Allow || out.Reason != ReasonOPADeny {
		t.Fatalf("verdict=%+v, veut deny %s (OPA consulté après validation)", out, ReasonOPADeny)
	}
	if !out.Forwarded {
		t.Fatal("monitor a bloqué (log only)")
	}
}

// ---------------------------------------------------------------------------
// Requêtes mal formées : 400/405, AUCUNE feuille (pas de décision rendue).
// ---------------------------------------------------------------------------

func TestListenerBadRequests(t *testing.T) {
	f := newListenerFixture(t, false)
	leaves := f.sink.count()

	if status, _ := postJSON(t, f.srv.URL+"/v1/evaluate", []byte("pas du json")); status != http.StatusBadRequest {
		t.Fatalf("json cassé: status=%d, veut 400", status)
	}
	body, _ := json.Marshal(EvaluateRequest{Token: "!!!pas-base64!!!", Action: "a", Resource: "r"})
	if status, _ := postJSON(t, f.srv.URL+"/v1/evaluate", body); status != http.StatusBadRequest {
		t.Fatalf("base64 cassé: status=%d, veut 400", status)
	}
	resp, err := http.Get(f.srv.URL + "/v1/evaluate")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET evaluate: status=%d, veut 405", resp.StatusCode)
	}
	if f.sink.count() != leaves {
		t.Fatalf("feuilles=%d, veut %d (aucune décision sur requête mal formée)", f.sink.count(), leaves)
	}
}

// ---------------------------------------------------------------------------
// Endpoint mode : GET rapporte ; POST exige un quorum valide (403 sinon).
// ---------------------------------------------------------------------------

func TestListenerModeEndpoint(t *testing.T) {
	f := newListenerFixture(t, false)

	resp, err := http.Get(f.adminSrv.URL + "/v1/mode")
	if err != nil {
		t.Fatalf("GET mode: %v", err)
	}
	var mr ModeResponse
	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if mr.Mode != "monitor" {
		t.Fatalf("mode=%q, veut monitor (défaut §5.3)", mr.Mode)
	}

	// POST avec preuve rejetée par le vérifieur ⇒ 403, toujours monitor.
	f.mc.SetQuorumVerifier(rejectQuorum)
	body, _ := json.Marshal(ModeChangeRequest{Mode: "closed"})
	status, _ := postJSON(t, f.adminSrv.URL+"/v1/mode", body)
	if status != http.StatusForbidden {
		t.Fatalf("bascule sans quorum: status=%d, veut 403", status)
	}
	if f.mc.Mode() != ModeMonitor {
		t.Fatal("mode basculé malgré le 403")
	}

	// POST mode inconnu ⇒ 400.
	body, _ = json.Marshal(ModeChangeRequest{Mode: "ouvert"})
	if status, _ := postJSON(t, f.adminSrv.URL+"/v1/mode", body); status != http.StatusBadRequest {
		t.Fatalf("mode inconnu: status=%d, veut 400", status)
	}
}

// ---------------------------------------------------------------------------
// Healthz : état du listener + statistiques de latence (§9.1 : mesurée dès
// le premier prototype).
// ---------------------------------------------------------------------------

func TestListenerHealthzAndLatencyStats(t *testing.T) {
	f := newListenerFixture(t, false)
	for i := 0; i < 4; i++ {
		claims := nominalClaims()
		j := jtiOf(byte(0x50 + i))
		claims.jti = j[:]
		evaluate(t, f, mintToken(t, claims))
	}

	resp, err := http.Get(f.adminSrv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET healthz: %v", err)
	}
	var hz struct {
		Status string        `json:"status"`
		Mode   string        `json:"mode"`
		Stats  ListenerStats `json:"stats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hz); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp.Body.Close()
	if hz.Status != "ok" || hz.Mode != "monitor" {
		t.Fatalf("healthz=%+v", hz)
	}
	if hz.Stats.Evaluations != 4 || hz.Stats.Forwarded != 4 {
		t.Fatalf("stats=%+v", hz.Stats)
	}
	if hz.Stats.MaxElapsedUs < 0 || hz.Stats.TotalElapsedUs < hz.Stats.MaxElapsedUs {
		t.Fatalf("latence: %+v (§9.1 : mesurée dès le prototype)", hz.Stats)
	}
}

// ---------------------------------------------------------------------------
// Séparation plan de données / plan d'administration (revue de sécurité
// #95, finding A10) : preuve POSITIVE de la scission — pas seulement que
// les bons appels fonctionnent, mais que les MAUVAIS échouent.
// ---------------------------------------------------------------------------

func TestListenerPlaneSeparation(t *testing.T) {
	f := newListenerFixture(t, false)

	// /v1/mode et /healthz sont ABSENTES du plan de données.
	resp, err := http.Get(f.srv.URL + "/v1/mode")
	if err != nil {
		t.Fatalf("GET mode sur plan de données: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /v1/mode sur le plan de DONNÉES: statut %d, attendu 404", resp.StatusCode)
	}
	resp, err = http.Get(f.srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET healthz sur plan de données: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /healthz sur le plan de DONNÉES: statut %d, attendu 404", resp.StatusCode)
	}

	// /v1/evaluate et /v1/passport/consume sont ABSENTES du plan
	// d'administration.
	status, _ := postJSON(t, f.adminSrv.URL+"/v1/evaluate", evalBody(t, mintToken(t, nominalClaims())))
	if status != http.StatusNotFound {
		t.Fatalf("POST /v1/evaluate sur le plan d'ADMINISTRATION: statut %d, attendu 404", status)
	}
	status, _ = postJSON(t, f.adminSrv.URL+"/v1/passport/consume", []byte(`{}`))
	if status != http.StatusNotFound {
		t.Fatalf("POST /v1/passport/consume sur le plan d'ADMINISTRATION: statut %d, attendu 404", status)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed dès la configuration + concurrence.
// ---------------------------------------------------------------------------

func TestNewListenerFailClosed(t *testing.T) {
	f := newListenerFixture(t, false)
	if _, err := NewListener(ListenerOptions{Mode: f.mc}); err == nil {
		t.Fatal("listener sans validateur accepté")
	}
	if _, err := NewListener(ListenerOptions{Validator: f.l.validator}); err == nil {
		t.Fatal("listener sans contrôleur de mode accepté (doctrine §5.3)")
	}
}

func TestListenerConcurrent(t *testing.T) {
	f := newListenerFixture(t, false)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 8; i++ {
				claims := nominalClaims()
				j := jtiOf(byte(g))
				j[1] = byte(i)
				claims.jti = j[:]
				body := evalBody(t, mintToken(t, claims))
				resp, err := http.Post(f.srv.URL+"/v1/evaluate", "application/json", bytes.NewReader(body))
				if err != nil {
					t.Errorf("POST: %v", err)
					return
				}
				resp.Body.Close()
			}
		}(g)
	}
	wg.Wait()
	if st := f.l.Stats(); st.Evaluations != 32*8 {
		t.Fatalf("évaluations=%d, veut %d", st.Evaluations, 32*8)
	}
}
