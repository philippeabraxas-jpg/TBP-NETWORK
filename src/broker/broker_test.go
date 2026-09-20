package broker

// Tests du broker T33. Doctrine : chaque chemin de la chaîne est exercé,
// et le test croisé (TestIssueValidateRoundTrip) fait valider les jetons
// émis par le validateur T9 — un seul format, vérifié des deux côtés.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Seams de test
// ---------------------------------------------------------------------------

// testSeed : clé de test n° 1 du RFC 8032 §7.1 (publique par construction,
// aucune valeur de production — comme dans schema.md §9).
var testSeed, _ = hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

var testSalt = []byte("t33-test-salt-0123456789abcdef")

var testPolicyID [32]byte // zéros — comme le vecteur de schema.md §9

type leafRecorder struct {
	mu     sync.Mutex
	leaves []registry.Leaf
	err    error

	// calls/failFromCall isolent une écriture précise (p.ex. la 2e — la
	// feuille d'émission du broker — après la 1re qui réussit, la feuille
	// OPA de T11) sans casser err (utilisé ailleurs pour un échec
	// inconditionnel dès le premier appel).
	calls        int
	failFromCall int   // 0 = désactivé ; sinon échoue à partir de cet appel (1-based)
	failErr      error // erreur rendue une fois failFromCall atteint
}

func (r *leafRecorder) Append(_ context.Context, l registry.Leaf) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return 0, r.err
	}
	if r.failFromCall > 0 && r.calls >= r.failFromCall {
		if r.failErr != nil {
			return 0, r.failErr
		}
		return 0, errors.New("leafRecorder: échec simulé (failFromCall)")
	}
	r.leaves = append(r.leaves, l)
	return uint64(len(r.leaves)), nil
}

func (r *leafRecorder) all() []registry.Leaf {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]registry.Leaf(nil), r.leaves...)
}

type tripRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (r *tripRecorder) trip(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
}

func (r *tripRecorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.reasons...)
}

// staticTranslator renvoie une traduction fixe (ou une erreur) — la couture
// Translator sans modèle.
type staticTranslator struct {
	tr  Translation
	err error
}

func (s staticTranslator) Translate(_ context.Context, _, _ string) (Translation, error) {
	return s.tr, s.err
}

// failSigner signe toujours en erreur — faute HSM simulée.
type failSigner struct {
	pub ed25519.PublicKey
}

func (s failSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("HSM simulé injoignable")
}

func (s failSigner) Public() ed25519.PublicKey { return s.pub }

// opaServer simule un sidecar OPA : allow selon allowFn, délai selon delay.
func opaServer(t *testing.T, allowFn func(input map[string]any) bool, delay time.Duration) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delay > 0 {
			time.Sleep(delay)
		}
		var body struct {
			Input map[string]any `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		allow := allowFn(body.Input)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"result":{"allow":%v}}`, allow)
	}))
}

// newTestBroker assemble un broker complet de test : OPA contre le serveur
// fourni, traducteur fixe, émetteur dev, époque fixe. Renvoie le broker,
// l'émetteur, le signataire, le registre de feuilles et l'enregistreur
// d'alarmes.
func newTestBroker(t *testing.T, opaURL string, tr Translator) (*Broker, *Issuer, *leafRecorder, *tripRecorder) {
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
		Timeout:  500 * time.Millisecond, // test : marge honnête, le circuit-breaker 5 ms est le défaut de prod
		CellID:   "tbp/registry/cell-test-01",
		Salt:     testSalt,
		Leaves:   leaves,
		OnTrip:   trips.trip,
	})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	b, err := NewBroker(BrokerOptions{
		CellID:     "tbp/registry/cell-test-01",
		Salt:       testSalt,
		Leaves:     leaves,
		OPA:        opa,
		Translator: tr,
		Issuer:     issuer,
		Epochs:     StaticEpoch(7),
		OnTrip:     trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}
	return b, issuer, leaves, trips
}

// newTestValidator assemble le validateur T9 du MÊME troussseau/policyID
// que l'émetteur de test — le test croisé.
func newTestValidator(t *testing.T, issuer *Issuer, signer *DevSigner, leaves *leafRecorder, quota pep.QuotaChecker) *pep.Validator {
	t.Helper()
	ar, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 1024})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	v, err := pep.NewValidator(pep.ValidatorOptions{
		CellID: "tbp/registry/cell-test-01",
		Keyring: map[[16]byte]ed25519.PublicKey{
			issuer.KeyID(): signer.Public(),
		},
		PolicyID:   testPolicyID,
		Salt:       testSalt,
		Leaves:     leaves,
		AntiReplay: ar,
		Quota:      quota,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// simpleIntent est une demande structurée minimale (action + resource).
func simpleIntent(action, resource string) string {
	return fmt.Sprintf(`{"action":%q,"resource":%q}`, action, resource)
}

// passportIntent est une demande structurée avec passeport (§4.1-bis).
func passportIntent(resource string, volumeMax, windowS uint64) string {
	return fmt.Sprintf(`{"action":"http.send","resource":%[1]q,"quota":{"resource":%[1]q,"operation":"POST","volume_max":%[2]d,"window_s":%[3]d}}`, resource, volumeMax, windowS)
}

// ---------------------------------------------------------------------------
// Configuration fail-closed
// ---------------------------------------------------------------------------

func TestBrokerOptionsFailClosed(t *testing.T) {
	signer, _ := NewDevSigner(testSeed)
	issuer, err := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	leaves := &leafRecorder{}
	opa, err := pep.NewOPAClient(pep.OPAOptions{Endpoint: srv.URL, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	env, err := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPEnvelopeEvaluator: %v", err)
	}
	ledger, err := NewEnvelopeLedger(16, nil)
	if err != nil {
		t.Fatalf("NewEnvelopeLedger: %v", err)
	}
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}

	full := BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: tr, Issuer: issuer, Epochs: StaticEpoch(1),
		Envelope: env, Ledger: ledger,
	}
	if _, err := NewBroker(full); err != nil {
		t.Fatalf("config complète refusée : %v", err)
	}

	cases := map[string]func(o *BrokerOptions){
		"cellID vide":           func(o *BrokerOptions) { o.CellID = "" },
		"sel court":             func(o *BrokerOptions) { o.Salt = []byte("court") },
		"feuilles absentes":     func(o *BrokerOptions) { o.Leaves = nil },
		"OPA absent":            func(o *BrokerOptions) { o.OPA = nil },
		"traducteur absent":     func(o *BrokerOptions) { o.Translator = nil },
		"émetteur absent":       func(o *BrokerOptions) { o.Issuer = nil },
		"époques absentes":      func(o *BrokerOptions) { o.Epochs = nil },
		"enveloppe sans ledger": func(o *BrokerOptions) { o.Ledger = nil },
		"ledger sans enveloppe": func(o *BrokerOptions) { o.Envelope = nil },
	}
	for name, mutate := range cases {
		opts := full
		mutate(&opts)
		if _, err := NewBroker(opts); err == nil {
			t.Fatalf("%s : configuration acceptée, fail-closed attendu", name)
		}
	}
}

func TestIssuerOptionsFailClosed(t *testing.T) {
	signer, _ := NewDevSigner(testSeed)
	if _, err := NewIssuer(IssuerOptions{Signer: signer, PolicyID: testPolicyID}); err == nil {
		t.Fatal("cellID vide accepté")
	}
	if _, err := NewIssuer(IssuerOptions{CellID: "c", PolicyID: testPolicyID}); err == nil {
		t.Fatal("signataire absent accepté")
	}
	for _, ttl := range []int64{-1, 1, 29, 61, 3600} {
		if _, err := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID, TTLSec: ttl}); err == nil {
			t.Fatalf("TTL %d accepté — bornes [30,60] (§4.1)", ttl)
		}
	}
	for _, ttl := range []int64{0, 30, 45, 60} {
		if _, err := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID, TTLSec: ttl}); err != nil {
			t.Fatalf("TTL %d refusé : %v", ttl, err)
		}
	}
	if _, err := NewDevSigner([]byte("trop-court")); err == nil {
		t.Fatal("seed de mauvaise taille acceptée")
	}
	if _, err := NewEnvelopeLedger(0, nil); err == nil {
		t.Fatal("ledger d'enveloppe capacité 0 accepté")
	}
	if _, err := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{}); err == nil {
		t.Fatal("endpoint d'enveloppe vide accepté")
	}
	if _, err := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: "http://x", Timeout: -time.Second}); err == nil {
		t.Fatal("timeout d'enveloppe négatif accepté")
	}
	if _, err := NewServer(ServerOptions{}); err == nil {
		t.Fatal("serveur sans broker accepté")
	}
}

// ---------------------------------------------------------------------------
// Chemin nominal + test croisé avec le validateur T9
// ---------------------------------------------------------------------------

func TestIssueValidateRoundTrip(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "http.send", Resource: "https://api.example.com/v1/messages"}}
	b, issuer, leaves, _ := newTestBroker(t, srv.URL, tr)

	res := b.HandleAction(context.Background(), "spiffe://tbp.example/agent/test", simpleIntent("http.send", "https://api.example.com/v1/messages"))
	if !res.Allow || res.Reason != pep.ReasonOK {
		t.Fatalf("allow=%v reason=%q, veut allow/ok", res.Allow, res.Reason)
	}
	if len(res.Token) == 0 || len(res.Token) > 1024 {
		t.Fatalf("jeton fil de %d octets — bornes (0, 1024]", len(res.Token))
	}
	if !res.LeafWritten {
		t.Fatal("feuille de décision OPA non écrite (T11)")
	}

	// Test croisé : le validateur T9 accepte le jeton émis, avec les MÊMES
	// action/ressource/époque — un seul format, vérifié des deux côtés.
	signer, _ := NewDevSigner(testSeed)
	v := newTestValidator(t, issuer, signer, leaves, nil)
	d := v.Validate(context.Background(), res.Token, pep.Request{
		Action:   "http.send",
		Resource: "https://api.example.com/v1/messages",
		Epoch:    7,
	})
	if !d.Allow {
		t.Fatalf("T9 refuse le jeton du broker : %q — le format n'est pas partagé", d.Reason)
	}
	if d.Token == nil || d.Token.JTI != res.JTI {
		t.Fatal("jti du jeton ≠ jti de la décision (§4.3)")
	}
	if d.Token.Class != pep.ClassW {
		t.Fatalf("claim −4 absent ⇒ classe %v, veut W (défaut fail-closed §5.3)", d.Token.Class)
	}
	if d.Token.Iss != "tbp/registry/cell-test-01" || d.Token.Sub != "spiffe://tbp.example/agent/test" {
		t.Fatal("claims iss/sub mal émises")
	}
	if ttl := d.Token.Exp - d.Token.Iat; ttl != 45 {
		t.Fatalf("TTL %d s, veut 45 (défaut dans [30,60], §4.1)", ttl)
	}

	// Le rejeu du même jeton est refusé par T9 (§4.3).
	d2 := v.Validate(context.Background(), res.Token, pep.Request{
		Action:   "http.send",
		Resource: "https://api.example.com/v1/messages",
		Epoch:    7,
	})
	if d2.Allow || d2.Reason != pep.ReasonReplay {
		t.Fatalf("rejeu : allow=%v reason=%q, veut deny/replay", d2.Allow, d2.Reason)
	}
}

func TestPassportOpensQuotaCounter(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	signer, _ := NewDevSigner(testSeed)
	issuer, err := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	opa, err := pep.NewOPAClient(pep.OPAOptions{Endpoint: srv.URL, Timeout: 500 * time.Millisecond, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	env, err := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: srv.URL, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewHTTPEnvelopeEvaluator: %v", err)
	}
	ledger, err := NewEnvelopeLedger(16, trips.trip)
	if err != nil {
		t.Fatalf("NewEnvelopeLedger: %v", err)
	}
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: issuer, Epochs: StaticEpoch(7),
		Envelope: env, Ledger: ledger, OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://api.example.com/v1/messages", 1<<20, 60))
	if !res.Allow {
		t.Fatalf("passeport refusé : %q", res.Reason)
	}

	// Le passeport émis ouvre un compteur T12 — le vecteur quota signé est
	// exploitable par l'exécution sans re-décodage ad hoc.
	ql, err := pep.NewQuotaLedger(pep.QuotaLedgerOptions{MaxPassports: 16, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewQuotaLedger: %v", err)
	}
	v, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:     "c",
		Keyring:    map[[16]byte]ed25519.PublicKey{issuer.KeyID(): signer.Public()},
		PolicyID:   testPolicyID,
		Salt:       testSalt,
		Leaves:     leaves,
		AntiReplay: mustAntiReplay(t),
		Quota:      ql,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	d := v.Validate(context.Background(), res.Token, pep.Request{
		Action:   "http.send",
		Resource: "https://api.example.com/v1/messages",
		Epoch:    7,
	})
	if !d.Allow {
		t.Fatalf("T9 refuse le passeport : %q", d.Reason)
	}
	counter, err := ql.Open(d.Token)
	if err != nil {
		t.Fatalf("QuotaLedger.Open : %v", err)
	}
	if err := counter.Consume(1 << 10); err != nil {
		t.Fatalf("Consume : %v", err)
	}
	if counter.Remaining() != (1<<20)-(1<<10) {
		t.Fatalf("remaining=%d, veut %d", counter.Remaining(), (1<<20)-(1<<10))
	}

	// L'agrégat d'enveloppe a été réservé à l'émission (§4.1-bis).
	if got := ledger.Aggregate("agent-1", 7); got != 1<<20 {
		t.Fatalf("agrégat d'enveloppe=%d, veut %d", got, 1<<20)
	}
}

func mustAntiReplay(t *testing.T) *pep.AntiReplay {
	t.Helper()
	ar, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 1024})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	return ar
}

// ---------------------------------------------------------------------------
// Fail-closed à chaque étape
// ---------------------------------------------------------------------------

func TestRequestInvalidDenies(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, leaves, _ := newTestBroker(t, srv.URL, tr)

	for name, tc := range map[string]struct{ subject, intent string }{
		"subject vide":      {"", simpleIntent("a", "r")},
		"intent vide":       {"agent-1", ""},
		"intent trop grand": {"agent-1", strings.Repeat("x", maxIntentBytes+1)},
		"subject trop long": {strings.Repeat("s", 256), simpleIntent("a", "r")},
	} {
		res := b.HandleAction(context.Background(), tc.subject, tc.intent)
		if res.Allow || res.Reason != ReasonRequestInvalid {
			t.Fatalf("%s : allow=%v reason=%q, veut deny/%q", name, res.Allow, res.Reason, ReasonRequestInvalid)
		}
	}
	// Chaque refus a laissé SA feuille (§4.1) — avec le jti nul, comme T9
	// pour un jeton mal formé.
	if n := len(leaves.all()); n != 4 {
		t.Fatalf("%d feuilles, veut 4", n)
	}
}

func TestTranslationFailureDenies(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{err: errors.New("je ne sais pas traduire")}
	b, _, leaves, trips := newTestBroker(t, srv.URL, tr)

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
	if res.Allow || res.Reason != ReasonTranslationFailed {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonTranslationFailed)
	}
	if len(trips.all()) != 0 {
		t.Fatalf("alarmes %v — un « je ne sais pas traduire » est un verdict sain (§4.5), pas une faute", trips.all())
	}
	if len(leaves.all()) != 1 {
		t.Fatalf("%d feuilles, veut 1 (le refus est tracé)", len(leaves.all()))
	}
	if got := b.Stats().TranslationFailures; got != 1 {
		t.Fatalf("TranslationFailures=%d, veut 1", got)
	}
}

func TestOPADenyPropagates(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return false }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, leaves, trips := newTestBroker(t, srv.URL, tr)

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
	if res.Allow || res.Reason != pep.ReasonOPADeny {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, pep.ReasonOPADeny)
	}
	if len(res.Token) != 0 {
		t.Fatal("un deny OPA ne doit JAMAIS produire de jeton")
	}
	if len(trips.all()) != 0 {
		t.Fatalf("alarmes %v — un deny métier d'un OPA sain n'alarme pas (T11)", trips.all())
	}
	// Une seule feuille : celle du client T11 (le broker n'en ajoute pas
	// une seconde au même stade).
	if len(leaves.all()) != 1 {
		t.Fatalf("%d feuilles, veut 1", len(leaves.all()))
	}
}

func TestOPAUnreachableDeniesWithAlarm(t *testing.T) {
	// Port fermé : personne n'écoute.
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	url := srv.URL
	srv.Close()

	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, _, trips := newTestBroker(t, url, tr)

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
	if res.Allow || res.Reason != pep.ReasonOPAUnreachable {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, pep.ReasonOPAUnreachable)
	}
	if len(trips.all()) != 1 || trips.all()[0] != pep.ReasonOPAUnreachable {
		t.Fatalf("alarmes %v, veut [%q] — une faute OPA alarme (T14)", trips.all(), pep.ReasonOPAUnreachable)
	}
}

func TestSigningFailureDenies(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	// Émetteur dont le signataire faute (HSM simulé injoignable).
	good, _ := NewDevSigner(testSeed)
	issuer, err := NewIssuer(IssuerOptions{CellID: "c", Signer: failSigner{pub: good.Public()}, PolicyID: testPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	opa, err := pep.NewOPAClient(pep.OPAOptions{Endpoint: srv.URL, Timeout: 500 * time.Millisecond, CellID: "c", Salt: testSalt, Leaves: leaves})
	if err != nil {
		t.Fatalf("NewOPAClient: %v", err)
	}
	env, _ := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: srv.URL, Timeout: 500 * time.Millisecond})
	ledger, _ := NewEnvelopeLedger(16, trips.trip)
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: issuer, Epochs: StaticEpoch(7),
		Envelope: env, Ledger: ledger, OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	// Passeport : la réservation d'enveloppe doit être LIBÉRÉE après
	// l'échec de signature — jamais de volume fantôme.
	res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1<<20, 60))
	if res.Allow || res.Reason != ReasonIssuanceFailed {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonIssuanceFailed)
	}
	if len(res.Token) != 0 {
		t.Fatal("émission partielle : un jeton ne doit JAMAIS exister après un échec de signature")
	}
	if len(trips.all()) == 0 || trips.all()[0] != ReasonIssuanceFailed {
		t.Fatalf("alarmes %v, veut [%q] en tête", trips.all(), ReasonIssuanceFailed)
	}
	if got := ledger.Aggregate("agent-1", 7); got != 0 {
		t.Fatalf("agrégat=%d après échec, veut 0 (réservation libérée)", got)
	}
	if got := b.Stats().IssuanceFailures; got != 1 {
		t.Fatalf("IssuanceFailures=%d, veut 1", got)
	}
}

// ---------------------------------------------------------------------------
// Enveloppe d'émission (§4.1-bis)
// ---------------------------------------------------------------------------

func TestEnvelopeExceededDenies(t *testing.T) {
	// Règle d'enveloppe : allow tant que l'agrégat (incluant la demande et
	// les demandes en vol) ≤ 3000 octets — la DÉCISION est chez OPA, le
	// ledger ne fait que compter.
	const envelopeMax = 3000
	allowFn := func(in map[string]any) bool {
		issued, _ := in["issued"].(float64)
		return issued <= envelopeMax
	}
	decisionSrv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer decisionSrv.Close()
	envelopeSrv := opaServer(t, allowFn, 0)
	defer envelopeSrv.Close()

	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	signer, _ := NewDevSigner(testSeed)
	issuer, _ := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	opa, _ := pep.NewOPAClient(pep.OPAOptions{Endpoint: decisionSrv.URL, Timeout: 500 * time.Millisecond, CellID: "c", Salt: testSalt, Leaves: leaves})
	env, _ := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: envelopeSrv.URL, Timeout: 500 * time.Millisecond})
	ledger, _ := NewEnvelopeLedger(16, trips.trip)
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: issuer, Epochs: StaticEpoch(7),
		Envelope: env, Ledger: ledger, OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	// 3 passeports de 1000 : agrégats 1000, 2000, 3000 — tous allow.
	for i := 1; i <= 3; i++ {
		res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1000, 60))
		if !res.Allow {
			t.Fatalf("passeport %d refusé : %q", i, res.Reason)
		}
	}
	// Le 4ᵉ porterait l'agrégat à 4000 > 3000 : refus À L'ÉMISSION —
	// l'agrégation de passeports individuellement légitimes est fermée.
	res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1000, 60))
	if res.Allow || res.Reason != ReasonEnvelopeDeny {
		t.Fatalf("4ᵉ passeport : allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonEnvelopeDeny)
	}
	if len(res.Token) != 0 {
		t.Fatal("un refus d'enveloppe ne doit JAMAIS produire de passeport")
	}
	// La réservation refusée est libérée : l'agrégat reste à 3000.
	if got := ledger.Aggregate("agent-1", 7); got != envelopeMax {
		t.Fatalf("agrégat=%d, veut %d", got, envelopeMax)
	}
	// Pas d'alarme : l'enveloppe pleine est un verdict sain.
	if len(trips.all()) != 0 {
		t.Fatalf("alarmes %v — un deny d'enveloppe n'alarme pas", trips.all())
	}
	if got := b.Stats().EnvelopeDenies; got != 1 {
		t.Fatalf("EnvelopeDenies=%d, veut 1", got)
	}
}

func TestEnvelopeUnverifiedWithoutConfig(t *testing.T) {
	// Broker SANS enveloppe configurée : toute demande de passeport est
	// refusée (envelope-unverified — même doctrine que quota-unverified T9).
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	b, _, _, _ := newTestBroker(t, srv.URL, StructuredTranslator{})

	res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1000, 60))
	if res.Allow || res.Reason != ReasonEnvelopeUnverified {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonEnvelopeUnverified)
	}
	// Les actions simples (sans passeport) continuent de passer.
	res2 := b.HandleAction(context.Background(), "agent-1", simpleIntent("http.get", "https://x"))
	if !res2.Allow {
		t.Fatalf("action simple refusée : %q", res2.Reason)
	}
}

func TestEnvelopeSaturationTrips(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	signer, _ := NewDevSigner(testSeed)
	issuer, _ := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	opa, _ := pep.NewOPAClient(pep.OPAOptions{Endpoint: srv.URL, Timeout: 500 * time.Millisecond, CellID: "c", Salt: testSalt, Leaves: leaves})
	env, _ := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: srv.URL, Timeout: 500 * time.Millisecond})
	ledger, _ := NewEnvelopeLedger(1, trips.trip) // UNE seule entité suivie
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: issuer, Epochs: StaticEpoch(7),
		Envelope: env, Ledger: ledger, OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1000, 60))
	if !res.Allow {
		t.Fatalf("premier passeport refusé : %q", res.Reason)
	}
	// Entité nouvelle, ledger plein : refus fail-closed — jamais
	// d'éviction d'une entité vivante (§4.3).
	res2 := b.HandleAction(context.Background(), "agent-2", passportIntent("https://x", 1000, 60))
	if res2.Allow || res2.Reason != ReasonEnvelopeSaturated {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res2.Allow, res2.Reason, ReasonEnvelopeSaturated)
	}
	// Alarme latchée : une seule fois, même après un second essai.
	b.HandleAction(context.Background(), "agent-3", passportIntent("https://x", 1000, 60))
	reasons := trips.all()
	if len(reasons) != 1 || reasons[0] != TripReasonEnvelopeSaturated {
		t.Fatalf("alarmes %v, veut [%q] latchée une fois", reasons, TripReasonEnvelopeSaturated)
	}
}

func TestEnvelopeFaultDeniesWithAlarm(t *testing.T) {
	decisionSrv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer decisionSrv.Close()
	envelopeSrv := opaServer(t, func(map[string]any) bool { return true }, 0)
	envelopeURL := envelopeSrv.URL
	envelopeSrv.Close() // injoignable

	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	signer, _ := NewDevSigner(testSeed)
	issuer, _ := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	opa, _ := pep.NewOPAClient(pep.OPAOptions{Endpoint: decisionSrv.URL, Timeout: 500 * time.Millisecond, CellID: "c", Salt: testSalt, Leaves: leaves})
	env, _ := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: envelopeURL, Timeout: 500 * time.Millisecond, OnTrip: trips.trip})
	ledger, _ := NewEnvelopeLedger(16, trips.trip)
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: issuer, Epochs: StaticEpoch(7),
		Envelope: env, Ledger: ledger, OnTrip: trips.trip,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	// Enveloppe injoignable = FAUTE : deny + alarme, réservation libérée,
	// jamais de passeport émis sur enveloppe non évaluée (§4.1-bis).
	res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1000, 60))
	if res.Allow || res.Reason != ReasonEnvelopeUnreachable {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, ReasonEnvelopeUnreachable)
	}
	if len(trips.all()) == 0 {
		t.Fatal("une faute d'enveloppe doit alarmer (T14)")
	}
	if got := ledger.Aggregate("agent-1", 7); got != 0 {
		t.Fatalf("agrégat=%d après faute, veut 0 (réservation libérée)", got)
	}
}

// ---------------------------------------------------------------------------
// Époque, déterminisme, concurrence
// ---------------------------------------------------------------------------

func TestEpochChangeRevokes(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, issuer, leaves, _ := newTestBroker(t, srv.URL, tr)

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
	if !res.Allow {
		t.Fatalf("émission refusée : %q", res.Reason)
	}
	signer, _ := NewDevSigner(testSeed)
	v := newTestValidator(t, issuer, signer, leaves, nil)

	// Époque 7 : valide.
	d := v.Validate(context.Background(), res.Token, pep.Request{Action: "a", Resource: "r", Epoch: 7})
	if !d.Allow {
		t.Fatalf("jeton refusé à son époque : %q", d.Reason)
	}

	// Révocation = nouvelle époque (§7.3) : le même jeton à l'époque 8 est
	// mort — avant même le contrôle anti-rejeu.
	ar2 := mustAntiReplay(t)
	v2, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:     "c",
		Keyring:    map[[16]byte]ed25519.PublicKey{issuer.KeyID(): signer.Public()},
		PolicyID:   testPolicyID,
		Salt:       testSalt,
		Leaves:     leaves,
		AntiReplay: ar2,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	d2 := v2.Validate(context.Background(), res.Token, pep.Request{Action: "a", Resource: "r", Epoch: 8})
	if d2.Allow || d2.Reason != pep.ReasonEpochMismatch {
		t.Fatalf("ancienne époque : allow=%v reason=%q, veut deny/%q", d2.Allow, d2.Reason, pep.ReasonEpochMismatch)
	}
}

func TestDeterministicVerdicts(t *testing.T) {
	// §11.3 : K demandes identiques ⇒ K verdicts/raisons identiques. Les
	// jti DIFFÈRENT (tirage aléatoire par construction, schema.md §4) — le
	// déterminisme porte sur les décisions, pas sur les identifiants.
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, _, _ := newTestBroker(t, srv.URL, tr)

	jtis := make(map[[16]byte]struct{})
	for i := 0; i < 32; i++ {
		res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
		if !res.Allow || res.Reason != pep.ReasonOK {
			t.Fatalf("itération %d : allow=%v reason=%q", i, res.Allow, res.Reason)
		}
		if _, dup := jtis[res.JTI]; dup {
			t.Fatalf("itération %d : jti dupliqué (§4.1 : jti unique)", i)
		}
		jtis[res.JTI] = struct{}{}
	}
}

func TestConcurrentBrokerNoOverIssue(t *testing.T) {
	// Course concurrente sur l'enveloppe : 64 demandes de passeport de
	// 1000 octets, règle allow si agrégat ≤ 10000. Jamais plus de 10
	// passeports émis — la réservation pessimiste interdit la sur-émission
	// (le sur-refus, lui, est admis : sens fail-closed).
	const envelopeMax = 10000
	envelopeSrv := opaServer(t, func(in map[string]any) bool {
		issued, _ := in["issued"].(float64)
		return issued <= envelopeMax
	}, 0)
	defer envelopeSrv.Close()
	decisionSrv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer decisionSrv.Close()

	leaves := &leafRecorder{}
	signer, _ := NewDevSigner(testSeed)
	issuer, _ := NewIssuer(IssuerOptions{CellID: "c", Signer: signer, PolicyID: testPolicyID})
	opa, _ := pep.NewOPAClient(pep.OPAOptions{Endpoint: decisionSrv.URL, Timeout: 5 * time.Second, CellID: "c", Salt: testSalt, Leaves: leaves})
	env, _ := NewHTTPEnvelopeEvaluator(HTTPEnvelopeOptions{Endpoint: envelopeSrv.URL, Timeout: 5 * time.Second})
	ledger, _ := NewEnvelopeLedger(64, nil)
	b, err := NewBroker(BrokerOptions{
		CellID: "c", Salt: testSalt, Leaves: leaves, OPA: opa,
		Translator: StructuredTranslator{}, Issuer: issuer, Epochs: StaticEpoch(7),
		Envelope: env, Ledger: ledger,
	})
	if err != nil {
		t.Fatalf("NewBroker: %v", err)
	}

	var allows atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := b.HandleAction(context.Background(), "agent-1", passportIntent("https://x", 1000, 60))
			if res.Allow {
				allows.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allows.Load(); got > envelopeMax/1000 {
		t.Fatalf("%d passeports émis, enveloppe %d/%d = %d max — SUR-ÉMISSION (§4.1-bis)", got, envelopeMax, 1000, envelopeMax/1000)
	}
	if got := ledger.Aggregate("agent-1", 7); got != uint64(allows.Load())*1000 {
		t.Fatalf("agrégat=%d, veut %d (émissions × 1000 — réservations libérées proprement)", got, allows.Load()*1000)
	}
	t.Logf("%d passeports émis sur 64 demandes concurrentes (enveloppe %d)", allows.Load(), envelopeMax)
}

// ---------------------------------------------------------------------------
// Serveur HTTP
// ---------------------------------------------------------------------------

func TestHTTPServerEndToEnd(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, _, _ := newTestBroker(t, srv.URL, tr)
	s, err := NewServer(ServerOptions{Broker: b})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	httpSrv := httptest.NewServer(s.Handler())
	defer httpSrv.Close()

	// Demande bien formée → 200, allow, jeton hex présent.
	body := `{"subject":"agent-1","intent":` + fmt.Sprintf("%q", simpleIntent("a", "r")) + `}`
	resp, err := http.Post(httpSrv.URL+"/v1/actions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST : %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("statut %d, veut 200", resp.StatusCode)
	}
	var out actionResponseJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("décodage : %v", err)
	}
	if !out.Allow || out.Reason != pep.ReasonOK || out.Token == "" || out.JTI == "" {
		t.Fatalf("réponse %+v — allow/token/jti attendus", out)
	}
	if _, err := hex.DecodeString(out.Token); err != nil {
		t.Fatalf("jeton non hex : %v", err)
	}

	// JSON mal formé → 400.
	resp2, err := http.Post(httpSrv.URL+"/v1/actions", "application/json", strings.NewReader("{pas json"))
	if err != nil {
		t.Fatalf("POST 2 : %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("statut %d, veut 400", resp2.StatusCode)
	}

	// Champ de contrebande → 400 (DisallowUnknownFields, fail-closed §1).
	resp3, err := http.Post(httpSrv.URL+"/v1/actions", "application/json", strings.NewReader(`{"subject":"a","intent":"x","backdoor":true}`))
	if err != nil {
		t.Fatalf("POST 3 : %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("statut %d, veut 400 (champ inconnu)", resp3.StatusCode)
	}
}

func TestStructuredTranslatorBounds(t *testing.T) {
	tr := StructuredTranslator{}
	ctx := context.Background()

	// Nominal minimal.
	out, err := tr.Translate(ctx, "agent-1", simpleIntent("http.send", "https://x"))
	if err != nil {
		t.Fatalf("nominal : %v", err)
	}
	if out.Action != "http.send" || out.Resource != "https://x" || out.Class != nil || out.Quota != nil {
		t.Fatalf("traduction %+v inattendue", out)
	}

	// Classe explicite.
	out, err = tr.Translate(ctx, "agent-1", `{"action":"a","resource":"r","class":0}`)
	if err != nil || out.Class == nil || *out.Class != pep.ClassF {
		t.Fatalf("classe F : %+v, %v", out, err)
	}
	// Classe hors bornes → « je ne sais pas traduire ».
	if _, err = tr.Translate(ctx, "agent-1", `{"action":"a","resource":"r","class":4}`); err == nil {
		t.Fatal("classe 4 acceptée")
	}
	// Sceau hex valide / invalide.
	sealHex := strings.Repeat("ab", 32)
	out, err = tr.Translate(ctx, "agent-1", `{"action":"a","resource":"r","object_seal":"`+sealHex+`"}`)
	if err != nil || out.ObjectSeal == nil {
		t.Fatalf("sceau : %+v, %v", out, err)
	}
	if _, err = tr.Translate(ctx, "agent-1", `{"action":"a","resource":"r","object_seal":"zz"}`); err == nil {
		t.Fatal("sceau non hex accepté")
	}
	if _, err = tr.Translate(ctx, "agent-1", `{"action":"a","resource":"r","object_seal":"abcd"}`); err == nil {
		t.Fatal("sceau de 2 octets accepté")
	}
	// Champs requis.
	if _, err = tr.Translate(ctx, "agent-1", `{"resource":"r"}`); err == nil {
		t.Fatal("action absente acceptée")
	}
	if _, err = tr.Translate(ctx, "agent-1", `{"action":"a"}`); err == nil {
		t.Fatal("resource absente acceptée")
	}
	if _, err = tr.Translate(ctx, "agent-1", `pas json`); err == nil {
		t.Fatal("intention non JSON acceptée")
	}
	// Passeport.
	out, err = tr.Translate(ctx, "agent-1", passportIntent("https://x", 1000, 60))
	if err != nil || out.Quota == nil || out.Quota.VolumeMax != 1000 || out.Quota.WindowS != 60 {
		t.Fatalf("passeport : %+v, %v", out, err)
	}
}

// TestLeafFailureFailsClosed vérifie la doctrine « pas de preuve, pas
// d'accès » sur les deux chemins de feuille :
//   - stade OPA (T11) : un allow sans feuille re-bascule en deny
//     leaf-write-failed, sans jeton — l'alarme n'est PAS déclenchée par
//     T11 (contrat documenté du client : LeafErr est rapporté dans la
//     décision, le latch reste l'affaire de T14) ;
//   - stade broker (feuille propre, writeLeaf) : une feuille impossible
//     est une FAUTE système — alarmée (T14) en plus du refus.
func TestLeafFailureFailsClosed(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	// Stade OPA : le registre en panne re-bascule l'allow en deny.
	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, leaves, _ := newTestBroker(t, srv.URL, tr)
	leaves.err = errors.New("disque plein simulé")

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
	if res.Allow || res.Reason != pep.ReasonLeafWriteFailed {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res.Allow, res.Reason, pep.ReasonLeafWriteFailed)
	}
	if len(res.Token) != 0 {
		t.Fatal("jeton émis sans preuve — fail-closed violé")
	}

	// Stade broker : feuille propre impossible → alarme leaf-write-failed.
	tr2 := staticTranslator{err: errors.New("je ne sais pas")}
	b2, _, leaves2, trips2 := newTestBroker(t, srv.URL, tr2)
	leaves2.err = errors.New("disque plein simulé")

	res2 := b2.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))
	if res2.Allow || res2.Reason != ReasonTranslationFailed {
		t.Fatalf("allow=%v reason=%q, veut deny/%q", res2.Allow, res2.Reason, ReasonTranslationFailed)
	}
	if res2.LeafWritten || res2.LeafErr == nil {
		t.Fatal("feuille broker : échec attendu rapporté dans LeafErr")
	}
	found := false
	for _, r := range trips2.all() {
		if r == pep.ReasonLeafWriteFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("alarmes %v — une feuille broker impossible alarme (T14)", trips2.all())
	}
}

// TestIssuanceLeafFailureRevokesAllow vérifie que le chemin ALLOW écrit
// SA PROPRE feuille d'émission (§4.1), distincte de la feuille OPA de
// l'étape 4 : la feuille OPA (T11) ne prouve que l'évaluation de l'action,
// ni l'enveloppe (§4.1-bis, OPAInput ne porte aucun champ quota) ni le
// fait qu'un jeton ait réellement été signé et remis. Le registre laisse
// réussir la 1re écriture (celle d'OPA) et échoue à partir de la 2e (celle
// de l'émission) : si le broker n'attemptait qu'une seule écriture, ce
// test ne verrait qu'un allow avec jeton — exactement le trou trouvé en
// revue de #63 (writeLeaf n'était jamais appelé sur le chemin Allow de
// HandleAction).
func TestIssuanceLeafFailureRevokesAllow(t *testing.T) {
	srv := opaServer(t, func(map[string]any) bool { return true }, 0)
	defer srv.Close()

	tr := staticTranslator{tr: Translation{Action: "a", Resource: "r"}}
	b, _, leaves, trips := newTestBroker(t, srv.URL, tr)
	leaves.failFromCall = 2 // laisse passer la feuille OPA, échoue sur celle du broker

	res := b.HandleAction(context.Background(), "agent-1", simpleIntent("a", "r"))

	if leaves.calls != 2 {
		t.Fatalf("Append() appelé %d fois, veut 2 (feuille OPA + feuille broker d'émission)", leaves.calls)
	}
	if res.Allow {
		t.Fatal("jeton émis malgré l'échec de la feuille d'émission du broker — pas de preuve, pas d'accès")
	}
	if res.Reason != pep.ReasonLeafWriteFailed {
		t.Fatalf("reason=%q, veut %q", res.Reason, pep.ReasonLeafWriteFailed)
	}
	if len(res.Token) != 0 {
		t.Fatal("un refus ne doit jamais porter un jeton exploitable")
	}
	if res.LeafErr == nil {
		t.Fatal("LeafErr doit rapporter l'échec d'écriture")
	}
	found := false
	for _, r := range trips.all() {
		if r == pep.ReasonLeafWriteFailed {
			found = true
		}
	}
	if !found {
		t.Fatalf("alarmes %v — une feuille d'émission impossible alarme (T14)", trips.all())
	}
}
