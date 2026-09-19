package pep

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// RFC 8032 §7.1 test key 1 — même vecteur que src/pep/token/schema.md §9.
var (
	testSeed = mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	testKID  = [16]byte{0x21, 0xfe, 0x31, 0xdf, 0xa1, 0x54, 0xa2, 0x61, 0x62, 0x6b, 0xf8, 0x54, 0x04, 0x6f, 0xd2, 0x27}
	testJTI  = [16]byte{0x26, 0x8d, 0x5b, 0xd7, 0xd3, 0xd7, 0x48, 0xf5, 0x87, 0x19, 0x8e, 0x45, 0xbf, 0xc0, 0x43, 0x86}
	testSalt = bytesOf(0x51, 32)

	// iat/exp du vecteur d'exemple T8.
	testIAT = int64(1758264000)
	testEXP = int64(1758264060)
)

var (
	policyV1 = mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	policyV2 = mustHex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	sealOK   = mustHex("cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe")
)

// Vecteur d'exemple figé de src/pep/token/schema.md §9 (370 octets).
const goldenVectorHex = "d28455a20127045021fe31dfa154a261626bf854046fd227a0590114ad01781a7462702f72656769737472792f63656c6c2d616c7068612d30310278217370696666653a2f2f7462702e6578616d706c652f6167656e742f636c61756465041a68ccfafc061a68ccfac007500123456789abcdeffedcba987654321020582000000000000000000000000000000000000000000000000000000000000000002169687474702e73656e6422782368747470733a2f2f6170692e6578616d706c652e636f6d2f76312f6d6573736167657323012458200000000000000000000000000000000000000000000000000000000000000000250726a401782368747470733a2f2f6170692e6578616d706c652e636f6d2f76312f6d657373616765730264504f5354031a0010000004183c280158408428028bfc398b7d02f8eec0aca8c2f5995d1c77559cdc28fce82d4e1bcd073cf2db81d86294a19d2939f776062f0095fe1ff305ecea2275ac483dd5b04cbe07"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func bytesOf(v byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func arr32(b []byte) [32]byte {
	var a [32]byte
	copy(a[:], b)
	return a
}

// ---------------------------------------------------------------------------
// Frappe de jetons de test (mint)
// ---------------------------------------------------------------------------

type testClaims struct {
	iss        string
	sub        string
	exp        int64
	iat        int64
	jti        []byte
	policyID   []byte
	action     string
	resource   string
	class      *int
	objectSeal []byte
	epoch      int
	quota      map[int]any
	version    int
	kid        []byte
}

func nominalClaims() testClaims {
	return testClaims{
		iss:      "tbp-cell-maitresse",
		sub:      "tbp-cell-037",
		exp:      testEXP,
		iat:      testIAT,
		jti:      testJTI[:],
		policyID: policyV1,
		action:   "read.list",
		resource: "registry/docs/42",
		class:    intPtr(0),
		epoch:    0,
		version:  1,
		kid:      testKID[:],
	}
}

func intPtr(v int) *int { return &v }

func claimsPayload(c testClaims) map[int]any {
	m := map[int]any{
		1:  c.iss,
		2:  c.sub,
		4:  c.exp,
		6:  c.iat,
		7:  c.jti,
		-1: c.policyID,
		-2: c.action,
		-3: c.resource,
		-6: c.epoch,
		-9: c.version,
	}
	if c.class != nil {
		m[-4] = *c.class
	}
	if c.objectSeal != nil {
		m[-5] = c.objectSeal
	}
	if c.quota != nil {
		m[-7] = c.quota
	}
	return m
}

var testCanonicalEnc, _ = cbor.CanonicalEncOptions().EncMode()

func mintToken(t testing.TB, c testClaims) []byte {
	t.Helper()
	payload, err := testCanonicalEnc.Marshal(claimsPayload(c))
	if err != nil {
		t.Fatalf("payload cbor: %v", err)
	}
	protected := map[any]any{int64(1): int64(-8)}
	if c.kid != nil {
		protected[int64(4)] = c.kid
	}
	priv := ed25519.NewKeyFromSeed(testSeed)
	signer, err := cose.NewSigner(cose.AlgorithmEd25519, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected = protected
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wire
}

// ---------------------------------------------------------------------------
// Seams de test
// ---------------------------------------------------------------------------

type stubSink struct {
	mu     sync.Mutex
	leaves []registry.Leaf
	err    error
}

func (s *stubSink) Append(_ context.Context, l registry.Leaf) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	s.leaves = append(s.leaves, l)
	return uint64(len(s.leaves)), nil
}

func (s *stubSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.leaves)
}

type stubAntiReplay struct{ consumed bool }

func (s *stubAntiReplay) CheckAndConsume(_ [16]byte, _ time.Time) bool {
	if s.consumed {
		return false
	}
	s.consumed = true
	return true
}

type stubQuota struct{ exhausted bool }

func (s *stubQuota) Exhausted(_ [16]byte) bool { return s.exhausted }

func newValidator(t *testing.T, sink LeafSink, ar AntiReplayCache, qc QuotaChecker) *Validator {
	t.Helper()
	return newValidatorP(t, sink, ar, qc, arr32(policyV1))
}

func newValidatorP(t *testing.T, sink LeafSink, ar AntiReplayCache, qc QuotaChecker, policy [32]byte) *Validator {
	t.Helper()
	v, err := NewValidator(ValidatorOptions{
		CellID:     "tbp/registry/cell-alpha-01",
		Keyring:    map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)},
		PolicyID:   policy,
		Salt:       testSalt,
		Leaves:     sink,
		AntiReplay: ar,
		Quota:      qc,
		Now:        func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func nominalRequest() Request {
	return Request{Action: "read.list", Resource: "registry/docs/42", Epoch: 0}
}

// ---------------------------------------------------------------------------
// §8 — les 4 scénarios fonctionnels (TDD : écrits avant l'implémentation)
// ---------------------------------------------------------------------------

func TestScenarioReplay(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)
	tok := mintToken(t, nominalClaims())

	d1 := v.Validate(context.Background(), tok, nominalRequest())
	if !d1.Allow || d1.Reason != "ok" {
		t.Fatalf("premier usage: allow=%v reason=%q, veut ok", d1.Allow, d1.Reason)
	}
	d2 := v.Validate(context.Background(), tok, nominalRequest())
	if d2.Allow || d2.Reason != "replay" {
		t.Fatalf("rejeu: allow=%v reason=%q, veut deny/replay", d2.Allow, d2.Reason)
	}
	if sink.count() != 2 {
		t.Fatalf("feuilles=%d, veut 2 (chaque décision laisse une feuille)", sink.count())
	}
}

func TestScenarioExpiredToken(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)
	tok := mintToken(t, nominalClaims())

	d := v.ValidateAt(context.Background(), tok, nominalRequest(), time.Unix(testEXP+1, 0))
	if d.Allow || d.Reason != "stale-token" {
		t.Fatalf("expiré: allow=%v reason=%q, veut deny/stale-token", d.Allow, d.Reason)
	}
	if ar.consumed {
		t.Fatal("un jeton expiré ne doit PAS consommer son jti")
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
}

func TestScenarioScopeMismatch(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)
	tok := mintToken(t, nominalClaims())

	d := v.Validate(context.Background(), tok, Request{Action: "write.append", Resource: "registry/docs/42", Epoch: 0})
	if d.Allow || d.Reason != "scope-mismatch" {
		t.Fatalf("portée: allow=%v reason=%q, veut deny/scope-mismatch", d.Allow, d.Reason)
	}
	if ar.consumed {
		t.Fatal("un jeton hors portée ne doit PAS consommer son jti")
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
}

func TestScenarioPassportExhausted(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	qc := &stubQuota{exhausted: true}
	v := newValidator(t, sink, ar, qc)

	c := nominalClaims()
	c.quota = map[int]any{1: "storage.artifacts", 2: "append", 3: 536870912, 4: 300}
	tok := mintToken(t, c)

	d := v.Validate(context.Background(), tok, nominalRequest())
	if d.Allow || d.Reason != "quota-exhausted" {
		t.Fatalf("passeport épuisé: allow=%v reason=%q, veut deny/quota-exhausted", d.Allow, d.Reason)
	}
	if ar.consumed {
		t.Fatal("un jeton refusé au quota ne doit PAS consommer son jti")
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d, veut 1", sink.count())
	}
}

// ---------------------------------------------------------------------------
// Vecteur d'or T8 (schema.md §9) — conformance cross-implémentation
// ---------------------------------------------------------------------------

func TestGoldenVectorT8(t *testing.T) {
	wire := mustHex(goldenVectorHex)
	if len(wire) != 370 {
		t.Fatalf("vecteur=%d octets, veut 370", len(wire))
	}
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	// Le vecteur d'exemple T8 (schema.md §9) : policy_id = 0×32, epoch 7,
	// classe I explicite, sceau 0×32, passeport POST 1 Mio / 60 s.
	v := newValidatorP(t, sink, ar, &stubQuota{}, [32]byte{})

	seal := [32]byte{}
	req := Request{
		Action:     "http.send",
		Resource:   "https://api.example.com/v1/messages",
		ObjectSeal: &seal,
		Epoch:      7,
	}
	d := v.Validate(context.Background(), wire, req)
	if !d.Allow || d.Reason != "ok" {
		t.Fatalf("vecteur d'or: allow=%v reason=%q, veut ok", d.Allow, d.Reason)
	}
	if d.Token == nil {
		t.Fatal("Token manquant sur une décision allow")
	}
	if d.Token.Iss != "tbp/registry/cell-alpha-01" || d.Token.Sub != "spiffe://tbp.example/agent/claude" {
		t.Errorf("iss/sub = %q/%q", d.Token.Iss, d.Token.Sub)
	}
	if d.Token.Action != "http.send" || d.Token.Resource != "https://api.example.com/v1/messages" {
		t.Errorf("scope = %q %q", d.Token.Action, d.Token.Resource)
	}
	if d.Token.Class != ClassI {
		t.Errorf("class = %d, veut ClassI", d.Token.Class)
	}
	if d.Token.Epoch != 7 {
		t.Errorf("epoch = %d, veut 7", d.Token.Epoch)
	}
	wantJTI := mustHex("0123456789abcdeffedcba9876543210")
	if !bytes.Equal(d.Token.JTI[:], wantJTI) {
		t.Errorf("jti = %x", d.Token.JTI)
	}
	if d.Token.ObjectSeal == nil || *d.Token.ObjectSeal != ([32]byte{}) {
		t.Errorf("sceau = %v, veut 0×32", d.Token.ObjectSeal)
	}
	if d.Token.Quota == nil || d.Token.Quota.Operation != "POST" ||
		d.Token.Quota.VolumeMax != 1048576 || d.Token.Quota.WindowS != 60 {
		t.Errorf("quota = %+v", d.Token.Quota)
	}
}

func TestClassDefaultW(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)

	c := nominalClaims()
	c.class = nil // absent ⇒ W par défaut (spec §5.3)
	tok := mintToken(t, c)

	d := v.Validate(context.Background(), tok, nominalRequest())
	if !d.Allow {
		t.Fatalf("allow=%v reason=%q", d.Allow, d.Reason)
	}
	if d.Token.Class != ClassW {
		t.Errorf("class=%d, veut ClassW (défaut)", d.Token.Class)
	}
}

// ---------------------------------------------------------------------------
// Batterie fail-closed : chaque falsification ⇒ deny + feuille
// ---------------------------------------------------------------------------

func TestFailClosedBattery(t *testing.T) {
	type tc struct {
		name   string
		wire   func(t *testing.T) []byte
		reason string
	}

	mint := func(mut func(c *testClaims)) func(t *testing.T) []byte {
		return func(t *testing.T) []byte {
			c := nominalClaims()
			if mut != nil {
				mut(&c)
			}
			return mintToken(t, c)
		}
	}

	cases := []tc{
		{name: "wire trop grand", reason: "token-too-large", wire: func(t *testing.T) []byte {
			return append(mustHex(goldenVectorHex), bytesOf(0x41, MaxTokenWireSize)...)
		}},
		{name: "cbor cassé", reason: "malformed-token", wire: func(t *testing.T) []byte {
			return mustHex(goldenVectorHex)[:37]
		}},
		{name: "unprotected non vide", reason: "bad-headers", wire: func(t *testing.T) []byte {
			// golden = d2 84 55<21 o protected> a0 <payload> <sig> — l'octet 24
			// (unprotected = a0) devient a1 01 02.
			golden := mustHex(goldenVectorHex)
			if golden[24] != 0xa0 {
				t.Fatalf("offset unprotected inattendu: %#x", golden[24])
			}
			out := append([]byte{}, golden[:24]...)
			out = append(out, 0xa1, 0x01, 0x02)
			return append(out, golden[25:]...)
		}},
		{name: "alg = ES256 (-7)", reason: "bad-alg", wire: func(t *testing.T) []byte {
			w := mustHex(goldenVectorHex)
			// protected bstr = 55 a2 01 27 04 50 <kid16> ; patcher 0x27 → 0x26 (-7)
			idx := bytes.Index(w, []byte{0x55, 0xa2, 0x01, 0x27, 0x04, 0x50})
			if idx < 0 {
				t.Fatal("protected bstr introuvable")
			}
			w[idx+3] = 0x26
			return w
		}},
		{name: "clé dupliquée dans payload", reason: "schema-violation", wire: func(t *testing.T) []byte {
			return mintWithPayload(t, []byte{0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62})
		}},
		{name: "jti tronqué (15 o)", reason: "schema-violation", wire: mint(func(c *testClaims) {
			c.jti = c.jti[:15]
		})},
		{name: "policy_id 31 o", reason: "schema-violation", wire: mint(func(c *testClaims) {
			c.policyID = c.policyID[:31]
		})},
		{name: "action 300 o (> schema.cddl .size(1..255))", reason: "schema-violation", wire: mint(func(c *testClaims) {
			c.action = strings.Repeat("A", 300)
		})},
		{name: "iss 300 o (> schema.cddl .size(1..255))", reason: "schema-violation", wire: mint(func(c *testClaims) {
			c.iss = strings.Repeat("B", 300)
		})},
		// Un `resource` isolément > 1024 o fait nécessairement dépasser
		// MaxTokenWireSize (le reste du jeton a un coût fixe non nul) :
		// le plafond de fil (token-too-large) prime toujours sur la
		// borne CDDL propre à ce champ — c'est la même doctrine
		// fail-closed par une voie différente, pas un défaut.
		{name: "resource 1025 o (> schema.cddl .size(1..1024), plafonné par MaxTokenWireSize d'abord)", reason: "token-too-large", wire: mint(func(c *testClaims) {
			c.resource = strings.Repeat("C", 1025)
		})},
		{name: "quota.operation 65 o (> schema.cddl .size(1..64))", reason: "schema-violation", wire: mint(func(c *testClaims) {
			c.quota = map[int]any{1: "storage.artifacts", 2: strings.Repeat("D", 65), 3: 536870912, 4: 300}
		})},
		{name: "quota.window_s = 0 (viole schema.cddl .gt 0)", reason: "schema-violation", wire: mint(func(c *testClaims) {
			c.quota = map[int]any{1: "storage.artifacts", 2: "append", 3: 536870912, 4: 0}
		})},
		{name: "v = 2", reason: "unsupported-version", wire: mint(func(c *testClaims) {
			c.version = 2
		})},
		{name: "kid inconnu", reason: "unknown-kid", wire: mint(func(c *testClaims) {
			c.kid = bytesOf(0x99, 16)
		})},
		{name: "signature falsifiée", reason: "bad-signature", wire: func(t *testing.T) []byte {
			w := mintToken(t, nominalClaims())
			w[len(w)-1] ^= 0x01
			return w
		}},
		{name: "ttl 120 s", reason: "ttl-out-of-range", wire: mint(func(c *testClaims) {
			c.exp = c.iat + 120
		})},
		{name: "iat futur", reason: "not-yet-valid", wire: func(t *testing.T) []byte {
			c := nominalClaims()
			c.iat = testIAT + 45 // now = testIAT+30
			c.exp = c.iat + 60
			return mintToken(t, c)
		}},
		{name: "policy v2", reason: "policy-mismatch", wire: mint(func(c *testClaims) {
			c.policyID = policyV2
		})},
		{name: "epoch 9 vs 0", reason: "epoch-mismatch", wire: mint(func(c *testClaims) {
			c.epoch = 9
		})},
		{name: "sceau absent de la requête", reason: "seal-mismatch", wire: mint(func(c *testClaims) {
			c.objectSeal = sealOK
		})},
		{name: "passeport sans quota checker", reason: "quota-unverified", wire: mint(func(c *testClaims) {
			c.quota = map[int]any{1: "storage.artifacts", 2: "append", 3: 536870912, 4: 300}
		})},
		{name: "entier non canonique", reason: "schema-violation", wire: func(t *testing.T) []byte {
			// epoch encodé en 8 octets : 1b 00..00 — non canonique (7 tient en uint court)
			payload := canonicalEncMust(t, map[int]any{
				1: "tbp-cell-maitresse", 2: "tbp-cell-037",
				4: testEXP, 6: testIAT, 7: testJTI[:],
				-1: policyV1, -2: "read.list", -3: "registry/docs/42",
				-4: 0,
				-6: cbor.RawMessage{0x1b, 0, 0, 0, 0, 0, 0, 0, 0}, // 0 en 64 bits
				-9: 1,
			})
			return signPayload(t, payload)
		}},
		{name: "map indéfinie", reason: "malformed-token", wire: func(t *testing.T) []byte {
			// golden[2:24] = bstr protected (55 + 21 o) — remplacé par une map
			// indéfinie nue : bf 01 27 04 50 <kid16> ff (interdite, RFC 8949).
			golden := mustHex(goldenVectorHex)
			prot := append([]byte{0xbf, 0x01, 0x27, 0x04, 0x50}, testKID[:]...)
			prot = append(prot, 0xff)
			out := append([]byte{}, golden[:2]...)
			out = append(out, prot...)
			return append(out, golden[24:]...)
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sink := &stubSink{}
			ar := &stubAntiReplay{}
			v := newValidator(t, sink, ar, nil)
			d := v.Validate(context.Background(), c.wire(t), nominalRequest())
			if d.Allow {
				t.Fatalf("falsification acceptée (%s)", c.name)
			}
			if d.Reason != c.reason {
				t.Fatalf("reason=%q, veut %q", d.Reason, c.reason)
			}
			if !d.LeafWritten {
				t.Fatal("deny sans feuille : violation §4.1 (chaque décision laisse une feuille)")
			}
			if sink.count() != 1 {
				t.Fatalf("feuilles=%d, veut 1", sink.count())
			}
		})
	}
}

// TestResourceSizeBoundEnforcedInIsolation appelle decodePayload directement
// (boîte blanche, même package) pour vérifier la borne schema.cddl
// `-3: tstr .size (1..1024)` de `resource` indépendamment du plafond de fil
// MaxTokenWireSize — un `resource` seul de 1025 o fait toujours dépasser ce
// plafond (cf. TestFailClosedBattery/"resource 1025 o"), donc ce cas précis
// n'est autrement jamais atteignable par un jeton complet.
func TestResourceSizeBoundEnforcedInIsolation(t *testing.T) {
	base := claimsPayload(nominalClaims())
	base[-3] = strings.Repeat("C", 1025)
	payload := canonicalEncMust(t, base)

	tok, reason := decodePayload(payload)
	if tok != nil || reason != ReasonSchemaViolation {
		t.Fatalf("resource 1025 o : tok=%v reason=%q, veut nil/schema-violation", tok, reason)
	}

	// Non-régression : exactement à la borne (1024 o), le champ doit passer.
	base[-3] = strings.Repeat("C", 1024)
	payload = canonicalEncMust(t, base)
	tok, reason = decodePayload(payload)
	if tok == nil || reason != "" {
		t.Fatalf("resource 1024 o (borne incluse) : tok=%v reason=%q, veut décodage OK", tok, reason)
	}
}

// helpers de falsification ---------------------------------------------------

func canonicalEncMust(t *testing.T, v any) []byte {
	t.Helper()
	b, err := testCanonicalEnc.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func signPayload(t testing.TB, payload []byte) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(testSeed)
	signer, err := cose.NewSigner(cose.AlgorithmEd25519, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected = map[any]any{int64(1): int64(-8), int64(4): testKID[:]}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return wire
}

func mintWithPayload(t *testing.T, payload []byte) []byte { return signPayload(t, payload) }

// ---------------------------------------------------------------------------
// Feuille de décision : contenu, salt côté producteur, fail-closed sur sink
// ---------------------------------------------------------------------------

func TestDecisionLeafContent(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)
	tok := mintToken(t, nominalClaims())

	d := v.Validate(context.Background(), tok, nominalRequest())
	if !d.Allow || !d.LeafWritten {
		t.Fatalf("allow=%v leaf=%v", d.Allow, d.LeafWritten)
	}
	if sink.count() != 1 {
		t.Fatalf("feuilles=%d", sink.count())
	}
	leaf := sink.leaves[0]
	if leaf.Kind != registry.KindDecision {
		t.Errorf("kind=%v, veut KindDecision", leaf.Kind)
	}
	if leaf.CellID != "tbp/registry/cell-alpha-01" {
		t.Errorf("cellID=%q", leaf.CellID)
	}
	// §6.2 : la feuille ne transporte QUE le hash salé. Le record attendu :
	// "TBPD1" ‖ jti ‖ verdict ‖ reasonLen ‖ reason, hashé avec le salt producteur.
	record := append([]byte("TBPD1"), testJTI[:]...)
	record = append(record, 0x01, byte(len("ok")))
	record = append(record, "ok"...)
	want := registry.HashPayload(testSalt, record)
	if leaf.PayloadHash != want {
		t.Errorf("payloadHash=%x, veut %x", leaf.PayloadHash, want)
	}
	// le jti en clair ne doit JAMAIS apparaître dans la charge hashée utile
	if strings.Contains(hex.EncodeToString(leaf.PayloadHash[:]), hex.EncodeToString(testJTI[:])) {
		t.Error("fuite du jti dans la feuille")
	}
}

func TestLeafWriteFailureFlipsAllow(t *testing.T) {
	sink := &stubSink{err: errors.New("disk full")}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)
	tok := mintToken(t, nominalClaims())

	d := v.Validate(context.Background(), tok, nominalRequest())
	if d.Allow {
		t.Fatal("sink en panne ⇒ la décision doit basculer en deny (fail-closed)")
	}
	if d.Reason != "leaf-write-failed" {
		t.Fatalf("reason=%q", d.Reason)
	}
	if d.LeafErr == nil {
		t.Fatal("LeafErr doit rapporter l'erreur du sink")
	}
}

// ---------------------------------------------------------------------------
// Latence §9.1 (chemin chaud, sink stub)
// ---------------------------------------------------------------------------

func TestLatencyBudget(t *testing.T) {
	sink := &stubSink{}
	v := newValidator(t, sink, &stubAntiReplay{}, nil)
	tok := mintToken(t, nominalClaims())
	req := nominalRequest()
	ctx := context.Background()

	const iters = 300
	start := time.Now()
	for i := 0; i < iters; i++ {
		ar := &stubAntiReplay{} // jti frais à chaque itération
		v.antiReplay = ar
		d := v.Validate(ctx, tok, req)
		if !d.Allow {
			t.Fatalf("iteration %d refusée: %s", i, d.Reason)
		}
	}
	mean := time.Since(start) / iters
	t.Logf("latence moyenne validation = %v", mean)
	if mean > time.Millisecond {
		t.Fatalf("latence moyenne %v > 1 ms (budget §9.1 : 5 ms avec marge)", mean)
	}
}

// ---------------------------------------------------------------------------
// Intégration registre réel : les feuilles atterrissent dans le CellLog
// ---------------------------------------------------------------------------

func TestLeavesLandInCellLog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	skey, vkey, err := registry.GenerateCellKey("tbp/registry/cell-alpha-01")
	if err != nil {
		t.Fatalf("GenerateCellKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	log, err := registry.Open(ctx, registry.Options{
		Dir:                dir,
		Signer:             signer,
		Verifier:           verifier,
		BatchSize:          1,
		BatchAge:           10 * time.Millisecond,
		CheckpointInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	defer func() {
		if err := log.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	_, beforeSize, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	v := newValidator(t, log, &stubAntiReplay{}, nil)

	d1 := v.Validate(ctx, mintToken(t, nominalClaims()), nominalRequest())
	d2 := v.Validate(ctx, mintToken(t, nominalClaims()), Request{Action: "bad", Resource: "x", Epoch: 0})
	d3 := v.ValidateAt(ctx, mintToken(t, nominalClaims()), nominalRequest(), time.Unix(testEXP+1, 0))

	if !d1.Allow || d2.Allow || d3.Allow {
		t.Fatalf("verdicts = %v/%v/%v", d1.Allow, d2.Allow, d3.Allow)
	}

	_, afterSize, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if afterSize != beforeSize+3 {
		t.Fatalf("taille log = %d, veut %d (+3 décisions)", afterSize, beforeSize+3)
	}
}

// ---------------------------------------------------------------------------
// Concurrence (-race) et benchmark
// ---------------------------------------------------------------------------

func TestConcurrentValidate(t *testing.T) {
	sink := &stubSink{}
	v := newValidator(t, sink, &concurrentAntiReplay{}, nil)
	ctx := context.Background()
	req := nominalRequest()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				c := nominalClaims()
				c.jti = bytesOf(byte(g*25+i+1), 16)
				v.Validate(ctx, mintToken(t, c), req)
			}
		}(g)
	}
	wg.Wait()
	if sink.count() != 200 {
		t.Fatalf("feuilles=%d, veut 200", sink.count())
	}
}

type concurrentAntiReplay struct {
	mu   sync.Mutex
	seen map[[16]byte]bool
}

func (c *concurrentAntiReplay) CheckAndConsume(jti [16]byte, _ time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[[16]byte]bool{}
	}
	if c.seen[jti] {
		return false
	}
	c.seen[jti] = true
	return true
}

func BenchmarkValidate(b *testing.B) {
	sink := &stubSink{}
	ar := &concurrentAntiReplay{}
	v, err := NewValidator(ValidatorOptions{
		CellID:     "tbp/registry/cell-alpha-01",
		Keyring:    map[[16]byte]ed25519.PublicKey{testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)},
		PolicyID:   arr32(policyV1),
		Salt:       testSalt,
		Leaves:     sink,
		AntiReplay: ar,
		Now:        func() time.Time { return time.Unix(testIAT+30, 0) },
	})
	if err != nil {
		b.Fatalf("NewValidator: %v", err)
	}
	ctx := context.Background()
	req := nominalRequest()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		c := nominalClaims()
		j := testJTI
		binary.BigEndian.PutUint32(j[12:], uint32(i))
		c.jti = j[:]
		tok := mintToken(b, c)
		b.StartTimer()
		v.Validate(ctx, tok, req)
	}
}
