// Package pep implante le point d'application de la politique (PEP) d'une
// cellule TBP. Ce fichier est le valideur de jetons (T9) : il vérifie les
// jetons CWT/COSE_Sign1 émis par la maîtresse contre le schéma figé de
// src/pep/token/schema.md (T8), dans l'ordre de validation du §7, et laisse
// une feuille KindDecision pour CHAQUE décision — allow comme deny (§4.1).
//
// Doctrine : fail-closed partout (§1). Toute anomalie — format, schéma,
// clé, signature, fraîcheur, époque, portée, sceau, quota, rejeu, ou même
// l'écriture de la feuille de décision — bascule la décision en deny.
// Aucune inspection de contenu (no-DPI) : le passeport de quota est un
// contour opaque, jamais ouvert au-delà de ses champs CDDL (§4.1-bis).
package pep

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// MaxTokenWireSize borne la taille d'un jeton sur le fil (schema.md §8).
const MaxTokenWireSize = 1024

// TTL borné du jeton (§4.1 : 30–60 s).
const (
	minTTLSec = 30
	maxTTLSec = 60
)

// tokenVersion est la version de schéma acceptée (claim −9).
const tokenVersion = 1

// Classes de la ressource (§5.3) — claim optionnel −4, absent ⇒ W.
type Class uint8

const (
	ClassF   Class = 0 // financier
	ClassI   Class = 1 // infrastructure
	ClassW   Class = 2 // survie
	ClassOut Class = 3 // hors F/I/W
)

// DefaultClass est la classe quand le claim −4 est absent (§5.3).
const DefaultClass = ClassW

// Quota est le passeport de quota (§4.1-bis, claim −7). TTL et jti sont
// hérités structurellement du jeton englobant — liés cryptographiquement,
// jamais inspectés au-delà des champs CDDL (no-DPI).
type Quota struct {
	Resource  string
	Operation string
	VolumeMax uint64
	WindowS   uint64
}

// Token est le jeton décodé et validé.
type Token struct {
	Iss        string
	Sub        string
	Iat        int64
	Exp        int64
	JTI        [16]byte
	PolicyID   [32]byte
	Action     string
	Resource   string
	Class      Class
	ObjectSeal *[32]byte
	Epoch      uint64
	Quota      *Quota
}

// Request est la demande d'accès confrontée au jeton.
type Request struct {
	Action     string
	Resource   string
	ObjectSeal *[32]byte // sceau présenté par le demandeur (§4.4(2)), si requis
	Epoch      uint64    // époque courante de la cellule (§7.2)
}

// Decision est le verdict. Toute décision — allow comme deny — produit une
// feuille KindDecision (§4.1) ; LeafWritten/LeafErr en rendent compte.
type Decision struct {
	Allow       bool
	Reason      string   // code machine ("ok", "replay", "scope-mismatch", …)
	Token       *Token   // jeton décodé, présent si le schéma a été validé
	JTI         [16]byte // jti porté par la feuille (zéros si indisponible)
	LeafWritten bool
	LeafErr     error
}

// Codes de raison (machine-readable, stables — consommés par T13/T14).
const (
	ReasonOK              = "ok"
	ReasonTokenTooLarge   = "token-too-large"
	ReasonMalformed       = "malformed-token"
	ReasonBadHeaders      = "bad-headers"
	ReasonBadAlg          = "bad-alg"
	ReasonSchemaViolation = "schema-violation"
	ReasonUnsupportedVer  = "unsupported-version"
	ReasonUnknownKID      = "unknown-kid"
	ReasonBadSignature    = "bad-signature"
	ReasonStaleToken      = "stale-token"
	ReasonNotYetValid     = "not-yet-valid"
	ReasonTTLOutOfRange   = "ttl-out-of-range"
	ReasonPolicyMismatch  = "policy-mismatch"
	ReasonEpochMismatch   = "epoch-mismatch"
	ReasonScopeMismatch   = "scope-mismatch"
	ReasonSealMismatch    = "seal-mismatch"
	ReasonQuotaExhausted  = "quota-exhausted"
	ReasonQuotaUnverified = "quota-unverified"
	ReasonReplay          = "replay"
	ReasonLeafWriteFailed = "leaf-write-failed"
)

// LeafSink est la couture vers le registre de la cellule (T7). *registry.CellLog
// l'implémente nativement.
type LeafSink interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// AntiReplayCache est la couture vers le cache borné anti-rejeu (T10, §4.3).
// CheckAndConsume est atomique : true si le jti était inconnu (et devient
// consommé jusqu'à exp), false s'il était déjà présent — la saturation du
// cache renvoie false (fail-closed, bascule T14), jamais d'éviction.
type AntiReplayCache interface {
	CheckAndConsume(jti [16]byte, exp time.Time) bool
}

// QuotaChecker est la couture vers le compteur de quota (T12). Exhausted
// rapporte si le passeport (identifié par le jti du jeton englobant) a
// déjà épuisé son volume dans sa fenêtre.
type QuotaChecker interface {
	Exhausted(jti [16]byte) bool
}

// ValidatorOptions paramètre le valideur.
type ValidatorOptions struct {
	// CellID est l'identité de la cellule émettrice des feuilles.
	CellID string
	// Keyring est le trousseau épinglé : kid = sha256(pub)[:16] → clé
	// publique Ed25519. Aucune résolution dynamique (§12, fail-closed).
	Keyring map[[16]byte]ed25519.PublicKey
	// PolicyID est le hash de la politique locale (§3 : policy_id = hash(P)).
	PolicyID [32]byte
	// Salt est le sel des feuilles de décision (§6.2 : hash-only, ≥ 16
	// octets). Il ne quitte JAMAIS la cellule.
	Salt []byte
	// Leaves reçoit la feuille de chaque décision. Obligatoire.
	Leaves LeafSink
	// AntiReplay est le cache borné anti-rejeu (T10). Obligatoire.
	AntiReplay AntiReplayCache
	// Quota est le compteur de passeports (T12). Peut être nil : tout jeton
	// portant un passeport est alors refusé (« quota-unverified »).
	Quota QuotaChecker
	// Now est l'horloge NTS de la cellule. Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// Validator valide les jetons contre le schéma T8 et la doctrine fail-closed.
// Sans état mutable après construction : sûr pour un usage concurrent.
type Validator struct {
	cellID     string
	keyring    map[[16]byte]ed25519.PublicKey
	policyID   [32]byte
	salt       []byte
	leaves     LeafSink
	antiReplay AntiReplayCache
	quota      QuotaChecker
	now        func() time.Time
}

// NewValidator construit un valideur. Fail-closed dès la configuration :
// trousseau vide, sel court, sink ou anti-rejeu absents ⇒ erreur.
func NewValidator(opts ValidatorOptions) (*Validator, error) {
	if opts.CellID == "" {
		return nil, errors.New("pep: CellID requis")
	}
	if len(opts.Keyring) == 0 {
		return nil, errors.New("pep: trousseau épinglé vide (§12)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: LeafSink requis (§4.1 : chaque décision laisse une feuille)")
	}
	if opts.AntiReplay == nil {
		return nil, errors.New("pep: cache anti-rejeu requis (§4.3)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &Validator{
		cellID:     opts.CellID,
		keyring:    opts.Keyring,
		policyID:   opts.PolicyID,
		salt:       salt,
		leaves:     opts.Leaves,
		antiReplay: opts.AntiReplay,
		quota:      opts.Quota,
		now:        now,
	}, nil
}

// KeyIDFromPublicKey dérive le kid d'une clé : sha256(pub)[:16] (schema.md §4).
func KeyIDFromPublicKey(pub ed25519.PublicKey) [16]byte {
	h := sha256.Sum256(pub)
	var kid [16]byte
	copy(kid[:], h[:16])
	return kid
}

// Modes CBOR : encodage canonique (RFC 8949 §4.2.1) pour le contrôle de
// canonicité, décodage strict (clés dupliquées rejetées, longueurs
// indéfinies interdites).
var (
	canonicalEnc, _ = cbor.CanonicalEncOptions().EncMode()
	strictDec, _    = cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
)

// Validate vérifie un jeton contre la requête, à l'horloge configurée.
func (v *Validator) Validate(ctx context.Context, wire []byte, req Request) Decision {
	return v.ValidateAt(ctx, wire, req, v.now())
}

// ValidateAt est Validate avec une horloge explicite (tests, rejeu §4.3).
func (v *Validator) ValidateAt(ctx context.Context, wire []byte, req Request, now time.Time) Decision {
	d := v.decide(wire, req, now)
	v.writeLeaf(ctx, &d, now)
	return d
}

// decide exécute la chaîne de validation (schema.md §7). Pure : n'écrit pas.
func (v *Validator) decide(wire []byte, req Request, now time.Time) Decision {
	deny := func(reason string, tok *Token, jti [16]byte) Decision {
		return Decision{Allow: false, Reason: reason, Token: tok, JTI: jti}
	}
	var zeroJTI [16]byte

	// 1. format : taille bornée puis structure COSE_Sign1.
	if len(wire) > MaxTokenWireSize {
		return deny(ReasonTokenTooLarge, nil, zeroJTI)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(wire); err != nil {
		return deny(ReasonMalformed, nil, zeroJTI)
	}

	// 2. en-têtes : unprotected vide (aucun paramètre hors signature),
	// protected décodable, alg == Ed25519, kid bstr(16).
	if len(msg.Headers.Unprotected) > 0 {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	// RawProtected est le bstr encodé : on décode le bstr, puis la carte.
	var protectedBytes []byte
	if err := strictDec.Unmarshal(msg.Headers.RawProtected, &protectedBytes); err != nil {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	var protected map[any]any
	if len(protectedBytes) == 0 {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	if err := strictDec.Unmarshal(protectedBytes, &protected); err != nil {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	if len(protected) > 2 {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	alg, ok := asInt(protected[int64(1)])
	if !ok {
		// fxamacker décode les labels positifs en uint64.
		alg, ok = asInt(protected[uint64(1)])
	}
	if !ok {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	if alg != int64(cose.AlgorithmEd25519) {
		return deny(ReasonBadAlg, nil, zeroJTI)
	}
	kidBytes, ok := bytesFromAny(protected[int64(4)])
	if !ok {
		kidBytes, ok = bytesFromAny(protected[uint64(4)])
	}
	if !ok || len(kidBytes) != 16 {
		return deny(ReasonBadHeaders, nil, zeroJTI)
	}
	var kid [16]byte
	copy(kid[:], kidBytes)

	// 3. schéma : décodage strict du payload, canonicité, champs CDDL.
	tok, reason := decodePayload(msg.Payload)
	if reason != "" {
		return deny(reason, nil, zeroJTI)
	}

	// 4. clé : kid résolu dans le trousseau épinglé (§12, pas de résolution).
	pub, ok := v.keyring[kid]
	if !ok {
		return deny(ReasonUnknownKID, tok, tok.JTI)
	}

	// 5. signature Ed25519 sur le Sig_structure exact (go-cose).
	verifier, err := cose.NewVerifier(cose.AlgorithmEd25519, pub)
	if err != nil {
		return deny(ReasonBadSignature, tok, tok.JTI)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return deny(ReasonBadSignature, tok, tok.JTI)
	}

	// 6. fraîcheur : iat ≤ now ≤ exp, TTL borné 30–60 s (§4.1).
	if tok.Iat > now.Unix() {
		return deny(ReasonNotYetValid, tok, tok.JTI)
	}
	if now.Unix() > tok.Exp {
		return deny(ReasonStaleToken, tok, tok.JTI)
	}
	if ttl := tok.Exp - tok.Iat; ttl < minTTLSec || ttl > maxTTLSec {
		return deny(ReasonTTLOutOfRange, tok, tok.JTI)
	}

	// policy_id = hash(P) de la politique locale (§3).
	if tok.PolicyID != v.policyID {
		return deny(ReasonPolicyMismatch, tok, tok.JTI)
	}

	// 7. époque : révocation = nouvelle époque, les anciens jetons sont morts (§7.3).
	if tok.Epoch != req.Epoch {
		return deny(ReasonEpochMismatch, tok, tok.JTI)
	}

	// 8. portée : action ET ressource revalidées ici, indépendamment de
	// tout moteur de politique amont (§4.5 : l'action vient du traducteur).
	if tok.Action != req.Action || tok.Resource != req.Resource {
		return deny(ReasonScopeMismatch, tok, tok.JTI)
	}

	// 9. sceau : capacité-objet (§4.4(2)) — si le jeton exige un sceau, le
	// demandeur doit présenter exactement le même.
	if tok.ObjectSeal != nil {
		if req.ObjectSeal == nil || *req.ObjectSeal != *tok.ObjectSeal {
			return deny(ReasonSealMismatch, tok, tok.JTI)
		}
	}

	// passeport de quota (§4.1-bis) : contour opaque — on ne lit jamais
	// autre chose que les champs CDDL, et sans compteur (T12) on refuse.
	if tok.Quota != nil {
		if v.quota == nil {
			return deny(ReasonQuotaUnverified, tok, tok.JTI)
		}
		if v.quota.Exhausted(tok.JTI) {
			return deny(ReasonQuotaExhausted, tok, tok.JTI)
		}
	}

	// 10. non-consommation : jti unique (§4.1) via le cache borné §4.3.
	// Atomique et en dernier : un jeton refusé amont ne consomme pas son jti.
	if !v.antiReplay.CheckAndConsume(tok.JTI, time.Unix(tok.Exp, 0)) {
		return deny(ReasonReplay, tok, tok.JTI)
	}

	return Decision{Allow: true, Reason: ReasonOK, Token: tok, JTI: tok.JTI}
}

// writeLeaf inscrit la feuille KindDecision (§4.1 + §6.2 : hash-only, le sel
// reste chez le producteur). Sur un allow, l'échec d'écriture bascule la
// décision en deny — fail-closed : pas de preuve, pas d'accès.
func (v *Validator) writeLeaf(ctx context.Context, d *Decision, now time.Time) {
	verdict := byte(0x00)
	if d.Allow {
		verdict = 0x01
	}
	// record = "TBPD1" ‖ jti(16) ‖ verdict(1) ‖ u8 len(reason) ‖ reason
	record := make([]byte, 0, 5+16+1+1+len(d.Reason))
	record = append(record, "TBPD1"...)
	record = append(record, d.JTI[:]...)
	record = append(record, verdict, byte(len(d.Reason)))
	record = append(record, d.Reason...)

	leaf := registry.Leaf{
		Kind:        registry.KindDecision,
		CellID:      v.cellID,
		PayloadHash: registry.HashPayload(v.salt, record),
		Timestamp:   now.UnixNano(),
	}
	if _, err := v.leaves.Append(ctx, leaf); err != nil {
		d.LeafWritten = false
		d.LeafErr = err
		if d.Allow {
			d.Allow = false
			d.Reason = ReasonLeafWriteFailed
		}
		return
	}
	d.LeafWritten = true
}

// ---------------------------------------------------------------------------
// Décodage strict du payload (étape « schéma » du §7)
// ---------------------------------------------------------------------------

// decodePayload décode le payload CBOR contre le schéma CDDL figé (T8) :
// clés inconnues rejetées, types exacts, tailles bstr exactes, canonicité
// vérifiée par ré-encodage. Renvoie le token ou un code de raison.
func decodePayload(payload []byte) (*Token, string) {
	var raw map[any]any
	if err := strictDec.Unmarshal(payload, &raw); err != nil {
		return nil, ReasonSchemaViolation
	}

	// Canonicité (RFC 8949 §4.2.1) : le ré-encodage canonique de la carte
	// décodée doit reproduire le payload octet pour octet — sinon l'émetteur
	// n'a pas suivi le profil déterministe (encodage long, tri des clés…).
	reEncoded, err := canonicalEnc.Marshal(raw)
	if err != nil || !bytes.Equal(reEncoded, payload) {
		return nil, ReasonSchemaViolation
	}

	claims := make(map[int64]any, len(raw))
	for k, val := range raw {
		key, ok := asInt(k)
		if !ok {
			return nil, ReasonSchemaViolation
		}
		claims[key] = val
	}
	for key := range claims {
		switch key {
		case 1, 2, 4, 6, 7, -1, -2, -3, -4, -5, -6, -7, -9:
		default:
			return nil, ReasonSchemaViolation // clé inconnue ⇒ rejet (§1)
		}
	}

	tok := &Token{Class: DefaultClass}
	var ok bool

	if tok.Iss, ok = stringClaim(claims, 1, true); !ok {
		return nil, ReasonSchemaViolation
	}
	if tok.Sub, ok = stringClaim(claims, 2, true); !ok {
		return nil, ReasonSchemaViolation
	}
	if tok.Exp, ok = intClaim(claims, 4, true); !ok {
		return nil, ReasonSchemaViolation
	}
	if tok.Iat, ok = intClaim(claims, 6, true); !ok {
		return nil, ReasonSchemaViolation
	}
	jti, ok := bytesClaim(claims, 7, true)
	if !ok || len(jti) != 16 {
		return nil, ReasonSchemaViolation
	}
	copy(tok.JTI[:], jti)
	policyID, ok := bytesClaim(claims, -1, true)
	if !ok || len(policyID) != 32 {
		return nil, ReasonSchemaViolation
	}
	copy(tok.PolicyID[:], policyID)
	if tok.Action, ok = stringClaim(claims, -2, true); !ok {
		return nil, ReasonSchemaViolation
	}
	if tok.Resource, ok = stringClaim(claims, -3, true); !ok {
		return nil, ReasonSchemaViolation
	}

	if c, present := claims[-4]; present {
		n, ok := asUint(c)
		if !ok || n > uint64(ClassOut) {
			return nil, ReasonSchemaViolation
		}
		tok.Class = Class(n)
	}
	if s, present := claims[-5]; present {
		b, ok := bytesFromAny(s)
		if !ok || len(b) != 32 {
			return nil, ReasonSchemaViolation
		}
		var seal [32]byte
		copy(seal[:], b)
		tok.ObjectSeal = &seal
	}
	epoch, ok := uintClaim(claims, -6, true)
	if !ok {
		return nil, ReasonSchemaViolation
	}
	tok.Epoch = epoch
	if q, present := claims[-7]; present {
		quota, ok := decodeQuota(q)
		if !ok {
			return nil, ReasonSchemaViolation
		}
		tok.Quota = quota
	}
	ver, ok := uintClaim(claims, -9, true)
	if !ok {
		return nil, ReasonSchemaViolation
	}
	if ver != tokenVersion {
		return nil, ReasonUnsupportedVer
	}
	return tok, ""
}

// decodeQuota décode le contour passeport (claim −7) : exactement les 4
// champs CDDL, jamais davantage — no-DPI (§4.1-bis).
func decodeQuota(v any) (*Quota, bool) {
	m, ok := v.(map[any]any)
	if !ok || len(m) != 4 {
		return nil, false
	}
	claims := make(map[int64]any, len(m))
	for k, val := range m {
		key, ok := asInt(k)
		if !ok {
			return nil, false
		}
		claims[key] = val
	}
	q := &Quota{}
	if q.Resource, ok = stringClaim(claims, 1, true); !ok {
		return nil, false
	}
	if q.Operation, ok = stringClaim(claims, 2, true); !ok {
		return nil, false
	}
	if q.VolumeMax, ok = uintClaim(claims, 3, true); !ok {
		return nil, false
	}
	if q.WindowS, ok = uintClaim(claims, 4, true); !ok {
		return nil, false
	}
	return q, true
}

// ---------------------------------------------------------------------------
// Helpers de typage CBOR (fxamacker : uint positif → uint64, négatif → int64)
// ---------------------------------------------------------------------------

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func asUint(v any) (uint64, bool) {
	if n, ok := v.(uint64); ok {
		return n, true
	}
	return 0, false
}

func bytesFromAny(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}

func stringClaim(claims map[int64]any, key int64, required bool) (string, bool) {
	v, present := claims[key]
	if !present {
		return "", !required
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func intClaim(claims map[int64]any, key int64, required bool) (int64, bool) {
	v, present := claims[key]
	if !present {
		return 0, !required
	}
	return asInt(v)
}

func uintClaim(claims map[int64]any, key int64, required bool) (uint64, bool) {
	v, present := claims[key]
	if !present {
		return 0, !required
	}
	return asUint(v)
}

func bytesClaim(claims map[int64]any, key int64, required bool) ([]byte, bool) {
	v, present := claims[key]
	if !present {
		return nil, !required
	}
	return bytesFromAny(v)
}

// compile-time : *registry.CellLog satisfait LeafSink (couture T7).
var _ LeafSink = (*registry.CellLog)(nil)
