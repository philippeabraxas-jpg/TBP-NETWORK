package broker

// Émetteur de jetons CWT/COSE_Sign1 du broker (T33, §4.1 + §4.1-bis).
//
// Ce fichier est le pendant ÉMISSION du validateur T9
// (src/pep/validator.go) : il produit des jetons conformes au schéma figé
// de src/pep/token/schema.md (T8) — mêmes clés, mêmes bornes, même CBOR
// déterministe (profil §6 du schéma), même enveloppe COSE (alg Ed25519,
// kid = SHA-256(clé publique)[0:16], unprotected vide). Le contrat est
// vérifié des DEUX côtés : les tests croisés (broker_test.go) font valider
// chaque jeton émis par le validateur T9 — un seul format, pas deux
// mécanismes qui coïncident par hasard.
//
// Doctrine : fail-closed dès la configuration (§1). TTL borné [30, 60] s
// (§4.1, claim 4−6 du schéma) ; aucun champ hors du jeu fermé de clés
// {1, 2, 4, 6, 7, −1, −2, −3, −4, −5, −6, −7, −9} ; taille fil bornée à
// 1024 octets (schema.md §8). « Jamais par nom, toujours par signature » :
// le jeton ne transporte aucune clé publique, aucune URL, aucun jwk.
//
// La signature elle-même est une couture (Signer) : en production elle
// vit dans le HSM de la cellule (§12 — Ed25519 partout, m-of-n pour la
// gouvernance) ; DevSigner existe pour le dev et les tests UNIQUEMENT,
// comme SoftHSM (§12 : jamais en gouvernance réelle).

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// TTL borné du jeton (§4.1 : 30–60 s, schema.md §4). Défaut : 45 s.
const (
	minTTLSec     = 30
	maxTTLSec     = 60
	defaultTTLSec = 45
)

// Version du schéma de jeton émis (claim −9, schema.md §8).
const tokenVersion = 1

// Bornes de taille des champs texte (schema.cddl : `tstr .size (a..b)`).
const (
	maxIssSubActionLen = 255  // 1: iss, 2: sub, −2: action
	maxResourceLen     = 1024 // −3: resource, quota.1: resource
	maxQuotaOpLen      = 64   // quota.2: operation
)

// maxTokenWireSize borne la taille fil d'un jeton émis (schema.md §8) —
// l'émetteur se refuse à produire ce que le validateur rejetterait.
const maxTokenWireSize = 1024

// Erreurs de configuration et d'émission — toutes fail-closed.
var (
	ErrSignerRequired  = errors.New("broker: signataire requis (§12 : Ed25519, HSM en production)")
	ErrCellIDInvalid   = errors.New("broker: cellID requis, ≤ 255 octets (claim 1 = origin du registre, §6)")
	ErrTTLInvalid      = errors.New("broker: TTL hors bornes [30, 60] s (§4.1, schema.md §4)")
	ErrSubjectInvalid  = errors.New("broker: subject requis, ≤ 255 octets (claim 2)")
	ErrActionInvalid   = errors.New("broker: action requise, ≤ 255 octets (claim −2 — produite par le traducteur, §4.5)")
	ErrResourceInvalid = errors.New("broker: resource requise, ≤ 1024 octets (claim −3)")
	ErrClassInvalid    = errors.New("broker: classe hors [0..3] (claim −4, §5.3)")
	ErrQuotaInvalid    = errors.New("broker: vecteur quota invalide (claim −7 : resource ≤ 1024, operation 1..64, window_s > 0, §4.1-bis)")
	ErrTokenTooLarge   = errors.New("broker: jeton émis > 1024 octets (schema.md §8 — borne DoS)")
)

// Signer est la couture de signature Ed25519 de la cellule (§12). En
// production : HSM (m-of-n pour la gouvernance). Le contenu signé est le
// Sig_structure COSE exact (RFC 9052 §4.4) — la séparation de domaine est
// assurée par go-cose, le Signer ne voit que les octets à signer.
type Signer interface {
	// Sign signe content avec la clé Ed25519 de la cellule (64 octets).
	Sign(content []byte) ([]byte, error)
	// Public rapporte la clé publique — kid = SHA-256(pub)[0:16].
	Public() ed25519.PublicKey
}

// DevSigner est un Signer par seed Ed25519 — DEV/TEST UNIQUEMENT, même
// restriction doctrinale que SoftHSM (§12 : jamais en gouvernance réelle).
// La clé de gouvernance d'une cellule réelle vit dans le HSM ; ce type
// existe pour le labo P1 et la CI.
type DevSigner struct {
	priv ed25519.PrivateKey
}

// NewDevSigner construit un signataire de dev depuis une seed de 32 octets
// (ed25519.NewKeyFromSeed). Toute autre taille est rejetée.
func NewDevSigner(seed []byte) (*DevSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("broker: seed de %d octets — ed25519 en exige %d", len(seed), ed25519.SeedSize)
	}
	return &DevSigner{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Sign signe avec la clé de dev (Ed25519 pur, déterministe — RFC 8032).
func (s *DevSigner) Sign(content []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, content), nil
}

// Public rapporte la clé publique de dev.
func (s *DevSigner) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// coseSignerAdapter adapte la couture Signer (HSM-ready) à l'interface
// cose.Signer de go-cose : la signature Ed25519 est produite par la couture,
// la mécanique Sig_structure par la bibliothèque auditée (§6 : pas de
// homebrew sur les parties publiquement auditées de l'écosystème).
type coseSignerAdapter struct {
	s Signer
}

func (a coseSignerAdapter) Algorithm() cose.Algorithm { return cose.AlgorithmEd25519 }

func (a coseSignerAdapter) Sign(_ io.Reader, content []byte) ([]byte, error) {
	return a.s.Sign(content)
}

// IssueParams porte les claims d'un jeton à émettre. JTI et Epoch sont
// fournis par l'appelant (le broker) : le jti est tiré AVANT l'évaluation
// OPA pour que feuille de décision et jeton portent le même identifiant
// (§4.3), et l'époque vient de l'EpochProvider de la cellule (§7.2).
type IssueParams struct {
	Subject    string     // claim 2 — entité gouvernée
	Action     string     // claim −2 — PRODUITE par le traducteur (§4.5)
	Resource   string     // claim −3 — ressource exacte
	Class      *pep.Class // claim −4 — nil ⇒ claim absent ⇒ W au PEP (défaut fail-closed, §5.3)
	ObjectSeal *[32]byte  // claim −5 — object-capability scellée (§4.4(2))
	Quota      *pep.Quota // claim −7 — passeport à quota (§4.1-bis)
	JTI        [16]byte   // claim 7 — tiré par le broker avant OPA
	Epoch      uint64     // claim −6 — époque d'émission (§7.2/§7.3)
	Iat        int64      // claim 6 — secondes unix (horloge NTS de la cellule)
}

// Issuer émet les jetons CWT/COSE_Sign1 de la cellule. Sans état mutable
// après construction : sûr pour un usage concurrent.
type Issuer struct {
	cellID   string
	signer   Signer
	policyID [32]byte
	ttlSec   int64
	kid      [16]byte
	enc      cbor.EncMode
}

// IssuerOptions paramètre l'émetteur. Fail-closed dès la configuration.
type IssuerOptions struct {
	// CellID est l'identifiant de la cellule émettrice (claim 1 = origin
	// du registre, schema.md §4). Requis.
	CellID string
	// Signer est la couture de signature Ed25519 (§12). Requis.
	Signer Signer
	// PolicyID est le hash du bundle de règles P (claim −1, §3 : le même
	// hash que le handshake et l'ancrage de bundle §7.4). Le broker ne
	// sert qu'un seul bundle — épinglé à la configuration.
	PolicyID [32]byte
	// TTLSec est la durée de validité des jetons, dans [30, 60] s (§4.1).
	// 0 ⇒ 45 s. Toute autre valeur hors bornes = erreur.
	TTLSec int64
}

// NewIssuer construit l'émetteur. Fail-closed : cellID, signataire et TTL
// borné requis ; le kid est dérivé de la clé publique du signataire.
func NewIssuer(opts IssuerOptions) (*Issuer, error) {
	if opts.CellID == "" || len(opts.CellID) > maxIssSubActionLen {
		return nil, ErrCellIDInvalid
	}
	if opts.Signer == nil {
		return nil, ErrSignerRequired
	}
	ttl := opts.TTLSec
	if ttl == 0 {
		ttl = defaultTTLSec
	}
	if ttl < minTTLSec || ttl > maxTTLSec {
		return nil, ErrTTLInvalid
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil { // inatteignable (options fixes) — fail-closed quand même
		return nil, fmt.Errorf("broker: encodage CBOR canonique indisponible : %w", err)
	}
	return &Issuer{
		cellID:   opts.CellID,
		signer:   opts.Signer,
		policyID: opts.PolicyID,
		ttlSec:   ttl,
		kid:      pep.KeyIDFromPublicKey(opts.Signer.Public()),
		enc:      enc,
	}, nil
}

// KeyID rapporte le kid dérivé de la clé du signataire — à publier dans le
// trousseau épinglé de la cellule (genèse T3, schema.md §3).
func (i *Issuer) KeyID() [16]byte { return i.kid }

// TTLSec rapporte le TTL appliqué à chaque jeton émis (§4.1).
func (i *Issuer) TTLSec() int64 { return i.ttlSec }

// Issue produit le jeton fil (CWT + COSE_Sign1, CBOR déterministe). Toute
// anomalie — champ hors bornes, signature impossible, jeton trop grand —
// est une erreur : l'appelant (le broker) bascule en refus, jamais
// d'émission partielle (§1).
func (i *Issuer) Issue(p IssueParams) ([]byte, error) {
	if len(p.Subject) < 1 || len(p.Subject) > maxIssSubActionLen {
		return nil, ErrSubjectInvalid
	}
	if len(p.Action) < 1 || len(p.Action) > maxIssSubActionLen {
		return nil, ErrActionInvalid
	}
	if len(p.Resource) < 1 || len(p.Resource) > maxResourceLen {
		return nil, ErrResourceInvalid
	}
	if p.Class != nil && (*p.Class < pep.ClassF || *p.Class > pep.ClassOut) {
		return nil, ErrClassInvalid
	}
	if p.Quota != nil {
		q := p.Quota
		if len(q.Resource) < 1 || len(q.Resource) > maxResourceLen ||
			len(q.Operation) < 1 || len(q.Operation) > maxQuotaOpLen ||
			q.WindowS == 0 {
			return nil, ErrQuotaInvalid
		}
	}

	// Claims : le jeu fermé du schéma v1, rien d'autre (schema.md §4/§5).
	claims := map[int64]any{
		1:  i.cellID,
		2:  p.Subject,
		4:  uint64(p.Iat + i.ttlSec),
		6:  uint64(p.Iat),
		7:  append([]byte(nil), p.JTI[:]...),
		-1: append([]byte(nil), i.policyID[:]...),
		-2: p.Action,
		-3: p.Resource,
		-6: p.Epoch,
		-9: uint64(tokenVersion),
	}
	if p.Class != nil {
		claims[-4] = uint64(*p.Class)
	}
	if p.ObjectSeal != nil {
		claims[-5] = append([]byte(nil), p.ObjectSeal[:]...)
	}
	if p.Quota != nil {
		claims[-7] = map[int64]any{
			1: p.Quota.Resource,
			2: p.Quota.Operation,
			3: p.Quota.VolumeMax,
			4: p.Quota.WindowS,
		}
	}

	// CBOR déterministe (profil §6 du schéma, RFC 8949 §4.2.1) : le
	// document signé est unique bit-à-bit (§11.3) — le validateur T9
	// vérifie la canonicité par ré-encodage.
	payload, err := i.enc.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("broker: encodage des claims : %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected = map[any]any{
		int64(1): int64(cose.AlgorithmEd25519), // alg = EdDSA (−8)
		int64(4): append([]byte(nil), i.kid[:]...),
	}
	if err := msg.Sign(rand.Reader, nil, coseSignerAdapter{i.signer}); err != nil {
		return nil, fmt.Errorf("broker: signature : %w", err)
	}
	wire, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("broker: sérialisation COSE : %w", err)
	}
	if len(wire) > maxTokenWireSize {
		return nil, ErrTokenTooLarge
	}
	return wire, nil
}
