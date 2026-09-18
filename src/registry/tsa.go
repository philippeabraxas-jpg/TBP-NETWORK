// src/registry/tsa.go — T6 (issue #6)
//
// Client TSA minimal RFC 3161 (Time-Stamp Protocol) pour l'ancrage des
// chaînes de cellules dans la master chain (§6.2 : « TSA RFC 3161 (≥ 2,
// sign-local/catch-up différé strictement borné) »).
//
// Ce fichier implémente UNIQUEMENT le protocole fil :
//   - construction de TimeStampReq (empreinte SHA-256 + nonce aléatoire) ;
//   - transport HTTP POST application/timestamp-query ;
//   - analyse de TimeStampResp et extraction du TSTInfo depuis le CMS ;
//   - vérification de LIAISON : statut granted, algorithme SHA-256,
//     empreinte == digest demandé, nonce == nonce envoyé.
//
// La vérification cryptographique complète du CMS (chaîne de certificats
// du TSA) nécessite un magasin de racines de confiance — décision de
// déploiement du pilote, hors scope T6. La liaison empreinte+nonce rend
// déjà impossible la substitution d'un jeton par un attaquant tiers ; la
// vérification de chaîne ajoutera l'opposabilité contre un TSA paresseux.
//
// Zéro dépendance externe : encoding/asn1 de la bibliothèque standard
// suffit (prototypé et validé contre une réponse réelle de freetsa.org,
// fixture golden dans tsa_test.go).
package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

// OID utilisés par le protocole.
var (
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}        // PKCS#7 signedData
	oidTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} // id-smime-ct-TSTInfo
)

const (
	tsQueryContentType = "application/timestamp-query"
	defaultTSATimeout  = 5 * time.Second
	// maxTSRespBytes borne la lecture de la réponse — jamais de corps
	// illimité depuis un tiers (heuristique défensive, cf. T2-T4).
	maxTSRespBytes = 1 << 20
)

// Stamp est une empreinte temporelle RFC 3161 dont la liaison
// (empreinte + nonce) a été vérifiée.
type Stamp struct {
	GenTime time.Time // temps délivré par le TSA (horloge externe, UTC)
	Policy  string    // OID de la politique de timestamp du TSA
	Serial  []byte    // numéro de série du jeton (unicité chez le TSA)
	Token   []byte    // ContentInfo CMS brut — preuve à conserver hors registre
	Source  string    // identité du TSA ayant répondu (URL ou nom)
}

// TSAClient est la couture vers un TSA RFC 3161 (≥ 2 distincts en
// production, composés via FallbackTSA).
type TSAClient interface {
	// Timestamp demande au TSA de dater digest. L'implémentation DOIT
	// vérifier la liaison empreinte+nonce avant de retourner le Stamp.
	Timestamp(ctx context.Context, digest [32]byte) (Stamp, error)
}

// ---------------------------------------------------------------------------
// Structures ASN.1 (RFC 3161 §2.4)
// ---------------------------------------------------------------------------

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type messageImprint struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

// timeStampReq est la requête : version, empreinte, nonce, certReq.
// reqPolicy et extensions sont inutilisés (politique par défaut du TSA).
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional,default:false"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"` // PKIFreeText (types de chaînes variables selon les TSA)
	FailInfo     asn1.BitString `asn1:"optional"`
}

type timeStampResp struct {
	Status pkiStatusInfo
	Token  asn1.RawValue `asn1:"optional"` // TimeStampToken = ContentInfo CMS
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       asn1.RawValue `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	// Tsa ([0]) et Extensions ([1]) ignorés : non nécessaires à la liaison.
}

// TSAFunc adapte une fonction en TSAClient (tests, stubs supervisés).
type TSAFunc func(ctx context.Context, digest [32]byte) (Stamp, error)

// Timestamp implémente TSAClient.
func (f TSAFunc) Timestamp(ctx context.Context, digest [32]byte) (Stamp, error) {
	return f(ctx, digest)
}

// ---------------------------------------------------------------------------
// Construction de la requête
// ---------------------------------------------------------------------------

// marshalTimeStampReq encode une TimeStampReq RFC 3161 pour un digest
// SHA-256, avec nonce anti-substitution et certReq=true (le certificat du
// TSA dans la réponse facilite la vérification de chaîne ultérieure).
func marshalTimeStampReq(digest [32]byte, nonce *big.Int) ([]byte, error) {
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			Algorithm: algorithmIdentifier{Algorithm: oidSHA256},
			Digest:    digest[:],
		},
		Nonce:   nonce,
		CertReq: true,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("tsa : encodage TimeStampReq: %w", err)
	}
	return der, nil
}

// newNonce tire un nonce 64 bits — anti-substitution : une réponse dont le
// nonce ne correspond pas à la requête est rejetée (fail-closed).
func newNonce() (*big.Int, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("tsa : tirage du nonce: %w", err)
	}
	return new(big.Int).SetBytes(buf), nil
}

// ---------------------------------------------------------------------------
// Analyse de la réponse
// ---------------------------------------------------------------------------

// parseTimeStampResp analyse une TimeStampResp et vérifie la LIAISON avec
// la requête : statut granted, empreinte SHA-256 == wantDigest, nonce ==
// wantNonce. Toute discordance est une erreur — jamais de jeton accepté
// « à peu près » (fail-closed).
func parseTimeStampResp(body []byte, wantDigest [32]byte, wantNonce *big.Int) (Stamp, error) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(body, &resp)
	if err != nil {
		return Stamp{}, fmt.Errorf("tsa : TimeStampResp illisible: %w", err)
	}
	if len(rest) != 0 {
		return Stamp{}, fmt.Errorf("tsa : %d octets après TimeStampResp", len(rest))
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		// PKIStatus : 2 rejection, 3 waiting, 4 revocationWarning, 5 revocationNotification
		return Stamp{}, fmt.Errorf("tsa : statut PKI %d (failInfo %v) — jeton refusé",
			resp.Status.Status, resp.Status.FailInfo.Bytes)
	}
	if len(resp.Token.FullBytes) == 0 {
		return Stamp{}, errors.New("tsa : statut granted mais jeton absent")
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(resp.Token.FullBytes, &ci); err != nil {
		return Stamp{}, fmt.Errorf("tsa : ContentInfo illisible: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return Stamp{}, fmt.Errorf("tsa : ContentInfo %s, attendu signedData", ci.ContentType)
	}

	// SignedData ::= SEQUENCE { version, digestAlgorithms SET,
	// encapContentInfo, certificates [0] OPTIONAL, crls [1] OPTIONAL,
	// signerInfos SET } — seul encapContentInfo nous intéresse.
	var sd asn1.RawValue
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return Stamp{}, fmt.Errorf("tsa : SignedData illisible: %w", err)
	}
	var sdVersion, digestAlgs, eciRaw asn1.RawValue
	tail, err := asn1.Unmarshal(sd.Bytes, &sdVersion)
	if err != nil {
		return Stamp{}, fmt.Errorf("tsa : version SignedData illisible: %w", err)
	}
	if tail, err = asn1.Unmarshal(tail, &digestAlgs); err != nil {
		return Stamp{}, fmt.Errorf("tsa : digestAlgorithms illisibles: %w", err)
	}
	if _, err = asn1.Unmarshal(tail, &eciRaw); err != nil {
		return Stamp{}, fmt.Errorf("tsa : encapContentInfo illisible: %w", err)
	}

	var eci encapContentInfo
	if _, err := asn1.Unmarshal(eciRaw.FullBytes, &eci); err != nil {
		return Stamp{}, fmt.Errorf("tsa : encapContentInfo mal formé: %w", err)
	}
	if !eci.EContentType.Equal(oidTSTInfo) {
		return Stamp{}, fmt.Errorf("tsa : eContent %s, attendu TSTInfo", eci.EContentType)
	}
	if len(eci.EContent.Bytes) == 0 {
		return Stamp{}, errors.New("tsa : eContent absent du SignedData")
	}

	// eContent est un OCTET STRING wrappant le DER du TSTInfo (RFC 3161 §2.4.2).
	var tstDER []byte
	if _, err := asn1.Unmarshal(eci.EContent.Bytes, &tstDER); err != nil {
		return Stamp{}, fmt.Errorf("tsa : OCTET STRING TSTInfo illisible: %w", err)
	}
	var tst tstInfo
	if _, err := asn1.Unmarshal(tstDER, &tst); err != nil {
		return Stamp{}, fmt.Errorf("tsa : TSTInfo illisible: %w", err)
	}
	if tst.Version != 1 {
		return Stamp{}, fmt.Errorf("tsa : TSTInfo version %d inconnue", tst.Version)
	}

	// Liaison : algorithme, empreinte, nonce.
	if !tst.MessageImprint.Algorithm.Algorithm.Equal(oidSHA256) {
		return Stamp{}, fmt.Errorf("tsa : empreinte %s, SHA-256 exigé",
			tst.MessageImprint.Algorithm.Algorithm)
	}
	if !bytes.Equal(tst.MessageImprint.Digest, wantDigest[:]) {
		return Stamp{}, errors.New("tsa : empreinte du jeton ≠ digest de la requête — substitution suspectée")
	}
	if tst.Nonce == nil {
		return Stamp{}, errors.New("tsa : nonce absent du jeton alors qu'il était demandé")
	}
	if tst.Nonce.Cmp(wantNonce) != 0 {
		return Stamp{}, errors.New("tsa : nonce du jeton ≠ nonce de la requête — substitution suspectée")
	}

	return Stamp{
		GenTime: tst.GenTime.UTC(),
		Policy:  tst.Policy.String(),
		Serial:  tst.SerialNumber.Bytes(),
		Token:   resp.Token.FullBytes,
	}, nil
}

// ---------------------------------------------------------------------------
// Transport HTTP
// ---------------------------------------------------------------------------

// HTTPTSA est un TSAClient RFC 3161 sur HTTP (§3.2.1 : POST
// application/timestamp-query).
type HTTPTSA struct {
	// URL du TSA, ex. "https://tsa.example.com/tsr".
	URL string
	// Client HTTP sous-jacent ; nil = http.DefaultClient.
	Client *http.Client
	// Timeout par requête ; zéro = 5 s. Le TSA est un TIERS : jamais
	// d'attente illimitée dans un chemin de preuve.
	Timeout time.Duration
	// NonceSource tire le nonce anti-substitution ; nil = crypto/rand
	// 64 bits. Couture de test (rejouer une réponse signée exige de
	// connaître le nonce à l'avance) — jamais fixé en production.
	NonceSource func() (*big.Int, error)
}

// Timestamp implémente TSAClient.
func (t HTTPTSA) Timestamp(ctx context.Context, digest [32]byte) (Stamp, error) {
	if t.URL == "" {
		return Stamp{}, errors.New("tsa : URL vide")
	}
	nonceSource := t.NonceSource
	if nonceSource == nil {
		nonceSource = newNonce
	}
	nonce, err := nonceSource()
	if err != nil {
		return Stamp{}, err
	}
	reqBody, err := marshalTimeStampReq(digest, nonce)
	if err != nil {
		return Stamp{}, err
	}

	timeout := t.Timeout
	if timeout == 0 {
		timeout = defaultTSATimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(reqBody))
	if err != nil {
		return Stamp{}, fmt.Errorf("tsa : construction requête: %w", err)
	}
	req.Header.Set("Content-Type", tsQueryContentType)

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	httpResp, err := client.Do(req)
	if err != nil {
		return Stamp{}, fmt.Errorf("tsa %s : %w", t.URL, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusOK {
		return Stamp{}, fmt.Errorf("tsa %s : HTTP %d", t.URL, httpResp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxTSRespBytes))
	if err != nil {
		return Stamp{}, fmt.Errorf("tsa %s : lecture réponse: %w", t.URL, err)
	}

	stamp, err := parseTimeStampResp(body, digest, nonce)
	if err != nil {
		return Stamp{}, fmt.Errorf("tsa %s : %w", t.URL, err)
	}
	stamp.Source = t.URL
	return stamp, nil
}

// ---------------------------------------------------------------------------
// Repli multi-TSA (§6.2 : ≥ 2 TSA distincts)
// ---------------------------------------------------------------------------

// FallbackTSA compose plusieurs TSAClient : le premier qui répond avec un
// jeton valide gagne. L'échec de tous est une erreur unique agrégée —
// l'ancreur traite alors l'absence d'horodatage (lag → fail-closed).
type FallbackTSA []TSAClient

// Timestamp implémente TSAClient.
func (f FallbackTSA) Timestamp(ctx context.Context, digest [32]byte) (Stamp, error) {
	if len(f) == 0 {
		return Stamp{}, errors.New("tsa : FallbackTSA vide — au moins un TSA requis")
	}
	errs := make([]error, 0, len(f))
	for _, c := range f {
		stamp, err := c.Timestamp(ctx, digest)
		if err == nil {
			return stamp, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break // annulation : inutile de toquer chez les autres TSA
		}
	}
	return Stamp{}, fmt.Errorf("tsa : tous injoignables: %w", errors.Join(errs...))
}
