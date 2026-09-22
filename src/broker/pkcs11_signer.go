package broker

// PKCS11Signer implémente Signer (§12) au-dessus d'un module PKCS#11 — la
// couture HSM réelle promise par la doctrine de custody (issuer.go,
// deploy/cellule.md : « la clé de gouvernance réelle vit dans le HSM, la
// couture Signer est déjà HSM-ready »). Avant ce fichier, cette promesse
// n'avait qu'une seule implémentation RÉELLE de Signer : DevSigner, une
// seed Ed25519 dans un fichier 0600 — la couture existait, rien ne la
// branchait à un HSM (revue de sécurité #90, point 5). C'est ce fichier
// qui la branche : la clé privée ne quitte JAMAIS le module (SoftHSM2 en
// labo — vérifié empiriquement dans ce dépôt, pkcs11_signer_test.go — un
// vrai HSM en production, même interface), seule la primitive de
// signature (CKM_EDDSA, EdDSA pur, RFC 8032 — pas de prehash, exactement
// ce que coseSignerAdapter présente déjà : le Sig_structure COSE en
// clair) en sort.

import (
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// PKCS11SignerOptions paramètre l'ouverture du signataire HSM. Fail-closed
// dès la construction (§1) : un module, un jeton ou une clé introuvables
// sont des erreurs de démarrage, jamais un repli silencieux vers un autre
// mécanisme (DevSigner ne se substitue JAMAIS automatiquement).
type PKCS11SignerOptions struct {
	// ModulePath est le chemin de la bibliothèque PKCS#11 du fournisseur
	// (ex. /usr/lib/softhsm/libsofthsm2.so en labo, le .so du HSM réel en
	// production). Requis.
	ModulePath string
	// TokenLabel identifie le jeton (slot) portant la clé — requis pour
	// ne jamais résoudre « le premier slot venu » (§1 : pas de résolution
	// implicite sur une couture de gouvernance).
	TokenLabel string
	// KeyLabel identifie la paire de clés Ed25519 DANS le jeton (CKA_LABEL
	// des objets clé publique/privée, provisionnée hors-bande — §12 : la
	// cérémonie de genèse, pas ce code). Requis.
	KeyLabel string
	// PIN utilisateur du jeton. Requis, jamais journalisé.
	PIN string
}

// PKCS11Signer est un Signer (§12) dont la clé privée Ed25519 ne quitte
// JAMAIS le module PKCS#11 — seule la primitive de signature (CKM_EDDSA)
// s'exécute à l'intérieur. Implémente broker.Signer : coseSignerAdapter le
// consomme sans rien savoir de PKCS#11.
type PKCS11Signer struct {
	session p11.Session
	priv    p11.PrivateKey
	pub     ed25519.PublicKey
}

// NewPKCS11Signer ouvre le module, résout le jeton par étiquette, s'y
// connecte, et résout la paire de clés Ed25519 par étiquette. Toute étape
// manquante est fatale — jamais un signataire à moitié résolu ; la session
// ouverte est fermée sur tout chemin d'erreur après son ouverture.
func NewPKCS11Signer(opts PKCS11SignerOptions) (*PKCS11Signer, error) {
	if opts.ModulePath == "" {
		return nil, errors.New("broker: PKCS11SignerOptions.ModulePath requis (§12)")
	}
	if opts.TokenLabel == "" {
		return nil, errors.New("broker: PKCS11SignerOptions.TokenLabel requis — pas de résolution implicite de jeton")
	}
	if opts.KeyLabel == "" {
		return nil, errors.New("broker: PKCS11SignerOptions.KeyLabel requis")
	}
	if opts.PIN == "" {
		return nil, errors.New("broker: PKCS11SignerOptions.PIN requis")
	}

	module, err := p11.OpenModule(opts.ModulePath)
	if err != nil {
		return nil, fmt.Errorf("broker: module PKCS#11 %q: %w", opts.ModulePath, err)
	}
	slots, err := module.Slots()
	if err != nil {
		return nil, fmt.Errorf("broker: énumération des slots PKCS#11: %w", err)
	}
	var slot *p11.Slot
	for i := range slots {
		info, err := slots[i].TokenInfo()
		if err != nil {
			continue
		}
		if info.Label == opts.TokenLabel {
			s := slots[i]
			slot = &s
			break
		}
	}
	if slot == nil {
		return nil, fmt.Errorf("broker: jeton PKCS#11 %q introuvable", opts.TokenLabel)
	}
	session, err := slot.OpenSession()
	if err != nil {
		return nil, fmt.Errorf("broker: ouverture de session PKCS#11: %w", err)
	}
	if err := session.Login(opts.PIN); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("broker: connexion PKCS#11: %w", err)
	}

	privObj, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, opts.KeyLabel),
	})
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("broker: clé privée %q introuvable dans le jeton %q: %w", opts.KeyLabel, opts.TokenLabel, err)
	}
	priv := p11.PrivateKey(privObj)
	pubObj, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, opts.KeyLabel),
	})
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("broker: clé publique %q introuvable dans le jeton %q: %w", opts.KeyLabel, opts.TokenLabel, err)
	}
	pointDER, err := pubObj.Attribute(pkcs11.CKA_EC_POINT)
	if err != nil || len(pointDER) == 0 {
		_ = session.Close()
		return nil, fmt.Errorf("broker: CKA_EC_POINT illisible pour %q: %w", opts.KeyLabel, err)
	}
	pub, err := decodeEdwardsPoint(pointDER)
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("broker: point EdDSA %q illisible: %w", opts.KeyLabel, err)
	}

	return &PKCS11Signer{session: session, priv: priv, pub: pub}, nil
}

// decodeEdwardsPoint décode CKA_EC_POINT — une OCTET STRING ASN.1
// enveloppant le point brut (PKCS#11 v3.0 §2.3.9) — vers les 32 octets
// bruts de la clé publique Ed25519.
func decodeEdwardsPoint(der []byte) (ed25519.PublicKey, error) {
	var raw []byte
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("ASN.1 OCTET STRING: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("point de %d octets, veut %d (Ed25519)", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Sign implémente Signer : CKM_EDDSA pur (pas de prehash) sur le
// Sig_structure COSE exact que coseSignerAdapter présente déjà en clair.
// La clé privée ne quitte jamais le module.
func (s *PKCS11Signer) Sign(content []byte) ([]byte, error) {
	sig, err := s.priv.Sign(*pkcs11.NewMechanism(CkmEddsa, nil), content)
	if err != nil {
		return nil, fmt.Errorf("broker: signature PKCS#11: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("broker: signature PKCS#11 de %d octets, veut %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// Public rapporte la clé publique Ed25519 lue au démarrage (CKA_EC_POINT).
func (s *PKCS11Signer) Public() ed25519.PublicKey {
	return s.pub
}

// Close ferme la session PKCS#11 (déconnexion — la clé ne quitte jamais le
// module, il n'y a rien d'autre à effacer côté process).
func (s *PKCS11Signer) Close() error {
	return s.session.Close()
}
