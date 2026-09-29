package pep

// token_verifier.go — vérification d'AUTHENTICITÉ d'un jeton par un composant
// qui n'a besoin que d'identifier de quel jeton (donc de quel échange) il
// s'agit : ano (#178). Le composant n'est pas un point de décision — il ne
// tient ni feuilles, ni anti-rejeu, ni époque, ni quota : la décision reste
// au Validator du PEP. Ici, seulement « ce jeton a bien été signé par un
// émetteur épinglé ».
//
// C'est la preuve de POSSESSION (schéma + signature Ed25519, étapes 1-5 du
// schéma §7), la même que /v1/passport/consume exige déjà (revue #90, point
// 3) — jamais une preuve d'AUTORISATION. La fraîcheur est rendue à l'appelant
// (Token.Exp) : ano refuse d'OUVRIR un échange sur un jeton expiré, mais
// accepte de reconstituer une réponse tardive tant que l'échange vit.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

// PossessionVerifier vérifie des jetons contre un trousseau épinglé. Sans
// état mutable : sûr pour un usage concurrent.
type PossessionVerifier struct {
	v   *Validator
	now func() time.Time
}

// NewPossessionVerifier construit le vérificateur. Fail-closed : trousseau
// vide refusé (§12 — aucune résolution dynamique de clé). now nil ⇒ time.Now.
func NewPossessionVerifier(keyring map[[16]byte]ed25519.PublicKey, now func() time.Time) (*PossessionVerifier, error) {
	if len(keyring) == 0 {
		return nil, errors.New("pep: trousseau épinglé vide (§12)")
	}
	if now == nil {
		now = time.Now
	}
	kr := make(map[[16]byte]ed25519.PublicKey, len(keyring))
	for k, v := range keyring {
		kr[k] = v
	}
	// verifySignedToken ne lit que le trousseau : le Validator n'est ici
	// qu'un porteur de cette vérification, jamais utilisé pour décider.
	return &PossessionVerifier{v: &Validator{keyring: kr}, now: now}, nil
}

// Verify vérifie schéma et signature, et rend le jeton décodé. Il ne juge PAS
// la fraîcheur : voir Fresh.
func (p *PossessionVerifier) Verify(wire []byte) (*Token, error) {
	return p.v.VerifyPossession(wire)
}

// Fresh rend une erreur si le jeton est expiré à l'horloge du vérificateur.
func (p *PossessionVerifier) Fresh(tok *Token) error {
	if tok == nil {
		return errors.New("pep: jeton absent")
	}
	if exp := time.Unix(tok.Exp, 0); !p.now().Before(exp) {
		return fmt.Errorf("pep: jeton expiré (exp=%d)", tok.Exp)
	}
	return nil
}
