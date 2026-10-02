package pep

// provisioning_authorize.go — l'autorisation d'une transition de provisionnement, partagée par
// les démons qui mesurent leurs fichiers de confiance (registry.ProvisioningGuard, #192).
//
// pepd et brokerd portent chacun leur copie de cette fermeture ; anod (#272) l'utilise d'ici.
// Même règle partout : la preuve est liée à la condition « base|from=…|to=… » (#236), vérifiée
// contre le trousseau de contrôleurs ET le k ATTESTÉS par le dernier témoin (#218, #224) —
// jamais contre le fichier ou l'environnement que l'attaquant vient d'éditer.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/strictjson"
)

// Noms logiques des fichiers d'autorité de la garde : le témoin conserve leur contenu, et
// l'autorisation les relit sous ces noms.
const (
	ProvisioningQuorumKeyringName  = "quorum-keyring"
	ProvisioningQuorumSettingsName = "quorum-settings"
)

// ParseKeyring décode un trousseau JSON {kid_hex: pub_hex} (§12, épinglé) — celui des
// émetteurs de jetons comme celui des contrôleurs. Séparé du chargement de fichier pour que le
// provisionnement lise le trousseau ATTESTÉ (octets du témoin), pas le fichier courant.
//
// Décodage STRICT (revue tierce du 2 octobre, 4.4 ; même doctrine que #241/#289) : une clé JSON
// dupliquée, un type inattendu ou un contenu final est refusé. Et l'ambiguïté qui survit à la
// syntaxe l'est aussi : deux identifiants qui ne diffèrent que par la casse de l'hexadécimal
// (« AB… » / « ab… ») décodent le MÊME kid — la carte Go d'un décodeur standard en gardait un au
// hasard (3 fois sur 40 la première, 37 la seconde) ; deux kid pour UNE clé publique laisseraient
// une seule signature compter pour deux dans un quorum.
func ParseKeyring(data []byte) (map[[16]byte]ed25519.PublicKey, error) {
	var raw map[string]string
	if err := strictjson.Decode(data, &raw); err != nil {
		return nil, fmt.Errorf("keyring JSON: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("keyring vide (§12)")
	}
	keyring := make(map[[16]byte]ed25519.PublicKey, len(raw))
	seenPub := make(map[string]string, len(raw))
	for kidHex, pubHex := range raw {
		kid, err := hex.DecodeString(kidHex)
		if err != nil || len(kid) != 16 {
			return nil, fmt.Errorf("keyring: kid %q illisible (hex 16 octets)", kidHex)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyring: clé %q illisible (Ed25519)", kidHex)
		}
		var k [16]byte
		copy(k[:], kid)
		if _, dup := keyring[k]; dup {
			return nil, fmt.Errorf("keyring: kid %q en double (même identifiant, casse hexadécimale différente) — refus : laquelle des clés serait retenue est indéterminée", kidHex)
		}
		if other, dup := seenPub[string(pub)]; dup {
			return nil, fmt.Errorf("keyring: la même clé publique sous deux identifiants (%q et %q) — une signature compterait deux fois dans un quorum", other, kidHex)
		}
		seenPub[string(pub)] = kidHex
		keyring[k] = ed25519.PublicKey(pub)
	}
	return keyring, nil
}

// NewProvisioningAuthorizer rend la fermeture AuthorizeTransition d'un démon : condBase est sa
// condition (« provisioning-transition-anod »), proofFile le fichier de preuve de quorum
// (TBP_PROVISIONING_TRANSITION_PROOF_FILE, vide ⇒ aucune preuve). Le refus annonce TOUJOURS la
// condition complète à signer (« ce qu'on voit est ce qu'on signe », #236).
func NewProvisioningAuthorizer(condBase, cellID string, quorumKeyring map[[16]byte]ed25519.PublicKey, quorumMin int, proofFile string) func(prev map[string][]byte, from, to [32]byte) error {
	return func(prev map[string][]byte, from, to [32]byte) error {
		cond := TransitionCondition(condBase, from, to)
		if proofFile == "" {
			return fmt.Errorf("aucune preuve de transition (TBP_PROVISIONING_TRANSITION_PROOF_FILE) ; condition à signer : %s", cond)
		}
		verr := func() error {
			keyring, k := quorumKeyring, quorumMin
			if raw, ok := prev[ProvisioningQuorumKeyringName]; ok {
				attested, err := ParseKeyring(raw)
				if err != nil {
					return fmt.Errorf("trousseau de contrôleurs attesté illisible: %w", err)
				}
				keyring = attested
			}
			// k est LUI AUSSI celui qui était attesté : sinon l'attaquant qui abaisse
			// TBP_QUORUM_MIN dans l'environnement autorise sa transition avec une seule clé (#224).
			if raw, ok := prev[ProvisioningQuorumSettingsName]; ok {
				attestedK, err := ParseQuorumSettings(raw)
				if err != nil {
					return fmt.Errorf("réglages de quorum attestés illisibles: %w", err)
				}
				k = attestedK
			}
			return VerifyQuorumProofFile(proofFile, cond, cellID, keyring, k)
		}()
		if verr != nil {
			return fmt.Errorf("%w ; condition à signer : %s", verr, cond)
		}
		return nil
	}
}
