package pep

// Vérifieur de quorum cryptographique (T15/T14, §5.3) — revue de sécurité
// #89 : l'ancien QuorumVerifier de pepd/main.go comptait des identités
// DÉCLARÉES par l'appelant ("signers": ["x","y"]), sans aucune signature.
// N'importe qui joignant le port de données pouvait donc couper
// l'application des règles (POST /v1/mode → monitor) ou lever une
// condition fail-closed classe W en inventant des noms. Ce fichier
// remplace ce contrôle par k signatures Ed25519 DISTINCTES d'un trousseau
// de contrôleurs épinglé (§12), sur un message qui lie la condition levée
// et une fenêtre de fraîcheur bornée — même doctrine que le quorum k-of-n
// de la classe W du broker (src/cluster/quorum.go, §7.5), adaptée ici à la
// gouvernance locale d'une cellule (pas d'action/resource/epoch à lier,
// juste la condition et la fraîcheur).

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// QuorumMessage est le message canonique signé par chaque contrôleur pour
// gouverner une bascule de posture (§5.3) ou lever une condition
// fail-closed classe W : "TBPQ1" ‖ len(condition) u16 BE ‖ condition ‖
// expiry u64 BE (secondes Unix). Lier la condition ET une fenêtre de
// fraîcheur empêche de rejouer la signature d'un contrôleur pour une AUTRE
// bascule, ou après coup (même patron que ApprovalMessage, §4.2).
func QuorumMessage(condition string, expiry time.Time) []byte {
	cond := []byte(condition)
	msg := make([]byte, 0, 5+2+len(cond)+8)
	msg = append(msg, "TBPQ1"...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(cond)))
	msg = append(msg, cond...)
	return binary.BigEndian.AppendUint64(msg, uint64(expiry.Unix()))
}

// QuorumSignature apparie l'identité d'un contrôleur épinglé (kid, §12) à
// sa signature Ed25519 sur QuorumMessage(condition, proof.Expiry).
type QuorumSignature struct {
	KeyID     [16]byte
	Signature []byte
}

// DefaultQuorumProofTTL borne la fraîcheur d'une preuve de quorum — même
// doctrine que cluster.DefaultMaxProofTTLSeconds (§7.2) : une co-signature
// n'est pas un blanc-seing permanent.
const DefaultQuorumProofTTL = 5 * time.Minute

// NewSignatureQuorumVerifier construit un QuorumVerifier cryptographique :
// k signatures Ed25519 DISTINCTES (trousseau de contrôleurs épinglé, §12)
// sur QuorumMessage(condition, proof.Expiry), preuve fraîche — expiry dans
// (now, now+maxTTL]. Fail-closed dès la configuration (trousseau vide, k
// incohérent, clé mal formée) : aucune valeur par défaut silencieuse pour
// un contrôle de gouvernance (§1).
func NewSignatureQuorumVerifier(keyring map[[16]byte]ed25519.PublicKey, k int, maxTTL time.Duration, now func() time.Time) (QuorumVerifier, error) {
	if len(keyring) == 0 {
		return nil, errors.New("pep: trousseau de contrôleurs épinglé vide (§12 : la gouvernance est une signature, jamais une identité déclarée)")
	}
	if k < 1 || k > len(keyring) {
		return nil, fmt.Errorf("pep: quorum incohérent : k=%d pour %d contrôleurs", k, len(keyring))
	}
	for kid, pub := range keyring {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pep: clé contrôleur %x de %d octets — Ed25519 en exige %d (§12)", kid, len(pub), ed25519.PublicKeySize)
		}
	}
	if maxTTL <= 0 {
		maxTTL = DefaultQuorumProofTTL
	}
	if now == nil {
		now = time.Now
	}
	keys := make(map[[16]byte]ed25519.PublicKey, len(keyring))
	for kid, pub := range keyring {
		keys[kid] = append(ed25519.PublicKey(nil), pub...)
	}

	return func(condition string, proof QuorumProof) bool {
		if proof.Expiry.IsZero() {
			return false
		}
		t := now()
		if !proof.Expiry.After(t) {
			return false // déjà expirée — fail-closed, jamais un blanc-seing
		}
		if proof.Expiry.After(t.Add(maxTTL)) {
			return false // fraîcheur invraisemblable : refusée, pas acceptée « au cas où »
		}
		msg := QuorumMessage(condition, proof.Expiry)
		seen := make(map[[16]byte]bool, len(proof.Signatures))
		valid := 0
		for _, sig := range proof.Signatures {
			if seen[sig.KeyID] {
				continue // même contrôleur compté deux fois : refusé (§7.5, même doctrine que le broker)
			}
			pub, ok := keys[sig.KeyID]
			if !ok {
				continue
			}
			if !ed25519.Verify(pub, msg, sig.Signature) {
				continue
			}
			seen[sig.KeyID] = true
			valid++
		}
		return valid >= k
	}, nil
}
