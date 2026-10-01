package pep

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// quorumProofFile est la forme JSON d'une preuve de quorum posée dans un
// fichier — MÊME forme que le corps de POST /v1/mode (ModeChangeRequest) : k
// signatures Ed25519 distinctes du trousseau de contrôleurs épinglé (§12) sur
// QuorumMessage(condition, cellID, expiry). Un fichier, pas un POST HTTP : les
// décisions qui se prennent AU DÉMARRAGE (transition du démarrage mesuré,
// transition du provisionnement, #192) précèdent l'existence du listener.
type quorumProofFile struct {
	Expiry     int64                `json:"expiry"`
	Signatures []quorumProofSigWire `json:"signatures"`
}

type quorumProofSigWire struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// TransitionCondition lie une condition de transition à l'état de départ ET à
// l'état cible : « base|from=<hex>|to=<hex> » (issue #236). Les contrôleurs
// signent donc CE QUE le démon va engager : une preuve valide ne vaut que pour
// la paire (attesté, cible) — sur un autre état cible le message signé diffère
// et la vérification échoue d'elle-même, et une fois la transition faite
// (l'attesté devient la cible) la même preuve ne peut plus ramener à l'état
// précédent. from nul = pas d'état attesté (premier engagement après perte du
// témoin). Le condensé est celui que le démon affiche en refusant, et que
// `quorumproof` montre avant de signer.
func TransitionCondition(base string, from, to [32]byte) string {
	return fmt.Sprintf("%s|from=%x|to=%x", base, from, to)
}

// VerifyQuorumProofFile lit et vérifie le fichier de preuve pour UNE condition.
// La condition est liée par la signature : une preuve pour « mode-closed » ne vaut
// jamais pour une transition de provisionnement, ni celle de pepd pour brokerd
// (conditions distinctes par démon). k = 1 est le profil d'échelle 1 (l'administrateur
// seul signe) ; k > 1 un quorum de contrôleurs — c'est TBP_QUORUM_MIN qui règle.
func VerifyQuorumProofFile(path, condition, cellID string, keyring map[[16]byte]ed25519.PublicKey, k int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("preuve de quorum illisible (%s): %w", path, err)
	}
	var pf quorumProofFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("preuve de quorum (%s) mal formée: %w", path, err)
	}
	sigs := make([]QuorumSignature, 0, len(pf.Signatures))
	for _, s := range pf.Signatures {
		kid, err := hex.DecodeString(s.KeyID)
		if err != nil || len(kid) != 16 {
			return errors.New("preuve de quorum: key_id illisible (hex 16 octets)")
		}
		sig, err := hex.DecodeString(s.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return errors.New("preuve de quorum: signature illisible (hex 64 octets Ed25519)")
		}
		var kidArr [16]byte
		copy(kidArr[:], kid)
		sigs = append(sigs, QuorumSignature{KeyID: kidArr, Signature: sig})
	}
	verify, err := NewSignatureQuorumVerifier(cellID, keyring, k, DefaultQuorumProofTTL, nil)
	if err != nil {
		return fmt.Errorf("quorum: %w", err)
	}
	if !verify(condition, QuorumProof{Expiry: time.Unix(pf.Expiry, 0), Signatures: sigs}) {
		return errors.New("preuve de quorum rejetée (signatures insuffisantes, invalides, ou expirées)")
	}
	return nil
}
