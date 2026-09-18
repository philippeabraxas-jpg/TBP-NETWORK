// src/registry/leaf.go — T4 (issue #8)
//
// Format de feuille du registre de cellule (§6.2, par analogie §4.5) :
// HASH-ONLY. Aucun contenu métier en clair ne transite par le registre —
// la feuille ne porte que le hash SALÉ du contenu (décision PEP,
// télémétrie…), l'identité de la cellule, le type et l'horodatage.
//
// Sérialisation binaire à layout fixe (déterministe, §11.3) :
//
//	offset 0      version      1 octet   = 0x01
//	offset 1      kind         1 octet   (KindDecision=1, KindTelemetry=2, KindBackpressure=3)
//	offset 2      timestamp    8 octets  int64 big-endian, ns depuis epoch Unix (horloge NTS de la cellule)
//	offset 10     cellIDLen    1 octet   longueur de cellID (≤ 255)
//	offset 11     cellID       cellIDLen octets (UTF-8)
//	suivant       payloadHash  32 octets sha256(salt ‖ contenu)
//
// Le sel N'EST PAS dans la feuille : il reste chez le producteur (c'est ce
// qui rend le hash non inversable par un lecteur du registre — §6.2 GDPR /
// rétention). Pour prouver ultérieurement qu'une feuille correspond à un
// contenu, le producteur révèle (sel, contenu) et l'auditeur re-hash.
package registry

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Types de feuilles (octet kind).
const (
	KindDecision     byte = 1 // feuille de décision du PEP
	KindTelemetry    byte = 2 // enregistrement de télémétrie
	KindBackpressure byte = 3 // arrêt propre avant engagement du backpressure (T5)
)

// leafVersion est la version du format de sérialisation.
const leafVersion byte = 0x01

// maxCellIDLen borne cellID pour tenir dans le champ de longueur d'un octet.
const maxCellIDLen = 255

// Leaf est une feuille du registre — hash-only, jamais de contenu en clair.
type Leaf struct {
	Kind        byte     // KindDecision | KindTelemetry | KindBackpressure
	CellID      string   // identité de la cellule émettrice
	PayloadHash [32]byte // sha256(salt ‖ contenu métier) — le sel reste chez le producteur
	Timestamp   int64    // ns depuis epoch Unix, horloge NTS de la cellule
}

// HashPayload calcule le hash salé du contenu métier : sha256(salt ‖ payload).
// Le sel (≥ 16 octets aléatoires, généré par le producteur) ne doit JAMAIS
// être écrit dans le registre ; il est conservé à part pour les preuves.
func HashPayload(salt, payload []byte) [32]byte {
	h := sha256.New()
	h.Write(salt)
	h.Write(payload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Marshal sérialise la feuille selon le layout documenté ci-dessus.
func (l Leaf) Marshal() ([]byte, error) {
	if len(l.CellID) == 0 || len(l.CellID) > maxCellIDLen {
		return nil, fmt.Errorf("cellID : longueur %d hors [1, %d]", len(l.CellID), maxCellIDLen)
	}
	switch l.Kind {
	case KindDecision, KindTelemetry, KindBackpressure:
	default:
		return nil, fmt.Errorf("kind %d inconnu", l.Kind)
	}
	buf := make([]byte, 0, 1+1+8+1+len(l.CellID)+32)
	buf = append(buf, leafVersion, l.Kind)
	buf = binary.BigEndian.AppendUint64(buf, uint64(l.Timestamp))
	buf = append(buf, byte(len(l.CellID)))
	buf = append(buf, l.CellID...)
	buf = append(buf, l.PayloadHash[:]...)
	return buf, nil
}

// UnmarshalLeaf est l'inverse de Marshal — lecture/audit (tests, T6, preuves).
func UnmarshalLeaf(data []byte) (Leaf, error) {
	var l Leaf
	if len(data) < 1+1+8+1+32 {
		return l, fmt.Errorf("feuille trop courte : %d octets", len(data))
	}
	if data[0] != leafVersion {
		return l, fmt.Errorf("version de feuille %d inconnue (attendu %d)", data[0], leafVersion)
	}
	l.Kind = data[1]
	switch l.Kind {
	case KindDecision, KindTelemetry, KindBackpressure:
	default:
		return l, fmt.Errorf("kind %d inconnu", l.Kind)
	}
	l.Timestamp = int64(binary.BigEndian.Uint64(data[2:10]))
	idLen := int(data[10])
	if idLen == 0 {
		// Marshal refuse un CellID vide (voir plus haut) : une feuille
		// bien formée n'en produit jamais. Sans ce garde, un flux
		// d'octets forgé à la main (idLen=0) passait le seul contrôle de
		// longueur ci-dessous et ressortait avec un CellID vide — brèche
		// de symétrie avec Marshal, pas une feuille que ce format admet.
		return l, fmt.Errorf("cellID vide : longueur annoncée 0")
	}
	if len(data) != 1+1+8+1+idLen+32 {
		return l, fmt.Errorf("longueur incohérente : %d octets, cellID annoncé %d", len(data), idLen)
	}
	l.CellID = string(data[11 : 11+idLen])
	copy(l.PayloadHash[:], data[11+idLen:])
	return l, nil
}
