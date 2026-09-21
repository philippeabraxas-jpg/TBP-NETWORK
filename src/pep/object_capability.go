// object_capability.go — T36 (issue #62) : le sceau objet-capacité
// généralisé (§4.4(2), décision D102).
//
// « Object-capabilities (token sealed to object/field/value hashes) » :
// le primitif existait bout-en-bout — claim −5 du schéma (T8),
// comparaison d'égalité dans le validateur (T9), transport traducteur →
// broker → issuer — mais RIEN ne le calculait hors du cas PostgreSQL
// (T16). Ce fichier est le contrat général de calcul, pour tout
// composant métier.
//
// Forme canonique (D102) — séparation de domaine « TBPO1 » (tag vérifié
// libre au moment de l'écriture contre le grep exhaustif des tags TBP*,
// revue #62) :
//
//	SHA-256("TBPO1" ‖ u8 len(cellID) ‖ cellID ‖ policyID(32) ‖ u16 BE n
//	        ‖ par champ trié (object, field) :
//	            u16 BE len(object) ‖ object
//	            ‖ u16 BE len(field) ‖ field
//	            ‖ u32 BE len(value) ‖ value)
//
// Même motif que T30 (HashPlan, domaine « TBPC1 ») : SHA-256 sur forme
// canonique à longueurs préfixées, AUCUNE map (déterminisme §11.3). Le
// tri est imposé par la fonction — l'appelant fournit les champs dans
// n'importe quel ordre, deux appels aux mêmes champs donnent le même
// sceau.
//
// Réconciliation T16 (D103) — un motif, TROIS domaines, à ne JAMAIS
// fusionner :
//
//   - « TBPO1 » (ici) : capacité sur un objet métier (objet/champ/valeur)
//     — protège l'EFFET d'une action isolée (§4.4(2)) ;
//   - extension PostgreSQL T16 (tbp_pg.c:346) : sceau de PLAN requête —
//     SHA-256(nodeToString(PlannedStmt) ‖ par paramètre lié : 0x1F ‖ oid
//     ‖ 0x1F ‖ (valeur texte | "NULL")) — protège la requête finalisée,
//     paramètres liés compris (trou PREPARE/EXECUTE) ;
//   - « TBPC1 » (T30, plan_contract.go) : sceau de plan d'ARBITRAGE
//     multi-étapes — protège la cohérence exécution ↔ plan montré à
//     l'humain (§4.2).
//
// Un sceau de plan n'est pas une capacité-objet : les unifier ferait
// qu'un hash calculé pour l'un serait accepté pour l'autre — exactement
// ce que la séparation de domaine existe pour empêcher. La cohérence est
// prouvée par un test croisé (object_capability_test.go), pas par
// fusion.
//
// Hash-only (§6.2) : la valeur n'entre QUE dans ce hash — jamais dans
// une feuille, jamais dans un journal. Le validateur (T9) ne compare que
// des sceaux ; ce qui est scellé reste chez le producteur.
package pep

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Bornes du contrat (§4.3 : état borné ; cohérentes avec l'existant —
// maxResourceLen=1024, maxIssSubActionLen=255, MaxPlanParamsBytes=4096).
const (
	// MaxSealFields borne le nombre de champs d'un sceau.
	MaxSealFields = 64
	// MaxSealObjectLen borne l'identifiant d'objet (comme une resource).
	MaxSealObjectLen = 1024
	// MaxSealFieldLen borne le nom de champ (comme une action).
	MaxSealFieldLen = 255
	// MaxSealValueLen borne la valeur opaque d'un champ.
	MaxSealValueLen = 4096
	// maxSealCellIDLen borne l'identifiant de cellule (u8 dans le sceau).
	maxSealCellIDLen = 255
)

// ErrSealBounds : une entrée dépasse les bornes du contrat — refus
// explicite à la construction, JAMAIS de troncature silencieuse (un
// sceau tronqué scellerait autre chose que ce que croit le producteur).
var ErrSealBounds = errors.New("pep: sceau objet-capacité hors bornes (§4.3)")

// ObjectField est un champ scellé : objet métier, nom de champ, valeur
// OPAQUE (le PEP ne l'interprète pas — no-DPI ; elle n'entre que dans
// le hash).
type ObjectField struct {
	Object string
	Field  string
	Value  []byte
}

// ComputeObjectSeal calcule le sceau §4.4(2) d'un ensemble de champs
// (D102). Déterministe : tri canonique interne (object, field) — deux
// appels aux mêmes champs donnent le même sceau quel que soit l'ordre
// fourni. Toute entrée hors bornes = ErrSealBounds (fail-closed).
func ComputeObjectSeal(cellID string, policyID [32]byte, fields []ObjectField) ([32]byte, error) {
	var zero [32]byte
	if len(cellID) == 0 || len(cellID) > maxSealCellIDLen {
		return zero, fmt.Errorf("%w : cellID=%d octets", ErrSealBounds, len(cellID))
	}
	if len(fields) > MaxSealFields {
		return zero, fmt.Errorf("%w : %d champs > %d", ErrSealBounds, len(fields), MaxSealFields)
	}
	// Copie avant tri : ne jamais muter la slice de l'appelant.
	sorted := make([]ObjectField, len(fields))
	copy(sorted, fields)
	for _, f := range sorted {
		if len(f.Object) == 0 || len(f.Object) > MaxSealObjectLen {
			return zero, fmt.Errorf("%w : object=%d octets", ErrSealBounds, len(f.Object))
		}
		if len(f.Field) == 0 || len(f.Field) > MaxSealFieldLen {
			return zero, fmt.Errorf("%w : field=%d octets", ErrSealBounds, len(f.Field))
		}
		if len(f.Value) > MaxSealValueLen {
			return zero, fmt.Errorf("%w : value=%d octets", ErrSealBounds, len(f.Value))
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Object != sorted[j].Object {
			return sorted[i].Object < sorted[j].Object
		}
		return sorted[i].Field < sorted[j].Field
	})

	h := sha256.New()
	h.Write([]byte("TBPO1"))
	h.Write([]byte{byte(len(cellID))})
	h.Write([]byte(cellID))
	h.Write(policyID[:])
	var buf [4]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(sorted)))
	h.Write(buf[:2])
	for _, f := range sorted {
		binary.BigEndian.PutUint16(buf[:2], uint16(len(f.Object)))
		h.Write(buf[:2])
		h.Write([]byte(f.Object))
		binary.BigEndian.PutUint16(buf[:2], uint16(len(f.Field)))
		h.Write(buf[:2])
		h.Write([]byte(f.Field))
		binary.BigEndian.PutUint32(buf[:4], uint32(len(f.Value)))
		h.Write(buf[:4])
		h.Write(f.Value)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
