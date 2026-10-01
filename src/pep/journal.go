package pep

// journal.go — #275 : les feuilles de décision du PEP laissent leur clair dans
// le journal d'enregistrements du démon (registry.RecordStore, #271), vérifiable
// ensuite avec `tbp-audit verify`.
//
// Chaque producteur de feuille de décision (validateur, client OPA, quota,
// dry-run) porte un champ Journal. Renseigné (pepd le renseigne toujours),
// le clair est journalisé AVANT la feuille : journal refusé ⇒ aucune feuille,
// donc le chemin « feuille non écrite » existant s'applique (un allow devient
// un deny, ReasonLeafWriteFailed — pas de preuve, pas d'accès). Absent
// (bibliothèque, tests), le comportement historique est conservé : feuille
// nue, clair introuvable. La couture reste donc optionnelle ici ; l'obligation
// vit dans pepd, qui refuse de démarrer sans journal.

import (
	"context"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// appendLeaf inscrit la feuille (kind, cellID, hash salé de record, ts) et, si
// journal != nil, journalise d'abord (sel, record).
func appendLeaf(ctx context.Context, sink LeafSink, journal *registry.RecordStore, kind byte, cellID string, salt, record []byte, ts int64) (uint64, error) {
	return registry.AppendLeaf(ctx, sink, journal, kind, cellID, salt, record, ts)
}
