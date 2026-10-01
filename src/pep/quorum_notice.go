package pep

import "fmt"

// QuorumResilienceNotice rend l'avertissement de démarrage sur un quorum fragile, ou ""
// (issue #199, deploy/recovery.md). Deux fragilités distinctes :
//
//   - k = 1 : une seule clé signe tout acte gouverné — pas de séparation des devoirs, et sa
//     fuite vaut contrôle total. C'est le profil d'ÉCHELLE 1, assumé : un avertissement, pas
//     un refus (comme #113 pour les échappatoires de dev, mais ici le réglage est légitime).
//   - n = k (aucune clé de rechange) : la perte d'UNE seule clé de contrôleur fait perdre le
//     quorum — la cellule ne peut plus rien signer, et la reprise est une réinstallation.
//
// n est le nombre de contrôleurs épinglés (trousseau de quorum ou manifeste de genèse).
func QuorumResilienceNotice(daemon string, k, n int) string {
	switch {
	case k <= 1:
		return fmt.Sprintf("%s: AVERTISSEMENT quorum k=1 (%d contrôleur(s) épinglé(s)) : une seule clé signe tout acte gouverné — profil d'échelle 1 assumé ; sa perte fait perdre le quorum (reprise : deploy/recovery.md), sa fuite vaut contrôle total. Copie hors machine OBLIGATOIRE (#199)", daemon, n)
	case n <= k:
		return fmt.Sprintf("%s: AVERTISSEMENT quorum %d-sur-%d sans clé de rechange : la perte d'UNE clé de contrôleur fait perdre le quorum (reprise : deploy/recovery.md). Prévoir n ≥ k+1 (#199)", daemon, k, n)
	}
	return ""
}
