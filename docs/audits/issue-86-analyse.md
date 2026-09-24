# Revue de sécurité post-#86 (issues #105 à #114)

Synthèse versionnée de la revue de code indépendante qui a produit les dix
issues de sécurité #105 à #114. Ce fichier remplace la référence morte
`notes/issue-86-analyse.md` (fichier de travail local au rapporteur, jamais
versionné) que ces dix issues portaient — voir #131.

Chaque issue ci-dessous reste la source de vérité pour le détail du
constat et du correctif attendu ; ce document n'en est qu'un index avec,
pour chacune, un résumé d'une ligne et le lien vers la Pull Request qui l'a
fermée.

## Méthode

Lecture manuelle du code livré pour #86 (fermeture des trous de sécurité
identifiés lors de la revue de la PR #80), contre le comportement RÉEL des
binaires (OPA, HSM/PKCS#11) plutôt que par lecture de la documentation
seule — même doctrine que §1 de la spec (« never by trust, always by
verifiable proof ») appliquée à la revue elle-même. Certains points n'ont
pas pu être exercés faute d'un HSM disponible (#114) ; ils sont notés
comme tels dans l'issue correspondante.

## Constats et correctifs

| Issue | Constat | Correctif (PR) |
|---|---|---|
| [#105](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/105) | La preuve de quorum « monitor » (5 min de validité) était rejouable : même cellule après redémarrage, ou une autre cellule — la signature ne couvrait ni CellID ni nonce. | [#115](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/115) — preuve liée au CellID + protection anti-rejeu persistante. |
| [#106](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/106) | La vérification de révision OPA n'était qu'une étiquette auto-déclarée au build — n'importe qui pouvait écrire un bundle avec la bonne révision sans preuve d'intégrité. | [#116](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/116) — bundles OPA signés, exigés et vérifiés. |
| [#107](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/107) | Le proxy bloquant n'incluait pas la query string dans la ressource évaluée (`GET /reports?action=delete_all` passait avec un jeton lecture). | [#117](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/117) — ressource liée à `URL.RequestURI()` (chemin + query). |
| [#108](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/108) | Le corps de la requête n'était pas examiné (montant arbitraire acceptable sur `/transfer` avec un jeton écriture). | [#117](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/117) — corps scellé (SHA-256) et vérifié contre `ObjectSeal`. |
| [#109](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/109) | Le jeton TBP était transmis tel quel au backend et écrasait l'en-tête `Authorization`, empêchant le backend de s'authentifier lui-même. | [#117](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/117) — jeton déplacé vers `X-TBP-Token`, toujours retiré avant transmission. |
| [#110](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/110) | Le proxy ouvrait un passeport de quota mais ne le décomptait jamais — seul un appel volontaire (`/v1/passport/consume`) le faisait. | [#123](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/123) — décompte d'un quantum par requête avant transmission, non contournable côté appelant. |
| [#111](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/111) | Effacer/déplacer le registre local remettait `pepd` en posture « monitor » (faux premier démarrage), détruisant la preuve locale. | [#119](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/119) — détection de redémarrage croisée avec le measured boot. |
| [#112](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/112) | Le measured boot était désactivé par défaut, se protégeait par le fichier même qu'il était censé vérifier, et sa référence était réinitialisable sans quorum. | [#119](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/119) — measured boot actif par défaut, transitions gate-ées par quorum. |
| [#113](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/113) | Des échappatoires « dev » (`TBP_OPA_DISABLED_DEV_UNSAFE`, `TBP_OPA_INSECURE_TCP_DEV`, clé d'émission sans drapeau dev) restaient utilisables en production, non détectées par le measured boot. | [#120](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/120) — sentinel hors-fichier-d'environnement requis pour toute échappatoire dev. |
| [#114](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/114) | Le support HSM (PKCS#11) n'était pas exercé par les tests ; pas de vérification que la clé chargée est non-extractible ; PIN stocké en clair sans protection dédiée. | [#121](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/121) — vérification de non-extractibilité au chargement, PIN durci, testé contre SoftHSM2. |

## Suites ouvertes après cette revue

Cette même revue indépendante a par la suite identifié des points hors du
périmètre direct de #105-#114, chacun tracké dans sa propre issue plutôt
que rattaché ici a posteriori : #124, #125 (déjà fermées), et #126, #127,
#128, #129, #130, #131 (l'issue courante) au moment de la rédaction de ce
document.
