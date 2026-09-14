# Glossaire de normalisation TBP

Extrait de référence rapide du §14 de [`spec-v1.4.2.md`](./spec-v1.4.2.md) — la
source de vérité reste ce fichier-là ; celui-ci existe pour être lié/grep-é
sans rouvrir toute la note technique. Un terme canonique par concept ; les
synonymes rencontrés dans les documents amont (manifeste réseau, références
de déploiement, discussions) sont mappés dessus — **le code et la
documentation de ce dépôt doivent utiliser la colonne « Terme canonique »**,
jamais un synonyme, y compris dans les commentaires et les noms de
variables/champs quand c'est raisonnable.

| Terme canonique | Synonymes mappés | Définition |
|---|---|---|
| cellule | TBP Cellule, enclave, edge | broker + registre local + politiques propres ; état par cellule |
| superviseur | TBP Supervisor, core, egress | cellule à périmètre élargi + registre maître ; jamais une boîte noire |
| maîtresse | master chain, chaîne centrale | agrégation des têtes de cellules, ancrée |
| collection référencée | règles ABC (standard), profils | règles publiques versionnées, hashées, épinglées |
| règles propres | règles XYZ, règles maison | règles locales signées, non révélées |
| passeport | sésame, capacité, token de session | token à quota (ressource, opération, volume, fenêtre, TTL, jti) |
| traitement différencié | couloir surveillé, verdict binaire | attesté / strict / refus selon l'état présenté |
| époque | epoch, fencing, jeton d'autorité | période d'autorité signée, TTL, révocable |
| traducteur | garde sémantique, traducteur local | IA locale produisant l'action exécutée |
| manifeste | état attesté, measured state | vecteur mesuré de la pile gouvernée (§6.3) |
| trou instrumenté | capteur, canal instrumenté | chemin hors mur dont la télémétrie alimente le registre |

**Ajouter un terme** : modifier d'abord le tableau du §14 dans
`spec-v1.4.2.md` (c'est la source), puis répercuter ici. Les deux tableaux
doivent rester identiques mot pour mot.
