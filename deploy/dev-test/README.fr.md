# deploy/dev-test — essayer TBP, l'attaquer, et nous dire ce qui s'est passé

_English version: [README.md](README.md)._

> **Pas pour la production.** Tout ici utilise des clés jetables, sur des machines que vous pouvez perdre, sans
> donnée réelle et sans agent réel derrière. Cela existe pour que vous puissiez essayer de casser TBP avant qu'une
> release de production ne le fasse.

TBP est fait pour être lancé, et attaqué, avant d'être cru. Cette page est la porte d'entrée : un déploiement assez
simple pour être monté en quelques minutes — les clés, la genèse et les règles sont générées pour vous — et qui fait
pourtant tourner **les vrais binaires avec la vraie application des règles** : le même quorum, les mêmes rôles, les
mêmes règles signées, les mêmes démarrages fail-closed. Plus il y a de gens qui cherchent à le casser maintenant,
moins une release de production portera de failles. La CI et le selftest demandent si le code est sain ; ceci
demande si l'ensemble **fonctionne**, et si vous pouvez passer à travers.

## Deux façons de le lancer

| | **Site** — trois machines | **Solo** — une machine |
|---|---|---|
| Page | **[site.fr.md](site.fr.md)** | [solo.fr.md](solo.fr.md) |
| Ce qui tourne | M1 la cellule (`brokerd`, OPA), M2 un serveur applicatif (`pepd`, une petite application), M3 un agent | la cellule seule (`brokerd`, OPA) |
| Ce que cela teste | **que ça marche de bout en bout** : un agent inscrit par son certificat, une décision en TLS mutuel, un jeton vérifié par un serveur, la posture du serveur gouvernée par les contrôleurs — et le réseau entre eux | la décision de la cellule : admission, plans, quorum, règles signées, démarrage fail-closed |
| Ce que cela ne teste pas | la garde des clés, la séparation entre de vraies personnes, une cérémonie de genèse | les jetons chez un serveur, l'inscription, le réseau |
| Pour | le test fonctionnel et le red team : **c'est la release DEV-TEST** | un coup d'œil rapide à la cellule |

Si vous n'essayez qu'une chose, essayez le site : c'est celui qui correspond à la façon dont TBP se déploie.

## Ce qui est simplifié, et ce qui ne l'est pas

| | Dans les deux | Pourquoi |
|---|---|---|
| Clés, genèse | générées pour vous, sans cérémonie ni HSM | **simplifié** : la garde des clés et la séparation de vraies personnes ne sont pas testées ici |
| Trace de décision | profil Site seulement : chaque machine consigne les requêtes qu'elle voit, `m1 trace` les présente (qui a demandé, ce que chaque composant a décidé, pourquoi) | **ajouté pour le test**, un second interrupteur de développement sur la cellule (la trace contient noms et intentions en clair) ; `pepd` n'est pas modifié |
| Clé d'émission | un fichier de graine au lieu d'un HSM — sur la cellule seulement | **simplifié**, un interrupteur de développement utilisé : la cellule déclare `/etc/tbp/DEV_ENVIRONMENT` et lève une alarme de haute priorité à chaque démarrage |
| Quorum, rôles | `k = 2` sur 3 contrôleurs, quatre clés d'opérateur avec rôles | **non simplifié** |
| Règles | le bundle d'exemple, capabilities restreintes, signé ; OPA refuse un bundle altéré | **non simplifié** |
| Provisionnement, démarrage mesuré | actifs : un fichier de confiance ou une échelle modifiés arrêtent le démarrage | **non simplifié** |

## Nous dire ce que vous avez trouvé

Nous voulons vos chiffres et vos commentaires — y compris « je suis resté bloqué ici » — **pour chaque environnement
que vous essayez**.

- **Chiffres.** Chaque machine a une commande `report` (`scripts/devtest/site.sh m1|m2|m3 report`, ou
  `scripts/devtest/devtest.sh report` pour solo). Elle note le système, les versions, les durées, les compteurs et les
  latences, et l'étiquette d'environnement libre que vous avez donnée à `init`, pour que nous distinguions les
  environnements. Elle ne contient aucune clé, graine, chemin, adresse ni nom de machine. Collez-la.
- **Commentaires.** Une issue GitHub publique, avec le modèle **Dev-test feedback** (le titre commence par
  `[dev-test]`) : une étape qui ne marche pas, une doc fausse, un comportement différent de ce qui est écrit, vos
  durées, une suggestion. Ce qui la rend utile : la commande exacte, ce que vous attendiez, ce qui s'est passé, et les
  rapports.
- **Tout ce qui est exploitable** — un moyen de passer un refus, une acceptation silencieuse, un secret qui fuit —
  va **en privé**, comme le dit [SECURITY.md](../../SECURITY.md), pas dans une issue publique.

Les limites connues sont écrites dans le [README](../../README.md) (« Honesty about where this stands »), dans
[CHANGELOG.md](../../CHANGELOG.md) et dans [governed-acts.fr.md](../governed-acts.fr.md) : une trouvaille qui en fait
partie est bienvenue comme issue ordinaire.
