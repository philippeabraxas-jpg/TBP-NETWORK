# deploy/scales.fr.md — briques de sécurité par échelle (issue #86)

_English version: [scales.md](scales.md)._

TBP se déploie à plusieurs échelles. On ne le **réécrit pas** pour chacune :
une seule base de code, et une échelle est un **réglage de briques de
sécurité** — certaines activées, d'autres non, d'autres à une force
différente. Cette page en est la liste. Chaque ligne nomme le réglage qui
existe aujourd'hui : un profil se lit dans un fichier d'environnement, un
bundle signé ou un registre, jamais dans un second produit.

Guides par échelle : [scale-1.fr.md](scale-1.fr.md) (une machine,
l'administrateur seul). L'échelle 2 (petit site) est suivie dans #86 ; les
échelles 3 et complète suivent les guides multi-cellules
([cellule.fr.md](cellule.fr.md), [superviseur.fr.md](superviseur.fr.md)) et le
handshake pleine échelle (#33).

## Où vit un profil

Un profil n'est **pas un nouveau fichier**. C'est l'ensemble des valeurs
ci-dessous, aux endroits où le code les lit déjà. Conséquence : rien de
nouveau à faire confiance, rien de nouveau à mesurer — le témoin de
provisionnement (#192) couvre déjà les trousseaux et registres, et le bundle
signé porte déjà les réglages Rego.

Pas encore fait : une feuille d'audit au démarrage qui consigne les réglages
effectifs, pour que « quel profil cette cellule appliquait-elle ce jour-là »
se lise dans le journal et non dans la mémoire d'un admin. Suivi dans #86.

## Les briques

| Brique | Réglage | Échelle 1 (admin seul) | Échelle 2 (petit site) | Échelle 3 (multi-cellules) | Complète |
|---|---|---|---|---|---|
| Quorum des actes gouvernés (posture, provisionnement, démarrage mesuré, classe W) | `TBP_QUORUM_MIN` + trousseau de quorum | **k = 1**, une clé d'administrateur | k ≥ 2 recommandé | k-sur-n, contrôleurs en HSM | défini au handshake (#33) |
| Topologie / fencing | `TBP_TOPOLOGY` | `mono` (pas de bail d'époque) | `mono` ou `multi` | `multi`, bail d'époque renouvelé m-sur-n (#197) | `multi` |
| Broker (`brokerd`) | `TBP_BROKER_*` | absent | présent | présent, un par cellule | présent |
| Listener réseau mTLS | `TBP_BROKER_TLS_*` | absent (socket Unix) | requis si agents distants | requis, CA dédiée aux agents | requis |
| Registre de skills + paliers | `TBP_SKILL_REGISTRY_FILE`, bundle `require_skill_registry` | sans objet (pas de broker) | recommandé, **poser `require_skill_registry`** | requis | requis |
| Périmètre par agent | bundle `agent_scope.require_agent_scope` | sans objet (pas de broker) | recommandé | requis | requis |
| Gestion des fautes OPA | `TBP_OPA_TRIP_AFTER`, `TBP_OPA_AUTOCLEAR_PROBES` | défauts (3 / 3) | défauts | défauts ; un second backend OPA est prévu | défini au handshake (#33) |
| Témoin de provisionnement | `TBP_PROVISIONING_WITNESS_FILE` | requis (l'admin signe un changement) | requis | requis | requis |
| Démarrage mesuré | `TBP_MEASURED_BOOT_*` | requis | requis | requis | requis |
| Superviseur / moniteur indépendant | `superviseur.md` | absent | optionnel | requis | requis |
| Transport inter-cellules chiffré | #187 | sans objet | sans objet | requis | requis |
| Règles inaliénables | (à définir) | à définir | à définir | à définir | à définir au handshake (#33) |

« sans objet » veut dire que la brique n'a rien à quoi s'accrocher à cette
échelle, pas qu'on l'a oubliée. « recommandé » et « requis » sont la
préconisation de ce dépôt ; le code fait respecter ceux qui ont un réglage
qui refuse de démarrer sans lui.

## Ce qu'aucune échelle ne peut désactiver

Ces briques n'ont pas d'interrupteur en production. Les seuls contournements
sont les drapeaux `*_DEV_UNSAFE` / `*_INSECURE_*_DEV`, qui exigent le sentinel
`DEV_ENVIRONMENT` à un chemin câblé dans les binaires (#113) et sont donc
refusés en production :

- refus par défaut et fail-closed au moindre doute ;
- feuilles hash-only avec un sel qui reste sur la machine (§6.2) ;
- OPA obligatoire, authentifié par le noyau, sur un bundle signé dont la
  révision est épinglée et revérifiée (#92, #106) ;
- redémarrage = `refused` jusqu'à ce qu'un quorum reconfirme une posture (#93) ;
- une approbation de plan pour les classes F, I et W (la classe W ajoute le
  quorum) ;
- le témoin de provisionnement et le démarrage mesuré au démarrage (#112, #192).

Une échappatoire dev est refusée sans le sentinel, et quand elle est acceptée
elle laisse une feuille de télémétrie dans le registre de la cellule (issue
#208 : les noms des échappatoires actives, hash seulement) — jamais seulement
une ligne de log.

Cette liste est le point de départ des « règles inaliénables » que le
handshake pleine échelle définira ; c'est ce qui existe dans le code
aujourd'hui, pas une décision. Savoir si une brique peut être relâchée à une
échelle donnée est une décision consignée ici, brique par brique, dans la PR
qui la change.

## Limite connue : le registre de skills est propre au déploiement (#195)

Un agent qui ne passe pas par `brokerd` n'a ni registre de skills ni
`input.skill` ; le paquet de paliers de skills ne dit alors rien. C'est
pourquoi `require_skill_registry` est un réglage explicite par échelle
ci-dessus et non un défaut : l'activer partout où `brokerd` fait front aux
agents. Il n'y a pas d'escalade au-delà du plancher `risk_tier` pour les
classes I et W.

## Décisions consignées

- **R-12 — `risk_tier` d'un skill face à la classe de l'agent : affaire de déploiement (#210).** Le
  registre ne recoupe pas le palier d'un skill avec la classe de l'agent qui l'appelle, et TBP
  n'ajoutera pas une seconde escalade au-dessus du paquet : un agent enregistré hors F/I/W qui appelle un
  skill provisionné `critical` est retenu par `tbp.pack.skill_tier` (`high` exige la classe I ou W,
  `critical` exige W), **à condition que le déploiement charge le paquet et pose
  `require_skill_registry`**. C'est le réglage par échelle du tableau ci-dessus ; le résidu est le même
  que pour #195 et se ferme de la même façon (enregistrer en classe W tout agent capable d'un acte
  irréversible ; donner `risk_tier: critical` à tout skill irréversible ; relire le fichier de registre,
  que le témoin de provisionnement #192 protège). Décidé avec l'auteur après la revue red team ; aucun
  code.
- **#181 — profil comportemental par séquence : après l'échelle 2.** La détection de salami /
  décomposition, des anomalies de coût et un plafond de coût par exécution demandent du vrai trafic
  multi-agents pour être spécifiés, et le passage à l'échelle ouvrira des besoins qu'on ne voit pas
  encore. Ce n'est donc **pas** une brique de l'échelle 2 : les lignes de catalogue qui en dépendent
  restent 🔴, suivies dans #181, et seront rouvertes quand le labo de l'échelle 2 aura produit des
  données pour concevoir.
