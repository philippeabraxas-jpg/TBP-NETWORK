# deploy/scale-2.fr.md — échelle 2 : un petit site derrière un seul `brokerd` (issue #86)

_English version: [scale-2.md](scale-2.md)._

L'échelle 2 est une petite équipe ou un petit site : quelques machines (serveurs applicatifs, agents) derrière
**un** `brokerd`, un seul registre, un seul administrateur — avec un **vrai quorum** : `k = 2` sur `n = 3`
contrôleurs, de sorte qu'aucune clé seule ne signe un acte gouverné et que la perte d'une clé ne ferme pas la
cellule ([recovery.fr.md](recovery.fr.md)). C'est le même TBP qu'à toutes les autres échelles, avec un autre
réglage des briques de sécurité : [scales.fr.md](scales.fr.md) les liste, et ce guide est la colonne « échelle 2 »
rendue exécutable.

Ce que l'échelle 2 ajoute à [scale-1.fr.md](scale-1.fr.md) :

| | Échelle 1 | Échelle 2 |
|---|---|---|
| Quorum | `k = 1`, une clé, `n = 1` | `k = 2` sur `n = 3` — une clé de rechange |
| `brokerd` | absent | présent : identité, classe et quota résolus par la cellule, jamais par l'agent |
| Classe W | sans objet | exige un plan **et** 2 contrôleurs |
| Agents | locaux | locaux, ou distants en mTLS ([cellule.fr.md](cellule.fr.md), #124) |
| Topologie | `mono` | `mono` (ce guide) — `multi` est l'échelle 3 |
| Superviseur | absent | optionnel ([superviseur.fr.md](superviseur.fr.md)) |

> La phase `scale2` de `deploy/selftest/` exécute les étapes 1 à 6 de ce guide contre les vrais binaires
> (`go run ./deploy/selftest -phase scale2`), avec les commandes `quorumproof` écrites ci-dessous. Si une
> commande diverge du selftest, le selftest casse : corriger le guide ou le code, jamais l'un dans le dos de
> l'autre. L'étape 7 (agents distants en mTLS, `pepd` des serveurs applicatifs) n'est **pas** exécutée par cette
> phase — voir sa note.

#### Étape 1 — Base : machine, binaires, OPA

**Prérequis vérifiable** : une machine Debian pour la cellule, `go` (la version épinglée par `go.mod`) et `opa`
dans le `PATH`.

**Commande** : suivre [cellule.fr.md](cellule.fr.md) **étapes 1 à 5** (machine, capabilities OPA restreintes,
bundle signé, OPA sur sa socket Unix), puis compiler les deux binaires de ce guide :

```bash
go build -o /usr/local/bin/brokerd ./src/broker/cmd/brokerd
go build -o /usr/local/bin/quorumproof ./src/pep/cmd/quorumproof
```

**Critère de succès observable** : `curl -s --unix-socket /run/tbp/opa.sock http://localhost/health` répond 200
avec la signature du bundle vérifiée ; les deux binaires sont en place.

**En cas d'échec : STOP** — ne pas démarrer `brokerd` contre un OPA qui n'a pas vérifié la signature du bundle.

#### Étape 2 — Trois contrôleurs, `k = 2`

**Prérequis vérifiable** : étape 1 verte ; un répertoire `/etc/tbp/keys` en 0700 ; **trois personnes ou trois
lieux** pour garder les clés de contrôleurs (une clé logicielle est le plancher de l'échelle 2 ; les mettre en
HSM dès que le site le peut — [cellule.fr.md](cellule.fr.md)).

**Commande** : créer les trois clés de contrôleurs **sur les machines qui signeront**, et construire le
manifeste de genèse à partir de leurs clés publiques, dans l'ordre (la position d'une clé dans le manifeste est
son `key_id`) :

```bash
for i in 1 2 3; do
  quorumproof keygen -key /etc/tbp/keys/controller-$i.key -keyring /etc/tbp/quorum-keyring.json
done                       # affiche  kid=…  public=<64 hex>  pour chacune
# genesis/manifest.json : {"pubkeys": ["<public 1>", "<public 2>", "<public 3>"]}  — dans cet ordre
```

Remettre chaque `controller-N.key` à son dépositaire ; seuls `/etc/tbp/quorum-keyring.json` et `manifest.json`
restent sur la cellule (clés publiques).

**Critère de succès observable** : trois lignes `public=` ont été affichées ; `quorum-keyring.json` contient
trois entrées ; le manifeste liste les mêmes trois clés. `TBP_QUORUM_MIN=2` vaut alors **2 sur 3** : deux
contrôleurs quelconques signent, le troisième est la rechange. Lancer `keygen` deux fois avec le même `-key`
échoue (une clé n'est jamais écrasée).

**En cas d'échec : STOP** — un trousseau de deux entrées pour `k = 2` n'a pas de rechange : perdre une clé ferme
la cellule (`brokerd` le dit au démarrage). Ne pas continuer avec `n ≤ k`.

#### Étape 3 — Démarrer `brokerd` (topologie `mono`, `k = 2`)

**Prérequis vérifiable** : étapes 1 et 2 vertes ; le registre d'agents (`agents.json` : chaque agent et sa
classe), les clés d'opérateurs (`operators.json`, les clés qui approuvent les plans), la graine de l'émetteur et
le sel de la cellule préparés comme en [cellule.fr.md](cellule.fr.md) étape 7 ; `TBP_PROVISIONING_WITNESS_FILE`
hors de `TBP_REGISTRY_DIR`. La **clé d'opérateur** se crée comme une clé de contrôleur — c'est une autre clé,
détenue par celui qui approuve les plans :
`quorumproof keygen -key /etc/tbp/keys/operator.key -keyring /tmp/operator-ring.json`, et son `public=` va dans
`operators.json` (`["<public>"]`).

**Commande** : écrire `/etc/tbp/brokerd.env` comme en cellule.fr.md étape 7 avec ces valeurs d'échelle 2, puis le
démarrer :

```bash
#   TBP_TOPOLOGY=mono                 # une cellule : pas de bail d'époque (#97)
#   TBP_CLUSTER_MEMBERS=cell-a        # mono : la cellule est son seul membre (#128)
#   TBP_QUORUM_MIN=2
#   TBP_GENESIS_DIR=/etc/tbp/genesis  # contient manifest.json (les 3 contrôleurs)
#   TBP_AGENT_REGISTRY_FILE=/etc/tbp/agents.json
#   TBP_OPERATOR_KEYS_FILE=/etc/tbp/operators.json
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/brokerd-provisioning-witness.json
set -a; . /etc/tbp/brokerd.env; set +a
/usr/local/bin/brokerd &
curl -s --unix-socket /run/tbp/broker-admin.sock http://localhost/v1/supervision/stats
```

**Critère de succès observable** : la route de statistiques répond 200 avec des compteurs à zéro ; le journal ne
contient **aucune** ligne `AVERTISSEMENT quorum` (`k = 2` avec une rechange est le cas sain) ;
`TBP_PROVISIONING_WITNESS_FILE` a été écrit.

**En cas d'échec : STOP** — un `AVERTISSEMENT quorum k=1` signifie que l'environnement dit `TBP_QUORUM_MIN=1` :
c'est l'échelle 1, pas la 2. Un refus nommant `quorum-settings` ou un fichier signifie que les fichiers de
confiance de la cellule ont changé depuis le témoin : voir [cellule.fr.md](cellule.fr.md), « Fichiers de
provisionnement ».

#### Étape 4 — Une action de classe W exige deux contrôleurs

**Prérequis vérifiable** : étape 3 verte ; un agent enregistré en classe W dans `agents.json` ; le
`TBP_POLICY_ID` de la cellule (le condensé du bundle).

**Commande** : l'opérateur soumet et approuve le plan, puis deux contrôleurs signent une preuve pour **cette**
action ; l'agent présente les deux :

```bash
# 1. soumettre le plan (socket d'administration) — répond {"plan_hash": "<hex>"}
curl -s --unix-socket /run/tbp/broker-admin.sock -X POST \
  -d '{"steps":[{"action":"read","resource":"doc-1","params_hex":""}]}' \
  http://localhost/v1/supervision/plan/submit
# 2. l'opérateur l'approuve avec la clé d'opérateur, puis le corps est posté
quorumproof planapprove -plan-hash <plan_hash> -key /etc/tbp/keys/operator.key -out /tmp/approval.json
curl -s --unix-socket /run/tbp/broker-admin.sock -X POST -d @/tmp/approval.json \
  http://localhost/v1/supervision/plan/approve
BINDING=$(quorumproof planbind -plan-hash <plan_hash>)
# 3. deux contrôleurs signent une preuve liée à (action, ressource, politique) — à usage unique (#206)
quorumproof wproof -manifest /etc/tbp/genesis/manifest.json -action read -resource doc-1 \
  -policy "$TBP_POLICY_ID" -key /etc/tbp/keys/controller-1.key -key /etc/tbp/keys/controller-3.key -out /tmp/proof.json
# 4. l'intention de l'agent porte plan_binding et quorum_proof (tous deux en hex) — POST /v1/actions
```

**Critère de succès observable** : la même action est **refusée** sans preuve (`quorum-required`) et avec la
preuve d'un seul contrôleur (`quorum-insufficient`), et **autorisée avec un jeton** avec deux — ici les
contrôleurs 1 et 3, parce que le 2 est indisponible : c'est à cela que sert la rechange. La preuve ne vaut pas
une seconde fois.

**En cas d'échec : STOP** — un allow avec une seule signature signifie que `TBP_QUORUM_MIN` n'est pas 2 ; ne pas
continuer. Les contrôleurs dont la clé est dans un HSM utilisent `quorumproof wmessage` (ce qu'il faut signer)
puis `quorumproof wassemble`.

#### Étape 5 — L'échelle est attestée

**Prérequis vérifiable** : étape 3 verte ; `brokerd` arrêté.

**Commande** : l'échelle — `TBP_QUORUM_MIN` et la topologie — fait partie de ce que le témoin de provisionnement
atteste (#224). Essayer de l'abaisser en éditant l'environnement, comme le ferait un attaquant :

```bash
TBP_QUORUM_MIN=1 /usr/local/bin/brokerd     # dans le même environnement par ailleurs
```

**Critère de succès observable** : `brokerd` **refuse de démarrer** et nomme `quorum-settings`. Même une preuve de
transition signée par **un** contrôleur ne l'autorise pas : le changement n'est autorisé que par le quorum qui
était **attesté** (2), pas par celui que vous venez d'écrire. Signée par deux contrôleurs
(`quorumproof sign -condition '<la condition qu'"'"'affiche le refus : provisioning-transition-brokerd|from=…|to=…>' -cell cell-a -key … -key …`, puis
`TBP_PROVISIONING_TRANSITION_PROOF_FILE`), elle est acceptée — et `brokerd` avertit ensuite à chaque démarrage que
`k = 1`. Monter d'échelle est le même acte gouverné dans l'autre sens.

**En cas d'échec : STOP** — un `brokerd` qui démarre avec `TBP_QUORUM_MIN=1` et sans preuve signifie que le témoin
n'atteste pas l'échelle : ne pas faire tourner la cellule.

#### Étape 6 — Exercice de redémarrage

**Prérequis vérifiable** : étapes 3 à 5 vertes.

**Commande** : tuer `brokerd` et le relancer avec le même environnement.

**Critère de succès observable** : il démarre (le témoin correspond : mêmes fichiers, même échelle). Selon les
règles de posture de [cellule.fr.md](cellule.fr.md), un redémarrage de `pepd` sur un serveur revient `refused`
tant qu'un quorum n'a pas reconfirmé une posture : avec `k = 2`, deux contrôleurs signent
(`quorumproof sign -condition mode-closed …`).

**En cas d'échec : STOP** — un redémarrage qui revient sans quorum est la régression de la revue de sécurité #93.

#### Étape 7 — Serveurs applicatifs et agents distants

**Prérequis vérifiable** : étapes 1 à 6 vertes ; les serveurs applicatifs préparés comme en
[serveur.fr.md](serveur.fr.md).

**Commande** : installer `pepd` sur chaque serveur comme en [serveur.fr.md](serveur.fr.md) avec `TBP_QUORUM_MIN=2`
et le **même** trousseau de quorum (`/etc/tbp/quorum-keyring.json`) ; pour les agents sur d'autres machines,
activer l'écoute mTLS de `brokerd` avec une CA d'agents dédiée ([cellule.fr.md](cellule.fr.md), #124) et lier
chaque agent à son certificat (`transport_identity` dans `agents.json`) — un tel agent est un agent **réseau** et est refusé sur le socket Unix (`agent-network-only`) ; un agent sans `transport_identity` est un agent du socket et est refusé sur le réseau. Donner deux entrées à un agent utilisé des deux façons. Puis prouver que rien ne sort du réseau
des agents autrement que par TBP : [network-isolation.fr.md](network-isolation.fr.md).

**Critère de succès observable** : un agent sans certificat de la CA d'agents est refusé à la poignée de main ;
`deploy/verify_network_isolation.sh --mode strict` rejette toute sonde sortante et atteint le proxy. Chaque
`pepd` démarre `refused` après un redémarrage et est reconfirmé par 2 contrôleurs.

**En cas d'échec : STOP** — ne pas accepter de trafic d'agents avant que le contrôle d'isolation ne passe. *Cette
étape n'est pas exécutée par la phase de selftest `scale2`* : le mTLS est couvert par les tests de `brokerd`
(`net_tls_test.go`) et les `pepd` des serveurs applicatifs par les phases `mono` et `scale1`.

## Deux clés, deux endroits

Les clés de contrôleurs et les **clés de la cellule** sont deux choses différentes : la clé de cellule
(`cell_log.key`, `TBP_REGISTRY_DIR`) signe le journal et reste sur la machine ; les clés de contrôleurs signent
des **actes** et ne restent **jamais** dessus. Clé de contrôleur perdue, quorum perdu, clé volée :
[recovery.fr.md](recovery.fr.md) — le répéter une fois avant d'en avoir besoin.

## Ce que cette échelle ne couvre pas, exprès

- Le profil effectif n'est pas encore écrit comme feuille de journal au démarrage : il se recalcule depuis le
  témoin (l'entrée `quorum-settings` est dans le condensé de la feuille de démarrage), mais un enregistrement
  lisible « quel profil tournait ce jour-là » est suivi dans #86.
- La détection comportementale par séquence (#181) vient **après** l'échelle 2 (décision consignée dans
  [scales.fr.md](scales.fr.md)).
- Plusieurs cellules, bail d'époque et fencing : échelle 3 ([cellule.fr.md](cellule.fr.md),
  [superviseur.fr.md](superviseur.fr.md)).
