# deploy/scale-1.fr.md — échelle 1 : une machine, l'administrateur seul (issue #86)

_English version: [scale-1.md](scale-1.md)._

L'échelle 1, c'est une machine, une cellule, un administrateur : `pepd` + un
OPA local + un registre. Pas de `brokerd`, pas de superviseur, pas de fencing.
C'est le même TBP que sur toutes les autres échelles avec un **autre réglage
des briques de sécurité** — [scales.fr.md](scales.fr.md) dit lesquelles et
pourquoi. Le quorum est la brique qui compte ici : `k = 1`, donc
**l'administrateur seul signe** chaque acte gouverné (bascule de posture,
transition de provisionnement, transition du démarrage mesuré).

`k = 1` ne veut pas dire « sans signature » : un acte sans signature valide
d'une clé épinglée dans le trousseau de quorum est refusé exactement comme à
n'importe quelle autre échelle.

> La phase `scale1` de `deploy/selftest/` rejoue la séquence de ce guide contre
> les vrais binaires (`go run ./deploy/selftest -phase scale1`). Si une commande
> ci-dessous diverge du selftest, le selftest casse : corriger le guide ou le
> code, jamais l'un dans le dos de l'autre.

Hors périmètre à cette échelle, volontairement : fencing multi-cellules et bail
d'époque (#197), transport inter-cellules (#187), listener réseau mTLS (#124).
Passer à l'échelle 2 ou plus, c'est changer des réglages, pas réinstaller :
voir [scales.fr.md](scales.fr.md).

#### Étape 1 — Base : machine, binaires, OPA

**Prérequis vérifiable** : une machine Debian que vous administrez seul, `go`
(la version épinglée par `go.mod`) et `opa` dans le `PATH`.

**Commande** : suivre [cellule.fr.md](cellule.fr.md) **étapes 1 à 5** sans
changement (machine, build de `pepd`, capabilities OPA restreintes, bundle
signé, OPA sur sa socket Unix). Rien dans ces étapes ne dépend de l'échelle.

**Critère de succès observable** : `curl -s --unix-socket /run/tbp/opa.sock
http://localhost/health` répond 200 et le bundle est chargé avec sa signature
vérifiée (cellule.fr.md étape 5).

**En cas d'échec : STOP** — ne pas démarrer `pepd` contre un OPA qui n'a pas
vérifié la signature du bundle.

#### Étape 2 — Créer la clé d'administrateur et le trousseau de quorum (k = 1)

**Prérequis vérifiable** : étape 1 verte ; un répertoire `/etc/tbp` en 0700
appartenant au compte de service ; un endroit **hors de cette machine** pour
garder une copie de la clé d'administrateur (enveloppe scellée, gestionnaire de
mots de passe, disque hors ligne).

**Commande** :

```bash
go build -o /usr/local/bin/quorumproof ./src/pep/cmd/quorumproof
quorumproof keygen -key /etc/tbp/admin.key -keyring /etc/tbp/quorum-keyring.json
```

**Critère de succès observable** : la commande affiche un `kid=` et un
`public=` ; `/etc/tbp/quorum-keyring.json` contient **exactement une** entrée
(`{"<kid>": "<clé publique>"}`) ; `/etc/tbp/admin.key` est en 0600. Relancer la
commande avec le même `-key` échoue (une clé existante n'est jamais écrasée).

**En cas d'échec : STOP** — un trousseau de plus d'une entrée n'est pas
l'échelle 1, et un trousseau vide bloque toute bascule. La clé est logicielle :
c'est le prix de l'échelle 1 (clé perdue ou volée = réépingler un nouveau
trousseau, ce qui est lui-même un acte gouverné). Garder la copie hors machine
**maintenant** ; sans elle, il n'y a pas de procédure de récupération (#199).

#### Étape 3 — Démarrer pepd avec les réglages de l'échelle 1

**Prérequis vérifiable** : étapes 1 et 2 vertes ; trousseau d'émetteur, sel de
cellule et `TBP_POLICY_ID` préparés comme à l'étape 6 de cellule.fr.md.

**Commande** : écrire `/etc/tbp/pepd.env` comme à l'étape 6 de
[cellule.fr.md](cellule.fr.md), avec ces valeurs (adapter les chemins à la
machine) :

```bash
#   TBP_TOPOLOGY=mono                # cellule unique, explicite (#128) — et
#                                    # AUCUN TBP_CELL_BROKER_SOCKET
#   TBP_QUORUM_MIN=1                 # l'administrateur seul
#   TBP_QUORUM_KEYRING_FILE=/etc/tbp/quorum-keyring.json
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/pepd-provisioning-witness.json
#   TBP_MEASURED_BOOT_MANIFEST_FILE=/var/lib/tbp/cell-a-measured-boot.json
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/v1/mode
```

**Critère de succès observable** : `GET /v1/mode` renvoie
`{"mode":"monitor"}` (premier démarrage seulement, §5.3) ; `pepd` refuse de
démarrer si `TBP_TOPOLOGY` manque ou si une socket de broker est posée avec
`mono`.

**En cas d'échec : STOP** — ne pas « corriger » un refus en posant un drapeau
`*_DEV_UNSAFE` : ils sont réservés au dev/labo et refusés en production par le
sentinel `DEV_ENVIRONMENT` (#113).

#### Étape 4 — Prouver que l'administrateur seul est le quorum

**Prérequis vérifiable** : étape 3 verte, mode `monitor`.

**Commande** :

```bash
# 1. aucune signature : refusé
curl -s -o /dev/null -w '%{http_code}\n' --unix-socket /run/tbp/pepd-admin.sock \
  -X POST -d '{"mode":"closed","signatures":[]}' http://localhost/v1/mode
# 2. l'administrateur signe l'acte « mode-closed » pour CETTE cellule
quorumproof sign -condition mode-closed -cell cell-a -key /etc/tbp/admin.key -out /tmp/proof.json
jq '. + {mode:"closed"}' /tmp/proof.json | curl -s -o /dev/null -w '%{http_code}\n' \
  --unix-socket /run/tbp/pepd-admin.sock -X POST -d @- http://localhost/v1/mode
shred -u /tmp/proof.json
```

**Critère de succès observable** : le premier appel affiche `403`, le second
`200`, puis `GET /v1/mode` renvoie `{"mode":"closed"}`. La preuve est liée à la
condition et à la cellule : le même fichier n'ouvre aucun autre acte ni aucune
autre cellule.

**En cas d'échec : STOP** — un `200` au premier appel signifie que le quorum
n'est pas appliqué ; ne pas aller plus loin ni activer le mode closed ailleurs.

#### Étape 5 — Exercice de redémarrage : refusé jusqu'à reconfirmation de l'administrateur

**Prérequis vérifiable** : étape 4 verte, mode `closed`.

**Commande** : tuer `pepd`, le redémarrer avec le même environnement, puis lire
`GET /v1/mode` ; reconfirmer avec `quorumproof sign -condition mode-monitor …`
et le même `POST` qu'à l'étape 4.

**Critère de succès observable** : après le redémarrage le mode est `refused`
(pas `monitor`) et toute évaluation est refusée ; après la signature de
l'administrateur, le mode est celui qui a été signé.

**En cas d'échec : STOP** — un redémarrage qui revient en `monitor` ou `closed`
sans signature est la régression de la revue de sécurité #93.
