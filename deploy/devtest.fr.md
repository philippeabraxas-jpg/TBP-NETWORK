# deploy/devtest.fr.md — un déploiement DEV-TEST : le lancer, l'attaquer, ne pas lui faire confiance

_English version: [devtest.md](devtest.md)._

> **Pas pour la production.** Chaque clé qu'il fabrique est jetable et vit sur la même machine. Il ne prouve rien
> sur la garde des clés, sur la séparation entre de vraies personnes, ni sur une cérémonie de genèse. Utilisez-le
> sur une machine virtuelle propre, sans donnée réelle et sans agent réel derrière.

Une commande met en place une cellule d'échelle 2 — `brokerd` et son OPA, la même chaîne que
[scale-2.fr.md](scale-2.fr.md) construit à la main — pour que vous puissiez la faire tourner, chercher à la casser
et signaler ce que vous trouvez, sans y passer un après-midi de cérémonies de clés. L'objectif est de tester **la
vraie chose** : les mêmes binaires, les mêmes chemins de code, les mêmes refus.

## Ce qui est simplifié, et ce qui ne l'est pas

| | Dans ce déploiement | Pourquoi on peut simplifier, ou non |
|---|---|---|
| Clés | générées pour vous, dans un seul dossier (0700) de l'utilisateur | **Simplifié.** La garde des clés et la séparation de vraies personnes ne sont pas testées ici |
| Genèse | un manifeste de trois clés publiques de contrôleurs, sans cérémonie ni HSM | **Simplifié.** La topologie `mono` n'a pas de bail d'époque |
| Clé d'émission | un fichier de graine (`TBP_ISSUER_SEED_FILE`) au lieu d'un HSM | **Simplifié, et c'est la seule échappatoire de développement utilisée** : c'est pourquoi `/etc/tbp/DEV_ENVIRONMENT` est créé et pourquoi `brokerd` lève une alarme de haute priorité à chaque démarrage |
| Règles | le bundle d'exemple de `policies/rego/`, capabilities restreintes, **signé** | Comme en production : OPA refuse un bundle non signé ou modifié |
| Quorum | `k = 2` sur `n = 3`, une clé de rechange | **Non simplifié** |
| Clés d'opérateur | quatre clés avec rôles : deux approuvent, une ne fait que couper (`revoke`, `arbitrate`), une soumet | **Non simplifié** : rôles, soumetteur ≠ approbateur, `k` approbations pour les classes F et W |
| OPA ↔ `brokerd` | socket Unix, authentifié par l'UID du pair | Même chemin de code qu'en production, **mais les deux tournent sous le même utilisateur** : cet utilisateur peut se faire passer pour OPA |
| Témoin de provisionnement | actif : l'échelle et les fichiers de confiance sont attestés au démarrage | **Non simplifié** : baisser `TBP_QUORUM_MIN` dans l'environnement est refusé |
| Réseau | rien n'écoute en TCP ; sockets Unix dans un dossier 0700 | |

Ce qu'il **ne démarre pas** : `pepd` sur les serveurs applicatifs, `supervisord`, `anod`, le listener mTLS et les
agents distants (étape 7 de [scale-2.fr.md](scale-2.fr.md)), et tout ce qui est multi-cellule. Ce qu'il **ne peut
pas** vous dire : si votre garde des clés, votre cérémonie ou votre isolation réseau tiennent.

## Avant de commencer

- Une machine virtuelle Debian 12 propre, que vous pouvez perdre. **Aucune donnée réelle, aucun identifiant réel,
  aucune route vers quoi que ce soit qui compte pour vous.** `init` refuse une machine qui contient déjà
  `/var/lib/tbp`, ou `/etc/tbp/brokerd.env`, `/etc/tbp/pepd.env` ou `/etc/tbp/quorum-keyring.json`.
- Un utilisateur normal (pas root). `sudo` sert une fois, pour écrire `/etc/tbp/DEV_ENVIRONMENT`. Dans un
  conteneur jetable, `DEVTEST_ALLOW_ROOT=1` autorise root.
- `opa` (≥ 1.0), `openssl`, `jq`, `curl`, et soit `go` (la version de `go.mod`), soit les binaires de la release :
  `bash scripts/release/build.sh dist` (le script utilise `dist/` s'il y trouve les binaires).

## Utilisation

```bash
scripts/devtest/devtest.sh init     # clés, règles, bundle signé, environnement — une fois
scripts/devtest/devtest.sh up       # OPA, puis brokerd, en arrière-plan
scripts/devtest/devtest.sh demo     # 12 contrôles : ce qui est refusé, ce qui est autorisé, et pourquoi
scripts/devtest/devtest.sh status
scripts/devtest/devtest.sh down
scripts/devtest/devtest.sh reset    # arrête, supprime tout, retire le sentinel si ce script l'a créé
```

Tout vit dans `$TBP_DEVTEST_HOME` (par défaut `~/tbp-devtest` ; gardez le chemin court : `init` en refuse un qui
ferait dépasser la limite des chemins de socket Unix) :

| Chemin | Contenu |
|---|---|
| `keys/controller-1..3.key` | les trois contrôleurs : deux suffisent pour une action de classe W (`k = 2` sur 3) |
| `keys/operator-1..4.key` | `operator-1`, `operator-2` : approuvent les plans · `operator-3` : `revoke` et `arbitrate` seulement · `operator-4` : soumet les plans |
| `genesis/manifest.json`, `keys/quorum-keyring.json` | les clés publiques des contrôleurs |
| `opa/` | capabilities restreintes, clé de signature, clé de vérification, bundle signé, arguments de lancement d'OPA |
| `brokerd.env`, `operators.json`, `agents.json` | les réglages de la cellule ; `agents.json` contient `agent-f` (classe F), `agent-i` (classe I), `agent-w` (classe W) |
| `run/` | les sockets Unix : `broker.sock` (agents, `POST /v1/actions`) et `broker-admin.sock` (opérateurs) |
| `registry/`, `audit/` | le journal de la cellule et le journal chiffré des clairs ([audit.fr.md](audit.fr.md)) |
| `log/` | `opa.log`, `brokerd.log` |

`demo` est le chemin le plus court pour voir la cellule fonctionner : un agent inconnu et un agent sans plan sont
refusés ; une action de classe I est autorisée après un plan signé et l'approbation d'un opérateur ; une action de
classe W est refusée sans preuve, refusée avec un contrôleur, autorisée avec deux, et la même preuve ne sert pas
deux fois. Il échoue, en montrant la réponse inattendue, si la cellule se comporte autrement.

## L'attaquer

Tout [scale-2.fr.md](scale-2.fr.md) est écrit pour être attaqué. Quelques points de départ, chacun avec le refus que
les guides promettent : baisser `TBP_QUORUM_MIN` dans `brokerd.env` et démarrer (refusé, `quorum-settings`) ;
modifier un octet du bundle, ou le re-signer avec une autre clé (OPA ne démarre pas) ; approuver un plan avec la clé
de celui qui l'a soumis ; approuver un plan de classe W avec un seul opérateur ; rejouer une preuve de contrôleur ;
signer un hash de plan que le broker n'a pas scellé (`quorumproof planhash`) ; couper un plan avec une signature
d'approbation (une révocation se signe autrement). Les refus laissent des feuilles dans le journal de la cellule,
dont [audit.fr.md](audit.fr.md) montre comment vérifier.

Les limites que le projet connaît déjà sont listées dans le [README](../README.md) (« Honesty about where this
stands »), dans [CHANGELOG.md](../CHANGELOG.md) et dans [governed-acts.fr.md](governed-acts.fr.md) : une trouvaille
qui en fait partie est bienvenue comme issue ordinaire ; tout ce qui est exploitable passe par
[SECURITY.md](../SECURITY.md).

## Ce que ce déploiement ne vous dira pas

Parce que les contrôleurs, les opérateurs et la cellule sont tous sous un seul utilisateur sur une seule machine,
la compromission de cet utilisateur est la compromission de toutes les clés. C'est ce qu'un vrai déploiement évite
avec des personnes distinctes et des HSM, et cela sort de ce que cette installation peut tester. Il en va de même
pour tout ce qui dépend d'un `pepd` sur un serveur que vous ne maîtrisez pas, du réseau, ou de plusieurs cellules.
