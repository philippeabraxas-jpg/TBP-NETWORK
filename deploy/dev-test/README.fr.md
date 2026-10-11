# deploy/dev-test — lancer une cellule d'échelle 2, l'attaquer, et nous dire ce qui s'est passé

_English version: [README.md](README.md)._

> **Pas pour la production.** Chaque clé qu'il fabrique est jetable et vit sur la même machine. Il ne prouve rien
> sur la garde des clés, sur la séparation entre de vraies personnes, ni sur une cérémonie de genèse. Utilisez-le
> sur une machine virtuelle que vous pouvez perdre, sans donnée réelle et sans agent réel derrière.

Une commande met en place une cellule d'échelle 2 — `brokerd` et son OPA, la même chaîne que
[scale-2.fr.md](../scale-2.fr.md) construit à la main — pour que vous puissiez la lancer, chercher à la casser et
signaler ce que vous trouvez, sans y passer un après-midi de cérémonies de clés. L'objectif est de tester **la
vraie chose** : les mêmes binaires, les mêmes chemins de code, les mêmes refus. Plus il y a de gens qui cherchent à
la casser maintenant, moins une release de production portera de failles.

## En dix minutes

Il vous faut une machine virtuelle Debian 12 (voir « De quelle machine avez-vous besoin » plus bas) et un
utilisateur avec `sudo`. Les commandes ci-dessous sont toute la procédure ; la première exécution se termine par
`demo passed`. Nous n'avons pas encore chronométré un démarrage à froid sur une Debian 12 neuve — votre durée fait
partie de ce que nous vous demandons.

```bash
# 1. Outils : git, curl, jq, openssl
sudo apt-get update && sudo apt-get install -y git curl jq openssl ca-certificates

# 2. OPA, la version que la CI utilise, vérifié avec sa somme de contrôle publiée
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static.sha256
sha256sum -c opa_linux_amd64_static.sha256          # doit répondre : opa_linux_amd64_static: OK
sudo install -m 0755 opa_linux_amd64_static /usr/local/bin/opa

# 3. Go, au moins la version de go.mod (le paquet Debian 12 est en 1.19, trop ancien). Comparez la somme de
#    contrôle de l'archive à celle de https://go.dev/dl/ avant de la décompresser.
curl -fsSLO https://go.dev/dl/go1.27.2.linux-amd64.tar.gz
sha256sum go1.27.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.27.2.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

# 4. Le dépôt, et la cellule
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/devtest.sh init      # compile trois binaires, fait les clés, signe les règles (~10 s, Go chaud)
scripts/devtest/devtest.sh up        # OPA, puis brokerd
scripts/devtest/devtest.sh demo      # 12 contrôles : ce qui est refusé, ce qui est autorisé, et pourquoi
```

`init` demande `sudo` une fois, pour écrire `/etc/tbp/DEV_ENVIRONMENT` (expliqué plus bas). Quand une release
DEV-TEST publiée portera les binaires, l'étape 3 et la compilation disparaîtront : il ne faudra plus qu'OPA et les
fichiers de la release.

Si `demo` ne se termine pas par `demo passed`, c'est déjà une trouvaille : lancez
`scripts/devtest/devtest.sh report` et dites-le-nous ([plus bas](#nous-dire-ce-que-vous-avez-trouvé)).

## De quelle machine avez-vous besoin

**Une seule.** Dans cette installation, la cellule, l'agent, les opérateurs, les contrôleurs et l'attaquant sont
des rôles que vous jouez sur la même machine virtuelle, par des sockets Unix dans un dossier que seul votre
utilisateur peut ouvrir. Rien n'écoute en TCP : pas de port à ouvrir, pas de seconde machine d'où attaquer, pas de
service cloud dont dépendre.

| Rôle | Où il tourne | Comment vous le jouez |
|---|---|---|
| La cellule | la VM | `devtest.sh up` démarre OPA et `brokerd` |
| Un agent | la VM | `curl` sur le **socket des agents** (`POST /v1/actions`) |
| Opérateurs et contrôleurs | la VM | `quorumproof` avec les fichiers de clés que `init` a faits |
| L'attaquant | la VM, sous le même utilisateur | vous, depuis l'une des trois positions ci-dessous |

Où mettre la VM : n'importe quelle machine virtuelle de cloud (un petit droplet ou une petite instance suffit) ou
une locale (KVM, VirtualBox, multipass). Pas sur un portable ou un serveur qui contient quoi que ce soit qui
compte pour vous, ni sur un réseau que vous ne pouvez pas vous permettre d'exposer : la cellule n'ouvre aucun
port, mais la machine reste à protéger. Nous n'avons pas mesuré la plus petite machine qui convient ; nos essais
ont utilisé 4 CPU et 16 Go. `report` note ce que vous avez utilisé, dites-le-nous.

Ce que cette installation ne permet **pas** de tester, c'est le réseau : un agent sur une autre machine, le
listener mTLS, l'isolation réseau entre les agents et l'extérieur (étape 7 de [scale-2.fr.md](../scale-2.fr.md)).
Cela demande une seconde machine et n'est pas mis en place ici.

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
agents distants, et tout ce qui est multi-cellule. Ce qu'il **ne peut pas** vous dire : si votre garde des clés,
votre cérémonie ou votre isolation réseau tiennent — parce que les contrôleurs, les opérateurs et la cellule sont
tous sous un seul utilisateur sur une seule machine, la compromission de cet utilisateur est la compromission de
toutes les clés. C'est ce qu'un vrai déploiement évite avec des personnes distinctes et des HSM.

## Ce que vous pouvez attaquer, depuis trois positions

Après `init` et `up`, chargez les variables une fois et définissez une fonction :

```bash
eval "$(scripts/devtest/devtest.sh env)"
post() { curl -sS --unix-socket "$1" -X POST "${@:3}" -w ' [%{http_code}]\n' "http://localhost$2"; }
```

Chaque tentative ci-dessous a été jouée contre un déploiement en marche et a donné la réponse indiquée ; **la
réponse attendue est ce que vous devez obtenir.** Une réponse différente est une trouvaille.

### Position 1 — un agent (il n'atteint que le socket des agents)

| Essai | Commande | Attendu |
|---|---|---|
| Deux sujets dans une requête | `post $DT_AGENT_SOCK /v1/actions -d '{"subject":"agent-i","subject":"agent-w","intent":"{}"}'` | `request-invalid`, `duplicate-key`, `[400]` |
| Un champ que le contrat n'a pas | `post $DT_AGENT_SOCK /v1/actions -d '{"subject":"agent-i","intent":"{}","class":2}'` | `request-invalid`, `unknown-field`, liste les champs acceptés, `[400]` |
| Annoncer une classe plus basse pour un agent de classe W | `post $DT_AGENT_SOCK /v1/actions -d '{"subject":"agent-w","intent":"{\"action\":\"read\",\"resource\":\"doc-1\",\"class\":1}"}'` | `quorum-required` : la classe vient du registre de la cellule, pas de l'agent |
| Un corps de plus de 64 Kio | `head -c 70000 /dev/zero \| tr '\0' a > /tmp/big; post $DT_AGENT_SOCK /v1/actions --data-binary @/tmp/big` | `request-invalid`, `body-unreadable`, `[400]` |

### Position 2 — un opérateur (il détient des clés d'opérateur et atteint le socket d'administration)

Faites d'abord un plan sur lequel travailler, signé par la clé qui peut soumettre, et gardez son hash :

```bash
echo '{"subject":"agent-i","steps":[{"action":"read","resource":"doc-9","params_hex":""}]}' > /tmp/plan.json
quorumproof plansubmit -cell $DT_CELL -plan /tmp/plan.json -key $DT_KEYS/operator-4.key -out /tmp/s4.json
H=$(curl -sS --unix-socket $DT_ADMIN_SOCK -X POST -d @/tmp/s4.json http://localhost/v1/supervision/plan/submit | jq -r .plan_hash)
```

| Essai | Commande | Attendu |
|---|---|---|
| Soumettre un plan sans signature | `post $DT_ADMIN_SOCK /v1/supervision/plan/submit -d @/tmp/plan.json` | refusé : la cellule veut savoir qui soumet, `[400]` |
| Soumettre avec une clé qui ne peut pas soumettre | `quorumproof plansubmit -cell $DT_CELL -plan /tmp/plan.json -key $DT_KEYS/operator-1.key -out /tmp/s.json && post $DT_ADMIN_SOCK /v1/supervision/plan/submit -d @/tmp/s.json` | refusé : la clé n'a pas le rôle de soumission, `[400]` |
| Soumettre un plan signé pour une autre cellule | `quorumproof plansubmit -cell cell-other -plan /tmp/plan.json -key $DT_KEYS/operator-4.key -out /tmp/s.json && post $DT_ADMIN_SOCK /v1/supervision/plan/submit -d @/tmp/s.json` | refusé : signature invalide pour le trousseau épinglé, `[400]` |
| Approuver un plan avec la clé qui l'a soumis | `quorumproof planapprove -plan-hash $H -expires-at $(date -u -d '+30 minutes' +%Y-%m-%dT%H:%M:%SZ) -key $DT_KEYS/operator-4.key -out /tmp/a.json && post $DT_ADMIN_SOCK /v1/supervision/plan/approve -d @/tmp/a.json` | refusé : la clé n'a pas le rôle d'approbation, `[400]` |
| Révoquer avec la clé d'un approbateur | `quorumproof planrevoke -plan-hash $H -key $DT_KEYS/operator-1.key -out /tmp/r.json && post $DT_ADMIN_SOCK /v1/supervision/plan/revoke -d @/tmp/r.json` | refusé : la clé n'a pas le rôle de révocation, `[400]` |
| Vérifier le hash du broker avant de signer | `quorumproof planhash -cell $DT_CELL -policy-id $DT_POLICY_ID -submitted-at 2026-01-01T00:00:00Z -plan /tmp/plan.json -expect $(printf 'a%.0s' $(seq 1 64))` | `plan_hash DIFFÉRENT … ne signez pas`, code de sortie 1 |

Le parcours complet qui, lui, **passe** — un plan de classe I, une action de classe W avec deux opérateurs et deux
contrôleurs — c'est `devtest.sh demo` ; lisez-le comme la spécification de ce qui doit passer.

### Position 3 — quelqu'un qui peut écrire dans les fichiers de la cellule

Ces essais empêchent la cellule de démarrer ; chacun laisse une raison claire. Lancez d'abord `devtest.sh down`,
et restaurez le fichier ensuite (gardez-en une copie).

| Essai | Commande | Attendu |
|---|---|---|
| Ajouter un agent au registre à la main | `cp $DT_HOME/agents.json /tmp/agents.bak; jq '. + {"agent-evil":{"class":3}}' /tmp/agents.bak > $DT_HOME/agents.json; scripts/devtest/devtest.sh up` | `brokerd` refuse de démarrer, nomme `agent-registry` et imprime la condition qu'un quorum devrait signer |
| Baisser le quorum | `sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' $DT_HOME/brokerd.env; scripts/devtest/devtest.sh up` | `brokerd` refuse de démarrer, en nommant `quorum-settings` |
| Altérer un octet des règles signées | éditer `$DT_HOME/opa/bundle.tar.gz` | OPA ne démarre pas : `load error: bundle …`, un `digest mismatch` ou une archive corrompue selon l'endroit touché |
| Faire confiance à un autre signataire | remplacer `$DT_HOME/opa/policy-verify.pub` par une autre clé publique | OPA ne démarre pas : `failed to verify JWT signature` |

Restaurez les originaux, puis `devtest.sh up` et `devtest.sh demo` doivent de nouveau passer. Tout ce que vous
pouvez faire depuis cette position et que la cellule **accepte en silence** est le genre de trouvaille que nous
voulons le plus.

Au-delà de cette liste, [scale-2.fr.md](../scale-2.fr.md), [governed-acts.fr.md](../governed-acts.fr.md) et
[integration-contract.fr.md](../integration-contract.fr.md) disent ce que chaque partie promet : une promesse que
vous cassez est une trouvaille. Les limites connues sont écrites dans le [README](../../README.md) (« Honesty about
where this stands »), dans [CHANGELOG.md](../../CHANGELOG.md) et dans [governed-acts.fr.md](../governed-acts.fr.md).

## Nous dire ce que vous avez trouvé

Nous voulons vos chiffres et vos commentaires, y compris « je suis resté bloqué ici ».

**Vos chiffres.** Lancez `scripts/devtest/devtest.sh report` et collez ce qu'il affiche. Il note le commit, le
système (OS, noyau, CPU, mémoire), les versions d'OPA et de Go, la durée de `init` et de `up`, le résultat de la
dernière `demo`, les compteurs du broker, et la latence de la décision la moins chère (un agent sans plan, refusé,
50 requêtes sur le socket Unix). Il ne contient **aucune** clé, graine, chemin, nom de machine ni adresse.

À propos de cette latence : d'après ce que nous voyons, l'essentiel est le temps d'écrire la feuille de la décision
dans le journal signé avant que le broker réponde (pas de feuille, pas de réponse) ; nous ne l'avons pas isolé. Sur
notre essai (4 CPU, 16 Go, Ubuntu 24.04), un refus a pris environ une demi-seconde. C'est une mesure de cette
installation sur votre machine, pas une affirmation de performance ; si la vôtre est très différente, c'est utile à
savoir.

**Vos commentaires**, de la façon qui convient à ce que vous avez trouvé :

| Quoi | Où |
|---|---|
| Une étape qui ne marche pas, une doc fausse, un comportement différent de ce qui est écrit, vos durées, une suggestion | une issue GitHub publique, avec le modèle **Dev-test feedback** (le titre commence par `[dev-test]`) |
| Tout ce qui est exploitable : un moyen de passer un refus, une acceptation silencieuse, un secret qui fuit | **en privé**, comme le dit [SECURITY.md](../../SECURITY.md) — pas une issue publique |

Ce qui rend un retour utile : ce que vous avez essayé (la commande exacte), ce que vous attendiez, ce qui s'est
passé, et la sortie de `report`. Une commande qui échoue est la meilleure reproduction.

## Commandes

| Commande | Ce qu'elle fait |
|---|---|
| `devtest.sh init` | compile ou copie les binaires, fait les clés, le bundle signé et l'environnement — une fois |
| `devtest.sh up` / `down` | démarre OPA et `brokerd` en arrière-plan / les arrête |
| `devtest.sh demo` | 12 contrôles ; échoue, en montrant la réponse inattendue, si la cellule se comporte autrement |
| `devtest.sh env` | affiche les variables utilisées plus haut (`DT_AGENT_SOCK`, `DT_ADMIN_SOCK`, `DT_KEYS`, `DT_CELL`, `DT_POLICY_ID`, …) |
| `devtest.sh status` | est-ce en marche ; les compteurs du broker |
| `devtest.sh report` | un rapport sans secret, à coller dans une issue |
| `devtest.sh reset` | arrête, supprime tout ce qui a été fait, retire `/etc/tbp/DEV_ENVIRONMENT` s'il l'a créé |

`init` refuse une machine qui contient déjà `/var/lib/tbp`, ou `/etc/tbp/brokerd.env`, `/etc/tbp/pepd.env` ou
`/etc/tbp/quorum-keyring.json` (elle ressemble à un vrai déploiement), refuse root sauf `DEVTEST_ALLOW_ROOT=1`
(conteneurs jetables), et refuse un `TBP_DEVTEST_HOME` trop long pour les chemins de socket Unix. Tout vit dans
`$TBP_DEVTEST_HOME` (par défaut `~/tbp-devtest`) :

| Chemin | Contenu |
|---|---|
| `keys/controller-1..3.key` | les trois contrôleurs : deux suffisent pour une action de classe W (`k = 2` sur 3) |
| `keys/operator-1..4.key` | `operator-1`, `operator-2` : approuvent les plans · `operator-3` : `revoke` et `arbitrate` seulement · `operator-4` : soumet les plans |
| `genesis/manifest.json`, `keys/quorum-keyring.json` | les clés publiques des contrôleurs |
| `opa/` | capabilities restreintes, clé de signature, clé de vérification, bundle signé, arguments de lancement d'OPA |
| `brokerd.env`, `operators.json`, `agents.json` | les réglages de la cellule ; `agents.json` contient `agent-f` (classe F), `agent-i` (classe I), `agent-w` (classe W) |
| `run/` | les sockets Unix : `broker.sock` (agents) et `broker-admin.sock` (opérateurs) |
| `registry/`, `audit/` | le journal de la cellule et le journal chiffré des clairs ([audit.fr.md](../audit.fr.md)) |
| `log/` | `opa.log`, `brokerd.log` — attendez-vous à une alarme de haute priorité au démarrage : un environnement de développement est déclaré |
