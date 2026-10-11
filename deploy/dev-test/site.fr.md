# deploy/dev-test/site — trois machines : M1 la cellule, M2 un serveur, M3 un agent

_English version: [site.md](site.md)._

> **Pas pour la production.** Chaque clé qu'il fabrique est jetable, et toutes les clés de gouvernance de la cellule
> sont sur M1. Utilisez trois machines virtuelles que vous pouvez perdre, sur un réseau privé, sans donnée réelle et
> sans agent réel derrière.

C'est le test fonctionnel d'un site d'échelle 2. La question n'est pas de savoir si le code est sain — la CI et le
selftest la posent déjà — mais **si l'ensemble fonctionne à travers des machines** : un agent inscrit par son
certificat, une décision de la cellule, un jeton vérifié par le point d'application d'un serveur, la posture du
serveur gouvernée par les contrôleurs. Et, puisque c'est la vraie chose, si vous pouvez la casser.

Un seul script, `scripts/devtest/site.sh`, déploie chaque machine en une commande ; cette page dit à quoi sert
chaque machine, pourquoi, comment la déployer, quoi tester et par où attaquer. Un démarrage rapide à une machine,
pour regarder la cellule seule, est [solo.fr.md](solo.fr.md).

## Les trois machines

```
 M3  l'agent                        M1  la cellule                       M2  un serveur applicatif
 curl + les certificats d'agents    OPA + brokerd, les clés              OPA + pepd + l'application

 1. demander une décision ──────►   :8443, TLS mutuel
                                     décide, signe un jeton
 2. le jeton ◄──────────────────
 3. présenter le jeton ────────────────────────────────────────────────►  :9000 l'application
                                                                           interroge pepd (127.0.0.1:8443)
                                                                           n'agit que si pepd transmet
 4. la réponse ◄───────────────────────────────────────────────────────

 L'administration — opérateurs et contrôleurs — se fait sur M1, en local.  Les paquets voyagent par scp : M1 → M2, M1 → M3.
```

| | M1 — la cellule | M2 — le serveur applicatif | M3 — l'agent |
|---|---|---|---|
| Ce qui tourne | OPA, `brokerd` avec un listener mTLS | OPA, `pepd`, une petite application | rien : `curl` et des certificats |
| Son rôle | décide qui peut faire quoi, et signe un jeton | vérifie le jeton avant que l'application n'agisse | joue l'agent : demande, puis présente ce qu'il a reçu |
| Ce qu'elle détient | les clés des contrôleurs et des opérateurs, les CA, la clé d'émission | du public seulement : la clé publique de l'émetteur, celles des contrôleurs, les règles signées | les certificats et clés de ses agents |
| Ce qu'elle ne détient jamais | — | **aucune clé de gouvernance**, aucune clé de CA | aucune clé de gouvernance, aucune clé de CA |
| Ce que vous y faites | inscrire, signer les plans, signer les preuves des contrôleurs | fermer et rouvrir `pepd` avec ces preuves | demander, rejouer, falsifier, usurper |

**Pourquoi ces trois-là.** C'est le plus petit ensemble qui exerce ce qu'un test à une machine ne peut pas :
l'*inscription* (les agents de M3 sont liés aux certificats que M1 a émis), une décision *par le réseau* (TLS
mutuel), et l'*application* par une machine différente de celle qui a décidé (M2 ne fait confiance à M1 que par ce
que le paquet de M1 a épinglé : elle n'appelle jamais M1). Un vrai site d'échelle 2 a la même forme avec plusieurs
serveurs et plusieurs hôtes d'agents : M1 est *la* cellule, M2 est l'un des serveurs applicatifs, M3 est un hôte
d'agents.

## Le réseau

Mettez les trois machines sur un même réseau privé (un VPC de cloud, ou un réseau hôte seul). Seuls ces flux sont
nécessaires :

| De → vers | Port | Quoi | Ouvert à |
|---|---|---|---|
| M3 → M1 | 8443/tcp | les décisions, TLS mutuel | l'adresse de M3 seulement |
| M3 → M2 | 9000/tcp | l'application | l'adresse de M3 seulement |
| vous → chacune | 22/tcp | ssh et `scp` | votre adresse seulement |

Rien d'autre, et **rien depuis Internet**. Utilisez le pare-feu ou les groupes de sécurité de votre fournisseur.
`pepd` écoute sur `127.0.0.1:8443` sur M2 : M3 ne peut donc pas l'atteindre ; l'administration de la cellule est un
socket Unix sur M1, pas un port réseau. Après le déploiement, vérifiez ce que chaque machine écoute vraiment :
`scripts/devtest/site.sh m1 listeners` (et `m2`, `m3`).

## Avant de commencer

| Machine | Il faut |
|---|---|
| M1 | Debian 12, un utilisateur avec `sudo`, `git curl jq openssl`, **OPA**, **Go** (la version de `go.mod`) — ou les binaires de la release |
| M2 | Debian 12, `git curl jq openssl python3` — rien d'autre : ses binaires viennent du paquet de M1 |
| M3 | Debian 12, `git curl jq perl` |

Nous n'avons pas mesuré la plus petite machine qui convient ; nos essais ont utilisé 4 CPU et 16 Go pour l'ensemble.
Chaque `report` note la vôtre, dites-le-nous. Nous n'avons pas non plus chronométré un déploiement à froid sur trois
machines neuves : cette durée fait partie de ce que nous demandons.

## Déployer

Remplacez `<M1>`, `<M2>` par les adresses **privées** des machines sur votre réseau. `--env` est une étiquette libre
(par exemple `fournisseur, taille, région`) que vos rapports répètent : c'est ainsi que nous distinguons les
environnements.

**Sur M1** — la cellule :

```bash
sudo apt-get update && sudo apt-get install -y git curl jq openssl ca-certificates
# OPA, la version que la CI utilise, vérifié avec sa somme de contrôle publiée
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static.sha256
sha256sum -c opa_linux_amd64_static.sha256          # doit répondre : opa_linux_amd64_static: OK
sudo install -m 0755 opa_linux_amd64_static /usr/local/bin/opa
# Go, au moins la version de go.mod (le paquet Debian 12 est en 1.19, trop ancien). Comparez la somme de contrôle
# de l'archive à celle de https://go.dev/dl/ avant de la décompresser.
curl -fsSLO https://go.dev/dl/go1.27.2.linux-amd64.tar.gz
sha256sum go1.27.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.27.2.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/site.sh m1 init --address <M1> --env "<fournisseur, taille, région>"
scripts/devtest/site.sh m1 up
scp ~/tbp-site-m1/packs/m2.pack.tgz <utilisateur>@<M2>:      # du public et des binaires : aucune clé de gouvernance
scp ~/tbp-site-m1/packs/m3.pack.tgz <utilisateur>@<M3>:      # les clés privées des agents : M3 seulement
```

`init` demande `sudo` une fois, pour écrire `/etc/tbp/DEV_ENVIRONMENT` : M1 utilise une graine d'émetteur en
fichier au lieu d'un HSM, l'un des deux interrupteurs de développement utilisés (l'autre est la trace de décision, [plus bas](#suivre-une-requête--de-son-émission-à-son-exécution-ou-à-son-rejet)), et `brokerd` les refuse sans ce sentinel.
Il lève une alarme de haute priorité à chaque démarrage ; c'est attendu. M2 et M3 n'ont pas besoin de sentinel.

**Sur M2** — le serveur applicatif :

```bash
sudo apt-get update && sudo apt-get install -y git curl jq openssl python3 ca-certificates
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/site.sh m2 init --pack ~/m2.pack.tgz --listen <M2>:9000 --env "<fournisseur, taille, région>"
scripts/devtest/site.sh m2 up
```

`up` se termine par `pepd's posture: monitor` : à son premier démarrage, `pepd` enregistre chaque verdict et ne
bloque rien.

**Sur M3** — l'agent :

```bash
sudo apt-get update && sudo apt-get install -y git curl jq perl ca-certificates
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/site.sh m3 init --pack ~/m3.pack.tgz --app http://<M2>:9000 --env "<fournisseur, taille, région>"
scripts/devtest/site.sh m3 check
```

`check` doit se terminer par `site M3: the plumbing works` : M3 atteint la cellule en TLS mutuel et y est refusée
comme il se doit (pas de plan ; le certificat d'un autre agent ; aucun certificat), et atteint l'application de M2,
qui refuse une requête sans jeton. Sinon, c'est déjà une trouvaille : lancez `report` sur les trois machines et
dites-le-nous ([plus bas](#nous-dire-ce-que-vous-avez-trouvé)).

## Quoi tester : est-ce que ça marche ?

Jouez ces étapes dans l'ordre. Chacune dit où elle se joue, et ce qu'elle prouve quand elle donne la réponse indiquée.

| # | Sur | Faire | Vous devez obtenir | Cela prouve |
|---|---|---|---|---|
| 1 | M3 | `site.sh m3 act agent-i read doc-1` | `plan-binding-required`, pas de jeton | la cellule n'admet rien qu'aucun opérateur n'ait approuvé |
| 2 | M1 | `site.sh m1 sign agent-i read doc-1`, puis tapez `sign` | le plan en clair, son hash recalculé par l'outil lui-même, puis un plan approuvé et la ligne `m3 act …` exacte à exécuter | le côté opérateurs comme le fait une personne : vous voyez ce que vous signez, et le hash signé est celui que vous avez calculé (`--yes` saute les questions, jamais le recalcul) |
| 3 | M3 | collez cette ligne | `{"allow":true,"reason":"ok"}`, puis sur M2 `{"executed": "read doc-1", "verdict": { … "mode": "monitor", "forwarded": true }}` `[200]` | **tout le chemin** : l'inscription par certificat, la décision, le jeton signé, `pepd` sur une autre machine qui le vérifie, l'application qui agit |
| 4 | M3 | `site.sh m3 call` (le même jeton de nouveau) | `[200]` mais `"reason": "replay"` | en monitor, `pepd` enregistre le refus qui aurait eu lieu et ne bloque rien |
| 5 | M1, M3 | obtenez un jeton neuf (2–3), puis `site.sh m3 call read doc-9` ; un autre, puis `site.sh m3 call --forge` | `scope-mismatch`, puis `bad-signature`, tous deux encore `[200]` en monitor | `pepd` vérifie la portée et la signature |
| 6 | M1 | `site.sh m1 mode-proof closed` | un fichier de preuve, signé par **un** contrôleur | fermer restreint : un contrôleur suffit |
| 7 | M2 | copiez ce fichier, `site.sh m2 mode closed --proof <fichier>` | `{"mode":"closed"}` | la posture est gouvernée par les contrôleurs, depuis M1, pas par M2 |
| 8 | M1, M3 | refaites 4 et 5 (un jeton neuf à chaque fois) | maintenant `[403]` pour le rejeu, l'autre ressource et le jeton falsifié ; l'étape 3 reste `[200]` | closed : le verdict de `pepd` est appliqué |
| 9 | M1, M2 | `m1 mode-proof monitor --controllers 1` → `m2 mode monitor --proof` | `[403]` | rouvrir élargit : un contrôleur ne suffit pas |
| 10 | M1, M2 | `m1 mode-proof monitor` (deux contrôleurs) → `m2 mode monitor --proof` | `{"mode":"monitor"}` | deux contrôleurs rouvrent |
| 11 | M1, M3 | `m1 sign agent-w read doc-1` (répondez `sign` aux opérateurs, puis aux contrôleurs), exécutez la ligne ; puis exécutez-la de nouveau **sans** `--proof …` | `executed` ; puis `quorum-required` | la classe W demande deux opérateurs **et** deux contrôleurs |
| 12 | M3 | `site.sh m3 act agent-i read doc-1 --as agent-w` ; `… --no-cert` | `agent-transport-unbound` ; un refus de poignée de main TLS | un agent ne peut ni utiliser le certificat d'un autre, ni aucun |
| 13 | M2 | `site.sh m2 down`, `site.sh m2 up`, puis l'étape 3 | `pepd's posture: refused`, puis `[403]` avec `"forwarded": false` | un redémarrage ne rouvre jamais en silence |
| 14 | M1, M2 | `m1 mode-proof monitor` → `m2 mode monitor --proof`, puis l'étape 3 | `[200]` de nouveau | deux contrôleurs reconfirment la posture |

**À chaque étape, suivez la requête.** Chaque `m3 act` affiche un identifiant de trace ; `m1 trace` montre où cette requête est allée, quel composant l'a arrêtée, et pourquoi ([plus bas](#suivre-une-requête--de-son-émission-à-son-exécution-ou-à-son-rejet)). Les étapes 1, 5, 8, 12 et 13 sont celles où le *pourquoi* compte.

**Lisez `forwarded`, pas `allow`.** L'application de M2 agit quand `pepd` dit `forwarded: true`, et c'est ce qu'elle
doit faire : en *refused*, le verdict peut porter à la fois `"allow": true` et `"forwarded": false` (le jeton est
valide, la posture bloque), et en *monitor* une requête refusée est transmise quand même. Une vraie application suit
`forwarded`.

Les preuves vivent quelques minutes (environ quatre) : faites les étapes 6–7, 9 et 10, et 14 sans longue pause
entre les machines.

## Suivre une requête : de son émission à son exécution ou à son rejet

Savoir *qu'*une requête est refusée ne suffit pas dans un test : il faut savoir **quel composant l'a arrêtée, et pourquoi**.
Chacune des trois machines consigne ce qu'elle voit, et M1 en fait une chronologie par requête.

```
scripts/devtest/site.sh m3 act agent-i read doc-1      # affiche  [trace t-1760180000-3fa2c1]
scripts/devtest/site.sh m2 trace-export                # sur M2 : emballe ce que M2 a vu    → ~/tbp-site-m2/trace-m2.tgz
scripts/devtest/site.sh m3 trace-export                # sur M3 : emballe ce que M3 a vu    → ~/tbp-site-m3/trace-m3.tgz
scp <M2>:tbp-site-m2/trace-m2.tgz <M3>:tbp-site-m3/trace-m3.tgz .          # vers M1 (ou tout endroit que M1 lit)
scripts/devtest/site.sh m1 trace --from trace-m2.tgz --from trace-m3.tgz [--id t-1760180000-3fa2c1]
```

```
t-1760180000-3fa2c1   agent-i asks: read doc-1
  +0.000s  M3  agent     agent-i asks: read doc-1   [certificate: agent-i]
  +0.772s  M1  brokerd   ALLOW ok   [agent-i · read doc-1 · certificate agent-i · mtls from 10.0.0.9 · 746.4 ms · jti a2332e25…]
  +0.790s  M3  agent     got: allow ok
  +0.821s  M2  app       request received: read doc-1 with a token   [from 10.0.0.9]
  +1.077s  M2  pepd      verdict allow ok   [posture monitor · forwarded true · 251.5 ms]
  +1.077s  M2  app       EXECUTED   [HTTP 200]
  → EXECUTED
```

Chaque ligne dit **où** (M1/M2/M3 et le composant), **ce qui a été décidé** et **pourquoi** (le code de raison,
expliqué à la fin d'une requête rejetée : *« REJECTED by the cell (M1) — plan-binding-required — the cell: plan
contract: an action of class I or W needs a plan approved by operators, and none was given »*). Le catalogue des
explications est [`scripts/devtest/reasons.tsv`](../../scripts/devtest/reasons.tsv) (en anglais, comme la sortie). Dans
la posture monitor, une requête que `pepd` refuserait s'exécute quand même, et la conclusion le dit :
*« EXECUTED — although pepd's verdict was replay »*.

**Ce que cela demande, et ce que cela expose.** L'identifiant voyage de `m3 act` vers la cellule et vers l'application
dans l'en-tête `X-TBP-Trace-Id`. Pour montrer le côté de la cellule — le certificat présenté, l'intention reçue, la
raison — le `brokerd` de M1 tourne avec un interrupteur de développement de plus, `TBP_DECISION_TRACE_DEV` (il exige le
même sentinel que la graine d'émission et figure avec elle dans l'alarme de démarrage et dans la liste des interrupteurs
de développement actifs). **`pepd` n'est pas modifié et M2 n'a toujours aucun interrupteur de développement** : le côté
M2 est le verdict que `pepd` a rendu à l'application, que l'application consigne.

**Requêtes sans identifiant.** Qui attaque avec `curl` n'envoie pas d'identifiant. Ses requêtes sont quand même vues —
la décision de la cellule avec le certificat et l'adresse d'où elle vient, le refus de l'application — et listées à
part, sous *without a trace id*. Une poignée de main TLS refusée ne devient jamais une requête côté cellule : elle est
lue dans le journal de `brokerd` (qui note des secondes entières) et rattachée à la requête de l'agent faite sans
certificat quand elles sont à moins de trois secondes l'une de l'autre, et le dit.

**Limites.** Les horloges des trois machines diffèrent : les écarts entre machines sont indicatifs (à la précision de
votre NTP) ; l'ordre *dans* une machine est exact. Une requête n'est complète que si vous avez donné à `m1 trace` les
fichiers de toutes les machines qui y ont pris part (sinon elle finit *INCOMPLETE*). La trace contient des noms
d'agents, des ressources, des noms de certificats et des adresses — **jamais un jeton, une clé ou une graine** — et
chaque fichier est en `0600` ; relisez une archive avant de la coller dans une issue publique.

## L'attaquer

**Depuis M3 — la position réseau.** M3 est la machine qu'un adversaire a le plus de chances de tenir. Essayez, et
attendez-vous à :

| Essai | Attendu |
|---|---|
| `scripts/devtest/site.sh m3 act … --no-cert` | la poignée de main est refusée : aucune réponse HTTP |
| `curl -i -X POST -d '{}' http://<M1>:8443/v1/actions` (HTTP en clair, sans TLS) | `400 Client sent an HTTP request to an HTTPS server` : jamais une décision, la cellule n'a pas de listener en clair |
| `curl http://<M2>:8443/v1/evaluate` (le port propre de pepd) | connexion refusée : `pepd` n'écoute que sur le loopback de M2 |
| scanner M1 et M2 (`nmap -p- <M1> <M2>`) | seulement les ports que vous avez ouverts : 22 et 8443 sur M1, 22 et 9000 sur M2 — rien d'autre que TBP ait démarré |
| `site.sh m3 act agent-i … --as agent-w` | `agent-transport-unbound` |
| une requête avec un jeton falsifié, rejoué ou d'une autre portée | `bad-signature`, `replay`, `scope-mismatch` : `[403]` une fois closed |
| une requête à l'application avec un jeton absent, vide ou géant | refusée avant `pepd` ou par lui, jamais exécutée |

**Sur M2 — quelqu'un qui peut écrire dans les fichiers du serveur.** Lancez d'abord `site.sh m2 down`, et restaurez
le fichier ensuite.

| Essai | Attendu au `m2 up` |
|---|---|
| ajouter une seconde clé à `~/tbp-site-m2/issuer-keyring.json` (faire confiance à un autre émetteur) | `pepd` refuse de démarrer : `provisioning-divergence` |
| `sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' ~/tbp-site-m2/m2.env` | `pepd` refuse de démarrer, en nommant `quorum-settings` |
| `echo changed >> ~/tbp-site-m2/app/ai-container.txt` (un fichier mesuré) | `pepd` refuse de démarrer : `manifest-boot-divergence` |
| altérer un octet de `~/tbp-site-m2/opa/bundle.tar.gz` | OPA ne démarre pas : `load error: bundle …` |

**Sur M1 — les fichiers de la cellule elle-même**, et les côtés opérateurs et agents de la cellule : les essais de
[solo.fr.md](solo.fr.md) (« Ce que vous pouvez attaquer, depuis trois positions ») s'appliquent à M1 tels quels,
avec `site.sh m1` pour les chemins et les variables ; baisser `TBP_QUORUM_MIN` dans `~/tbp-site-m1/m1.env` arrête
`brokerd`, en nommant `quorum-settings`.

Tout ce que vous pouvez faire et que le système **accepte en silence** est le genre de trouvaille que nous voulons le
plus. Les limites connues sont dans le [README](../../README.md) (« Honesty about where this stands »), dans
[CHANGELOG.md](../../CHANGELOG.md) et dans [governed-acts.fr.md](../governed-acts.fr.md).

## Nous dire ce que vous avez trouvé

Nous voulons vos chiffres et vos commentaires — y compris « je suis resté bloqué ici » — **pour chaque environnement
que vous essayez**.

**Vos chiffres.** Sur chaque machine, lancez `scripts/devtest/site.sh m1 report` (ou `m2`, `m3`) et collez les trois
rapports. Un rapport note le commit, le système (OS, noyau, CPU, mémoire), l'étiquette d'environnement que vous avez
donnée, les versions, la durée de `init` et de `up`, et :

- **M1** les compteurs de la cellule ;
- **M2** la posture et les compteurs de `pepd`, et la latence du verdict application → `pepd` (un jeton mal formé, le
  verdict le moins cher) ;
- **M3** l'aller-retour de décision vers la cellule en TLS mutuel (une nouvelle connexion à chaque fois : il inclut
  donc la poignée de main TLS et **votre réseau**) et l'aller-retour vers l'application.

Aucun rapport ne contient de clé, de graine, de chemin, d'adresse ni de nom de machine.

À propos de la latence : la feuille d'une décision est écrite dans le journal signé avant que la cellule réponde
(pas de feuille, pas de réponse) ; sur nos essais une décision prend donc environ une demi-seconde, dont l'essentiel,
d'après ce que nous voyons, est cette écriture ; nous ne l'avons pas isolée. Ce que votre réseau ajoute est la
différence que vous verrez sur M3. Ce sont des mesures de cette installation dans votre environnement, pas des
affirmations de performance : si les vôtres diffèrent beaucoup, c'est utile à savoir.

**Vos commentaires**, de la façon qui convient :

| Quoi | Où |
|---|---|
| Une étape qui ne marche pas, une doc fausse, un comportement différent de ce qui est écrit, vos durées, une suggestion | une issue GitHub publique, avec le modèle **Dev-test feedback** (le titre commence par `[dev-test]`), les trois rapports collés |
| Tout ce qui est exploitable : un moyen de passer un refus, une acceptation silencieuse, un secret qui fuit | **en privé**, comme le dit [SECURITY.md](../../SECURITY.md) — pas une issue publique |

Ce qui rend un retour utile : ce que vous avez essayé (la commande exacte), ce que vous attendiez, ce qui s'est
passé, et les rapports.

## Ce que cela ne vous dit pas

- **La garde des clés et la séparation entre personnes.** Toutes les clés de gouvernance — celles des contrôleurs,
  des opérateurs, des CA — sont dans un seul dossier sur M1, sous un seul utilisateur. La compromission de cet
  utilisateur est la compromission de la cellule. Un vrai site l'évite avec des personnes distinctes et des HSM.
- **La clé d'émission est une graine en fichier**, et la cellule écrit une trace de décision avec noms et intentions en clair : c'est pourquoi M1 déclare le sentinel de développement.
- **Les certificats vivent 30 jours**, émis par deux CA sur M1 (une pour le certificat de la cellule, une dédiée aux
  agents).
- **Le démarrage mesuré de M2 utilise deux substituts** — le binaire `pepd` à la place d'un binaire de broker, un
  fichier vide à la place d'un conteneur d'IA — et enregistre sa référence au premier démarrage. Un vrai serveur
  mesure les vrais.
- **Il n'y a pas de console.** Tout se fait en ligne de commande : `m1 sign` vous montre un plan et vous demande de
  taper `sign` ; `m1 mode-proof` signe les preuves des contrôleurs ; `m1 status` et `report` donnent des compteurs ; `m1 watch` est une vue texte en lecture seule de la cellule
  (processus, règles en vigueur, décisions, fautes, plans en attente par hash, journal d'audit ; une source qui ne
  répond pas s'affiche `UNKNOWN`, jamais en vert ; `--every 5` la répète) ; la piste d'audit se lit avec
  `tbp-audit verify`. Il n'y a ni tableau de bord ni écran. `supervisord` (JSON en lecture seule sur un socket Unix,
  [superviseur.fr.md](../superviseur.fr.md)) existe dans ce dépôt mais ne fait pas partie de ce test, et rien dans le
  dépôt ne permet à un opérateur de *signer* autrement qu'en ligne de commande. Ce qu'une console doit montrer et
  permettre de faire, et sous quelle forme, est une question ouverte ([#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329)) : dites-nous ce qui vous a manqué.
- **Un de chaque.** Une cellule, un serveur, un hôte d'agents. Pas de superviseur, pas de multi-cellule, pas de NAC
  802.1X, et l'isolation réseau de [network-isolation.fr.md](../network-isolation.fr.md) n'est pas mise en place :
  le pare-feu est le vôtre.
- **L'application est un substitut** (`scripts/devtest/site-app.py`, bibliothèque standard de Python), pas un vrai
  service.

## Commandes

| `site.sh` | Fait |
|---|---|
| `m1 init --address <M1> [--listen addr:port] [--env étiquette]` | compile les binaires, fait les clés, les règles signées, les deux CA et les certificats d'agents, l'environnement et les deux paquets |
| `m1 up` / `down` / `status` | démarre OPA et `brokerd` / les arrête / les montre avec les compteurs |
| `m1 sign <agent> <action> <ressource> [--yes]` | le côté opérateurs (et, pour la classe W, contrôleurs) d'une action : soumet le plan, le montre en clair, recalcule son hash, vous demande de taper `sign` ; affiche la ligne `m3 act` à exécuter |
| `m1 grant <agent> <action> <ressource>` | identique à `sign --yes` (sans questions ; le hash est quand même recalculé) |
| `m1 watch [--every SECONDES]` | une vue en lecture seule de la cellule : processus, règles, décisions, fautes, plans en attente (par hash), journal d'audit ; `UNKNOWN` quand une source ne répond pas, code de sortie non nul |
| `m1 mode-proof closed\|monitor [--controllers N]` | la preuve des contrôleurs pour le `pepd` de M2 : un contrôleur pour fermer, deux pour rouvrir |
| `m1 trace [--from <archive ou répertoire> ...] [--id <identifiant>]` | les requêtes consignées par M1 et par les machines dont vous donnez les archives, une chronologie chacune : qui a demandé, ce que chaque composant a décidé, pourquoi, comment cela s'est terminé |
| `<rôle> trace-export` | emballe ce que cette machine a consigné des requêtes qu'elle a vues, à porter vers M1 |
| `m1 pack` | réécrit les deux paquets |
| `m2 init --pack <m2.pack.tgz> --listen <M2>:9000 [--env étiquette]` | décompresse, écrit l'environnement de `pepd` (un vrai démarrage mesuré, aucune échappatoire de développement) |
| `m2 up` / `down` / `status` | démarre OPA, `pepd` et l'application / les arrête / les montre |
| `m2 mode closed\|monitor --proof <fichier>` | envoie la preuve des contrôleurs à `pepd` |
| `m3 init --pack <m3.pack.tgz> --app http://<M2>:9000 [--env étiquette]` | installe les certificats des agents |
| `m3 check` | la plomberie : atteint la cellule et l'application, refusée comme il se doit |
| `m3 act <agent> <action> <ressource> [--binding HEX] [--proof HEX] [--as agent] [--no-cert]` | interroge la cellule, puis présente le jeton à M2 |
| `m3 call [<action> <ressource>] [--forge]` | présente de nouveau le dernier jeton, pour une autre ressource, ou un octet changé |
| `<rôle> report` · `<rôle> listeners` · `<rôle> reset` | le rapport à coller · ce que la machine écoute · arrête et supprime tout ce qui a été fait (M1 retire le sentinel s'il l'a créé) |

`init` refuse une machine qui contient déjà `/var/lib/tbp`, ou `/etc/tbp/brokerd.env`, `/etc/tbp/pepd.env` ou
`/etc/tbp/quorum-keyring.json` (elle ressemble à un vrai déploiement), refuse root sauf `DEVTEST_ALLOW_ROOT=1`
(conteneurs jetables), et un `TBP_SITE_HOME` trop long pour les chemins de socket Unix. Les fichiers de chaque
machine vivent dans `$TBP_SITE_HOME` (par défaut `~/tbp-site-m1`, `~/tbp-site-m2`, `~/tbp-site-m3`). Quand vous avez
fini, `reset` sur chaque machine, ou détruisez les machines.
