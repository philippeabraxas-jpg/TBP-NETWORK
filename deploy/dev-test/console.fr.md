# La console temps réel : voir une requête traverser les trois machines, dans un navigateur

_English version: [console.md](console.md). Fait partie de [deploy/dev-test](README.fr.md) ; les machines sont décrites
dans [site.fr.md](site.fr.md)._

> **Pas pour la production.** La console est un outil de test : elle montre en clair les noms, ressources et adresses de
> vos machines de test, en HTTP simple, derrière une clé. Elle est **en lecture seule** : rien sur la page n'agit sur le
> test.

Vous déployez les trois machines, vous ouvrez **une adresse** dans un navigateur, et vous voyez — pendant que vous agissez —
**le trajet** de chaque requête (agent → TLS et identité → décision de la cellule → application → `pepd` → exécutée ou
rejetée), **l'état** de chaque composant, et **la latence** de chaque étape.

![ce que montre la page : les composants en haut, les requêtes et le trajet de la requête choisie en dessous, le tableau des latences](console.png)

## L'ouvrir

`m1 up` affiche l'adresse, avec sa clé :

```
site M1: up. Agents reach the cell at https://10.0.0.5:8443 (mutual TLS).
         the live console (open it in a browser): http://10.0.0.5:9100/?key=07a79b9cd60a7332e79ab8c779273240
```

Ouvrez cette adresse depuis votre propre machine. (`site.sh m1 console-url` la réaffiche.) La clé est gardée dans un
cookie et retirée de la barre d'adresse. Il existe deux clés, différentes : celle de l'adresse **ouvre la page** ; l'autre
**permet à M1, M2 et M3 d'envoyer** ce qu'elles voient. Qui peut envoyer ne peut pas lire, et qui peut lire ne peut pas
envoyer.

La console tourne **sur M1 par défaut**, et **écoute sur l'adresse de M1, port 9100**. Elle demande trois flux réseau en
plus de ceux de [site.fr.md](site.fr.md#le-réseau) :

| De → vers | Port | Quoi | Ouvert à |
|---|---|---|---|
| vous (navigateur) → la console | 9100/tcp | la page | votre adresse seulement |
| M2 → la console | 9100/tcp | les événements et l'état des composants de M2 | l'adresse de M2 seulement |
| M3 → la console | 9100/tcp | les événements de M3 | l'adresse de M3 seulement |

(Les événements de M1 ne quittent pas M1 quand la console y est.) Filtrez le port 9100 comme le 22 : votre adresse et les
trois machines, **rien depuis Internet**.

### Sur une machine à part, ou n'importe où

« Sur M1 ou ailleurs » : la console peut tourner sur toute machine que M1, M2, M3 et votre navigateur atteignent — une
quatrième machine, ou votre portable. Donnez son adresse à M1 à l'`init`, puis démarrez la console là avec la même clé :

```bash
KEY=$(openssl rand -hex 16)
# sur M1 (à la place de la console par défaut sur M1) :
scripts/devtest/site.sh m1 init --address <M1> --console-url http://<C>:9100 --console-key "$KEY" --env "…"
# sur la machine C (Go, `curl`, `openssl` ; le dépôt) :
scripts/devtest/site.sh console up --listen <C>:9100 --ingest-key "$KEY"      # affiche l'adresse à ouvrir
```

M2 et M3 apprennent l'adresse et la clé par leurs paquets : rien d'autre à configurer. `console down`, `console url`,
`console status` et `console reset` font ce qu'ils disent.

## Ce que montre la page

**Composants.** Une carte par machine, avec l'état de chaque composant et **depuis combien de temps il a rapporté pour la
dernière fois** : `M1` — OPA et `brokerd` (décisions jusqu'ici, refus par cause, fautes de la cellule elle-même, règles en
vigueur, plans en attente) ; `M2` — OPA, `pepd` (sa **posture**, `monitor`/`closed`/`refused`, ses verdicts et leur durée
moyenne et maximale) et l'application ; `M3` — l'agent, qui n'a pas de démon : il est `idle`, jamais `down`, et la carte dit
quand il a agi pour la dernière fois. **Une machine qui ne rapporte plus passe `UNKNOWN` après 8 secondes — elle n'est
jamais laissée en vert.**

**Requêtes.** La plus récente en haut. Chaque ligne : l'heure, ce qui a été demandé, un mini-trajet de six points, comment
cela s'est terminé, la durée de bout en bout. Filtrez par issue, **Pause** pour lire, cliquez une ligne pour l'ouvrir (son
adresse prend `#<identifiant de trace>` : vous pouvez l'envoyer à quelqu'un).

**Le trajet de la requête choisie.** Six étapes — *agent → TLS / identité → décision de la cellule → application → verdict
de pepd → exécutée* — chacune verte (passée), ambre (passée bien que `pepd` ait dit non : la posture monitor), rouge
(**c'est ici qu'elle a été arrêtée**), ou grise (non atteinte, ou pas encore). Dessous, **la dernière ligne dit comment
cela s'est terminé et pourquoi**, en mots : *« REJECTED by the cell (M1) — plan-binding-required — the cell: plan
contract: an action of class I or W needs a plan approved by operators, and none was given »*. Chaque code de raison est
expliqué ([`reasons.tsv`](../../scripts/devtest/reasons.tsv), en anglais comme la page).

**La latence de la requête choisie**, étape par étape, et **les percentiles sur les 500 dernières requêtes** (p50, p95,
p99, max) dans le tableau plus bas.

**Sans identifiant de trace.** Un client qui n'est pas nos scripts — `curl`, un scanner, un red team — n'envoie pas
d'identifiant. Ce que la cellule et l'application en ont vu est listé ici, une ligne par événement, avec le certificat
présenté et l'adresse d'où cela venait. C'est là qu'apparaît **votre propre attaque**.

## Comment la latence est mesurée

Chaque durée est mesurée **sur une seule machine, avec une seule horloge** : il ne faut donc jamais comparer les horloges
des trois machines (elles diffèrent) :

| Étape | Mesurée par | Comment |
|---|---|---|
| connexion TCP, poignée de main TLS | M3 | les chronomètres de `curl` |
| **réseau + HTTP** vers la cellule | M3 et M1 | l'attente du premier octet côté M3, **moins** le temps de décision de la cellule |
| **décision de la cellule** | M1 (`brokerd`) | de la lecture de la requête au verdict |
| aller-retour vers la cellule | M3 | le total de `curl` |
| **réseau + HTTP** vers l'application | M3 et M2 | l'attente côté M3, moins le temps de traitement de l'application |
| **traitement de l'application** | M2 (l'application) | de la réception de la requête à sa réponse |
| **verdict de `pepd`** | M2 (`pepd`) | la mesure de `pepd` lui-même |
| aller-retour vers l'application | M3 | le total de `curl` |
| de bout en bout | M3 | les deux allers-retours additionnés (hors le temps entre les deux) |

« Réseau + HTTP » est ce qui reste d'une attente une fois le travail propre de l'autre côté retiré : le réseau, la pile
HTTP et les files d'attente. S'il est grand, regardez le réseau ; si la décision de la cellule ou le verdict de `pepd`
est grand, regardez ce composant. L'ordre des lignes d'une requête suit les étapes qu'elle a traversées, pas les horloges.

## Lire le reste

**La fin d'une requête :**

| Elle dit | Signifie |
|---|---|
| `EXECUTED` | l'application a agi |
| `EXECUTED — although pepd's verdict was …` | `pepd` a dit non mais la posture est `monitor` : elle enregistre et ne bloque rien. Fermez pour bloquer ([monitor-to-closed.fr.md](../monitor-to-closed.fr.md)) |
| `REJECTED by the cell (M1) — <raison> — <où> : <pourquoi>` | la cellule a refusé : aucun jeton émis |
| `REJECTED at the TLS handshake (M1)` | pas de certificat client (ou le mauvais) : la cellule n'a jamais vu de requête |
| `REJECTED by pepd (M2) — <raison> …` | le jeton était mauvais, rejoué ou pour autre chose, **et** la posture bloque (`closed`/`refused`) |
| `REJECTED by the application (M2) — no-token` | la requête ne portait aucun jeton |
| `TOKEN ISSUED by the cell, not presented …` | l'agent a reçu un jeton et ne l'a pas utilisé (ou la machine qui le montrerait ne rapporte pas) |
| `INCOMPLETE — no end seen …` | une machine a pris part et ne rapporte pas à cette console |

Une poignée de main TLS refusée ne devient jamais une requête côté cellule : le journal de `brokerd` est le seul à la
connaître, et l'expéditeur de M1 le lit. Elle est rattachée à la requête qu'un agent a faite sans certificat quand elles
sont à moins de 3 secondes l'une de l'autre, et la ligne le dit.

## Recettes

**« Ma requête a été refusée et je ne sais pas pourquoi. »** Lancez `m3 act …` et regardez la console : la requête est la
ligne du haut, l'étape rouge est le composant qui l'a arrêtée, la dernière ligne dit pourquoi.

**« J'attaque la cellule avec `curl`. »** Faites votre attaque ; ouvrez l'onglet *Without a trace id*. Une connexion refusée
à la poignée de main TLS s'affiche `transport … TLS handshake failed`.

**« Je ferme `pepd` : qu'est-ce qui change ? »** Faites la même requête avant et après, et comparez les deux lignes :
l'étape ambre *pepd verdict* devient rouge, la conclusion passe de *EXECUTED — although …* à *REJECTED by pepd*.

**« Où passe le temps ? »** Faites 20 requêtes, puis lisez le tableau des percentiles. L'étape au plus grand p95 est celle
à regarder.

**« Une carte dit UNKNOWN. »** Cette machine ne rapporte plus : son expéditeur est arrêté, elle ne joint pas la console (le
pare-feu), ou la machine est arrêtée. `site.sh m2 status` dessus. UNKNOWN n'est jamais bon signe.

## Sans navigateur

La même information, dans un terminal sur M1 — utile sur une mauvaise liaison, ou pour garder une trace. Elles lisent des
fichiers et des sockets ; aucune ne change le test.

| Commande | Montre |
|---|---|
| `scripts/devtest/site.sh m1 watch` (`--every 5` la répète) | la page d'état de la cellule : processus, règles, décisions, fautes, plans en attente (par hash), journal d'audit. Une source qui ne répond pas est `UNKNOWN`, et le code de sortie est non nul |
| `scripts/devtest/site.sh m2 trace-export` et `m3 trace-export` | emballent ce que cette machine a consigné, à copier sur M1 |
| `scripts/devtest/site.sh m1 trace --from trace-m2.tgz --from trace-m3.tgz [--id t-…]` | une chronologie par requête, avec les mêmes conclusions que la page (un test vérifie qu'elles concordent). Les requêtes sans identifiant sont listées à part, sous *without a trace id* ; une requête dont le fichier d'une machine manque se termine par *INCOMPLETE* |
| `scripts/devtest/site.sh m1 sign <agent> <action> <ressource>` | **le seul endroit où une personne approuve quelque chose** : il montre le plan en clair, recalcule son hash, vous demande de taper `sign` |

Chaque `m3 act` affiche un identifiant de trace (`[trace t-…]`) : le même identifiant voyage jusqu'à la cellule et
l'application dans l'en-tête `X-TBP-Trace-Id`, c'est ainsi que les enregistrements de trois machines sont joints.

## Ce qu'elle ne fait pas

- **Elle n'agit pas.** Aucun bouton n'approuve, ne révoque, ne ferme `pepd` ni ne signe. La signature reste dans
  `m1 sign`, la fermeture et la réouverture dans `m1 mode-proof` et `m2 mode`. Ce que devrait être une vraie console
  d'opérateur — ce qu'elle doit faire et montrer — est la question ouverte de
  [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329) : dites-nous ce qui vous a manqué.
- **Elle ne garde pas d'historique.** Elle tient les 2000 dernières requêtes **en mémoire**. Redémarrer la console la
  vide ; `m1 down` puis `m1 up` la redémarrent et rejouent les événements consignés par M1, `m2 down` puis `m2 up`
  rejouent ceux de M2 (les fichiers sont conservés) ; ceux de M3 ne sont pas rejoués.
- **Elle n'est pas authentifiée comme un service de production.** HTTP simple, deux clés secrètes : utilisez un réseau
  privé et un pare-feu. Tout ce qu'une requête porte — sujet, ressource, intention, adresses — est affiché **comme du
  texte**, jamais comme du contenu de page : un red team peut y mettre n'importe quoi, la page ne l'exécute pas (un test
  ouvre la page dans un vrai navigateur pour le vérifier). Ne collez pas une capture de la page dans une issue publique
  sans la relire.
- **Les horloges.** Les décalages entre machines ne sont pas montrés, car ils tromperaient. Les durées le sont, car chacune
  est mesurée par une seule machine.
- **La vue propre de `pepd`.** Les lignes `pepd` sont le verdict qu'il a rendu à l'application, et ses compteurs. `pepd`
  lui-même n'est pas modifié, et M2 n'a aucun interrupteur de développement pour la console. La cellule, M1, en a un : sa
  trace de décision est le second interrupteur de développement (`TBP_DECISION_TRACE_DEV`, derrière le même sentinel que
  la graine d'émission).
