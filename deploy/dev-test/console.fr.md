# Le moniteur : où il est, comment le lire, comment s'en servir

_English version: [console.md](console.md). Fait partie de [deploy/dev-test](README.fr.md) ; les machines sont décrites
dans [site.fr.md](site.fr.md)._

> **Il n'y a pas d'écran à ouvrir.** La « console » du site DEV-TEST, ce sont trois commandes que vous tapez dans un
> terminal **sur M1**, la cellule. Rien n'écoute pour elle, pas d'URL, pas de connexion : celui qui peut lancer `site.sh`
> avec l'utilisateur qui a fait `m1 init` est l'opérateur. (Ce que devrait être une vraie console est une question
> ouverte, [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329) : dites-nous ce qui vous a manqué.)

## Que voulez-vous savoir ?

| Vous voulez savoir | Lancez | Sur | Cela montre |
|---|---|---|---|
| La cellule va-t-elle bien, qu'a-t-elle décidé jusqu'ici, quelque chose attend-il ? | `scripts/devtest/site.sh m1 watch` | M1 | une page d'état de 7 lignes |
| Ce qui est arrivé à **ma requête** : qui l'a arrêtée, et pourquoi ? | `scripts/devtest/site.sh m1 trace` | M1 | une chronologie par requête, à travers les trois machines |
| Que vais-je signer, et est-ce ce que la cellule a scellé ? | `scripts/devtest/site.sh m1 sign <agent> <action> <ressource>` | M1 | le plan en clair, un hash recalculé, une question |
| Les processus de cette machine tournent-ils ? | `scripts/devtest/site.sh m1\|m2 status` | M1, M2 | up / DOWN, compteurs |
| Sur quoi cette machine écoute-t-elle ? | `scripts/devtest/site.sh m1\|m2\|m3 listeners` | toutes | ports et adresses |
| Que vous envoyer quand quelque chose a mal tourné ? | `scripts/devtest/site.sh m1\|m2\|m3 report` | toutes | des chiffres, aucun secret |

## Y accéder

1. Connectez-vous à **M1** (SSH) avec l'utilisateur qui a lancé `site.sh m1 init`, dans la copie du dépôt. Si vous avez
   donné à `init` un autre répertoire, positionnez d'abord `TBP_SITE_HOME` dessus (défaut `~/tbp-site-m1`).
2. Tout ce qui suit se lance de là. Les commandes ne font que **lire** (`watch`, `trace`) ou vous demandent avant d'agir
   (`sign`) ; aucune ne change l'état du test.
3. Pour voir ce qu'ont consigné **M2** et **M3**, vous apportez leurs fichiers sur M1 (le moniteur lit des fichiers ; il
   n'appelle pas ces machines) :

```
# sur M2 et sur M3, une fois vos requêtes faites
scripts/devtest/site.sh m2 trace-export      # → ~/tbp-site-m2/trace-m2.tgz
scripts/devtest/site.sh m3 trace-export      # → ~/tbp-site-m3/trace-m3.tgz
# sur M1
scp <user>@<M2>:tbp-site-m2/trace-m2.tgz <user>@<M3>:tbp-site-m3/trace-m3.tgz .
scripts/devtest/site.sh m1 trace --from trace-m2.tgz --from trace-m3.tgz
```

Sans `--from`, `m1 trace` ne montre que ce que M1 a vu : une requête refusée par la cellule est complète, une requête
acceptée se termine par *TOKEN ISSUED … not presented* parce que les fichiers de M2 et M3 manquent — c'est normal, pas une
faute. Refaites l'export après de nouvelles requêtes : une archive est un instantané.

## Lire `m1 watch`

```
cell cell-site · 2026-10-11T11:05:27Z · read-only view (a line says UNKNOWN when its source does not answer)
processes  : opa up · brokerd up
rules      : 601b4836a09855f4… (signed bundle) · OPA healthy · unanswered 0 · shed 0
decisions  : 12 requests · 4 allowed · 8 denied (quorum 0, plan 5, envelope 0)
faults     : none (issuance, ledger leaves, translation)
epoch      : single cell, no fencing (epoch 0)
pending    : 2 plan(s) waiting (hash only — the cell keeps no plan in clear)
audit      : 14 record(s) checked, 0 failure(s) (hash match only; inclusion in the signed log: tbp-audit verify -log …)
```

| Ligne | Signifie | Inquiétez-vous quand |
|---|---|---|
| `processes` | OPA (le moteur de règles) et `brokerd` (la cellule) tournent | `DOWN` |
| `rules` | les 16 premiers chiffres hexa des règles signées en vigueur, si OPA répond, s'il délaisse des requêtes | `STALLED`, `unanswered` ou `shed` qui grandit |
| `decisions` | requêtes décidées par la cellule depuis son démarrage, et les refus par cause | `quorum` ou `plan` qui grandit sans que vous l'attendiez : quelqu'un demande sans plan approuvé |
| `faults` | échecs **de la cellule elle-même** (n'a pas pu signer un jeton, écrire une feuille, traduire) | autre chose que `none` : une faute n'est jamais un refus normal |
| `epoch` | l'époque de la cellule ; une cellule seule n'a pas de fencing | — |
| `pending` | plans soumis et pas encore approuvés, par hash seulement : la cellule ne garde aucun plan en clair, ce qu'un plan *dit* se lit là où vous signez (`m1 sign`), pas ici | un nombre qui ne redescend jamais |
| `audit` | le journal d'audit de la cellule correspond toujours à ses feuilles | `! the journal does not verify` |

**`UNKNOWN` et `DOWN` ne sont jamais verts.** Si une source ne répond pas, sa ligne le dit et la commande **sort en code
non nul**, un script peut donc s'y fier. Une cellule arrêtée affiche `UNKNOWN` sur chaque ligne. `--every 5` répète la
vue toutes les 5 secondes (Ctrl-C pour arrêter).

## Lire `m1 trace`

```
t-1791718709-30e71f   token presented again: read doc-1
  +0.000s  M3  agent     token presented again: read doc-1
  +0.015s  M2  app       request received: read doc-1 with a token   [from 10.0.0.9]
  +0.017s  M2  pepd      verdict deny replay   [posture monitor · forwarded true · 0.7 ms]
  +0.017s  M2  app       EXECUTED   [HTTP 200]
  → EXECUTED — although pepd's verdict was replay: in the monitor posture pepd records and blocks nothing
```

**L'en-tête** est l'**identifiant de trace** de la requête, affiché par `m3 act` et `m3 call` (`[trace t-…]`). Le même
identifiant voyage jusqu'à la cellule et l'application dans l'en-tête `X-TBP-Trace-Id` : c'est ainsi que les
enregistrements de trois machines sont joints.

**Chaque ligne :** `+décalage` depuis le premier événement · la machine (`M1` cellule, `M2` serveur, `M3` agent) · le
composant · ce qu'il a fait, détails entre crochets.

| Composant | Machine | C'est | Sa ligne dit |
|---|---|---|---|
| `agent` | M3 | le script qui joue l'agent | ce qu'il a demandé, avec quel certificat, ce qu'il a reçu |
| `brokerd` | M1 | la cellule | `ALLOW`/`DENY` et la **raison** ; entre crochets : l'agent, l'action, le **certificat** présenté, mTLS ou socket Unix, l'**adresse** d'où cela venait, la durée, l'identifiant du jeton (`jti`) |
| `transport` | M1 | la couche TLS devant la cellule | une connexion qui a échoué **avant** de devenir une requête (pas de certificat client, ou le mauvais) |
| `pepd` | M2 | le point d'application | son **verdict** sur le jeton, la posture (`monitor`, `closed`, `refused`) et `forwarded` |
| `app` | M2 | la petite application | la requête reçue, et ce qu'elle en a fait : `EXECUTED` ou `REFUSED` |

**La dernière ligne (`→`) répond à « que s'est-il passé ? » :**

| Elle dit | Signifie |
|---|---|
| `EXECUTED` | l'application a agi |
| `EXECUTED — although pepd's verdict was …` | `pepd` a dit non mais la posture est `monitor` : elle enregistre et ne bloque rien. Fermez pour bloquer ([monitor-to-closed.fr.md](../monitor-to-closed.fr.md)) |
| `REJECTED by the cell (M1) — <raison> — <où> : <pourquoi>` | la cellule a refusé : aucun jeton émis. Le `où` nomme l'étape (identité, contrat de plan, quorum, politique…) |
| `REJECTED at the TLS handshake (M1)` | pas de certificat client (ou le mauvais) : la cellule n'a jamais vu de requête |
| `REJECTED by pepd (M2) — <raison> …` | le jeton était mauvais, rejoué ou pour autre chose, **et** la posture bloque (`closed`/`refused`) |
| `REJECTED by the application (M2) — no-token` | la requête ne portait aucun jeton |
| `TOKEN ISSUED by the cell, not presented …` | l'agent a reçu un jeton et ne l'a pas utilisé (ou le fichier de M2 manque) |
| `INCOMPLETE — no end seen …` | le fichier d'une machine manque : ajoutez son `--from` |

Chaque code de raison (`opa-deny`, `plan-binding-required`, `replay`…) est expliqué à la fin d'une requête rejetée ; le
catalogue complet est [`scripts/devtest/reasons.tsv`](../../scripts/devtest/reasons.tsv) (en anglais, comme la sortie).

**La section « without a trace id ».** Un client qui n'est pas nos scripts — `curl`, un scanner, un red team — n'envoie
pas d'identifiant. Ces requêtes sont quand même vues par la cellule (ligne `brokerd`, avec le certificat et l'adresse) et
par l'application, et sont listées à part, une ligne par événement, du plus ancien au plus récent. C'est là qu'il faut
regarder pour voir **votre propre attaque**.

## S'en servir

| Pour | Faites |
|---|---|
| voir une seule requête | `m1 trace … --id t-1791718709-30e71f` |
| suivre pendant que vous testez | `watch -n 5 scripts/devtest/site.sh m1 watch` (ou `m1 watch --every 5`) ; pour `trace`, réexportez et relancez — il travaille sur des instantanés |
| signer le plan d'une action | `m1 sign agent-i read doc-1` : il montre le plan, recalcule son hash, vous demande de taper `sign`. Toute autre réponse ne signe rien. `grant` est `sign --yes` (sans questions, le hash est quand même recalculé) |
| fermer ou rouvrir `pepd` | `m1 mode-proof closed\|monitor` sur M1, puis `m2 mode … --proof <fichier>` sur M2 : un contrôleur pour fermer, deux pour rouvrir |
| vérifier la piste d'audit contre le log signé | `tbp-audit verify -records … -key … -log … -vkey-file …` (voir [audit.fr.md](../audit.fr.md)) |

C'est tout : **vous ne pouvez rien approuver, révoquer ni changer depuis `watch` ou `trace`.** Les seuls endroits où une
personne agit sont `m1 sign` et `m1 mode-proof`, et tous deux disent ce qu'ils vont faire.

## Recettes

**« Ma requête a été refusée et je ne sais pas pourquoi. »** Lancez `m3 act …`, notez le `[trace t-…]`, exportez M2 et
M3, puis `m1 trace --from … --id t-…`. Lisez la dernière ligne.

**« J'attaque la cellule avec `curl` et je veux voir ce qu'elle a vu. »** Faites votre attaque, puis `m1 trace` : vos
requêtes sont sous *without a trace id*, avec le certificat présenté et votre adresse. Une connexion refusée à la poignée
de main TLS s'affiche `transport … TLS handshake failed`.

**« J'ai fermé `pepd` : qu'est-ce qui change ? »** Faites la même requête avant et après. Avant : `EXECUTED — although
pepd's verdict was replay`. Après : `REJECTED by pepd (M2) — replay`.

**« Rien ne s'affiche. »** `m1 trace` écrit `no request recorded yet` tant qu'aucune requête n'a été faite *depuis que
la cellule tourne avec la trace* (une cellule démarrée par un ancien `m1 init` ne trace pas : refaites `m1 init` sur un
répertoire propre).

## Ce qu'il ne montre pas

- **Les horloges.** Les horloges des trois machines diffèrent : les décalages *entre* machines sont indicatifs ; l'ordre
  *dans* une machine est exact. Une poignée de main TLS refusée est rattachée **par le temps** à la requête qui
  l'explique (le journal de la cellule note des secondes entières, à 3 s près), et la ligne le dit.
- **La vue propre de `pepd`.** Les lignes `pepd` sont le verdict qu'il a rendu à l'application. `pepd` lui-même n'est pas
  modifié et M2 n'a aucun interrupteur de développement.
- **Le contenu d'un plan.** `watch` montre les plans par hash ; leur contenu s'affiche quand vous signez.
- **Les secrets.** Aucun jeton, clé ni graine n'est jamais consigné. Les fichiers contiennent des noms d'agents, des
  ressources, des noms de certificats et des adresses : **relisez une archive avant de la coller dans une issue
  publique.**
