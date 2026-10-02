# Enregistrements d'audit — où vit le clair, comment le vérifier (#271)

_English version: [audit.md](audit.md)._

Les feuilles du registre sont **hash-only** (§6.2) : `sha256(sel ‖ record)`,
jamais le record. Le sel et le record restent chez le **producteur** (le démon
qui a écrit la feuille). Cette page fixe ce qui manquait : **le fichier où vit
le clair**, et **la commande qui prouve qu'un record appartient à une
feuille**. Le lecteur d'audit de l'outil d'administration (#86) montre ce que
cette page définit, rien d'autre.

## Décision

Option 1 de #271 : **un journal d'enregistrements local et chiffré par démon.**
Le clair ne quitte jamais la cellule ; le registre et la master chain restent
hash-only. (Écartées : le clair dans le registre — contredit hash-only ; aucun
clair — l'audit ne montrerait que des hash.)

## Le journal

`registry.RecordStore` — ajout seul, JSON lignes, une entrée par feuille :

```
{"v":1,"leaf":"<hex des octets exacts de la feuille>","nonce":"<b64>","ct":"<b64>"}
```

- `leaf` est public (la feuille est dans le log) et indexe l'entrée sans clé.
- `ct` = AES-256-GCM(clé du journal, `len(sel) ‖ sel ‖ record`), avec les
  **octets de la feuille en données authentifiées** : une entrée déplacée sous
  une autre feuille, ou une feuille éditée dans le fichier, ne se déchiffre plus.
- `Put` refuse un record qui ne hache pas vers la feuille, un sel < 16 octets et
  un horodatage nul. Chaque écriture est fsyncée.

**Ordre d'écriture (fail-closed).** `registry.AppendSealed` écrit le record dans
le journal **avant** d'inscrire la feuille. Si le journal refuse, **aucune
feuille** n'est écrite : il n'existe jamais de feuille dont le clair n'existe
pas. Le cas inverse (record écrit, feuille non inscrite) laisse un record
**orphelin** : inoffensif, et signalé par la vérification.

**Une exception documentée : les feuilles écrites autour du verrou de backpressure.** La feuille
d'arrêt (`KindBackpressure`) et la feuille d'épisode de durabilité (`TBAD1`) sont la preuve que la
cellule s'est arrêtée, et le journal est le plus souvent sur le disque qui vient de se remplir. Si le
journal refuse leur clair, la feuille est **quand même écrite, nue** (hash seul), et le démon le dit :
la raison de l'alarme du backpressure porte `+journal-write-failed` (pepd journalise `ALARME journal
d'audit` pour la feuille d'épisode). Le verrou tient dans les deux cas. La feuille est ensuite listée
par `tbp-audit verify -coverage`. (Décision prise dans #275 : un arrêt sans trace dans le log signé est
pire qu'un arrêt dont le clair manque et est signalé.)

## La clé du journal

Un secret de 32 octets, en hex dans un fichier `0600` (un mode plus large est
refusé au chargement). Elle protège contre la lecture du **seul fichier de
journal**. Si elle est sur le même disque, qui prend le disque prend les deux :
la garder en HSM ou sur un volume séparé (limite, pas une garantie). À générer
une fois :

```
tbp-audit keygen -out /etc/tbp/records.key      # n'écrase jamais
```

## Vérifier — `tbp-audit`

```
tbp-audit verify -records records.jsonl -key records.key \
    -log /var/lib/tbp/registry -vkey-file cell_log.pub [-index N] [-reveal]
```

Sans `-log`, seul `sha256(sel ‖ record)` = hash de la feuille est contrôlé
(`hash-ok`). Avec `-log`, la feuille doit en plus être **dans le log** sous un
**checkpoint signé** (clé publique exigée — un checkpoint non vérifié n'est pas
une preuve), avec une preuve d'inclusion RFC 6962 vérifiée contre sa racine
(`inclus index=N`).

| Statut | Sens |
|---|---|
| `inclus index=N` | record conforme à la feuille, feuille prouvée dans le log |
| `hash-ok` | record conforme au hash de la feuille ; log non consulté |
| `ORPHELIN` | record journalisé, feuille absente du log |
| `HASH-DIFFÉRENT` | le clair ne hache pas vers la feuille (record altéré) |
| `REJETÉ` | signature de checkpoint / preuve d'inclusion rejetée |

Code de sortie : `0` tout vérifié, `1` au moins un échec, `2` usage ou journal
illisible (mauvaise clé, ligne altérée — un journal lisible en partie ne passe
pas pour complet). Le clair n'est affiché qu'avec `-reveal`.

**La vérification inverse : `-coverage`.** `verify` va du journal vers le log : il voit un
enregistrement orphelin, mais **pas** une feuille qui est dans le log sans entrée de journal.
`-coverage` (exige `-log`) relit **toutes les feuilles du log** sous le checkpoint signé et liste
celles sans entrée de journal (`SANS-CLAIR`), code de sortie `1` s'il y en a :

```
tbp-audit verify -records records.jsonl -key records.key \
    -log /var/lib/tbp/registry -vkey-file cell_log.pub -coverage
feuille index=412 kind=3 cell=cell-a ts=… SANS-CLAIR : aucune entrée de journal
```

Une telle feuille n'est attendue que dans deux cas : une feuille **antérieure au journal**, et
l'**exception documentée** ci-dessous (journal refusé sur un disque plein). Tout autre cas est un
producteur non câblé — le selftest lance cette vérification sur le log de chaque démon.

## Producteurs

Câblés à ce jour :

| Producteur | Feuilles | Configuration |
|---|---|---|
| `pepd` — décisions : validateur (`TBPD1`/`TBPD2`), client OPA, coupures de quota, refus dry-run | `KindDecision` | `TBP_AUDIT_RECORDS` (chemin du journal) + `TBP_AUDIT_RECORDS_KEY_FILE` (`tbp-audit keygen`). **Requis** par `pepd` (sans journal il ne démarre pas). Un journal qui refuse d'écrire ⇒ aucune feuille ⇒ un allow devient un deny (`leaf-write-failed`). |
| `pepd` — audit de réécriture d'ano (`TBAN1`, #178) | `KindTelemetry` | même journal (partagé) |
| `pepd` / `brokerd` — feuilles d'état et d'alarme : déclenchements et levées fail-closed (`TBFF1`), alarmes d'horloge (`TBPC1`), bascules de posture (`TBPM1`), alarmes de révision OPA (`TBPR1`), télémétrie dry-run (`TBPF2`) | `KindTelemetry` | même journal (partagé) |
| `brokerd` — chaîne de décision (`TBPD1`), client OPA, contrats de plan (`TBPL1`/`TBPL2`, signature comprise), quorum classe W (`TBPQ1`) | `KindDecision`, `KindContract`, `KindQuorum` | son propre `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**requis** : `brokerd` ne démarre pas sans eux). Même ordre fail-closed : journal refusé ⇒ aucune feuille ⇒ l'émission est refusée. |
| `pepd` / `brokerd` / `anod` — garde de provisionnement (`TBPL3` : genèse, démarrage, transition, refus, ré-engagement) | `KindManifest` | même journal (partagé) ; `anod` a son propre `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**requis** : `anod` ne démarre pas sans eux). Un journal qui refuse ⇒ aucune feuille ⇒ la garde refuse le démarrage. |
| `pepd` — manifeste du démarrage mesuré (`TBPL2`) | `KindManifest` | même journal (partagé) |
| `brokerd` — suivi d'époque (`TBPE1`), feuille d'épisode de l'écrivain asynchrone de `pepd` (`TBAD1`) | `KindEpoch`, `KindTelemetry` | même journal (partagé) |
| Producteurs de bibliothèque à option `Journal`, câblés par le démon qui les fait tourner : contrôleur de promotion (`TBPP1`), ancreur, feuille d'arrêt du backpressure | `KindPromotion`, `KindAnchor`, `KindBackpressure` | option `Journal` (nil = feuille nue). La feuille d'arrêt et la feuille d'épisode s'écrivent autour du verrou de backpressure : un journal qui refuse ⇒ la feuille est **quand même écrite, nue** et l'alarme dit `+journal-write-failed` (voir « une exception documentée ») ; le verrou tient. |
| `supervisord` — alertes du moniteur (`TBPS1`, sel compris) | `KindSupervision` | son propre `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**requis** : sans journal `supervisord` ne démarre pas). Un journal qui refuse ⇒ aucune feuille ⇒ aucune alerte notifiée. |
| `pepd` / `brokerd` — drapeaux d'échappatoires dev (`TBDV1`) | `KindTelemetry` | même journal (partagé) ; un journal qui refuse ⇒ le démarrage est refusé |
| `tmetrics` — mesure du traducteur (`TBTM1`) | `KindTelemetry` | `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**requis**), qui désignent le journal du service (pepd ou brokerd) propriétaire du registre où il inscrit |
| `brokerd` — arbitrage humain des demandes dégradées, **opt-in** avec la garde (#275) : mise en file, décision d'opérateur (approuve / refuse, avec le kid de l'opérateur) et consommation à usage unique (`TBAR1`, hash-only : id de la demande, sujet, jamais le contenu) | `KindTelemetry` | même journal (partagé) ; un journal qui refuse ⇒ aucun effet (rien mis en file, décidé ni consommé) et alarme `arbiter-leaf-write-failed` |
| `brokerd` — promotions du miroir, **opt-in** avec la garde (#275) : chaque décision du `PromotionController` sur un reçu du miroir, acceptée ou refusée (`TBPP1`) | `KindPromotion` | même journal (partagé) ; un journal qui refuse ⇒ le refus est rendu comme non tracé et rien n'est promu |
| `brokerd` — garde de dégradation du traducteur, **opt-in** `TBP_TRANSLATOR_GUARD=1` (#275) : épisodes down / reprise et chaque refus en mode dégradé (`TBTD1`) | `KindTelemetry` | même journal (partagé) ; un journal qui refuse ⇒ pas de feuille et alarme `translator-leaf-write-failed`, la direction d'échec reste le déni |
| `pepd` — pipeline de télémétrie de passeport, **opt-in** `TBP_TELEMETRY=1` (#275) : agrégateur à fenêtres (`TBAG1`, une feuille par fenêtre scellée, vides comprises), détecteur anti-dribble (`TBAD1`), purge de rétention (`TBRP1`) | `KindTelemetry`, `KindTelemetryAlert`, `KindRetentionPurge` | même journal (partagé) ; un journal qui refuse ⇒ pas de feuille et alarme `leaf-write-failed`, jamais un silence |
| Producteurs de bibliothèque à option `Journal`, pas encore exécutés dans un démon : puits de feuilles de l'exporteur de télémétrie (`TBTM1`, un `fsync` par record — à brancher en connaissance de cause) | `KindTelemetry` | option `Journal` (nil = feuille nue) |

Tout producteur de feuilles de ce dépôt a désormais une couture de journal, et
tout démon qui écrit des feuilles exige son journal. Un producteur de
bibliothèque n'est nu que tant que son hôte ne branche pas `Journal` : `pepd`
fait tourner le pipeline de télémétrie (opt-in) et `brokerd` le contrôleur de
dégradation du traducteur (opt-in) ; rien dans le dépôt ne fait encore tourner
le puits de feuilles de l'exporteur de télémétrie dans un démon.
