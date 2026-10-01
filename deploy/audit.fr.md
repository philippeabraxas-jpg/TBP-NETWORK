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

## Producteurs

Câblés à ce jour :

| Producteur | Feuilles | Configuration |
|---|---|---|
| `pepd` — décisions : validateur (`TBPD1`/`TBPD2`), client OPA, coupures de quota, refus dry-run | `KindDecision` | `TBP_AUDIT_RECORDS` (chemin du journal) + `TBP_AUDIT_RECORDS_KEY_FILE` (`tbp-audit keygen`). **Requis** par `pepd` (sans journal il ne démarre pas). Un journal qui refuse d'écrire ⇒ aucune feuille ⇒ un allow devient un deny (`leaf-write-failed`). |
| `pepd` — audit de réécriture d'ano (`TBAN1`, #178) | `KindTelemetry` | même journal (partagé) |
| `brokerd` — chaîne de décision (`TBPD1`), client OPA, contrats de plan (`TBPL1`/`TBPL2`, signature comprise), quorum classe W (`TBPQ1`) | `KindDecision`, `KindContract`, `KindQuorum` | son propre `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**requis** : `brokerd` ne démarre pas sans eux). Même ordre fail-closed : journal refusé ⇒ aucune feuille ⇒ l'émission est refusée. |

Tous les autres producteurs (supervisord, le suivi d'époque, la surveillance de
révision OPA, la garde de provisionnement, les drapeaux dev, le manifeste,
l'ancrage, la feuille de télémétrie du dry-run, alarmes d'horloge, bascules de
mode, déclenchements fail-closed, …) inscrivent encore une feuille nue : leurs
feuilles n'ont pas d'entrée de journal et `tbp-audit` n'a rien à en dire. Les
câbler est suivi dans #275, un producteur à la fois.
