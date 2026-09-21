# Déploiement multi-machine (T35, issue #61)

Guides de déploiement du réseau TBP à l'échelle : rôles par machine, ordre
d'installation (§13), instructions côté serveur (§5.1). Public visé : un
opérateur **non-auteur** — chaque étape porte un prérequis vérifiable, un
critère de succès observable, et un « En cas d'échec : STOP ». Ne jamais
continuer après un prérequis rouge.

**Commencer par la vue d'ensemble** — quoi, où, pourquoi, prérequis :
[apercu.md](apercu.md). Revenir ici pour l'ordre d'installation, la
custody des clés et les étapes communes.

## Rôles et machines

| Rôle | Machine | Services | Guide |
|---|---|---|---|
| Routeur | Debian 12 dédiée (ou VM, 2+ interfaces) | NAC 802.1X (FreeRADIUS EAP-TLS), nftables, VLANs §5.1 | [router-debian.md](router-debian.md) |
| Cellule | VM par cellule (a, b, …) | broker, registre tessera, OPA, tracker d'époques, HSM (genèse §12) | [cellule.md](cellule.md) |
| Serveur | hôte applicatif (PostgreSQL, …) | PEP (pepd), acceptation via le broker de SA cellule uniquement | [serveur.md](serveur.md) |
| Superviseur | VM indépendante | registre maître (master chain), moniteur indépendant, console | [superviseur.md](superviseur.md) |

Bascule de posture (monitor → closed, §5.3) : [monitor-to-closed.md](monitor-to-closed.md).
Checklists de recette par machine : [checklists/](checklists/).

## Custody des clés (décision D97 — « jamais de clé de gouvernance hors son rôle »)

| Clé | Vit sur | Jamais sur | Référence |
|---|---|---|---|
| Clés des contrôleurs de quorum (genèse) | HSM de la cérémonie (superviseur) | cellules, serveurs, routeur | §12, scripts/genesis |
| Clé de registre de cellule (`cell_log.key`) | SA cellule uniquement | toute autre machine | §4.1, motif pepd |
| Sel de hachage des feuilles (≥ 16 octets) | le producteur des feuilles | registres, superviseur | §6.2 |
| Clés privées EAP-TLS (PKI §3) | routeur (RADIUS) + supplicants | repo, cellules | config/freeradius (à adapter) |
| Clé du moniteur indépendant | superviseur | cellules surveillées | §2, §7.1 (T34) |

Conséquence repo : `*.pem`, `*.key`, `config/freeradius/certs/` (à adapter, jamais copiée),
`policies/capabilities.json` et les sorties de selftest sont gitignorés —
rien de tout cela ne se committe, jamais.

## Ordre d'installation (§13 décliné — décision D98)

```
0. prérequis communs (ci-dessous)
1. genèse              scripts/genesis — clés contrôleurs + epoch 0 (HSM)
2. fencing             trackers d'époques sur chaque cellule (éprouvé par
                       deploy/selftest, phase fencing 2-cellules)
3. OPA + registre      capabilities restreintes, registre tessera
4. PEP / broker        pepd en mode MONITOR (§5.3), rien d'autre
5. NAC routeur         802.1X + VLANs — dernier maillon réseau
6. traducteur          optionnel, en dernier (src/translator, T24)
```

L'ordre n'est pas cosmétique : la gouvernance (1-2) précède la politique
(3), qui précède l'application (4), qui précède le réseau (5). Déployer le
NAC avant le fencing laisserait des clients admis sans gouvernance
d'époque — exactement le défaut que le fencing existe pour empêcher.

## Étapes communes

#### Étape 1 — Vérifier les binaires de base sur CHAQUE machine

**Prérequis vérifiable** : accès shell à la machine, droits sudo.

**Commande** :

```bash
go version    # ≥ 1.24
opa version   # ≥ 1.0
python3 --version
```

**Critère de succès observable** : les trois commandes répondent avec des
versions conformes.

**En cas d'échec : STOP** — installer les binaires avant toute chose ; ne
jamais « adapter » une étape suivante pour contourner un prérequis rouge.

#### Étape 2 — Récupérer le dépôt et vérifier l'auto-test de déploiement

**Prérequis vérifiable** : étape 1 verte ; le dépôt est cloné.

**Commande** :

```bash
bash deploy/selftest/selftest.sh
```

**Critère de succès observable** : `selftest.sh: tout est vert` — 82
contrôles (cellule mono réelle, fencing 2-cellules, démons
brokerd/supervisord réels) et la vérification formelle des guides
passent ; rapport dans `deploy/selftest/out/selftest-report.json`.

**En cas d'échec : STOP** — le guide lu dérive du code ; lire le contrôle
rouge du rapport, corriger la cause (jamais le contrôle).

#### Étape 3 — Préparer la genèse (machine superviseur, HSM requis)

**Prérequis vérifiable** : étape 2 verte ; HSM ou SoftHSM (DEV
uniquement — SoftHSM n'est jamais une racine de gouvernance, §12) ;
`softhsm2-util` et `libsofthsm2.so` présents.

**Commande** :

```bash
N=3 M=2 AUTHORITY=cell-a GENESIS_HOME=scripts/genesis/out \
  bash scripts/genesis/genesis_dev.sh
```

**Critère de succès observable** : `manifest.json`, `pubkeys/*.hex`,
`epoch0.json`, `anchor_epoch0.txt` produits sous `GENESIS_HOME`.

**En cas d'échec : STOP** — pas de jeton d'époque 0, pas de cluster ;
corriger la cérémonie, ne pas fabriquer d'epoch 0 à la main.

#### Étape 4 — Dérouler les guides par rôle dans l'ordre §13

**Prérequis vérifiable** : étapes 1-3 vertes ; artefacts de genèse
distribués selon la matrice de custody ci-dessus (pubkeys aux cellules,
jamais les clés privées des contrôleurs).

**Commande** :

```bash
# Dans l'ordre : cellules (deploy/cellule.md), serveurs
# (deploy/serveur.md), superviseur (deploy/superviseur.md),
# routeur (deploy/router-debian.md). Posture : MONITOR partout.
ls deploy/checklists/   # une checklist de recette par machine
```

**Critère de succès observable** : chaque checklist de recette est verte
sur sa machine ; tous les PEP répondent `{"mode":"monitor"}` sur
`GET /v1/mode`.

**En cas d'échec : STOP** — une checklist rouge bloque la suite ; le mode
closed ne se demande qu'après [monitor-to-closed.md](monitor-to-closed.md).

## Règles transverses (rappelées dans chaque guide)

- **`config/` est un point de départ à adapter**, jamais copié tel quel
  (D99 — le vérificateur formel casse toute référence sans « adapter »).
- **Monitor avant closed** (§5.3) : aucune instruction de mode fermé tant
  que les points de mesure §9.1 ne sont pas installés (D100).
- **Points de mesure §9.1 d'abord** : le harness T27
  (`tests/p1_friction/`) est la référence exécutable des métriques.
- **Ed25519 partout** (§12) ; le sel des feuilles reste chez le
  producteur (§6.2) ; toute décision laisse une feuille (§4.1).
- **Trous déclarés** : `opa run --capabilities` a disparu en OPA ≥ 1.0 :
  la forme supportée (bundle compilé avec capabilities restreintes) est
  documentée dans [cellule.md](cellule.md) et exécutée par le selftest.
  Le scénario netns/FreeRADIUS complet se joue en lab
  (`lab/containerlab/`), pas en sandbox — les causes réelles sont citées
  dans [router-debian.md](router-debian.md). Les démons `brokerd` et
  `supervisord` (T37, issue #74) sont livrés avec leurs units systemd —
  la phase daemons du selftest les exerce réellement.
