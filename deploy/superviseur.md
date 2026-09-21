# deploy/superviseur.md — machine « superviseur » (T35, issue #61)

Le superviseur porte trois fonctions INDÉPENDANTES des cellules (§2,
§7.1) : le **registre maître** (master chain, T6 — ancres des bundles par
époque, fenêtres saines lues par la promotion §7.4), le **moniteur
indépendant** (T34 — sa propre clé et son propre log, il n'écrit JAMAIS
dans les chaînes surveillées) et la **console** (arbitrages, époques,
indicateurs §9.1). La génèse (scripts/genesis) se célèbre ici, sur HSM.

> Trou déclaré **#74** : il n'existe pas de binaire `supervisord` —
> `src/supervision` est une bibliothèque (NewMonitor, NewConsole,
> ChainWatcher) à assembler, comme pepd assemble le PEP. Patron à
> l'étape 3.

#### Étape 1 — Célébrer la genèse (HSM)

**Prérequis vérifiable** : étapes communes de [README.md](README.md)
vertes ; HSM branché (ou SoftHSM — DEV uniquement, jamais racine de
gouvernance §12) ; `softhsm2-util`, `libsofthsm2.so`, `go` présents.

**Commande** :

```bash
N=3 M=2 AUTHORITY=cell-a GENESIS_HOME=scripts/genesis/out \
  bash scripts/genesis/genesis_dev.sh
cat scripts/genesis/out/manifest.json   # clés des contrôleurs, quorum 2-of-3
```

**Critère de succès observable** : `manifest.json`, `pubkeys/*.hex`,
`epoch0.json`, `anchor_epoch0.txt` produits ; le manifest liste les M-of-N
convenus.

**En cas d'échec : STOP** — pas de genèse, pas de réseau. Ne jamais
fabriquer epoch0.json à la main : la phase fencing du selftest montre
qu'un jeton équivoque est refusé et alarmé — un epoch 0 artisanal serait
indistinguable d'une faute.

#### Étape 2 — Distribuer selon la custody (D97)

**Prérequis vérifiable** : étape 1 verte.

**Commande** :

```bash
# Aux cellules : pubkeys/*.hex + epoch0.json (canal authentifié).
# Aux serveurs : rien de la genèse (ils n'ont pas de gouvernance à vérifier).
# ICI : les clés privées des contrôleurs restent dans le HSM — jamais
# exportées sur une autre machine, jamais dans le dépôt.
sha256sum scripts/genesis/out/pubkeys/*.hex
```

**Critère de succès observable** : chaque cellule accuse réception des
pubkeys et d'epoch0 ; aucune clé privée n'a quitté le HSM (journal HSM).

**En cas d'échec : STOP** — une clé privée de contrôleur copiée hors HSM
invalide la cérémonie : refaire la genèse, révoquer l'ancienne.

#### Étape 3 — Assembler moniteur et console (patron — trou #74)

**Prérequis vérifiable** : étape 1 verte ; les cellules à surveiller
tournent en monitor (cellule.md étape 6).

**Commande** :

```bash
# Patron d'assemblage (à compléter dans un cmd/supervisord — #74) :
#   mon := supervision.NewMonitor(MonitorOptions{
#     MonitorCellID, Log: log du MONITEUR (sa chaîne, §7.1),
#     Cells: []CellSpec (≥1), Master: MasterSpec (requis),
#     MaxAnchorLag, Sink: AlarmSink, Now, Trigger})
#   con := supervision.NewConsole(ConsoleOptions{Stats: <source de
#     compteurs broker — requis, §9.1>, …})
#   con.Serve(ctx, lis)  # GET /v1/arbitration, /v1/epoch, /v1/indicators
go test ./src/supervision/   # les contrats assemblés sont testés (T34)
```

**Critère de succès observable** : les tests du paquet passent ; le motif
ChainWatcher (scan vérifié : checkpoint signé + cohérence Merkle) est
celui que la phase fencing du selftest utilise pour compter les feuilles
des deux cellules.

**En cas d'échec : STOP** — ne pas inventer un démon ; suivre #74. Un
moniteur qui écrirait dans les chaînes surveillées violerait §2/§7.1 :
refuser toute assemblage qui lui en donne le moyen.

#### Étape 4 — Surveiller sans écrire

**Prérequis vérifiable** : étape 3 verte ; `cell_log.vkey` de chaque
cellule récupéré (clé PUBLIQUE de checkpoint — seule pièce nécessaire au
scan vérifié, custody D97).

**Commande** :

```bash
# Le moniteur rejoue les registres des cellules en LECTURE vérifiée.
# Toute anomalie (équivoque d'époque, retard d'ancre, fraude de
# continuation) devient une alerte — jamais une écriture corrective.
go run ./deploy/selftest -phase fencing   # démontre la boucle complète
```

**Critère de succès observable** : le rapport fencing montre les feuilles
`KindEpoch` des DEUX cellules lues par scan vérifié (4 sur cell-a, 3 sur
cell-b dans le scénario de référence) ; les alertes arrivent sur le Sink.

**En cas d'échec : STOP** — un scan qui échoue (checkpoint invalide,
chaîne cassée) est une ALARME, pas un incident à contourner.

#### Étape 5 — Fenêtres saines et promotion (§7.4)

**Prérequis vérifiable** : étapes 1-4 vertes ; le master chain ancre les
bundles par époque.

**Commande** :

```bash
# La fenêtre saine est LUE dans le master, jamais mesurée par le canari :
# PromotionController refuse toute promotion dont l'ancre ou la fenêtre
# est indisponible (partition = refus fail-closed — démontré par la phase
# fencing du selftest : ErrPromotionAnchorUnavailable).
grep -n "HealthyWindow\|BundleAnchor" src/cluster/promotion.go | head -5
```

**Critère de succès observable** : les ancres et fenêtres sont publiées
par époque dans le master ; le selftest fencing prouve admission (fenêtre
saine) et refus (partition) avec feuilles `KindPromotion` des deux côtés.

**En cas d'échec : STOP** — sans ancre d'époque, aucune promotion n'est
possible ; c'est le comportement voulu, pas une panne à réparer.

## Durcissement

Unités systemd sur le patron T24 (`src/translator/tbp-translator.service`)
à adapter ; la machine superviseur ne rejoint AUCUN VLAN de production
(§5.1) — son canal est la supervision, pas le trafic.
