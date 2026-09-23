# deploy/superviseur.md — machine « superviseur » (T35, issue #61)

_English version: [superviseur.md](superviseur.md)._

Le superviseur porte trois fonctions INDÉPENDANTES des cellules (§2,
§7.1) : le **registre maître** (master chain, T6 — ancres des bundles par
époque, fenêtres saines lues par la promotion §7.4), le **moniteur
indépendant** (T34 — sa propre clé et son propre log, il n'écrit JAMAIS
dans les chaînes surveillées) et la **console** (arbitrages, époques,
indicateurs §9.1). La génèse (scripts/genesis) se célèbre ici, sur HSM.

> Le démon `supervisord` (T37 — issue #74) assemble moniteur et console ;
> la phase daemons de `deploy/selftest/` exécute l'étape 3 de ce guide
> contre les vrais binaires (build, témoins fail-closed, lectures LIVE,
> 503 d'honnêteté quand la source tombe). Si une commande ci-dessous
> diverge du selftest, le selftest casse : corrigez le guide ou le code.

#### Étape 1 — Célébrer la genèse (HSM)

**Prérequis vérifiable** : étapes communes de [README.md](README.fr.md)
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

#### Étape 3 — Compiler et démarrer supervisord (moniteur + console, T37)

**Prérequis vérifiable** : étape 1 verte ; les cellules à surveiller
tournent (cellule.md étape 7 : le brokerd de chaque cellule sert ses
vues de supervision sur son socket Unix) ; `cell_log.vkey` de chaque
cellule et de la master chain récupérés (clés PUBLIQUES de checkpoint
— seules pièces nécessaires au scan vérifié, custody D97) ; accès
LECTURE SEULE aux répertoires des chaînes surveillées accordé à
l'utilisateur du service (groupe dédié ou ACL — `cell_log.key` ne
quitte JAMAIS la cellule).

**Commande** :

```bash
go build -o /usr/local/bin/supervisord ./src/supervision/cmd/supervisord
/usr/local/bin/supervisord 2>&1 | head -1   # sans environnement : doit refuser

# /etc/tbp/cells.json — chaînes surveillées (à adapter ; vkeys publiques
# seulement) :
#   {"cells":[{"cell_id":"cell-a","log_dir":"/var/lib/tbp/broker",
#              "origin":"cell-a",
#              "vkey_file":"/var/lib/tbp/broker/cell_log.vkey",
#              "manifest_dir":"/var/lib/tbp/broker/manifests"}],
#    "master":{"cell_id":"master","log_dir":"/var/lib/tbp/master",
#              "origin":"master",
#              "vkey_file":"/var/lib/tbp/master/cell_log.vkey"}}
# /etc/tbp/supervisord.env (0600) — valeurs d'exemple, à adapter :
#   TBP_MONITOR_CELL_ID=monitor-01
#   TBP_SALT=<hex 32 car. — sel de la chaîne DU MONITEUR, généré ici>
#   TBP_REGISTRY_DIR=/var/lib/tbp/supervision
#   TBP_CELLS_FILE=/etc/tbp/cells.json
#   TBP_CELL_BROKER_SOCKET=/run/tbp/broker-admin.sock  # plan ADMIN (§95) :
#     supervisord ne lit que GET /v1/supervision/*, jamais POST /v1/actions —
#     le socket du plan de DONNÉES (broker.sock) ne sert pas ces routes.
#   TBP_TICK_MS=5000
#   TBP_CONSOLE_SOCKET=/run/tbp/supervision.sock
install -m 0644 src/supervision/tbp-supervisord.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tbp-supervisord
curl -s --unix-socket /run/tbp/supervision.sock http://localhost/v1/epoch
```

**Critère de succès observable** : le binaire se construit ; lancé sans
environnement, il sort immédiatement avec
`supervisord: TBP_MONITOR_CELL_ID requis` (fail-closed — ce refus EST le
critère) ; un brokerd de cellule injoignable AU DÉMARRAGE est fatal
aussi (sonde des sources : pas de console dont les sources sont mortes
à la naissance) ; la console répond en GET seul : `/v1/epoch` rend
l'état du tracker de la cellule (lecture LIVE via brokerd, jamais de
cache), `/v1/arbitration` la file des plans en attente (hash scellé et
bornes temporelles — jamais les étapes), `/v1/indicators` les
indicateurs §9.1 et la santé des chaînes surveillées. Un brokerd qui
TOMBE en cours de route ⇒ 503 `{"error":"source indisponible"}` sur la
route concernée, jamais une valeur figée ni une zero-value (§1).

**En cas d'échec : STOP** — un supervisord qui démarrerait sans sel,
sans master chain ou avec un brokerd injoignable est fail-open :
corriger la cause. Un moniteur qui écrirait dans les chaînes
surveillées violerait §2/§7.1 : l'unit livrée le rend structurellement
impossible (ProtectSystem=strict) — ne pas élargir ReadWritePaths.

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

Unités systemd sur le patron T24 (`src/translator/tbp-translator.service`) ;
l'unité du superviseur est LIVRÉE : `src/supervision/tbp-supervisord.service`
(T37 — lecture seule structurelle sur les chaînes surveillées, aucune
famille réseau). La machine superviseur ne rejoint AUCUN VLAN de production
(§5.1) — son canal est la supervision, pas le trafic.
