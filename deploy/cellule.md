# deploy/cellule.md — machine « cellule » (T35, issue #61)

Une cellule porte : le **broker** (patron d'assemblage — trou déclaré
#74), le **registre tessera** (T7), **OPA** (T11, capabilities restreintes
§12), le **tracker d'époques** (§7.2) et le PEP `pepd`. Chaque décision
laisse une feuille (§4.1) ; le sel des feuilles reste sur CETTE machine
(§6.2). Posture au démarrage : **monitor**, toujours (§5.3).

> La phase mono de `deploy/selftest/` exécute les étapes 1 à 6 de ce
> guide contre les vrais binaires. Si une commande ci-dessous diverge du
> selftest, le selftest casse : corrigez le guide ou le code, jamais les
> deux à l'insu l'un de l'autre.

#### Étape 1 — Vérifier les prérequis de la machine

**Prérequis vérifiable** : étapes communes de [README.md](README.md)
vertes ; artefacts de genèse reçus selon la matrice de custody
(`pubkeys/*.hex` des contrôleurs, `epoch0.json` — JAMAIS de clé privée de
contrôleur sur cette machine).

**Commande** :

```bash
go version && opa version
ls "$GENESIS_HOME/manifest.json" "$GENESIS_HOME/pubkeys/" "$GENESIS_HOME/epoch0.json"
```

**Critère de succès observable** : versions conformes ; les trois
artefacts de genèse existent et sont lisibles.

**En cas d'échec : STOP** — sans artefacts de genèse, pas de tracker
d'époques ; retour à l'étape 3 du README.

#### Étape 2 — Compiler le PEP (pepd)

**Prérequis vérifiable** : étape 1 verte ; dépôt présent sur la machine.

**Commande** :

```bash
go build -o /usr/local/bin/pepd ./src/pep/cmd/pepd
/usr/local/bin/pepd 2>&1 | head -1   # sans TBP_SALT : doit refuser
```

**Critère de succès observable** : le binaire se construit ; lancé sans
environnement, il sort immédiatement avec `pepd: TBP_SALT requis`
(fail-closed au démarrage — ce refus EST le critère).

**En cas d'échec : STOP** — un PEP qui démarre sans sel est fail-open ;
ne pas continuer, corriger la cause (binaire, environnement).

#### Étape 3 — Générer les capabilities OPA restreintes (§12)

**Prérequis vérifiable** : `opa` ≥ 1.0 installé (étape 1).

**Commande** :

```bash
bash policies/gen_capabilities.sh
# écrit policies/capabilities.json (gitignoré, jamais commité) et prouve
# qu'une règle appelant http.send est refusée au chargement
```

**Critère de succès observable** : `vérification négative OK` affiché ;
`capabilities.json` écrit ; les built-ins interdits (`http.send`,
`net.lookup_ip_addr`, `time.now_ns`, `opa.runtime`) y sont absents.

**En cas d'échec : STOP** — si un interdit est « absent de la liste
générée », la version d'OPA a changé : revoir FORBIDDEN avant tout
déploiement. Ne jamais écrire capabilities.json à la main.

#### Étape 4 — Compiler le bundle de règles AVEC les capabilities (OPA ≥ 1.0)

**Prérequis vérifiable** : étape 3 verte ; règles propres du pilote
rédigées (les squelettes de `policies/rego/` sont des exemples à adapter,
§14 — jamais une politique de référence à copier).

**Commande** :

```bash
# 'opa run' n'a PLUS de flag --capabilities depuis OPA 1.0 : la
# restriction se fige à la compilation du bundle.
opa build --capabilities policies/capabilities.json policies/rego/ \
  -o /etc/tbp/bundle.tar.gz
sha256sum /etc/tbp/bundle.tar.gz   # ce hash = TBP_POLICY_ID (claim −1)
```

**Critère de succès observable** : le build réussit ; une règle appelant
`http.send` ajoutée à titre de test casse le build (retirer le test
après).

**En cas d'échec : STOP** — un bundle compilé sans capabilities n'impose
rien à l'exécution ; ne pas contourner avec `opa run` sur les .rego nus.

#### Étape 5 — Lancer OPA en serveur local (bundle uniquement)

**Prérequis vérifiable** : étape 4 verte ; bundle présent.

**Commande** :

```bash
opa run --server --addr 127.0.0.1:8181 /etc/tbp/bundle.tar.gz &
curl -s http://127.0.0.1:8181/health
```

**Critère de succès observable** : `/health` répond 200 ; OPA n'écoute
QUE sur loopback (seul pepd l'appelle — pas d'exposition réseau).

**En cas d'échec : STOP** — lire le log OPA ; un bundle invalide ou un
port déjà pris se corrigent avant pepd, jamais après.

#### Étape 6 — Démarrer pepd en mode monitor (§5.3)

**Prérequis vérifiable** : étapes 2 et 5 vertes ; keyring des émetteurs
de la cellule installé (JSON `{"kid_hex": "pubkey_ed25519_hex"}`, kid de
16 octets) ; sel de cellule généré localement (≥ 16 octets, reste ici) ;
`/etc/tbp/pepd.env` en 0600, propriété du service.

**Commande** :

```bash
# /etc/tbp/pepd.env — valeurs d'exemple, à adapter à la cellule :
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<hex 32 car. — généré localement, jamais partagé>
#   TBP_KEYRING_FILE=/etc/tbp/keyring.json
#   TBP_POLICY_ID=<sha256 du bundle, étape 4>
#   TBP_REGISTRY_DIR=/var/lib/tbp/cell-a
#   TBP_LISTEN_ADDR=127.0.0.1:8443
#   TBP_OPA_ENDPOINT=http://127.0.0.1:8181/v1/data/tbp/example/action
#   TBP_QUORUM_MIN=2
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s http://127.0.0.1:8443/healthz
curl -s http://127.0.0.1:8443/v1/mode
```

**Critère de succès observable** : `/healthz` répond 200 ;
`GET /v1/mode` rend `{"mode":"monitor"}` — pepd démarre TOUJOURS en
monitor, la bascule closed est gouvernée (étape 8 et
[monitor-to-closed.md](monitor-to-closed.md)) ; au premier démarrage,
`cell_log.key` (0600) et `cell_log.vkey` sont créés dans
`TBP_REGISTRY_DIR` (clé de registre de LA cellule — custody D97).

**En cas d'échec : STOP** — un démarrage sans keyring, sans policy ID ou
sans sel doit échouer ; s'il réussit, le binaire n'est pas celui du
dépôt. Le mode closed N'EST PAS l'objectif de cette étape.

#### Étape 7 — Assembler le tracker d'époques et le broker (patron — trou #74)

**Prérequis vérifiable** : étape 6 verte ; artefacts de genèse (étape 1)
en place ; vous avez lu l'issue **#74** : il n'existe PAS de binaire
`brokerd` — `src/broker` et `src/cluster` sont des bibliothèques à
assembler, comme `src/pep/cmd/pepd/main.go` assemble le PEP.

**Commande** :

```bash
# Patron d'assemblage (à compléter dans un cmd/brokerd — #74) :
#   tr  := cluster.NewTracker(TrackerConfig{CellID, Salt, Leaves: cellLog,
#         Controllers: pubkeys de la genèse, Quorum: M, Members, Now, OnAlarm})
#   tr.Accept(ctx, epoch0.json)          # puis canal de bascule §7.2
#   brk := broker.NewBroker(broker.BrokerOptions{… fail-closed …})
#   srv := broker.NewServer(broker.ServerOptions{Broker: brk, MaxBody: …})
#   srv.Serve(ctx, lis)                  # ou socket Unix (déploiement v1)
go test ./src/cluster/ ./src/broker/   # les contrats assemblés sont testés
```

**Critère de succès observable** : les tests des deux paquets passent ;
la phase fencing du selftest (`deploy/selftest -phase fencing`) démontre
la séquence epoch 0 → rotation → révocation sur registres réels.

**En cas d'échec : STOP** — ne pas inventer un `systemctl start brokerd`
qui n'existe pas ; suivre #74 pour le binaire, ou assembler un main local
en reprenant les options fail-closed de pepd.

#### Étape 8 — Points de mesure §9.1 AVANT toute bascule (D100)

**Prérequis vérifiable** : étapes 6-7 vertes ; la cellule tourne en
monitor depuis une fenêtre d'observation convenue avec le superviseur.

**Commande** :

```bash
# Le harness T27 est la référence exécutable des points de mesure §9.1 :
go test ./tests/p1_friction/ -run . -count=1
# Registre de la cellule : scan vérifié (checkpoint signé + Merkle) —
# le moniteur indépendant (deploy/superviseur.md) le rejoue à distance.
```

**Critère de succès observable** : métriques collectées (latences,
would-deny, forwarded) ; le registre de la cellule contient des feuilles
`KindDecision` en monitor (le trafic est journalisé, pas bloqué).

**En cas d'échec : STOP** — sans mesure, pas de closed : la bascule est
la procédure [monitor-to-closed.md](monitor-to-closed.md), avec quorum.

## Unités systemd

Patron de durcissement : `src/translator/tbp-translator.service` (T24 —
cap-drop, seccomp `@system-service`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`) à adapter pour `pepd.service` et `opa.service`,
avec `EnvironmentFile=/etc/tbp/pepd.env` (0600). Le script
`src/translator/audit_confinement.sh` donne le motif de vérification
post-déploiement, à adapter aux unités de la cellule.

## Durcissement système

`config/sysctl/99-tbp-hardening.conf` est un point de départ à adapter au
noyau et à la carte réseau locaux — jamais copié tel quel (D99).
