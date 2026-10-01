# deploy/cellule.md — machine « cellule » (T35, issue #61)

_English version: [cellule.md](cellule.md)._

Une cellule porte : le **broker** `brokerd` (T37 — issue #74), le
**registre tessera** (T7), **OPA** (T11, capabilities restreintes
§12), le **tracker d'époques** (§7.2) et le PEP `pepd`. Chaque décision
laisse une feuille (§4.1) ; le sel des feuilles reste sur CETTE machine
(§6.2). Posture au démarrage : **monitor**, au PREMIER déploiement
seulement (§5.3). Revue de sécurité #93 : tout REDÉMARRAGE (la clé de
registre de la cellule existe déjà) démarre en **refused** — tout est
refusé, même une évaluation par ailleurs autorisée — jusqu'à ce qu'un
quorum reconfirme explicitement une posture via `POST /v1/mode`. Un
redémarrage ne reprend jamais silencieusement la posture précédente.

> La phase mono de `deploy/selftest/` exécute les étapes 1 à 6 de ce
> guide contre les vrais binaires, et la phase daemons l'étape 7
> (brokerd réel, OPA réel, action de bout en bout). Si une commande
> ci-dessous diverge du selftest, le selftest casse : corrigez le guide
> ou le code, jamais les deux à l'insu l'un de l'autre.

#### Étape 1 — Vérifier les prérequis de la machine

**Prérequis vérifiable** : étapes communes de [README.md](README.fr.md)
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
`net.lookup_ip_addr`, `time.now_ns`, `opa.runtime`, et les non
déterministes : `rand.intn`, `uuid.rfc4122`, `io.jwt.decode_verify`,
`io.jwt.encode_sign*`, `crypto.x509.parse_and_verify_certificates*`) y
sont absents.

**En cas d'échec : STOP** — si un interdit est « absent de la liste
générée », la version d'OPA a changé : revoir FORBIDDEN avant tout
déploiement. Ne jamais écrire capabilities.json à la main.

#### Étape 4 — Signer et compiler le bundle de règles AVEC les capabilities (OPA ≥ 1.0)

**Prérequis vérifiable** : étape 3 verte ; règles propres du pilote
rédigées (les squelettes de `policies/rego/` sont des exemples à adapter,
§14 — jamais une politique de référence à copier) ; `openssl` présent.

**Pourquoi signer le bundle** (revue de sécurité #106) : `TBP_POLICY_ID`
seul est une étiquette auto-déclarée, choisie au moment du build — qui
peut écrire `/etc/tbp/bundle.tar.gz` peut simplement y mettre la valeur
correspondante, et `OPARevisionWatcher` (revue de sécurité #92, finding
A5) ne verrait rien d'anormal. Seule une SIGNATURE cryptographique,
vérifiée par OPA lui-même AVANT qu'il accepte de servir, prouve que le
contenu du bundle n'a pas été altéré après que celui qui l'a construit
l'a signé. La clé PRIVÉE de signature ne touche jamais une cellule — même
frontière de custody que les clés des contrôleurs du quorum (§12) : la
générer une fois, hors ligne ou sur la machine/CI qui construit les
bundles, l'y garder ; ne distribuer que la clé PUBLIQUE de vérification à
chaque cellule et chaque broker, avec `cell_log.vkey` / `keyring.json`
(D97).

**Commande** :

```bash
# UNE FOIS, sur la machine hors ligne/de build — JAMAIS sur une cellule.
# À refaire seulement pour tourner la clé (alors le policy-verify.pub de
# chaque cellule doit être mis à jour ensemble, sinon OPA sur les cellules
# non mises à jour refusera tous les bundles futurs — un fail-closed
# délibéré, pas un bug).
openssl genrsa -out policy-signing.key 2048
openssl rsa -in policy-signing.key -pubout -out policy-verify.pub
# policy-signing.key reste sur la machine de build (custody comme les
# clés de contrôleurs §12). Copier SEULEMENT policy-verify.pub dans
# /etc/tbp/ de chaque cellule et broker.

# TBP_POLICY_ID est choisi ICI, AVANT le build — il devient la révision
# épinglée du bundle (revue de sécurité #92, finding A5) : la révision
# qu'OPA sert RÉELLEMENT est vérifiée PÉRIODIQUEMENT contre cette chaîne
# exacte, jamais contre le hash de l'artefact construit (que --revision
# modifie, donc impossible à calculer APRÈS le build sans un autre build
# circulaire). Tout identifiant stable convient (un hash des sources de
# policies/rego/, un tag de version) tant qu'il est régénéré à chaque
# changement de règles.
POLICY_ID=$(sha256sum -- policies/rego/*.rego | sha256sum | cut -d' ' -f1)
# 'opa run' n'a plus de flag --capabilities depuis OPA 1.0 : la
# restriction est figée à la compilation du bundle. -b (mode bundle) est
# REQUIS pour que --signing-key prenne effet — opa build refuse de signer
# en silence sans lui (vérifié contre le vrai binaire opa).
opa build --capabilities policies/capabilities.json --revision "$POLICY_ID" \
  --signing-key policy-signing.key --signing-alg RS256 \
  -b policies/rego/ -o /etc/tbp/bundle.tar.gz
echo "$POLICY_ID"   # cette valeur = TBP_POLICY_ID ci-dessous (claim −1)
```

**Critère de succès observable** : le build réussit ; une règle appelant
`http.send` ajoutée à titre de test casse le build (retirer le test
après) ; `tar tzf /etc/tbp/bundle.tar.gz` liste un membre
`.signatures.json`.

**En cas d'échec : STOP** — un bundle compilé sans capabilities n'impose
rien à l'exécution ; ne pas contourner avec `opa run` sur les .rego nus.
Un bundle construit sans `--signing-key` retombe droit sur le trou #106
(révision seule, aucune preuve) — OPA refusera de le démarrer à l'étape 5
de toute façon (`--verification-key` n'y a volontairement aucun repli
`--skip-verify` documenté ici).

#### Étape 5 — Lancer OPA en serveur local (bundle uniquement, socket Unix, signature vérifiée)

**Prérequis vérifiable** : étape 4 verte ; bundle présent ;
`policy-verify.pub` installé dans `/etc/tbp/policy-verify.pub`.

**Commande** :

```bash
# Socket Unix, PAS TCP loopback (revue de sécurité #92, finding A3) : un
# port TCP qu'un imposteur pourrait occuper et sur lequel répondre
# allow-à-tout est indiscernable du vrai OPA pour pepd/brokerd. L'UID
# propriétaire du socket est ce que pepd/brokerd vérifient via SO_PEERCRED
# à chaque connexion — lancer OPA sous un utilisateur DÉDIÉ, noter son UID
# (`id -u tbp-opa`).
#
# --bundle (pas un chemin positionnel nu) est REQUIS pour que la
# vérification de signature s'active (vérifié contre le vrai binaire opa :
# un chemin de bundle positionnel saute la vérification en silence même
# avec --verification-key — c'est la seule substitution de flag qui
# rendrait la signature de l'étape 4 entièrement cosmétique).
install -d -o tbp-opa -g tbp-opa -m 0750 /run/tbp
opa run --server --addr unix:///run/tbp/opa.sock \
  --bundle /etc/tbp/bundle.tar.gz \
  --verification-key /etc/tbp/policy-verify.pub --verification-key-id default &
curl -s --unix-socket /run/tbp/opa.sock http://localhost/health
```

**Critère de succès observable** : `/health` répond 200 sur le socket ;
OPA n'écoute sur AUCUN port TCP (`ss -ltnp | grep 8181` ne trouve rien) —
pas d'exposition réseau, pas de transport non authentifié. Preuve que la
signature est réellement appliquée, pas cosmétique (revue de sécurité
#106) : modifier un octet d'un fichier `.rego` dans une copie du bundle et
le reconditionner — `opa run` sur cette copie sort immédiatement avec une
erreur de digest et n'ouvre jamais le socket ; un bundle re-signé avec une
clé privée DIFFÉRENTE de celle derrière `policy-verify.pub` est refusé de
la même façon.

**En cas d'échec : STOP** — lire le log OPA ; un bundle invalide, une
signature qui ne vérifie pas ou un fichier socket résiduel se corrigent
avant pepd, jamais après. Ne jamais lancer pepd contre un OPA qui a échoué
cette étape — `TBP_OPA_REVISION_CHECK_INTERVAL_MS` (étape 6) attrape une
substitution de bundle ULTÉRIEURE, il ne rend pas rétroactivement sûr un
démarrage déjà compromis.

#### Étape 6 — Démarrer pepd en mode monitor (§5.3)

**Prérequis vérifiable** : étapes 2 et 5 vertes ; keyring des émetteurs
de la cellule installé (JSON `{"kid_hex": "pubkey_ed25519_hex"}`, kid de
16 octets) ; keyring des contrôleurs du quorum installé de même
(`TBP_QUORUM_KEYRING_FILE` — revue de sécurité #89 : aucune bascule de
posture n'est possible sans lui) ; sel de cellule généré localement
(≥ 16 octets, reste ici) ; `/etc/tbp/pepd.env` en 0600, propriété du
service.

**Commande** :

```bash
# /etc/tbp/pepd.env — valeurs d'exemple, à adapter à la cellule :
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<hex 32 car. — généré localement, jamais partagé>
#   TBP_KEYRING_FILE=/etc/tbp/keyring.json
#   TBP_POLICY_ID=<$POLICY_ID choisi à l'étape 4 — PAS le hash du bundle>
#   TBP_REGISTRY_DIR=/var/lib/tbp/cell-a
#   TBP_AUDIT_RECORDS=/var/lib/tbp/cell-a-audit/pepd-records.jsonl  # #275 : REQUIS —
#   TBP_AUDIT_RECORDS_KEY_FILE=/etc/tbp/pepd-records.key  # clair chiffré de chaque
#                                  # feuille de décision ; clé 0600 issue de
#                                  # `tbp-audit keygen -out <fichier>` ; vérifier
#                                  # avec `tbp-audit verify` (deploy/audit.fr.md).
#                                  # Journal HORS du répertoire du registre, clé
#                                  # hors du disque du journal si possible
#   TBP_LISTEN_ADDR=127.0.0.1:8443  # plan de DONNÉES seulement (revue de
#                                  # sécurité #95) : /v1/evaluate,
#                                  # /v1/passport/consume
#   TBP_ADMIN_SOCKET=/run/tbp/pepd-admin.sock  # plan d'ADMINISTRATION (revue
#                                  # de sécurité #95, finding A10) : /v1/mode,
#                                  # /healthz. Défaut montré ici ; permissions
#                                  # 0660, même doctrine que le socket du
#                                  # broker ci-dessous — JAMAIS sur le canal
#                                  # TCP de l'agent
#   TBP_OPA_ENDPOINT=http://opa/v1/data/tbp/example/action  # la partie hôte
#                                  # est sans effet via TBP_OPA_SOCKET — la
#                                  # connexion au socket l'ignore
#   TBP_OPA_SOCKET=/run/tbp/opa.sock          # revue de sécurité #92, A3 :
#                                  # OPA est maintenant REQUIS, authentifié
#                                  # par SO_PEERCRED — obligatoire sauf
#                                  # TBP_OPA_INSECURE_TCP_DEV=1 (dev/labo
#                                  # seulement, jamais en production — revue
#                                  # de sécurité #113 : refusé aussi au
#                                  # démarrage sauf si /etc/tbp/DEV_ENVIRONMENT
#                                  # existe, chemin FIXE codé en dur dans le
#                                  # binaire, jamais lu depuis ce fichier —
#                                  # même garde sur
#                                  # TBP_OPA_DISABLED_DEV_UNSAFE=1)
#   TBP_OPA_EXPECTED_UID=$(id -u tbp-opa)     # UID que le noyau doit
#                                  # rapporter pour le processus OPA à CHAQUE
#                                  # connexion
#   TBP_QUORUM_MIN=2               # k signatures Ed25519 DISTINCTES (revue de
#                                  # sécurité #89 — plus un simple compte de
#                                  # noms)
#   TBP_QUORUM_KEYRING_FILE=/etc/tbp/quorum-keyring.json  # clés publiques des
#                                  # contrôleurs épinglées (§12), même forme
#                                  # JSON que TBP_KEYRING_FILE — requis : sans
#                                  # lui, AUCUNE bascule de posture possible
#   TBP_TOPOLOGY=multi              # "mono" ou "multi" — revue de sécurité
#                                  # post-#86 (issue #128) : REQUIS, et vérifié
#                                  # contre TBP_CELL_BROKER_SOCKET ci-dessous
#                                  # (multi ⇒ présent, mono ⇒ absent) — refuse
#                                  # de démarrer sinon. "multi" ici car cet
#                                  # exemple co-localise brokerd (étape 7) ; un
#                                  # pepd scale-1 autonome utilise "mono" et
#                                  # retire la ligne suivante.
#   TBP_CELL_BROKER_SOCKET=/run/tbp/broker.sock  # requis avec
#                                  # TBP_TOPOLOGY=multi : époque VÉRIFIÉE en
#                                  # direct depuis le brokerd co-localisé
#                                  # (étape 7), §7.2-§7.3. mono ⇒
#                                  # FixedEpoch(0), le choix scale-1 explicite
#                                  # (une seule cellule, pas de fencing)
#   TBP_DURABILITY=async-bounded   # défaut (T38/#71) : verdict à
#                                  # l'acceptation, rattrapage borné ;
#                                  # "sync" = ancien chemin synchrone
#   TBP_DURABILITY_WINDOW_MS=1000  # fenêtre d'opposabilité (défaut 1 s ;
#                                  # plancher 4 × intervalle de checkpoint)
#   TBP_OPA_REVISION_CHECK_INTERVAL_MS=10000  # optionnel (revue de sécurité
#                                  # #92, A5) — fréquence de vérification que
#                                  # la révision qu'OPA sert RÉELLEMENT
#                                  # correspond à TBP_POLICY_ID ; vérifiée une
#                                  # fois, SYNCHRONEMENT, avant que pepd serve
#                                  # — un écart y refuse le démarrage
#   TBP_MEASURED_BOOT_MANIFEST_FILE=/var/lib/tbp/cell-a-measured-boot.json
#                                  # revue de sécurité #112 : le démarrage
#                                  # mesuré est maintenant REQUIS par défaut —
#                                  # le chemin DOIT être hors de
#                                  # TBP_REGISTRY_DIR (revue #111 : effacer le
#                                  # registre ne doit jamais effacer aussi
#                                  # l'unique témoin que c'est un redémarrage,
#                                  # pas un premier démarrage) ; seul
#                                  # TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1
#                                  # (dev/labo, jamais en production) peut le
#                                  # remplacer
#   TBP_MEASURED_BOOT_ROOT_FILE=/var/lib/tbp/measured-root  # mesureur de
#                                  # racine de dev (registry.FileRootMeasurer)
#                                  # — un vrai déploiement met un vrai
#                                  # mesureur TPM/HSM (issue #32)
#   TBP_MEASURED_BOOT_EXPECTED_ROOT=<64 car. hex>  # hash de racine attendu
#                                  # au moment de CheckBoot
#   TBP_MEASURED_BOOT_POLICY_BUNDLE=/etc/tbp/opa/tbp-example.tar.gz
#   TBP_MEASURED_BOOT_OPA_CONFIG=/etc/tbp/opa-config.yaml
#   TBP_MEASURED_BOOT_BROKER_BINARY=/usr/local/bin/brokerd
#   TBP_MEASURED_BOOT_AI_CONTAINER=<digest ou chemin de l'image conteneur>
#   TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE=/etc/tbp/measured-boot-transition-proof.json
#                                  # (la preuve signe la condition que le démon affiche en
#                                  # refusant : measured-boot-transition|from=…|to=…, #236)
#                                  # optionnel — présent seulement pour une
#                                  # ré-engagement DÉLIBÉRÉ de la référence
#                                  # (mise à jour de bundle/config). Revue de
#                                  # sécurité #112 : remplace l'ancien simple
#                                  # drapeau TBP_MEASURED_BOOT_TRANSITION=1 —
#                                  # exige maintenant une preuve de quorum de
#                                  # contrôleurs (même
#                                  # TBP_QUORUM_KEYRING_FILE que
#                                  # POST /v1/mode, §89/§105), jamais un
#                                  # simple drapeau d'environnement
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/pepd-provisioning-witness.json
#                                  # issue #192 : pepd mesure à chaque démarrage
#                                  # les deux trousseaux épinglés auxquels il
#                                  # fait confiance (TBP_KEYRING_FILE,
#                                  # TBP_QUORUM_KEYRING_FILE — dérivés, pas
#                                  # listés ici) ; un fichier modifié refuse le
#                                  # démarrage. REQUIS, hors de
#                                  # TBP_REGISTRY_DIR (même raison que le
#                                  # manifeste du démarrage mesuré, #111).
#                                  # Seul TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1
#                                  # (dev/labo, exige la sentinelle
#                                  # DEV_ENVIRONMENT, jamais en production) peut
#                                  # le remplacer. Voir « Fichiers de
#                                  # provisionnement » après l'étape 7.
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/healthz
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/v1/mode
```

**Critère de succès observable** : `/healthz` répond 200 ;
`GET /v1/mode` rend `{"mode":"monitor"}` à ce PREMIER démarrage, la
bascule closed est gouvernée (étape 8 et
[monitor-to-closed.md](monitor-to-closed.fr.md)) ; les deux routes ne
répondent QUE sur le socket Unix d'administration (revue de sécurité
#95) — une requête vers `http://127.0.0.1:8443/v1/mode` (le port du plan
de données de l'agent) reçoit 404 ; `cell_log.key` (0600) et
`cell_log.vkey` sont créés dans `TBP_REGISTRY_DIR` (clé de registre de LA
cellule — custody D97). Revue de sécurité #93 : tuer ce processus et le
relancer avec le MÊME environnement — `GET /v1/mode` rend maintenant
`{"mode":"refused"}`, et les évaluations sont refusées même avec un jeton
par ailleurs valide, jusqu'à un `POST /v1/mode` signé par quorum (même
forme qu'à l'étape 8) qui reconfirme explicitement une posture.

**En cas d'échec : STOP** — un démarrage sans keyring, sans policy ID ou
sans sel doit échouer ; s'il réussit, le binaire n'est pas celui du
dépôt. Le mode closed N'EST PAS l'objectif de cette étape. Un REDÉMARRAGE
qui rapporte silencieusement `monitor` (au lieu de `refused`) est la
régression exacte que la revue de sécurité #93 corrige — ne jamais la
contourner.

#### Étape 7 — Compiler et démarrer brokerd (chaîne de décision complète, T37)

**Prérequis vérifiable** : étape 6 verte ; manifeste de genèse (étape 1)
en place sous `$GENESIS_HOME` — `epoch0.json` aussi, SAUF si
`TBP_TOPOLOGY=mono` ET que `TBP_CLUSTER_MEMBERS` ci-dessous ne nomme
qu'une seule cellule (mode mono-cellule, revue de sécurité #97 : avec une
seule cellule il n'y a pas de conflit d'autorité à clôturer, donc aucun
bail d'époque n'est émis ni requis — l'exemple à deux cellules qui suit
déclare `TBP_TOPOLOGY=multi` et a toujours besoin de son `epoch0.json` ;
revue de sécurité post-#86, issue #128 : les deux réglages sont vérifiés
pour cohérence, donc en déclarer un sans l'autre correspondant refuse de
démarrer) ; clés PUBLIQUES d'opérateurs du store de contrats installées
(T30 — JSON `["pubkey_ed25519_hex", …]`, ≥ 1) ; custody de l'émetteur
provisionnée — SOIT un seed émetteur de DEV en 0600 (labo/CI P1
seulement) SOIT un vrai token HSM/SoftHSM2 avec une paire de clés Ed25519
générée à l'intérieur et son PIN en 0600 (revue de sécurité #90, point 5
— la clé privée ne quitte jamais le module ; voir
`src/broker/pkcs11_signer_test.go` pour un exemple SoftHSM2
exécutable) ; sel du broker généré localement (≥ 16 octets, reste ici —
la chaîne du broker est la SIENNE, distincte de celle de pepd).

**Commande** :

```bash
go build -o /usr/local/bin/brokerd ./src/broker/cmd/brokerd
/usr/local/bin/brokerd 2>&1 | head -1   # sans environnement : doit refuser

# /etc/tbp/brokerd.env (0600, propriété du service) — valeurs d'exemple,
# à adapter à la cellule. La custody de l'émetteur est EXACTEMENT UN des
# deux blocs ci-dessous — jamais les deux, jamais aucun (fail-closed,
# revue de sécurité #90.5) :
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<hex 32 car. — sel de la chaîne DU BROKER, généré ici>
#   TBP_POLICY_ID=<$POLICY_ID choisi à l'étape 4 — PAS le hash du bundle>
#   TBP_REGISTRY_DIR=/var/lib/tbp/broker
#   TBP_AUDIT_RECORDS=/var/lib/tbp/broker-audit/records.jsonl  # #275 : REQUIS —
#   TBP_AUDIT_RECORDS_KEY_FILE=/etc/tbp/broker-records.key  # clair chiffré des
#                                      # feuilles de décision / contrat / quorum
#                                      # du broker ; clé 0600 issue de
#                                      # `tbp-audit keygen` (deploy/audit.fr.md)
#   TBP_OPA_ENDPOINT=http://opa/v1/data/tbp/example/action  # partie hôte
#                                      # sans effet via TBP_OPA_SOCKET
#   TBP_OPA_SOCKET=/run/tbp/opa.sock  # revue de sécurité #92, A3 : REQUIS
#                                      # (authentifié par SO_PEERCRED)
#                                      # sauf TBP_OPA_INSECURE_TCP_DEV=1
#                                      # (dev/labo seulement — revue de
#                                      # sécurité #113 : refusé aussi au
#                                      # démarrage sans
#                                      # /etc/tbp/DEV_ENVIRONMENT, voir le
#                                      # bloc de custody de l'émetteur
#                                      # ci-dessous)
#   TBP_OPA_EXPECTED_UID=$(id -u tbp-opa)  # UID que le noyau doit rapporter
#                                      # pour OPA à chaque connexion
#   TBP_TRANSLATOR=structured
#   # --- custody DEV (labo/CI seulement) — revue de sécurité #113 : contrairement
#   # aux deux drapeaux de dev d'OPA ci-dessus, celui-ci était accepté sans
#   # AUCUN drapeau dédié ; refusé maintenant au démarrage sauf si
#   # /etc/tbp/DEV_ENVIRONMENT existe (chemin fixe, codé en dur dans le
#   # binaire — JAMAIS lu depuis ce fichier, donc le fuiter ou le mal
#   # configurer ne suffit plus à déclarer silencieusement un environnement
#   # de dev) ---
#   TBP_ISSUER_SEED_FILE=/etc/tbp/issuer.seed
#   # --- OU custody HSM (production, §12) ---
#   # TBP_ISSUER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
#   # TBP_ISSUER_PKCS11_TOKEN_LABEL=cell-a
#   # TBP_ISSUER_PKCS11_KEY_LABEL=issuer-key-1  # revue de sécurité #114 :
#   #                                    # la clé DOIT être provisionnée
#   #                                    # CKA_SENSITIVE=true ET
#   #                                    # CKA_EXTRACTABLE=false — brokerd
#   #                                    # vérifie maintenant les deux au
#   #                                    # chargement et refuse de démarrer
#   #                                    # sinon
#   # TBP_ISSUER_PKCS11_PIN_FILE=/etc/tbp/issuer.pin  # 0600, même exigence
#   #                                    # de custody que TBP_ISSUER_SEED_FILE —
#   #                                    # revue de sécurité #114 : c'est
#   #                                    # toujours un secret en clair SUR
#   #                                    # DISQUE, ni scellé ni restreint à un
#   #                                    # canal ; préférer un chemin
#   #                                    # d'authentification protégé PKCS#11
#   #                                    # (clavier PIN physique) quand le HSM
#   #                                    # en propose un, ou un identifiant
#   #                                    # géré par le service (systemd
#   #                                    # LoadCredential=, un tmpfs dédié
#   #                                    # vidé à l'arrêt) plutôt qu'un fichier
#   #                                    # persistant comme celui-ci
#   TBP_GENESIS_DIR=<GENESIS_HOME>
#   TBP_QUORUM_MIN=2
#   TBP_TOPOLOGY=multi                 # "mono" ou "multi" — revue de sécurité
#                                      # post-#86 (issue #128) : REQUIS, et
#                                      # vérifié pour cohérence contre le
#                                      # nombre de membres ci-dessous (mono ⇒
#                                      # exactement un, multi ⇒ ≥ 2) — refuse
#                                      # de démarrer sinon
#   TBP_CLUSTER_MEMBERS=cell-a,cell-b  # UNE cellule ici (ex. "cell-a", avec
#                                      # TBP_TOPOLOGY=mono) ⇒ mode
#                                      # mono-cellule (#97) : aucun bail
#                                      # d'époque émis, epoch0.json non lu
#   TBP_OPERATOR_KEYS_FILE=/etc/tbp/operators.json
#   TBP_AGENT_REGISTRY_FILE=/etc/tbp/agents.json  # revue de sécurité #125 :
#                                      # JSON {"<subject>": {"class": 0..3,
#                                      # "quota"?: {"max_volume",
#                                      # "max_window_s"},
#                                      # "transport_identity"?: "<CN mTLS>"}, …}
#                                      # « class » est OBLIGATOIRE et tout
#                                      # champ inconnu est refusé au chargement
#                                      # (#241) : une faute de frappe (« clas »)
#                                      # ne devient jamais la classe 0.
#                                      # — identité/classe/quota résolues
#                                      # d'ICI, jamais de la déclaration de
#                                      # l'agent dans sa demande d'émission.
#                                      # Classes 0 (F, financière), 1 (I) et
#                                      # 2 (W) EXIGENT un plan_binding sur
#                                      # chaque action (#177) ; la classe 2
#                                      # exige aussi une preuve de quorum. 3 =
#                                      # hors F/I/W n'exige ni l'un ni l'autre.
#                                      # La classe est celle de l'AGENT
#                                      # (registre), pas de l'action (issue
#                                      # #195) : enregistrer en 2 tout agent
#                                      # qui peut faire un acte irréversible.
#                                      # Même doctrine de custody hors-bande
#                                      # que TBP_OPERATOR_KEYS_FILE ci-dessus
#                                      # — aucune échappatoire de dev ; un
#                                      # sujet absent de cette table est
#                                      # refusé (agent-unknown), et un agent
#                                      # sans entrée "quota" ne peut demander
#                                      # aucun passeport.
#                                      # transport_identity (revue de sécurité
#                                      # #162/#163) : requis pour que ce sujet
#                                      # soit utilisable sur l'écoute mTLS
#                                      # RÉSEAU ci-dessous — une requête dont
#                                      # le CN du certificat client ne
#                                      # correspond pas est refusée
#                                      # (agent-transport-unbound), même si le
#                                      # certificat est valide. Absent ⇒ cet
#                                      # agent n'est joignable que par le
#                                      # socket Unix.
#                                      # Présent ⇒ le RÉSEAU seulement : le
#                                      # socket Unix le refuse
#                                      # (agent-network-only) car il ne
#                                      # porte aucune identité — un agent
#                                      # est soit un agent réseau, soit un
#                                      # agent du socket, jamais les deux
#                                      # (un processus local qui peut écrire
#                                      # sur le socket ne doit pas pouvoir
#                                      # parler en tant qu'agent lié à un
#                                      # certificat).
#   # TBP_SKILL_REGISTRY_FILE=/etc/tbp/skills.json  # OPTIONNEL — ferme le
#                                      # trou structurel confirmé sept fois de
#                                      # façon indépendante par le catalogue de
#                                      # conformité (#142-#161) : TBP n'avait
#                                      # aucune notion de « skill »
#                                      # installable. JSON {"<action>":
#                                      # {"provenance": "<éditeur/source>",
#                                      # "scope": ["<ressource>", …],
#                                      # "risk_tier":
#                                      # "low|medium|high|critical"}, …}.
#                                      # risk_tier est REQUIS (aucun niveau par
#                                      # défaut) et recoupé avec la taille du
#                                      # périmètre au démarrage (low ≤ 8
#                                      # ressources, medium ≤ 32, high ≤ 128,
#                                      # critical illimité — garde-fou de
#                                      # cohérence, pas frontière de sécurité) ;
#                                      # brokerd refuse de démarrer sinon. Il
#                                      # est transmis à OPA comme input.skill
#                                      # {risk_tier, scope_size} ; le paquet de
#                                      # règles policies/rego/pack_skill_tier
#                                      # .rego en fait un contrôle : high ⇒
#                                      # classe I/W (plan), critical ⇒ classe W
#                                      # (plan + quorum). Absent ⇒ aucune
#                                      # notion de skill — comportement
#                                      # historique inchangé, PAS une
#                                      # régression cachée, un choix délibéré de
#                                      # compatibilité (à activer en
#                                      # production). Présent ⇒ fail-closed
#                                      # pour TOUTE action : celle dont le nom
#                                      # ne correspond à aucun skill enregistré
#                                      # est refusée (skill-unknown), celle
#                                      # visant une ressource hors du périmètre
#                                      # déclaré est refusée
#                                      # (skill-scope-violation) — comparaison
#                                      # exacte de chaîne, jamais un préfixe
#                                      # (même classe de confusion que
#                                      # #107/#108). Même doctrine de custody
#                                      # hors-bande que TBP_AGENT_REGISTRY_FILE
#                                      # ci-dessus : aucun chemin de
#                                      # rechargement à chaud dans le code —
#                                      # un agent ne peut jamais ajouter,
#                                      # élargir ni retirer une entrée ; seul
#                                      # un opérateur qui édite ce fichier et
#                                      # redémarre brokerd le peut.
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/broker-provisioning-witness.json
#                                      # issue #192 : brokerd mesure, à chaque
#                                      # démarrage, les fichiers qui portent la
#                                      # confiance de la cellule — clés
#                                      # d'opérateurs, registre d'agents,
#                                      # manifeste de genèse (contrôleurs),
#                                      # registre de skills et CA cliente mTLS si
#                                      # configurée. La liste est DÉRIVÉE de
#                                      # cette configuration ;
#                                      # TBP_PROVISIONING_EXTRA_FILES="nom=chemin,…"
#                                      # s'y ajoute. Un fichier modifié refuse le
#                                      # démarrage et le nomme. REQUIS, hors de
#                                      # TBP_REGISTRY_DIR, différent de celui de
#                                      # pepd. Échappatoire (dev/labo seulement,
#                                      # exige la sentinelle) :
#                                      # TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1.
#                                      # Voir « Fichiers de provisionnement ».
#   TBP_BROKER_SOCKET=/run/tbp/broker.sock  # plan de DONNÉES : POST /v1/actions
#   TBP_BROKER_ADMIN_SOCKET=/run/tbp/broker-admin.sock  # plan
#                                      # d'ADMINISTRATION (revue de sécurité
#                                      # #95, finding A10) : GET
#                                      # /v1/supervision/*. Socket séparé,
#                                      # jamais multiplexé sur
#                                      # TBP_BROKER_SOCKET
#   TBP_OPA_REVISION_CHECK_INTERVAL_MS=10000  # optionnel (revue de sécurité
#                                      # #92, A5) — vérifié une fois,
#                                      # SYNCHRONEMENT, avant que brokerd
#                                      # serve ; un écart refuse de démarrer
#   # --- écoute RÉSEAU optionnelle du plan de données (revue de sécurité
#   # #124) — le socket Unix ci-dessus (TBP_BROKER_SOCKET) continue de
#   # fonctionner sans changement ; ces quatre variables sont ABSENTES par
#   # défaut (Unix seul) et, si utilisées, sont requises LES QUATRE ENSEMBLE —
#   # brokerd refuse de démarrer sur un jeu partiel. Il n'existe aucune
#   # option TCP en clair : une écoute réseau non authentifiée laisserait un
#   # imposteur occupant cette adresse émettre des jetons indiscernables de
#   # ceux du vrai broker (même classe de faute que #92.A3, côté émission
#   # cette fois) ---
#   # TBP_BROKER_LISTEN_ADDR=0.0.0.0:8443
#   # TBP_BROKER_TLS_CERT_FILE=/etc/tbp/broker-tls.pem     # feuille serveur
#   # TBP_BROKER_TLS_KEY_FILE=/etc/tbp/broker-tls.key.pem  # 0600
#   # TBP_BROKER_TLS_CLIENT_CA_FILE=/etc/tbp/broker-client-ca.pem
#   #                                      # tout pair sans certificat signé
#   #                                      # par cette CA est rejeté à la
#   #                                      # poignée de main TLS (TLS 1.3
#   #                                      # minimum, authentification mutuelle
#   #                                      # requise) — n'atteint jamais le mux
#   #                                      # applicatif. Le CN du certificat
#   #                                      # vérifié est ensuite comparé au
#   #                                      # transport_identity de chaque
#   #                                      # sujet dans TBP_AGENT_REGISTRY_FILE
#   #                                      # (revue de sécurité #162/#163) : un
#   #                                      # certificat valide qui revendique un
#   #                                      # sujet auquel il n'est pas rattaché
#   #                                      # est refusé par le broker lui-même,
#   #                                      # pas seulement par la poignée de
#   #                                      # main TLS.
#   #                                      # UTILISER UNE CA DÉDIÉE AUX
#   #                                      # CERTIFICATS CLIENTS D'AGENTS ici —
#   #                                      # jamais la CA partagée avec d'autres
#   #                                      # services ou le NAC (la spec permet
#   #                                      # une PKI unique pour les deux) :
#   #                                      # tout certificat qu'elle signe avec
#   #                                      # un CN donné peut agir comme cet
#   #                                      # agent. La pile TLS de Go exige déjà
#   #                                      # l'usage de clé étendu clientAuth ;
#   #                                      # émettre les certificats d'agents
#   #                                      # avec cet EKU seul, CN = le sujet de
#   #                                      # l'agent, un par agent, de courte
#   #                                      # durée. L'identité est le CN seul :
#   #                                      # SAN et autres champs de profil ne
#   #                                      # sont pas vérifiés (suivi dans le
#   #                                      # catalogue de conformité,
#   #                                      # tbp-compliance/162).
install -m 0644 src/broker/tbp-brokerd.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tbp-brokerd
curl -s --unix-socket /run/tbp/broker-admin.sock http://localhost/v1/supervision/epoch
```

**Critère de succès observable** : le binaire se construit ; lancé sans
environnement, il sort immédiatement avec `brokerd: TBP_CELL_ID requis`
(fail-closed au démarrage — ce refus EST le critère) ; le service est
actif ; le socket Unix d'ADMINISTRATION répond en GET seul :
`/v1/supervision/epoch` rend l'époque 0 et l'autorité de la cellule,
`/v1/supervision/arbitration` rend le `policy_id` du bundle (étape 4)
et une file d'arbitrage, `/v1/supervision/stats` les compteurs du
broker ; un POST sur ces vues reçoit 405 ; le même GET sur le socket de
DONNÉES (`/run/tbp/broker.sock`) reçoit 404 — les deux plans sont sur des
sockets séparés (revue de sécurité #95). Au premier démarrage,
`cell_log.key` (0600) et `cell_log.vkey` sont créés dans
`TBP_REGISTRY_DIR` — la chaîne du broker est la sienne (§7.1).

**Bail d'époque multi-cellules — limite opérationnelle connue** (issue
#197) : avec `TBP_TOPOLOGY=multi`, le bail d'époque doit être renouvelé
par une signature m-of-n AVANT chaque expiration (`scripts/genesis renew`,
puis `POST /v1/epoch/renew` sur le socket d'administration ; TTL de 60 s
par défaut, 10 à 300 s). Il n'y a pas de renouvellement automatique, par
conception — un quorum injoignable laisse le bail expirer et la cellule
s'arrête (clôture, §7). Prévoir cette cadence, ou utiliser `mono` pour une
cellule seule ; un schéma de renouvellement soutenable est la décision
ouverte de #197.

Un jeton de renouvellement n'est appliqué que tant que son propre bail est vivant
(issue #207) : un jeton authentique mais déjà échu à la livraison est refusé
(`epoch-token-expired`, tracé) et ne change rien — il installerait sinon une
époque morte par-dessus une époque vivante, grillerait son numéro `N` (un jeton
frais au même `N` passerait pour une équivoque) et, en mode `auto`, consommerait
le budget de bascule. Signer le renouvellement juste avant de le livrer ; si un
jeton a été manqué, en signer un nouveau (un `issued_at` frais, le même `N` ou un
`N` supérieur). Exception : sans époque en cours, l'`epoch0.json` de la genèse
est importé même échu — `brokerd` démarre des jours après la cérémonie, et la
cellule ne sert pas tant qu'aucun bail vivant n'est installé.

**En cas d'échec : STOP** — un brokerd qui démarre sans sel, sans
genèse, sans OPA ou sans clés d'opérateurs est fail-open : corriger la
cause, ne jamais contourner. Un `epoch0` refusé signifie une genèse qui
ne correspond pas au manifest : refaire la distribution (étape 1),
jamais bricoler le jeton à la main.

## Fichiers de provisionnement — mesurés à chaque démarrage (issue #192)

Le démarrage mesuré de `pepd` atteste quatre artefacts (bundle, config OPA, binaire
`brokerd`, conteneur IA). Les fichiers qui portent la CONFIANCE de la cellule sont mesurés
par le démon qui les charge : éditer `agents.json` (classe W → F, ce qui supprime plan et
quorum), ajouter une clé à un trousseau d'opérateurs ou de contrôleurs, ou élargir le
périmètre d'un skill passait jusqu'ici sans aucune alarme.

- **Ce qui est mesuré.** `brokerd` : clés d'opérateurs, registre d'agents, manifeste de
  genèse, registre de skills, CA cliente mTLS. `pepd` : trousseau des émetteurs, trousseau
  du quorum. Les deux attestent aussi les **réglages d'échelle** (`quorum-settings` : `TBP_QUORUM_MIN` et
  la topologie, #224) : abaisser k en éditant l'environnement est une divergence, et le changement est
  autorisé par le k qui était attesté. Adopter cela sur une cellule qui a déjà tourné demande une preuve de
  transition (la nouvelle entrée change le condensé). Les deux acceptent `TBP_PROVISIONING_EXTRA_FILES` (par exemple le fichier de
  règles d'`anod`).
- **Comment.** Un condensé sur la liste triée (nom, SHA-256) est engagé au premier démarrage
  dans un témoin signé par la clé de cellule, hors de `TBP_REGISTRY_DIR`. À chaque démarrage
  suivant le condensé doit correspondre ; sinon le démon refuse de démarrer, écrit une
  feuille de refus, lève l'alarme et nomme le fichier modifié (jamais son contenu).
- **Changement légitime** (nouvel agent, clé remplacée). Éditer le fichier, puis faire signer
  une preuve par les contrôleurs — le même k que la classe W (`TBP_QUORUM_MIN`) : à
  l'échelle 1 l'administrateur seul signe, k = 1 ; au-dessus, un quorum k-of-n :

  ```bash
  go build -o /usr/local/bin/quorumproof ./src/pep/cmd/quorumproof
  # 1. démarrer SANS preuve : le démon refuse et affiche ce qu'il faut signer, par ex.
  #      condition à signer : provisioning-transition-brokerd|from=<condensé attesté>|to=<condensé cible>
  # 2. les contrôleurs signent EXACTEMENT cette condition (ils voient ce qu'ils approuvent)
  quorumproof sign -condition 'provisioning-transition-brokerd|from=…|to=…' -cell cell-a \
    -key /secure/admin.key -out /etc/tbp/provisioning-proof.json
  # 3. dans brokerd.env : TBP_PROVISIONING_TRANSITION_PROOF_FILE=/etc/tbp/provisioning-proof.json
  #    redémarrer, vérifier le démarrage, puis RETIRER la ligne (la preuve vit 4 minutes par défaut)
  ```

  Conditions : `provisioning-transition-brokerd` et `provisioning-transition-pepd` (la preuve
  de l'un ne vaut jamais pour l'autre, ni pour une bascule de posture). **Une preuve est liée
  à l'état qu'elle approuve (issue #236)** : la condition porte le condensé attesté (`from`)
  et le condensé cible (`to`). Elle ne ré-engage aucun autre état — si le fichier est édité
  de nouveau après la signature, le démon refuse et affiche la nouvelle condition — et elle
  ne ramène pas l'état précédent une fois la transition faite. Les contrôleurs dont
  la clé est dans un HSM utilisent `quorumproof message` (ce qu'il faut signer) puis
  `quorumproof assemble`.
- **Qui peut signer un changement (issue #218).** La preuve est vérifiée contre les clés de
  contrôleurs *telles qu'attestées dans le témoin* (trousseau de quorum pour `pepd`,
  manifeste de genèse pour `brokerd`), jamais contre le fichier présent sur le disque. Sinon
  qui peut écrire ce fichier y ajoute ses propres k clés et signe sa propre transition.
  Conséquence : une **rotation légitime des contrôleurs eux-mêmes** est signée par les
  ANCIENS contrôleurs ; le nouvel ensemble devient ensuite la référence. Un témoin écrit
  avant ce correctif n'a pas d'instantané : un démarrage sans changement le met à niveau sur
  place, mais un fichier *modifié* est refusé, avec ou sans preuve — ré-engager explicitement
  (ci-dessous).
- **Ré-engager après un témoin perdu.** Il n'y a rien d'attesté à opposer : la preuve se
  vérifie alors contre le trousseau actuellement sur le disque — confiance à la première
  utilisation, comme au premier démarrage. C'est un acte d'installation de l'administrateur,
  pas une transition ; sauvegarder le témoin (lecture seule, hors de l'hôte de la cellule) et
  traiter sa perte comme un incident.
- **Adopter cette brique sur une cellule qui a déjà tourné.** Sans témoin et avec un registre
  qui a déjà vécu, le démon refuse de démarrer (un fichier édité serait sinon adopté comme un
  « premier démarrage », §111) : fournir une fois une preuve de transition comme ci-dessus.
- **Limites.** Les fichiers sont chargés une fois au démarrage (aucun rechargement à chaud) :
  un changement est attrapé au démarrage suivant, pas pendant l'exécution. Un attaquant qui
  détient la clé de cellule ET peut écrire le témoin peut le forger (même confiance que le
  manifeste du démarrage mesuré). L'échelle est un réglage de la preuve, pas du mécanisme : la
  même brique tourne à toutes les échelles.

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
la procédure [monitor-to-closed.md](monitor-to-closed.fr.md), avec quorum.

## Fautes OPA : ce que fait la cellule, et comment lever un verrou (issue #205)

Toute faute OPA (timeout, injoignable, statut non 200) **refuse cette requête**
et laisse une feuille — cela ne change pas. Ce qui change, c'est le verrou
*global* (le point fail-closed qui refuse toute décision) :

- il bascule après `TBP_OPA_TRIP_AFTER` fautes **consécutives** (défaut 3 ; `1`
  restitue l'ancien « la première faute verrouille la cellule ») ; une décision
  saine remet le compte à zéro. Une réponse qui rompt le contrat
  (`opa-bad-response`) le bascule immédiatement — ce n'est pas une faute de
  disponibilité ;
- le watcher de révision, en arrière-plan, bascule `opa-revision-unverifiable`
  quand il ne peut pas lire la révision d'OPA (redémarrage d'OPA). Cette
  condition est de classe I et **se lève seule** ; `opa-revision-mismatch`
  (bundle substitué) est de classe W et ne se lève jamais seule ;
- une sonde hors du chemin de décision lève les conditions OPA transitoires
  quand OPA répond **et sert exactement la révision de bundle épinglée**,
  `TBP_OPA_AUTOCLEAR_PROBES` fois de suite (défaut 3, toutes les
  `TBP_OPA_AUTOCLEAR_INTERVAL_MS`, défaut 2000). Une condition qui rebascule peu
  après double le nombre de sondes exigé (jusqu'à ×8) : un OPA qui flappe ne se
  lève ni par réflexe ni en noyant l'opérateur d'alarmes.
  `TBP_OPA_AUTOCLEAR_PROBES=0` la désactive : levée manuelle seulement, le
  profil le plus strict ;
- jamais levés automatiquement : `opa-bad-response`, `opa-revision-mismatch`,
  dérive d'horloge, saturations, retard d'ancrage.

Lire et lever depuis le socket d'administration (l'accès au socket est le
contrôle d'accès, #95) :

```bash
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/v1/failclosed
# classe I : décision d'opérateur, tracée
curl -s --unix-socket /run/tbp/pepd-admin.sock -X POST \
  -d '{"condition":"opa-bad-response"}' http://localhost/v1/failclosed/clear
# classe W : preuve de quorum signée pour CETTE condition (rejeu refusé, #105)
quorumproof sign -condition opa-revision-mismatch -cell cell-a -key /etc/tbp/admin.key -out /tmp/p.json
jq '. + {condition:"opa-revision-mismatch"}' /tmp/p.json | curl -s --unix-socket /run/tbp/pepd-admin.sock \
  -X POST -d @- http://localhost/v1/failclosed/clear
```

**Note d'honnêteté :** c'est de la résilience à une faute du **processus** OPA.
Cela ne fait pas survivre une machine à sa propre perte ; un second backend OPA
et les miroirs du §7.4 sont un chantier séparé (échelle 3).

## Les preuves de quorum de classe W sont à usage unique (issue #206)

Une action de classe W porte une preuve de quorum k-of-n liée à (action,
ressource, politique, époque, expiry). Le broker la **consomme** : la première
présentation est admise, toute présentation ultérieure du même énoncé est
refusée (`quorum-proof-replayed` dans la feuille de quorum,
`quorum-insufficient` côté appelant). L'identité d'une preuve est son énoncé
signé, pas ses signatures — un autre sous-ensemble de signataires du même
énoncé est la même autorisation.

- Pour autoriser une seconde exécution, les contrôleurs signent un **nouvel**
  énoncé (autre expiry). Ne collecter les signatures que lorsque le demandeur
  est prêt.
- Une preuve invalide ne consomme jamais un énoncé ; une preuve valide est
  brûlée **avant** la feuille d'admission et avant l'étape du plan : un crash
  ou un refus plus loin dans la chaîne la laisse brûlée (re-signer), jamais
  rejouable.
- L'ensemble consommé vit dans `TBP_REGISTRY_DIR/quorum_proofs_consumed.json`
  (0600, même custody que `cell_log.key`), survit aux redémarrages, purge les
  entrées à leur expiry et n'évince jamais une entrée vivante ; un ensemble
  plein (4096) refuse. Un fichier corrompu refuse de démarrer.
- **Limite :** supprimer ou remplacer ce fichier rouvre la fenêtre de rejeu des
  preuves encore dans leur TTL (≤ 300 s). Il fait partie de l'état de la
  cellule : à protéger comme la clé du registre.

## Bornes de requête et délais de lecture (issue #209)

`pepd` borne chaque corps de requête et le temps de le lire, sur tous ses
listeners, pour qu'un client de la cellule (le port de données, les sockets Unix)
ne puisse pas tenir de la mémoire ou des goroutines avec une requête énorme ou
calée :

- `/v1/evaluate` et `/v1/passport/consume` : 16 Kio au plus (la plus grande
  requête légitime — un jeton de 1024 octets, action ≤ 255, ressource ≤ 1024,
  échappement JSON le plus défavorable — fait environ 9 Kio) ; `/v1/mode` et
  `/v1/failclosed/clear` : 64 Kio au plus. Au-delà, la réponse est **413**, sans
  que le corps soit traité.
- Chaque serveur de `pepd` et de `brokerd` : 5 s pour lire les en-têtes, 10 s pour
  lire la requête entière (corps compris), 60 s de connexion persistante
  inactive. Un client qui envoie les en-têtes puis cale est coupé à 10 s.
- **Exception, volontaire :** le proxy bloquant (`TBP_PROXY_ADDR`) relaie du vrai
  trafic, donc n'a pas de délai de lecture (un téléversement ou un flux long est
  légitime) ; ses délais d'en-têtes et d'inactivité restent appliqués.
- Ces bornes ne sont pas des réglages : une requête qui n'y tient pas n'est pas
  une requête TBP.

## Unités systemd

Patron de durcissement : `src/translator/tbp-translator.service` (T24 —
cap-drop, seccomp `@system-service`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`). L'unité du broker est LIVRÉE :
`src/broker/tbp-brokerd.service` (T37 — registre propre seul inscriptible,
aucun périphérique, W^X tenue). Reste à adapter sur le même patron :
`pepd.service` et `opa.service`, avec `EnvironmentFile=/etc/tbp/pepd.env`
(0600). Le script `src/translator/audit_confinement.sh` donne le motif de
vérification post-déploiement, à adapter aux unités de la cellule.

## Durcissement système

`config/sysctl/99-tbp-hardening.conf` est un point de départ à adapter au
noyau et à la carte réseau locaux — jamais copié tel quel (D99).

**Référence de durcissement OS** (catalogue de conformité #158, CIS
Benchmarks) : appliquer le [CIS Debian Linux
Benchmark](https://www.cisecurity.org/benchmark/debian_linux) à la
machine hôte avant d'y déployer la cellule. TBP n'est ni un runtime de
conteneurs ni un système d'exploitation et n'applique jamais lui-même la
configuration de l'hôte (§7.1 : le broker est du bétail, jamais la racine
de confiance de son propre hôte) — c'est un prérequis de déploiement,
documenté sur le même modèle que le NAC 802.1X dans
`router-debian.fr.md`, jamais une fonctionnalité de TBP.
