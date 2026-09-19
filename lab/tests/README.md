# lab/tests — tests fail-closed du NAC (T20, issue #17)

Suite de tests du §5.3 (« les défauts d'usine tuent ») sur la topologie P1 :
**le système échoue vers le déni, jamais vers l'approbation silencieuse** (§9.1).
Exécutable sans docker (network namespaces, mêmes `startup-configs/` que le
lab containerlab).

```sh
# pré-requis : ip, bridge, nft, hostapd, wpa_supplicant, freeradius,
# eapol_test, radclient, socat, nc, openssl + scripts T18 du dépôt
export TBP_LAB=/chemin/du/depot
./test_radius_failclosed.sh     # RADIUS down → fail-closed au switch
./test_ocsp_remediation.sh      # CRL/OCSP down → VLAN remédiation + feedback
./test_mab_iot_vlan.sh          # MAB → VLAN IoT instrumenté, jamais production
```

## Décisions (plan sur l'issue #17)

### D14 — RADIUS down : fail-closed structurel + watchdog canari

Sans `EAP-SUCCESS`, aucun port ne sort du captif : le fail-closed est une
**propriété de construction** du switch (PVID 66 par défaut), pas une option
à configurer — c'est exactement l'inverse du défaut d'usine fail-open dénoncé
au §5.3. Reste le « jamais silencieux » : `radius-watchdog.sh` authentifie
périodiquement un **certificat canari** (`swprobe`, enrôlé via T18) contre le
RADIUS avec `eapol_test` :

| Résultat canari | État | Conséquence |
|---|---|---|
| `SUCCESS` | `ok` | sortie de mode remédiation le cas échéant |
| FAILURE + `timed out` | `radius-down` | alarme + feuille ; aucune nouvelle auth possible |
| FAILURE sans timeout | `verification-degraded` | armement du mode remédiation (D15) |

**Politique des sessions établies (v1)** : une session authentifiée AVANT la
coupure **persiste jusqu'à déconnexion** — `eap_reauth_period=0`
(`hostapd-port.conf.tmpl`), pas de ré-authentification périodique en v1, donc
pas de surprise : la coupure RADIUS ne déconnecte personne, mais **aucune
nouvelle authentification n'est possible** tant qu'il est down. Chaque
transition d'état du watchdog est une feuille JSONL (`nac-watchdog.jsonl`)
et un événement `nac-decisions.log`.

### D15 — vérification dégradée (CRL/OCSP injoignable) → remédiation

Un `Reply-Message` RADIUS n'apparaît pas dans le journal hostapd (mesuré,
Exp A du plan) : le switch ne peut pas connaître la cause d'un rejet en
parsant hostapd. La détection est donc portée par le **canari** : un rejet
explicite du canari sain (alors que RADIUS répond) signifie que la couche de
vérification est dégradée. Le watchdog arme alors `remediation.mode` et
`switchd.sh` envoie tout `EAP-FAILURE` en **VLAN 77 (remédiation)** au lieu
de laisser le port en captif :

- la remédiation n'a **aucun** accès au VLAN serveur (mur routeur, compteur
  `mur_rem_serveur`) — quarantaine réelle, §9.1 ;
- sa seule voie est le **feedback explicite** (bannière `TBP-REMEDIATION`
  sur le routeur, 10.77.77.1:8080) — jamais de rejet aveugle ;
- en mode dégradé, certificat invalide et certificat invérifiable sont
  indistinguables : tous les échecs partent en remédiation (sûr, jamais
  fail-open) ;
- au rétablissement (canari `SUCCESS`), le mode est désarmé et la transition
  est tracée.

La panne est simulée dans le test par un `ca.pem` amputé de la CRL avec
`check_crl=yes` — toute vérification échoue « unable to get certificate
CRL », comme une CRL réellement injoignable.

### D16 — MAB : canal instrumenté, VLAN IoT dédié

`mabd.sh` (switch) surveille les MAC apprises sur les ports captifs
(`bridge fdb`). Une MAC n'est candidate au MAB qu'après **quiétude**
(`MAB_QUIET_POLLS` scrutations sur un port resté captif) — le 802.1X a
toujours la priorité. Chaque MAC candidate est authentifiée par MAC-auth
RADIUS (`User-Name = User-Password = MAC`, entrées du module `files`,
fichier injecté via `TBP_MAB_FILE` dans `raddb-setup.sh`) :

- **Accept** → PVID 33 (VLAN IoT) + feuille `mab-decisions.jsonl` (MAC
  **hachée**, §6.2). Le VLAN IoT n'a aucune route vers le serveur
  (compteur `mur_iot_serveur`) ; sa seule voie est le collecteur de
  télémétrie du routeur (10.33.33.1:8888, compteur `voie_iot_telemetry` —
  placeholder T21) : canal **instrumenté** ;
- **Reject** → le port reste captif + feuille failure + alarme :
  **jamais de MAB silencieux vers un VLAN de production**.

## Couverture des tests

| Test | Assertions clés |
|---|---|
| `test_radius_failclosed.sh` | coupure détectée + alarme + feuille ; session établie préservée ; nouvel arrivant (cert valide) refusé, port captif ; rétablissement tracé, auth à nouveau possible |
| `test_ocsp_remediation.sh` | dégradation distinguée de la coupure ; cert valide → VLAN 77 ; pas d'accès broker ; feedback joignable ; compteurs ; rétablissement tracé |
| `test_mab_iot_vlan.sh` | MAC autorisée → VLAN 33 + feuille ; télémétrie comptée ; aucun chemin IoT→serveur ; MAC inconnue → captif + alarme |

Note historique : le test MAB a d'abord révélé (et condamné) un **fail-open**
dans `mabd.sh` — la chaîne `Expected Access-Accept got Access-Reject` de
radclient contient la sous-chaîne `Access-Accept` ; la décision est désormais
ancrée sur `Received Access-Accept` (paquet réellement reçu).
