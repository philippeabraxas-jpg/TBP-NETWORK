# lab/containerlab — topologie du pilote P1

Topologie réseau complète du pilote P1 (spec §13) : **le mur et l'aiguillage**
(§5.1) de bout en bout, avec l'authentification 802.1X/EAP-TLS adossée à la
PKI du handshake (T18) et la preuve qu'aucun endpoint non authentifié n'a de
chemin vers les cellules — ni routé, ni en forgeant des tags 802.1Q (§5.2).

## Décisions d'implémentation

- **D11 — le switch est un nœud Linux** (bridge VLAN-aware + `hostapd` en mode
  *wired* comme authenticator 802.1X de référence). Les images propriétaires
  (ceos, cvx…) sont exclues : non redistribuables, non reproductibles.
- **D12 — l'aiguillage VLAN est LOCAL au switch** : sur décision d'auth,
  `switchd.sh` change le PVID du port (`bridge vlan … pvid`). **Pas** de
  VLAN assigné par attributs RADIUS `Tunnel-*` : interdit en v1 (§5.3), le
  switch reste seul maître de ses ports (fail-closed par défaut : PVID 66).
- **D13 — double harnais de preuve** : le scénario est rejoué à l'identique
  (a) par containerlab/docker (`run_scenario_minimal.sh`) et (b) par network
  namespaces pures (`tests/scenario_minimal_netns.sh`), sans docker, avec les
  mêmes configs et les mêmes assertions. La preuve de référence en CI/sandbox
  est le harnais netns.

## Plan VLAN / IP (P1)

| VLAN | Rôle | Subnet | Notes |
|------|------|--------|-------|
| 10 | serveur (cellules) | 10.10.10.0/24 | cell-a .11, cell-b .12 |
| 20 | endpoints authentifiés | 10.20.20.0/24 | aiguillé localement (D12) |
| 66 | captif (fail-closed) | 10.66.66.0/24 | PVID par défaut des ports endpoints |
| 99 | management | 10.99.99.0/24 | switch .2, radius .3 |

Le routeur Debian porte `.1` sur chaque VLAN (sous-interfaces `eth1.<vid>` du
tronc `swp3`) et applique `config/nftables/router-p1.nft` — le **mur** :
politique `drop` partout ; seule voie = `authentifié → serveur` (compteur
nommé `voie_auth_serveur`) ; tout trafic `captif → serveur` est compté
(`mur_captif_serveur`) et journalisé avant d'être jeté (§5.3, mode moniteur) ;
du captif, seul le port d'enrôlement (8080) est ouvert.

## Nœuds et câblage (`p1.clab.yml`)

7 nœuds Linux : `router`, `switch` (swp1..swp6), `radius`, `cell-a`,
`cell-b`, `endpoint-ok`, `endpoint-ko`. **Aucun lien direct endpoint↔cell** :
tout passe par le switch puis le routeur (§5.1 — pas de chemin direct
client→serveur).

## Contenu

```
p1.clab.yml                      topologie containerlab
run_scenario_minimal.sh          orchestrateur containerlab (build → deploy → scénario)
tests/scenario_minimal_netns.sh  même scénario en network namespaces (sans docker)
startup-configs/                 configs consommées par les DEUX harnais
  switch/bridge-setup.sh         bridge VLAN-aware, ports endpoints en captif 66
  switch/hostapd-port.conf.tmpl  authenticator 802.1X wired (relayé au RADIUS)
  switch/switchd.sh              hook d'aiguillage : EAP-SUCCESS → PVID 20, journal NAC
  router/router-setup.sh         sysctl durcis + le mur nftables + bannière d'enrôlement
  radius/raddb-setup.sh          fixture raddb : EAP-TLS seul, PKI T18, check_crl=yes
  endpoint/wpa_supplicant.conf.tmpl  supplicant EAP-TLS
images/*.Dockerfile              images debian:bookworm-slim minimales (5 rôles)
```

## Exécution

### Harnais containerlab (hôte docker)

```sh
cd lab/containerlab
./run_scenario_minimal.sh        # build des images + deploy + scénario + destroy
SKIP_BUILD=1 ./run_scenario_minimal.sh   # images déjà construites
```

### Harnais netns (sans docker — preuve de référence)

```sh
./tests/scenario_minimal_netns.sh   # nécessite : ip, bridge, nft, hostapd,
                                    # wpa_supplicant, freeradius, socat, nc
```

Sortie attendue dans les deux cas : `SCÉNARIO MINIMAL P1 : VERT`.

## Ce que le scénario prouve

1. **Pré-auth** : un endpoint dans le VLAN captif ne joint pas le broker —
   mur fermé par défaut (§1).
2. **endpoint-ok** : EAP-TLS avec certificat de la PKI du handshake → succès
   → bascule locale du port en VLAN 20 → ping + TCP vers `cell-a:9000`.
3. **endpoint-ko** : certificat d'une PKI étrangère → rejet RADIUS → le port
   **reste** en captif 66.
4. **Anti-bypass** (§5.2) : ni routé (mur routeur) ni en forgeant des trames
   taguées VLAN 10 (le bridge n'admet que 66/20 sur les ports endpoints).
5. **Captif** : la seule voie ouverte est le service d'enrôlement
   (10.66.66.1:8080).
6. **Observabilité** (§4.1) : compteurs nommés du mur, journal des décisions
   NAC (`nac-decisions.log`, succès ET échecs), journal RADIUS
   (`Login OK` / `Login incorrect`), feuille d'enrôlement hash-only (§6.2).
