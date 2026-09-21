# deploy/router-debian.md — machine « routeur » (T35, issue #61)

_English version: [router-debian.md](router-debian.md)._

Le routeur est le point d'entrée réseau (§5.1) : NAC 802.1X (FreeRADIUS
EAP-TLS, même PKI que le handshake §3), segmentation VLAN, murs nftables
entre segments. Doctrine : **fail-closed au switch** — le VLAN par défaut
est le VLAN captif, jamais un VLAN de confiance ; un équipement non authentifié
ne devient jamais silencieusement un équipement admis.

Segments du pilote P1 (§5.1, config à adapter) :

| VLAN | Rôle | Doctrine |
|---|---|---|
| 10 | serveurs + cellules | trafic gouverné (PEP/broker) |
| 20 | authentification | EAP/RADIUS uniquement |
| 33 | IoT / MAB | canal instrumenté — JAMAIS silencieux (checklist) |
| 66 | captif | VLAN par défaut (échec/sans auth) |
| 77 | remédiation | certificat révoqué, OCSP/CRL injoignable |
| 99 | management | administration hors production |

#### Étape 1 — Prérequis machine

**Prérequis vérifiable** : Debian 12, ≥ 2 interfaces, accès root ; étapes
communes de [README.md](README.fr.md) vertes ; les cellules et serveurs
sont déjà en monitor (le NAC est le DERNIER maillon, ordre §13).

**Commande** :

```bash
lsb_release -d; ip -brief link; command -v nft freeradius hostapd
```

**Critère de succès observable** : Debian 12 ; interfaces listées ;
`nft`, `freeradius` présents (installer sinon).

**En cas d'échec : STOP** — pas de nftables/FreeRADIUS, pas de NAC ;
installer avant toute règle.

#### Étape 2 — Créer les VLANs §5.1

**Prérequis vérifiable** : étape 1 verte ; plan d'adressage du pilote
arrêté (le fichier config est à adapter, pas à copier).

**Commande** :

```bash
# À adapter : noms d'interfaces, VLAN IDs, plan d'adressage —
# config/nftables/router-p1.nft est le point de départ à adapter (D99) :
ip link add link eth0 name eth0.10 type vlan id 10    # serveur
ip link add link eth0 name eth0.20 type vlan id 20    # auth
ip link add link eth0 name eth0.33 type vlan id 33    # IoT/MAB
ip link add link eth0 name eth0.66 type vlan id 66    # captif
ip link add link eth0 name eth0.77 type vlan id 77    # remédiation
ip link add link eth0 name eth0.99 type vlan id 99    # mgmt
ip -brief link | grep -c eth0.
```

**Critère de succès observable** : les six sous-interfaces existent et
sont `UP` après adressage.

**En cas d'échec : STOP** — « Operation not supported » = noyau sans
802.1Q ou conteneur sans CAP_NET_ADMIN : corriger l'hôte, ne pas
« simplifier » le plan de segmentation.

#### Étape 3 — Installer les murs nftables

**Prérequis vérifiable** : étape 2 verte.

**Commande** :

```bash
# À adapter : table inet tbp_p1, compteurs par voie (mur_captif_serveur,
# mur_iot_serveur, voie_auth_serveur…) — le fichier de référence est à
# adapter au plan local (D99) :
nft -c -f /etc/nftables/tbp-p1.nft   # vérification syntaxique d'abord
nft -f /etc/nftables/tbp-p1.nft
nft list table inet tbp_p1 | grep -c counter
```

**Critère de succès observable** : la table est chargée ; les compteurs
par voie existent (tout paquet traversant un mur est compté — la
visibilité précède le filtrage, comme monitor précède closed §5.3).

**En cas d'échec : STOP** — `nft -c` rouge = syntaxe à corriger ; ne
jamais charger un fichier non vérifié (couperait le management).

#### Étape 4 — FreeRADIUS en EAP-TLS sur la PKI §3

**Prérequis vérifiable** : étape 3 verte ; PKI du pilote issue de §3 —
les fichiers de config/freeradius/ sont un point de départ à adapter
(D99) et `config/freeradius/certs/` est gitignoré — config à adapter,
certificats jamais commités : ils se génèrent pour CE déploiement.

**Commande** :

```bash
# À adapter : mods-enabled/eap (tls-config), clients.conf (switch),
# sites-enabled/default. EAP-TLS uniquement — pas de PEAP/MSCHAP.
freeradius -XC   # vérification de configuration
systemctl start freeradius && ss -lunp | grep 1812
```

**Critère de succès observable** : `freeradius -XC` conclut «
configuration appears to be OK » ; RADIUS écoute en UDP/1812 sur le VLAN
auth (20) uniquement.

**En cas d'échec : STOP** — une config RADIUS invalide ne se « teste »
pas en production : corriger en `-XC` jusqu'au vert.

#### Étape 5 — Politique d'échec : captif ou remédiation, jamais confiance

**Prérequis vérifiable** : étape 4 verte.

**Commande** :

```bash
# Au switch (802.1X) : VLAN par défaut = 66 (captif) ; certificat révoqué
# ou OCSP/CRL injoignable = 77 (remédiation) — cf. config/freeradius/ (à adapter).
# Le MAB (équipements sans supplicant) est configuré
# sur le VLAN 33 : canal instrumenté, journalisé, JAMAIS silencieux —
# item dédié de checklists/routeur.md.
radtest -x -t eap-tls …  # à adapter au supplicant de test du pilote
```

**Critère de succès observable** : un supplicant valide obtient le VLAN
10 ; un inconnu tombe en 66 ; un révoqué en 77 — les trois issues sont
observées, pas supposées.

**En cas d'échec : STOP** — si l'échec d'authentification admet quand
même (VLAN de confiance par défaut), le switch est fail-open : corriger
la politique avant tout branchement.

#### Étape 6 — Redirection vers le PEP

**Prérequis vérifiable** : étapes 2-5 vertes ; pepd en monitor sur les
serveurs (serveur.md).

**Commande** :

```bash
# À adapter : config/nftables/pep-redirect.nft — redirection du trafic
# du VLAN 10 vers le PEP de la cellule (D99).
nft -c -f /etc/nftables/pep-redirect.nft && nft -f /etc/nftables/pep-redirect.nft
nft list table inet tbp_p1 | grep -c redirect
```

**Critère de succès observable** : les règles de redirection sont
chargées ; en monitor, le trafic est journalisé par le PEP (feuilles
`KindDecision`) sans être bloqué.

**En cas d'échec : STOP** — une redirection vers un PEP absent casse le
service ; vérifier pepd d'abord (serveur.md étape 2).

#### Étape 7 — Rejouer le scénario en lab avant la production

**Prérequis vérifiable** : étapes 2-6 vertes ; machine de lab avec root +
CAP_NET_ADMIN, ou containerlab (`lab/containerlab/p1.clab.yml` décrit la
topologie P1 : routeur, switch, radius, cell-a, cell-b, hostapd filaire).

**Commande** :

```bash
# Honnêteté de sandbox (constaté à la relecture) : selon l'hôte,
#   unshare -n -- true   → « Operation not permitted » (sans CAP_NET_ADMIN)
# ou réussit puis casse plus tard (VLAN « Operation not supported »,
# bind IPv6 FreeRADIUS). Les deux causes sont réelles ; le lab lève les
# deux. En containerlab :
containerlab deploy -t lab/containerlab/p1.clab.yml   # lab uniquement
```

**Critère de succès observable** : le scénario EAP-TLS complet (admis →
VLAN 10, inconnu → captif, révoqué → remédiation) est rejoué en lab avec
les compteurs nftables qui bougent.

**En cas d'échec : STOP** — ne pas promouvoir en production une politique
jamais rejouée ; le lab est le dernier prérequis avant le pilote miroir.
