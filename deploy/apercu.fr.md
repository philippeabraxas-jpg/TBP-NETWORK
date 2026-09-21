# deploy/apercu.md — vue d'ensemble : quoi, où, pourquoi, prérequis

_English version: [apercu.md](apercu.md)._

Ce document est le **point d'entrée** d'un déploiement TBP-NETWORK : ce
qu'on déploie, où chaque pièce va, pourquoi elle existe, et ce qu'il faut
avant de commencer. Il synthétise ; les guides par machine
([router-debian.md](router-debian.fr.md), [cellule.md](cellule.fr.md),
[serveur.md](serveur.fr.md), [superviseur.md](superviseur.fr.md)) exécutent.
En cas de doute, la spec ([`docs/spec-en-v1.0.md`](../docs/spec-en-v1.0.md))
gouverne — et `deploy/selftest/` tranche : un guide qui dérive du code
casse là, pas chez l'opérateur.

## Pourquoi — la doctrine en cinq points

1. **Jamais par confiance, toujours par preuve vérifiable** (§1, §3) :
   l'admission d'une entité au réseau se fait par poignée de main
   attestée, pas par réputation ni par segment « de confiance ».
2. **Chaque décision laisse une feuille** (§4.1), et la feuille est
   **hash-only** (§6.2) : le registre prouve sans révéler — le sel reste
   chez le producteur, jamais dans un registre.
3. **Fail-closed partout** (§1) : OPA injoignable, horloge désynchronisée,
   ancre absente, quota saturé ⇒ refus tracé et alarmé. Un trou silencieux
   est une faute, pas une tolérance.
4. **Monitor avant closed** (§5.3) : la posture fermée ne s'installe pas,
   elle se mérite — mesure §9.1 d'abord, fenêtre d'observation, quorum
   pour basculer ([monitor-to-closed.md](monitor-to-closed.fr.md)).
5. **Une cellule est du bétail, jamais une racine de confiance** (§7.1) :
   les clés de gouvernance vivent sur HSM à la genèse ; les cellules
   vérifient et appliquent, elles ne détiennent rien de souverain.

## Quoi — les composants et leur provenance

| Composant | Rôle | Provenance |
|---|---|---|
| Routeur NAC | 802.1X/EAP-TLS (même PKI que le handshake §3), VLANs, murs nftables | `config/freeradius/`, `config/nftables/` — **à adapter**, jamais copier (D99) |
| Cellule | `brokerd` (point d'entrée §5.1), `pepd`, registre tessera, OPA, tracker d'époques | `src/broker/`, `src/pep/`, `src/registry/`, `src/cluster/` — binaires Go du dépôt |
| Serveur applicatif | Application (PostgreSQL, …) + PEP d'acceptation via SA cellule | `src/pep/` (+ `src/pep/postgres-extension/` pour le PEP en processus, §4.4) |
| Superviseur | Master chain (ancres par époque), moniteur indépendant + console (`supervisord`), genèse | `src/registry/` (ancrage), `src/supervision/`, `scripts/genesis/` (HSM) |
| Traducteur | IA locale produisant l'action — runtime durci, dégradation contrôlée, mesure qualité | `src/translator/` (T24, T25, T26) — **optionnel, en dernier** (§13) |
| Cœur du protocole | HSM signer, chaîne d'audit Merkle, moteur de politique OPA | submodule `tbp4.2.1/` — pointeur figé, jamais modifié ici |

Ce que le dépôt ne fournit PAS : la cérémonie de genèse elle-même
(procédurale, §7.2/§3.2 — l'outillage est dans `scripts/genesis/`), le
plan d'adressage du site, la PKI de production, les corpus natifs du
traducteur (à constituer au pilote, §15).

## Où — topologie du pilote P1 et flux

Segments (§5.1, à adapter — `config/nftables/router-p1.nft` est le point
de départ) :

| VLAN | Rôle | Doctrine |
|---|---|---|
| 10 | serveurs + cellules | trafic gouverné (PEP/broker) |
| 20 | authentification | EAP/RADIUS uniquement |
| 33 | IoT / MAB | canal instrumenté — JAMAIS silencieux |
| 66 | captif | **VLAN par défaut** (échec / sans auth) |
| 77 | remédiation | certificat révoqué, OCSP/CRL injoignable |
| 99 | management | administration hors production |

Machines (P1 §13 : 1 VLAN serveur, routeur Debian, **2 cellules**,
802.1X, registre central) : 1 routeur, 2 cellules (VM), 1 serveur
applicatif, 1 superviseur (VM indépendante + HSM).

Flux de décision : agent → **broker** de sa cellule (socket Unix, v1) →
traducteur (`structured`) → OPA (capabilities restreintes §12) → quorum
classe W si requis (§7.5) → contrat de plan si scellé (§4.2) → jeton
CWT/COSE Ed25519 → **PEP** devant la ressource (validation, anti-rejeu,
quota, fail-closed) → action. Chaque étape laisse une feuille dans le
**registre de la cellule** ; les ancres montent à la **master chain** du
superviseur, que le **moniteur indépendant** relit en vérifié
(ChainWatcher : checkpoint signé + cohérence Merkle) sans jamais y
écrire. Le serveur n'accepte que via le broker de SA cellule (§5.1) ;
aucun chemin client → serveur direct.

Custody : aucune clé de gouvernance hors de son rôle — la matrice
complète est dans [README.md](README.fr.md) (décision D97) : clés
contrôleurs sur HSM uniquement, `cell_log.key` dans SA cellule, sel des
feuilles chez le producteur, clé du moniteur au superviseur.

## Prérequis (requirements)

### Matériel — pilote P1 minimal

- 1 routeur : Debian 12, **≥ 2 interfaces** (dédié ou VM) ; un switch
  802.1X pour le NAC réel — sinon `lab/containerlab/` pour l'éprouver.
- 2 VM cellules (une seule cellule peut différer le fencing, un pilote
  ne peut pas — §7.2/§13).
- 1 hôte serveur applicatif (PostgreSQL si l'extension PEP est visée).
- 1 VM superviseur + **HSM** (SoftHSM toléré en DEV uniquement — jamais
  racine de gouvernance, §12).

### Logiciel — chaque machine

- Debian 12 (bookworm, cible du dépôt), **Go ≥ 1.24**, **OPA ≥ 1.0**,
  python3 — vérifiés à l'étape commune 1 de [README.md](README.fr.md).
- Routeur : `nftables`, `freeradius`, `hostapd`.
- Superviseur : `softhsm2-util` (dev) ou le PKCS#11 du HSM (prod).
- Serveur : PostgreSQL + en-têtes de dev si l'extension est compilée.
- Durcissement : `config/sysctl/99-tbp-hardening.conf` (à adapter au
  site) sur toute machine portant un composant TBP.

### Procédural — avant toute commande

- **Genèse d'abord** : quorum m-of-n de contrôleurs sur HSM, ancrée
  hors-bande. Rien dans le dépôt ne remplace cette cérémonie ; ses
  artefacts (`manifest.json`, `pubkeys/*.hex`, `epoch0.json`) sont le
  prérequis vérifiable de la première étape cellule.
- Plan d'adressage arrêté ; `config/` est à **adapter**, pas à copier.
- Custody D97 comprise et acceptée : `*.pem`, `*.key`,
  `config/freeradius/certs/` (exemple à adapter, jamais copier),
  `policies/capabilities.json` ne se committent jamais (gitignorés).

### Humain

- Les guides sont écrits pour un **opérateur non-auteur** : chaque étape
  porte un prérequis vérifiable, un critère de succès observable et un
  « En cas d'échec : STOP ». Ne jamais continuer sur un prérequis rouge.
- La bascule monitor → closed exige un **quorum** : un opérateur seul ne
  peut pas fermer le réseau (démontré par le selftest : 1 signataire →
  403, quorum → 200).

## Dans quel ordre — §13 décliné (D98)

```
0. prérequis communs            deploy/README.md (étapes communes)
1. genèse (superviseur, HSM)    scripts/genesis + superviseur.md étape 1
2. fencing (trackers d'époques) cellule.md — éprouvé par le selftest (2 cellules)
3. OPA + registre               cellule.md étapes 3-6 (capabilities restreintes §12)
4. PEP / broker (MONITOR)       cellule.md étape 7, serveur.md — rien d'autre que monitor
5. NAC routeur                  router-debian.md — DERNIER maillon réseau
6. traducteur (optionnel)       src/translator/README.md — en dernier, toujours
```

L'ordre n'est pas cosmétique : la gouvernance (1-2) précède la politique
(3), qui précède l'application (4), qui précède le réseau (5). Déployer
le NAC avant le fencing laisserait des clients admis sans gouvernance
d'époque — exactement le défaut que le fencing existe pour empêcher.

Avant de toucher une machine réelle : `bash deploy/selftest/selftest.sh`
— **82 contrôles** (cellule mono réelle, fencing 2 cellules, démons
brokerd/supervisord réels), fail-closed, rapport JSON dans
`deploy/selftest/out/`. Puis les checklists de recette par machine
([checklists/](checklists/)).

## Critères de succès du pilote

- Selftest vert et checklists de recette signées sur chaque machine.
- **Budget de friction §9.1 respecté** ([`tests/p1_friction/`](../tests/p1_friction/)) :
  régression d'expérience utilisateur mesurée = 0 — le pilote échoue si
  la latence ou le taux d'arbitrage dépassent les seuils, même si tout
  le reste fonctionne.
- Zéro action non tracée : toute décision produit une feuille vérifiable ;
  toute alarme a un destinataire.
- La bascule closed intervient après la fenêtre d'observation, sur mesure
  §9.1 alimentée, par quorum ([monitor-to-closed.md](monitor-to-closed.fr.md)).

## Limites honnêtes (à date — 2026-09-22)

- Les **corpus natifs** du traducteur restent à constituer au pilote
  (§15) ; la chaîne de mesure (replay, métriques par classe, feuille
  « TBTM1 ») est livrée et testée sur un mini-corpus d'exemple.
- `brokerd` v1 n'accepte que le traducteur `structured` : le chemin
  langage naturel / escalade humaine n'est pas câblé (le contrôleur de
  dégradation, lui, est livré et testé).
- L'inter-domaine est différé par la spec elle-même (§13, issue #33).
- La durabilité bornée-async du registre (T38) est livrée (PR #78,
  fusionnée).
- `config/` n'est jamais déployée telle quelle — toujours adapter ;
  chaque fichier le dit, ce document le répète.
