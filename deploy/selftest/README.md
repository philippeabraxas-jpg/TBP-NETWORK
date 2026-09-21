# deploy/selftest — auto-vérification exécutable des guides (T35, issue #61)

Ce dossier **exécute** les guides de `deploy/` au lieu de se contenter de
les relire. Un guide qui dérive du code casse ici, pas chez l'opérateur —
c'est le filet du critère d'acceptation de l'issue : « un opérateur
non-auteur déroule le guide ».

## Lancer

```bash
# depuis la racine du dépôt ; prérequis : go ≥ 1.24, opa ≥ 1.0, python3
bash deploy/selftest/selftest.sh
```

Code de sortie 1 dès qu'un contrôle échoue (fail-closed). Rapport JSON :
`deploy/selftest/out/selftest-report.json` (gitignoré).

## Ce qui est exécuté pour de vrai

**Phase `mono`** (une cellule, vrais binaires) :

1. build de `pepd` depuis `src/pep/cmd/pepd` ;
2. témoin fail-closed : `pepd` sans `TBP_SALT` refuse de démarrer ;
3. capabilities OPA : `opa capabilities --current`, présence des interdits
   (`http.send`, `net.lookup_ip_addr`, `time.now_ns`, `opa.runtime`)
   **avant** retrait (non-vacuité), retrait, absence **après**, rejet au
   chargement (`opa check`) et au build (`opa build`) d'une règle
   `http.send` — même recette que `policies/gen_capabilities.sh` ;
4. OPA ≥ 1.0 : `opa run` n'a plus de flag `--capabilities` — le selftest
   compile un bundle avec les capabilities restreintes et l'exécute ;
5. `pepd` démarré en **monitor** (§5.3) avec OPA branché et registre
   tessera réel ;
6. jeton valide (`read` → allow OPA), témoins : `write` → veto OPA
   (`reason=opa-deny`), clé inconnue → `bad-headers` ;
7. bascule gouvernée : 1 signataire → 403, quorum 2 → closed ; en closed,
   le veto OPA bloque (`forwarded=false`) ;
8. registre : delta mesuré — une évaluation allow = **deux** feuilles
   `KindDecision` (verdict + passeport §4.1-bis), bascule de posture =
   feuille `KindTelemetry`.

**Phase `fencing`** (deux cellules in-process, registres tessera réels,
horloge manuelle — motif T27/T28, exigence de relecture) :

1. epoch 0 (autorité cell-a) : seul le détenteur sert, cell-b refuse
   (fail-closed) ;
2. équivoque (même N, autre autorité) : refus tracé (`KindEpoch`) + alarme
   (couture T14) ;
3. rotation émise avant expiration : invariant notBefore §7.2 prouvé par
   balayage fin — **jamais deux autorités simultanées** (la contrepartie
   est un trou de service fail-closed, documenté dans les guides) ;
4. révocation §7.3 : `roster=[cell-b]` → cell-a en quarantaine, vue des
   deux côtés ;
5. QuorumGate §7.5 : preuve 1-of-3 refusée et tracée, 2-of-3 admise et
   tracée (`KindQuorum`) ;
6. promotion §7.4 : fenêtre saine + ancre conforme → admise ; partition du
   master → refus fail-closed (`ErrPromotionAnchorUnavailable`) ; les deux
   tracés (`KindPromotion`).

**Vérificateur formel** (`check_steps.py`) : chaque étape des six guides
porte les quatre blocs D96 (`Prérequis vérifiable` / `Commande` /
`Critère de succès observable` / `En cas d'échec : STOP`), dans l'ordre ;
toute référence à `config/` explicite « adapter » (D99). Ses propres tests
(`test_check_steps.py`) prouvent la non-vacuité par mutations.

## Substitution DEV documentée

La genèse réelle exige SoftHSM (`scripts/genesis`, §12 — jamais de clé
logicielle en production). Ici, faute de HSM, les clés d'émetteur, de
contrôleurs et de cellules sont dérivées de seeds fixes en pure Go.
**C'est une substitution de test, pas une genèse** : les guides renvoient
à `scripts/genesis` pour la vraie cérémonie. Le trou symétrique —
l'absence de binaire `brokerd` et de démon de supervision — est suivi en
issue **#74** ; les guides documentent le patron d'assemblage en attendant.

## Hors périmètre (exécuté en lab, pas ici)

Le scénario netns/FreeRADIUS complet (VLAN, EAP-TLS) exige root +
`CAP_NET_ADMIN` ou containerlab ; selon l'hôte, `unshare -n` échoue
(《 Operation not permitted 》, sandbox sans cap) ou réussit puis casse
plus tard (sous-interfaces VLAN non supportées, bind IPv6 FreeRADIUS).
`deploy/router-debian.md` cite ces deux causes réelles et délègue au lab
(`lab/containerlab/`).
