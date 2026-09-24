# scripts/genesis — outillage de genèse DEV/TEST (T3)

> ⚠ **DEV/TEST UNIQUEMENT.** SoftHSM n'est jamais une racine de confiance de
> gouvernance (spec §12). Rien ici ne produit un epoch 0 légitime.

## Pourquoi cet outillage existe

Rien n'est signable avant la genèse (§13, étape 1). La cérémonie de genèse
**réelle** est *procédurale, pas du code* :

- un quorum de **contrôleurs humains** (m-of-n) se réunit ;
- les clés Ed25519 sont générées **dans des HSM véritables**, sans extraction
  possible (ici, SoftHSM ne supportant pas `C_GenerateKeyPair` pour
  `CKM_EDDSA`, la clé transite par la mémoire du processus avant import —
  acceptable en dev, inacceptable en gouvernance) ;
- le jeton d'epoch 0 `(N=0, authority, TTL ~60 s)` (§7.2) est signé à m-of-n ;
- l'ancrage est publié sur un **canal hors-bande authentifié et indépendant**
  (§3.2 : la légitimité reste hors protocole) — un fichier local ne saurait
  s'y substituer.

Cet outillage fournit aux phases suivantes (registre, PEP, NAC) des clés et
un epoch 0 **signés et vérifiables** sans attendre la cérémonie réelle. Il
matérialise la *forme* des artefacts (manifest, jeton, ancre), pas leur
*légitimité*.

## Usage

```sh
scripts/genesis/genesis_dev.sh            # n=3, m=2, authority=cell-a
N=5 M=3 AUTHORITY=cell-b scripts/genesis/genesis_dev.sh
```

Le script :

1. initialise un token SoftHSM `tbp-genesis-dev` (isolé sous
   `scripts/genesis/out/`, réutilisé s'il existe) ;
2. génère les paires Ed25519 des `n` contrôleurs dans le token
   (`tbp-controller-<i>`) — Ed25519 partout (§12) ;
3. signe le jeton d'epoch 0 à `m`-of-`n` — les clés privées ne quittent pas
   le HSM (`CKM_EDDSA` via PKCS#11) ;
4. écrit un ancrage hors-bande **simulé** (`anchor_epoch0.txt` = hash du
   jeton, canal « indépendant » de dev) ;
5. vérifie : intégrité du manifest, signatures valides de signataires
   **distincts**, quorum atteint, concordance avec l'ancre.

Le script est idempotent : `keygen` détruit puis régénère les clés d'un
label existant, et `findKey` refuse un token incohérent (clé en double).

## Artefacts produits (dans `out/`)

| Fichier               | Rôle                                                        |
|-----------------------|-------------------------------------------------------------|
| `manifest.json`       | clés publiques (hex) + hash engageant l'ensemble + warning  |
| `pubkeys/*.hex`       | une clé publique par contrôleur                             |
| `epoch0.json`         | payload signé `(n, authority, issued_at, ttl_s)` + signatures + quorum + warning |
| `anchor_epoch0.txt`   | hash du jeton — ancrage hors-bande simulé                   |

Chaque artefact porte l'avertissement « DEV/TEST UNIQUEMENT — SoftHSM n'est
jamais une racine de confiance de gouvernance (spec §12) ».

## Binaire `genesis` (usage direct)

```sh
go build -o genesis .          # nécessite CGO et libsofthsm2.so
export SOFTHSM2_MODULE=/chemin/libsofthsm2.so TBP_DEV_PIN=0000
./genesis keygen -n 3 -out out
./genesis sign  -m 2 -n 3 -authority cell-a -out out
./genesis anchor -out out
./genesis verify -m 2 -out out
```

`verify` est volontairement **hors HSM** : la vérification Ed25519 est
publique (`crypto/ed25519`), un entrant tardif n'a besoin que du manifest,
du jeton et de l'ancre reçue par le canal hors-bande (§3.2).

## Renouvellement du bail d'époque (issue #126)

Un déploiement multi-cellules (§7.2, `TBP_TOPOLOGY=multi`) sert sous un bail
d'époque `(N, authority, ttl_s)` — `epoch0.json` ci-dessus n'en est que le
premier. Sans renouvellement, le bail expire à `ttl_s` et la cellule cesse
de servir (`epoch-unavailable`, fail-closed) : jamais de mécanisme
« automatique » qui prolongerait un bail sans repasser par le quorum — ce
serait autoriser une autorité à se maintenir elle-même, exactement ce que
le fencing (§7.2) existe pour empêcher.

**Qui signe** : les MÊMES contrôleurs, le même trousseau, le même quorum
m-of-n que la genèse — aucune nouvelle autorité introduite. **Quel
quorum** : celui déjà configuré (`TBP_QUORUM_MIN` / manifest de
contrôleurs), jamais un paramètre séparé. **À quelle fréquence** :
décision opérationnelle de l'opérateur (humaine ou scriptée côté
surveillance), jamais automatique côté `brokerd` — surveiller
`GET /v1/supervision/epoch` (champ `expires_at`) et renouveler avant
expiration, avec la même marge que pour toute rotation manuelle (§7.2).

```sh
# Sur la machine qui détient les clés de contrôleurs (même custody que la
# genèse — jamais sur la cellule elle-même) :
./genesis renew -m 2 -n 3 -out out
#   -authority <cellule>   optionnel : vide = même autorité (renouvellement
#                          pur) ; différente = bascule volontaire, même
#                          mécanisme
#   -ttl <secondes>        optionnel, défaut 60 (§7.2 : 10-300 s)
#   -prev <fichier>        optionnel, défaut out/epoch0.json au premier
#                          renouvellement ; passer le epoch-N.json produit
#                          par le renouvellement précédent ensuite

# Sur (ou via un accès administratif à) la cellule qui fait tourner brokerd,
# plan d'ADMINISTRATION (revue #95) — l'accès au socket EST le contrôle
# d'accès :
curl --unix-socket "$TBP_BROKER_ADMIN_SOCKET" \
     -X POST --data-binary @out/epoch-1.json \
     http://localhost/v1/epoch/renew
```

`POST /v1/epoch/renew` n'ajoute aucune logique de fencing : il expose
l'admission déjà exercée par `tracker.Accept` au démarrage (`epoch0.json`)
comme opération d'administration — même vérification stricte (forme, TTL
borné, signatures m-of-n distinctes, monotonie de N, anti-équivoque), même
feuille `KindEpoch` tracée. Un jeton insuffisamment signé ou mal formé est
refusé (400) sans toucher à l'époque servie ; en mode mono-cellule (#97,
aucun tracker), l'appel est refusé honnêtement (409) plutôt que de simuler
un bail inexistant.

## Dépendances

- Go ≥ 1.23, CGO
- SoftHSM2 (`softhsm2-util`, `libsofthsm2.so`)
- `github.com/miekg/pkcs11` v1.1.1 (voir `go.mod` / `go.sum`)

## Références spec

- §3.2 — bootstrap : epoch 0 signé par le quorum, ancré hors-bande ;
  vérification par un entrant tardif (chaîne de clés hors-bande).
- §7.2 — epoch fencing : jeton `(N, authority, TTL ~60 s)`, m-of-n, HSM.
- §11.3 — profil de déterminisme : struct à champs fixes → JSON canonique ;
  hash du manifest sur clés triées.
- §12 — Ed25519 partout ; SoftHSM dev/test uniquement, jamais en gouvernance.
