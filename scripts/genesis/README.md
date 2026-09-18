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
