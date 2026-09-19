# scripts — enrôlement 802.1X/EAP-TLS sur la PKI du handshake (T18)

Une seule infrastructure d'identité (§3) : la même PKI Ed25519 (§12) sert
l'admission réseau (802.1X/EAP-TLS) et l'attestation applicative des agents.

## Scripts

| script | rôle |
|---|---|
| `ca_dev.sh` | bootstrap de la CA X.509 Ed25519 de **DEV** ancrée sur l'identité du handshake. Idempotent. Produit CA + CRL initiale + certificat serveur RADIUS (profil `nac-server`) + `leaves.jsonl`. |
| `enroll_client.sh <hostname>` | enrôle un endpoint : clé Ed25519, CSR, certificat profil `nac-client` (EKU `clientAuth`, SAN `DNS:<host>.<cell>` + `URI:host/<host>.<cell>`), déploiement `client.key`/`client.crt`/`ca.crt` + `wpa_supplicant.conf`. Refuse le double enrôlement (fail-closed, §1). Feuille `enrollment`. |
| `revoke_client.sh <hostname>` | révoque le certificat, régénère la CRL et `crl/ca-with-crl.pem` (fichier combiné pour `ca_file` FreeRADIUS avec `check_crl = yes`). Idempotent (une révocation déjà faite régénère quand même la CRL). Feuille `revocation`. |
| `test_eap_tls.sh` | validation RÉELLE : FreeRADIUS + `eapol_test` (paquets Debian épinglés). Voir ci-dessous. |

## Doctrine

- **DEV/TEST UNIQUEMENT** : la clé de CA transite par un fichier `0400` sous
  `config/freeradius/certs/dev` (couvert par `.gitignore`, jamais commitée).
  Même doctrine que `scripts/genesis` (T3) : ces outils matérialisent la
  FORME des artefacts, pas leur légitimité. En production, la clé de CA vit
  dans un HSM (PKCS#11), générée sans extraction possible — la procédure est
  identique (§12).
- **Enrôlement et révocation sont des actions gouvernées** (§4.1) : chacune
  laisse une feuille hash-only (§6.2) dans `$TBP_PKI_HOME/leaves.jsonl` —
  SHA-256 du DER du certificat, numéro de série, opérateur, horodatage.
  Jamais le certificat complet ni la clé.
- **Révocation → réseau** : §5.3 — un contrôle OCSP/CRL injoignable ne doit
  JAMAIS ouvrir l'accès ; le supplicant part en VLAN de remediation. La CRL
  n'est relue par FreeRADIUS qu'au (re)démarrage : en production, prévoir la
  cadence de rechargement (ou OCSP) — testé ici par redémarrage explicite.
- **Pas de VLAN assigné par RADIUS en v1** (§5.3) : le serveur répond
  Access-Accept / Access-Reject ; la logique VLAN captif/remediation reste
  côté switch (T19).

## Test réel (`test_eap_tls.sh`)

Prérequis : FreeRADIUS 3.2 (binaire + arbre de config stock + modules) et
`eapol_test` (wpa-supplicant). Sur Debian : `apt install freeradius
wpasupplicant` — ou paquets épinglés extraits (`dpkg -x`), voir variables.

```sh
TBP_FREERADIUS=/usr/sbin/freeradius \
TBP_FREERADIUS_RADDB=/etc/freeradius/3.0 \
TBP_EAPOL_TEST=/usr/bin/eapol_test \
sh test_eap_tls.sh
```

Critères vérifiés (critère d'acceptation de #18) :

1. certificat de la PKI du handshake → **Access-Accept** (EAP-TLS) ;
2. certificat d'une PKI étrangère → **Access-Reject** (le VLAN captif est
   côté switch — ici on prouve le Reject) ;
3. certificat révoqué (CRL, `check_crl = yes`) → **Access-Reject** après
   rechargement de la CRL ;
4. enrôlement et révocation laissent chacun leur feuille (§4.1, §6.2) ;
5. double enrôlement refusé explicitement (fail-closed, §1).

Le serveur de test utilise une fixture générée dans un répertoire jetable à
partir de l'arbre de config stock (symlinks `mods-enabled`/`sites-enabled`
recréés, chemins ajustés) — la configuration FreeRADIUS de production
(clients.conf, site, politiques VLAN) reste à T19/T20.

Astuce sandbox : si les binaires proviennent de paquets extraits hors
`dpkg -i`, le dictionnaire compilé (`/usr/share/freeradius`) peut manquer ;
un namespace utilisateur + bind-mount suffit :

```sh
unshare -rm sh -c '
  mount -t tmpfs tmpfs /usr/share &&
  mkdir /usr/share/freeradius &&
  cp -a /chemin/extrait/usr/share/freeradius/. /usr/share/freeradius/ &&
  exec sh test_eap_tls.sh'
```

## Variables

| variable | défaut | rôle |
|---|---|---|
| `TBP_PKI_HOME` | `../certs/dev` | racine de la CA de dev |
| `TBP_CELL` | `cell-alpha-01` | cellule (suffixe DNS des SAN) |
| `TBP_NAC_HOME` | `/etc/tbp/nac` | déploiement des certificats clients |
| `DAYS_CA` / `DAYS_CERT` | 3650 / 730 | durées de validité |
| `TBP_FREERADIUS*` / `TBP_EAPOL_TEST` | chemins système | binaires et arbres pour le test |
