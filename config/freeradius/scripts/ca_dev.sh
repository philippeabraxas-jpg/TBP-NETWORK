#!/bin/sh
# ca_dev.sh — bootstrap de la CA X.509 Ed25519 de DEV ancrée sur l'identité
# du handshake (spec §3) — UNE seule infrastructure d'identité pour
# l'admission réseau (802.1X/EAP-TLS) et l'attestation applicative.
#
# ⚠ DEV/TEST UNIQUEMENT. Même doctrine que scripts/genesis (T3) : cet
# outillage matérialise la FORME des artefacts, pas leur légitimité. En
# production, la clé de CA vit dans un HSM (PKCS#11), générée sans
# extraction possible — ici elle transite par un fichier 0400 (§12).
#
# Produit (sous TBP_PKI_HOME, défaut config/freeradius/certs/dev — couvert
# par .gitignore, jamais commité) :
#   ca/ca.key          clé Ed25519 de la CA (0400)
#   ca/ca.crt          certificat CA auto-signé (la « PKI du handshake »)
#   openssl-ca.cnf     profils nac-server / nac-client (EKU dédiés)
#   index.txt, serial, crlnumber   base openssl ca
#   crl/ca.crl         CRL initiale (vide)
#   certs/radius.*     certificat serveur RADIUS (profil nac-server)
#   leaves.jsonl       registre de dev des actions gouvernées (§4.1, §6.2)
#
# Usage : ca_dev.sh
# Variables : TBP_PKI_HOME, TBP_CELL (défaut cell-alpha-01), DAYS_CA (3650)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TBP_PKI_HOME=${TBP_PKI_HOME:-"${SCRIPT_DIR}/../certs/dev"}
TBP_CELL=${TBP_CELL:-cell-alpha-01}
DAYS_CA=${DAYS_CA:-3650}
DAYS_CERT=${DAYS_CERT:-730}

command -v openssl >/dev/null 2>&1 || {
	echo "erreur: openssl introuvable" >&2; exit 1; }

mkdir -p "$TBP_PKI_HOME"
PKI=$(CDPATH= cd -- "$TBP_PKI_HOME" && pwd)

if [ -f "$PKI/ca/ca.key" ]; then
	echo "CA déjà initialisée dans $PKI — rien à faire (idempotent)"
	exit 0
fi

echo "=== ca_dev — DEV/TEST UNIQUEMENT (clé CA en fichier, spec §12) ==="
mkdir -p "$PKI/ca" "$PKI/certs" "$PKI/csr" "$PKI/crl" "$PKI/newcerts"
touch "$PKI/index.txt"
echo 1000 > "$PKI/serial"
echo 1000 > "$PKI/crlnumber"
touch "$PKI/leaves.jsonl"
chmod 700 "$PKI/ca"

# --- Configuration openssl ca : profils dédiés NAC -------------------------
# Une seule CA, deux profils d'usage — le même certificat d'identité ne
# sert jamais à deux rôles confondus (§1 : par signature, pas par nom).
cat > "$PKI/openssl-ca.cnf" <<EOF
[ ca ]
default_ca = tbp_ca

[ tbp_ca ]
dir               = $PKI
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
certificate       = \$dir/ca/ca.crt
private_key       = \$dir/ca/ca.key
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
default_md        = sha256
default_days      = $DAYS_CERT
default_crl_days  = 30
unique_subject    = no
# le SAN vient de la CSR (générée par enroll_client.sh / le bloc serveur
# ci-dessous) : les extensions de la CSR sont recopiées dans le certificat
copy_extensions   = copy

[ policy_nac ]
commonName             = supplied
countryName            = optional
organizationName       = optional
organizationalUnitName = optional

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = TBP handshake dev CA ($TBP_CELL)

[ ca_ext ]
basicConstraints = critical, CA:TRUE
keyUsage         = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

# Profil serveur RADIUS (EAP-TLS) : authentification serveur seulement.
[ nac_server ]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

# Profil client NAC : authentification client (802.1X) — la même PKI sert
# l'attestation applicative (§3) : une identité, un canal par rôle.
[ nac_client ]
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# --- CA Ed25519 (§12 : Ed25519 partout) ------------------------------------
openssl genpkey -algorithm Ed25519 -out "$PKI/ca/ca.key" 2>/dev/null
chmod 400 "$PKI/ca/ca.key"
openssl req -x509 -new -key "$PKI/ca/ca.key" -out "$PKI/ca/ca.crt" \
	-days "$DAYS_CA" -config "$PKI/openssl-ca.cnf" -extensions ca_ext 2>/dev/null
echo "CA Ed25519 « PKI du handshake » (dev) : $PKI/ca/ca.crt"

# --- CRL initiale (vide) ----------------------------------------------------
openssl ca -gencrl -config "$PKI/openssl-ca.cnf" -out "$PKI/crl/ca.crl" 2>/dev/null

# --- Certificat serveur RADIUS (profil nac-server) --------------------------
openssl genpkey -algorithm Ed25519 -out "$PKI/certs/radius.key" 2>/dev/null
chmod 400 "$PKI/certs/radius.key"
openssl req -new -key "$PKI/certs/radius.key" -out "$PKI/csr/radius.csr" \
	-subj "/CN=radius.$TBP_CELL" \
	-addext "subjectAltName=DNS:radius.$TBP_CELL,URI:host/radius.$TBP_CELL" 2>/dev/null
openssl ca -batch -config "$PKI/openssl-ca.cnf" -extensions nac_server \
	-policy policy_nac -in "$PKI/csr/radius.csr" \
	-out "$PKI/certs/radius.crt" >/dev/null 2>&1
echo "certificat serveur RADIUS : $PKI/certs/radius.crt"

echo "=== CA dev prête dans $PKI ==="
echo "rappel : production = clé CA en HSM (PKCS#11), même procédure (§12)"
