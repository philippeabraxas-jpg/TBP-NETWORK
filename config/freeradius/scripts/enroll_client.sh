#!/bin/sh
# enroll_client.sh <hostname> — enrôlement EAP-TLS d'un endpoint sur la PKI
# du handshake (spec §3, §5.1). L'enrôlement est une ACTION GOUVERNÉE :
# il produit une feuille au registre (§4.1), hash-only (§6.2).
#
# Usage :
#   enroll_client.sh <hostname>
# Variables :
#   TBP_PKI_HOME   CA de dev (défaut ../certs/dev — créée par ca_dev.sh)
#   TBP_CELL       cellule (défaut cell-alpha-01)
#   TBP_NAC_HOME   racine de déploiement (défaut /etc/tbp/nac ; en dev,
#                  pointer un répertoire local)
#   TBP_NAC_USER   propriétaire dédié des clés déployées (défaut : l'appelant)
#
# Fail-closed partout (§1) : pas de CA initialisée, hostname invalide ou
# certificat déjà enrôlé ⇒ refus, jamais de double enrôlement silencieux.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TBP_PKI_HOME=${TBP_PKI_HOME:-"${SCRIPT_DIR}/../certs/dev"}
TBP_CELL=${TBP_CELL:-cell-alpha-01}
TBP_NAC_HOME=${TBP_NAC_HOME:-/etc/tbp/nac}
TBP_NAC_USER=${TBP_NAC_USER:-$(id -un)}

[ $# -eq 1 ] || { echo "usage: enroll_client.sh <hostname>" >&2; exit 2; }
HOST=$1

# Normalisation d'identité (§14) : minuscules, [a-z0-9-], sans point.
case "$HOST" in
	*[!a-z0-9-]*|"")
		echo "erreur: hostname invalide « $HOST » ([a-z0-9-]+)" >&2; exit 2 ;;
esac

PKI=$(CDPATH= cd -- "$(dirname -- "$TBP_PKI_HOME")" && pwd)/$(basename "$TBP_PKI_HOME")
[ -f "$PKI/ca/ca.key" ] || {
	echo "erreur: CA absente — lancer ca_dev.sh d'abord (fail-closed, §1)" >&2
	exit 1; }
[ -f "$PKI/certs/$HOST.crt" ] && {
	echo "erreur: $HOST déjà enrôlé — révoquer d'abord (revoke_client.sh), " >&2
	echo "        jamais de double enrôlement silencieux" >&2
	exit 1; }

# --- 1. Clé client Ed25519 (§12 : Ed25519 partout) --------------------------
openssl genpkey -algorithm Ed25519 -out "$PKI/certs/$HOST.key" 2>/dev/null
chmod 400 "$PKI/certs/$HOST.key"

# --- 2. CSR + signature par la CA du handshake (même PKI que §3) ------------
# SAN : l'identité de cellule host/<hostname>.<cell> en URI (le slash est
# interdit dans un SAN DNS), doublée d'un SAN DNS d'usage courant.
openssl req -new -key "$PKI/certs/$HOST.key" -out "$PKI/csr/$HOST.csr" \
	-subj "/CN=$HOST" \
	-addext "subjectAltName=DNS:$HOST.$TBP_CELL,URI:host/$HOST.$TBP_CELL" 2>/dev/null
openssl ca -batch -config "$PKI/openssl-ca.cnf" -extensions nac_client \
	-policy policy_nac -in "$PKI/csr/$HOST.csr" \
	-out "$PKI/certs/$HOST.crt" >/dev/null 2>&1

# --- 3. Déploiement + configuration supplicant ------------------------------
DEST="$TBP_NAC_HOME/$HOST"
mkdir -p "$DEST"
install -m 0400 "$PKI/certs/$HOST.key" "$DEST/client.key"
install -m 0444 "$PKI/certs/$HOST.crt" "$DEST/client.crt"
install -m 0444 "$PKI/ca/ca.crt" "$DEST/ca.crt"
if [ "$(id -un)" = root ]; then
	chown "$TBP_NAC_USER:$TBP_NAC_USER" "$DEST/client.key"
fi
cat > "$DEST/wpa_supplicant.conf" <<EOF
# $HOST — supplicant 802.1X EAP-TLS sur la PKI du handshake (§3)
network={
    key_mgmt=IEEE8021X
    eap=TLS
    identity="$HOST"
    ca_cert="$DEST/ca.crt"
    client_cert="$DEST/client.crt"
    private_key="$DEST/client.key"
}
EOF
chmod 0400 "$DEST/wpa_supplicant.conf"

# --- 4. Feuille registre : l'enrôlement est gouverné (§4.1), hash-only ------
# (§6.2 : on consigne le HASH du certificat, jamais le certificat ni la clé)
CERT_HASH=$(openssl x509 -in "$PKI/certs/$HOST.crt" -outform DER 2>/dev/null \
	| openssl dgst -sha256 -r | cut -d' ' -f1)
SERIAL=$(openssl x509 -in "$PKI/certs/$HOST.crt" -noout -serial | cut -d= -f2)
printf '{"v":1,"action":"enrollment","cell":"%s","subject":"%s","cert_sha256":"%s","serial":"%s","operator":"%s","ts":%s}\n' \
	"$TBP_CELL" "$HOST" "$CERT_HASH" "$SERIAL" "$(id -un)" "$(date +%s)" \
	>> "$PKI/leaves.jsonl"

echo "enrôlé: $HOST (profil nac-client, serial $SERIAL)"
echo "  déployé dans $DEST (clé 0400, wpa_supplicant.conf)"
echo "  feuille enrollment → $PKI/leaves.jsonl"
