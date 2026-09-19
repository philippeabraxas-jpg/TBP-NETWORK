#!/bin/sh
# revoke_client.sh <hostname> — révocation EAP-TLS : CRL/OCSP + feuille.
#
# La révocation est une action gouvernée (§4.1) : feuille au registre,
# hash-only (§6.2). Effet attendu : le certificat est refusé dès la CRL
# régénérée (check_crl côté RADIUS). OCSP injoignable ⇒ VLAN de remédiation
# avec feedback, jamais de soft-fail aveugle (§5.3 — testé côté switch en
# T20, lab/tests/test_ocsp_remediation.sh).
#
# Usage :
#   revoke_client.sh <hostname>
# Variables : TBP_PKI_HOME, TBP_CELL (comme enroll_client.sh)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TBP_PKI_HOME=${TBP_PKI_HOME:-"${SCRIPT_DIR}/../certs/dev"}
TBP_CELL=${TBP_CELL:-cell-alpha-01}

[ $# -eq 1 ] || { echo "usage: revoke_client.sh <hostname>" >&2; exit 2; }
HOST=$1

PKI=$(CDPATH= cd -- "$(dirname -- "$TBP_PKI_HOME")" && pwd)/$(basename "$TBP_PKI_HOME")
[ -f "$PKI/ca/ca.key" ] || {
	echo "erreur: CA absente — lancer ca_dev.sh d'abord (fail-closed, §1)" >&2
	exit 1; }
[ -f "$PKI/certs/$HOST.crt" ] || {
	echo "erreur: pas de certificat pour « $HOST » (jamais enrôlé ?)" >&2
	exit 1; }

# Idempotence : déjà révoqué ⇒ on le signale, la CRL est régénérée quand
# même (une révocation partiellement appliquée ne doit pas rester muette).
OUT=$(openssl ca -config "$PKI/openssl-ca.cnf" -revoke "$PKI/certs/$HOST.crt" 2>&1) || true
case "$OUT" in
	*"Already revoked"*)
		echo "info: $HOST déjà révoqué — régénération CRL quand même" ;;
	*"Revoking Certificate"*) : ;;
	*)	echo "erreur révocation: $OUT" >&2; exit 1 ;;
esac

# CRL régénérée — FreeRADIUS la consomme via ca_file (CA+CRL concaténés) ;
# on régénère le fichier combiné pour que le rechargement suffise.
openssl ca -gencrl -config "$PKI/openssl-ca.cnf" -out "$PKI/crl/ca.crl" 2>/dev/null
cat "$PKI/ca/ca.crt" "$PKI/crl/ca.crl" > "$PKI/crl/ca-with-crl.pem"

CERT_HASH=$(openssl x509 -in "$PKI/certs/$HOST.crt" -outform DER 2>/dev/null \
	| openssl dgst -sha256 -r | cut -d' ' -f1)
SERIAL=$(openssl x509 -in "$PKI/certs/$HOST.crt" -noout -serial | cut -d= -f2)
printf '{"v":1,"action":"revocation","cell":"%s","subject":"%s","cert_sha256":"%s","serial":"%s","operator":"%s","ts":%s}\n' \
	"$TBP_CELL" "$HOST" "$CERT_HASH" "$SERIAL" "$(id -un)" "$(date +%s)" \
	>> "$PKI/leaves.jsonl"

echo "révoqué: $HOST (serial $SERIAL)"
echo "  CRL régénérée: $PKI/crl/ca.crl (+ ca-with-crl.pem combiné)"
echo "  feuille revocation → $PKI/leaves.jsonl"
echo "  rappel §5.3 : OCSP/CRL injoignable ⇒ VLAN de remédiation avec"
echo "  feedback, jamais de soft-fail aveugle (testé côté switch en T20)"
