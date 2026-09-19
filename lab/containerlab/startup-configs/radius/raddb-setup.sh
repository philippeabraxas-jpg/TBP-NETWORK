#!/bin/sh
# raddb-setup.sh — prépare la config FreeRADIUS du pilote P1 à partir de
# l'arbre STOCK Debian + la PKI du handshake (T18) : EAP-TLS seul (une seule
# voie d'authentification, §1), CA du handshake, check_crl=yes (révocation
# effective), journal des décisions d'authentification (§4.1).
#
# Produit $TBP_WORK/raddb prêt pour :
#   freeradius -f -d $TBP_WORK/raddb -l $TBP_WORK/log/radius.log
#
# Env : TBP_WORK (défaut /run/tbp-p1), TBP_PKI_HOME (défaut $TBP_WORK/pki),
# RADDB_SRC (arbre stock, défaut /etc/freeradius/3.0), FR_LIBDIR (modules,
# si non standard), SWITCH_IP (défaut 10.99.99.2), RADIUS_SECRET (défaut
# testing123 — LAB UNIQUEMENT).
set -eu

WORK=${TBP_WORK:-/run/tbp-p1}
PKI=${TBP_PKI_HOME:-$WORK/pki}
RADDB_SRC=${RADDB_SRC:-/etc/freeradius/3.0}
CONF=$WORK/raddb

[ -d "$RADDB_SRC" ] || { echo "erreur: raddb stock absent: $RADDB_SRC" >&2; exit 1; }
[ -f "$PKI/ca/ca.crt" ] || { echo "erreur: PKI absente — ca_dev.sh d'abord" >&2; exit 1; }

rm -rf "$CONF"
cp -a "$RADDB_SRC" "$CONF"
chmod -R u+w "$CONF"

# un arbre issu de « dpkg -x » n'a pas les symlinks de postinst : recréer
# l'ensemble de modules par défaut de Debian ; site « default » seul
for m in always attr_filter cache_eap chap date detail detail.log digest \
		dynamic_clients eap echo exec expiration expr files linelog \
		logintime mschap ntlm_auth pap passwd preprocess radutmp realm \
		replicate sradutmp totp unix unpack utf8; do
	[ -e "$CONF/mods-available/$m" ] && \
		ln -sf "../mods-available/$m" "$CONF/mods-enabled/$m" || true
done
[ -e "$CONF/sites-available/default" ] && \
	ln -sf ../sites-available/default "$CONF/sites-enabled/default" || true

mkdir -p "$CONF/certs" "$WORK/log" "$WORK/var/run/freeradius"
install -m 0400 "$PKI/certs/radius.key" "$CONF/certs/server.key"
install -m 0444 "$PKI/certs/radius.crt" "$CONF/certs/server.pem"
cat "$PKI/ca/ca.crt" "$PKI/crl/ca.crl" > "$CONF/certs/ca.pem"

sed -i \
	-e "s|^[[:space:]]*user = .*|\tuser = $(id -un)|" \
	-e "s|^[[:space:]]*group = .*|\tgroup = $(id -gn)|" \
	-e "s|^logdir = .*|logdir = $WORK/log|" \
	-e "s|^localstatedir = .*|localstatedir = $WORK/var|" \
	"$CONF/radiusd.conf"
[ -n "${FR_LIBDIR:-}" ] && \
	sed -i "s|^libdir = .*|libdir = $FR_LIBDIR|" "$CONF/radiusd.conf"
# journal des DÉCISIONS d'authentification (§4.1) : Login OK / Login incorrect
sed -i "s|^[[:space:]#]*auth = .*|\t\tauth = yes|" "$CONF/radiusd.conf"

# module eap : TLS seul (§1), CA du handshake, vérification CRL
sed -i \
	-e "s|private_key_file = .*|private_key_file = \${certdir}/server.key|" \
	-e "s|certificate_file = .*|certificate_file = \${certdir}/server.pem|" \
	-e "s|ca_file = .*|ca_file = \${certdir}/ca.pem|" \
	-e "s|^[[:space:]#]*check_crl = .*|\t\tcheck_crl = yes|" \
	-e "s|default_eap_type = md5|default_eap_type = tls|" \
	"$CONF/mods-available/eap"

# NAS autorisés : le switch P1 (et localhost pour les sondes locales)
cat > "$CONF/clients.conf" <<EOF
client switch-p1 {
	ipaddr = ${SWITCH_IP:-10.99.99.2}
	secret = ${RADIUS_SECRET:-testing123}
	nas_type = other
}
client localhost {
	ipaddr = 127.0.0.1
	secret = ${RADIUS_SECRET:-testing123}
}
EOF

# MAB (D16) : si TBP_MAB_FILE pointe un fichier d'autorisations MAC (format
# « files » : '<mac>' Cleartext-Password := '<mac>'), il est inclus dans
# l'authorize — canal MAB instrumenté, jamais silencieux (§5.3).
if [ -n "${TBP_MAB_FILE:-}" ] && [ -f "$TBP_MAB_FILE" ]; then
	cat "$TBP_MAB_FILE" >> "$CONF/mods-config/files/authorize"
	CNT=$(grep -c Cleartext-Password "$TBP_MAB_FILE")
	echo "raddb-setup: MAB — $CNT MAC autorisée(s)"
fi

echo "raddb-setup: $CONF prêt (EAP-TLS, PKI du handshake, check_crl=yes)"
