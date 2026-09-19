#!/bin/sh
# test_eap_tls.sh — validation RÉELLE du critère d'acceptation T18 (#18) :
# FreeRADIUS + eapol_test (802.1X/EAP-TLS sans switch, le lab T19 viendra).
#
#   1. certificat de la PKI du handshake (§3) → Access-Accept ;
#   2. certificat d'une PKI ÉTRANGÈRE → Access-Reject (vers VLAN captif,
#      côté switch — ici on prouve le Reject) ;
#   3. certificat RÉVOQUÉ (CRL, check_crl=yes) → Access-Reject ;
#   4. enrôlement et révocation ont chacun leur feuille (§4.1, hash-only §6.2).
#
# Variables d'environnement :
#   TBP_FREERADIUS        binaire freeradius (requis)
#   TBP_FREERADIUS_RADDB  arbre de config stock (ex. /etc/freeradius/3.0)
#   TBP_FREERADIUS_LIBDIR répertoire des modules rlm_*
#   TBP_FREERADIUS_PREFIX préfixe d'installation (chemins compilés)
#   TBP_EAPOL_TEST        binaire eapol_test (requis)
#   TBP_RADIUS_PORT       port auth du serveur de test (défaut 1812, stock)
#   TBP_TEST_KEEP         si non vide, conserve le répertoire de travail
#   LD_LIBRARY_PATH       conservé tel quel pour les binaires extraits
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FR=${TBP_FREERADIUS:-freeradius}
EAPOL=${TBP_EAPOL_TEST:-eapol_test}
RADDB_SRC=${TBP_FREERADIUS_RADDB:-/etc/freeradius/3.0}
PORT=${TBP_RADIUS_PORT:-1812}   # port auth stock (listen port=0 du site default)

for b in "$FR" "$EAPOL" openssl; do
	command -v "$b" >/dev/null 2>&1 || [ -x "$b" ] || {
		echo "erreur: $b introuvable" >&2; exit 2; }
done
[ -d "$RADDB_SRC" ] || { echo "erreur: raddb stock introuvable: $RADDB_SRC" >&2; exit 2; }

WORK=$(mktemp -d /tmp/tbp_t18_test.XXXXXX)
trap 'kill $(cat "$WORK/freeradius.pid" 2>/dev/null) 2>/dev/null || true; [ -n "${TBP_TEST_KEEP:-}" ] && { echo "WORK conservé: $WORK"; exit 0; }; rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# --- 1. CA + enrôlement -----------------------------------------------------
export TBP_PKI_HOME="$WORK/pki"
export TBP_NAC_HOME="$WORK/nac"   # défaut /etc/tbp/nac — ici répertoire jetable
TBP_CELL=t18-test
export TBP_CELL
sh "$SCRIPT_DIR/ca_dev.sh" >/dev/null || fail "ca_dev.sh"
sh "$SCRIPT_DIR/enroll_client.sh" endpoint-ok >/dev/null || fail "enroll endpoint-ok"
PKI="$WORK/pki"

grep -q '"action":"enrollment"' "$PKI/leaves.jsonl" \
	|| fail "pas de feuille enrollment"
grep -q '"subject":"endpoint-ok"' "$PKI/leaves.jsonl" \
	|| fail "feuille enrollment sans sujet"
grep '"action":"enrollment"' "$PKI/leaves.jsonl" | grep -q '"cert_sha256":"[0-9a-f]\{64\}"' \
	|| fail "feuille enrollment sans hash du certificat (§6.2)"
ok "enrôlement endpoint-ok + feuille registre (hash-only)"

# --- PKI étrangère (attaque : cert valide mais pas de NOTRE CA) -------------
mkdir -p "$WORK/foreign"
openssl genpkey -algorithm Ed25519 -out "$WORK/foreign/ca.key" 2>/dev/null
openssl req -x509 -new -key "$WORK/foreign/ca.key" -days 30 \
	-subj "/CN=foreign CA" -out "$WORK/foreign/ca.crt" 2>/dev/null
openssl genpkey -algorithm Ed25519 -out "$WORK/foreign/rogue.key" 2>/dev/null
openssl req -new -key "$WORK/foreign/rogue.key" -subj "/CN=rogue" \
	-out "$WORK/foreign/rogue.csr" 2>/dev/null
openssl x509 -req -in "$WORK/foreign/rogue.csr" -CA "$WORK/foreign/ca.crt" \
	-CAkey "$WORK/foreign/ca.key" -CAcreateserial -days 30 \
	-out "$WORK/foreign/rogue.crt" 2>/dev/null
ok "PKI étrangère générée (certificat « rogue » valide mais hors PKI)"

# --- 2. Configuration FreeRADIUS de test (fixture — la config de production
#        reste à T19/T20 ; on part de l'arbre stock ajusté) ------------------
CONF="$WORK/raddb"
cp -a "$RADDB_SRC" "$CONF"
chmod -R u+w "$CONF"
# un arbre issu de « dpkg -x » n'a pas les symlinks créés par postinst :
# recréer l'ensemble de modules/sites par défaut de Debian
for m in always attr_filter cache_eap chap date detail detail.log digest \
		dynamic_clients eap echo exec expiration expr files linelog \
		logintime mschap ntlm_auth pap passwd preprocess radutmp realm \
		replicate sradutmp totp unix unpack utf8; do
	[ -e "$CONF/mods-available/$m" ] && \
		ln -sf "../mods-available/$m" "$CONF/mods-enabled/$m" || true
done
for s in default inner-tunnel; do
	[ -e "$CONF/sites-available/$s" ] && \
		ln -sf "../sites-available/$s" "$CONF/sites-enabled/$s" || true
done
mkdir -p "$CONF/certs" "$WORK/log" "$WORK/var/run/freeradius"
# certificats : serveur RADIUS (profil nac-server), CA+CRL combinés
install -m 0400 "$PKI/certs/radius.key" "$CONF/certs/server.key"
install -m 0444 "$PKI/certs/radius.crt" "$CONF/certs/server.pem"
cat "$PKI/ca/ca.crt" "$PKI/crl/ca.crl" > "$CONF/certs/ca.pem"

sed -i \
	-e "s|^[[:space:]]*user = .*|\tuser = $(id -un)|" \
	-e "s|^[[:space:]]*group = .*|\tgroup = $(id -gn)|" \
	-e "s|^logdir = .*|logdir = $WORK/log|" \
	-e "s|^localstatedir = .*|localstatedir = $WORK/var|" \
	"$CONF/radiusd.conf"
[ -n "${TBP_FREERADIUS_LIBDIR:-}" ] && \
	sed -i "s|^libdir = .*|libdir = $TBP_FREERADIUS_LIBDIR|" "$CONF/radiusd.conf"
[ -n "${TBP_FREERADIUS_PREFIX:-}" ] && \
	sed -i "s|^prefix = .*|prefix = $TBP_FREERADIUS_PREFIX|" "$CONF/radiusd.conf"

# module eap : TLS seul (une seule voie d'authentification, §1), CA du
# handshake, vérification CRL
sed -i \
	-e "s|private_key_file = .*|private_key_file = \${certdir}/server.key|" \
	-e "s|certificate_file = .*|certificate_file = \${certdir}/server.pem|" \
	-e "s|ca_file = .*|ca_file = \${certdir}/ca.pem|" \
	-e "s|^[[:space:]#]*check_crl = .*|\t\tcheck_crl = yes|" \
	-e "s|default_eap_type = md5|default_eap_type = tls|" \
	"$CONF/mods-available/eap"

start_radius() {
	# pas de -i/-p : les sections « listen » du site default héritent du
	# port global (port = 0) et restent rattachées au serveur virtuel
	# -f : rester au premier plan (sans -X radiusd se détache en démon et
	# le PID piégé serait celui du parent mort — fuite de processus)
	"$FR" -f -d "$CONF" -xx -l "$WORK/log/radius.log" &
	echo $! > "$WORK/freeradius.pid"
	for _ in $(seq 1 50); do
		grep -q "Ready to process requests" "$WORK/log/radius.log" 2>/dev/null && return 0
		sleep 0.2
	done
	fail "freeradius ne démarre pas — voir $WORK/log/radius.log"
}
stop_radius() {
	kill "$(cat "$WORK/freeradius.pid")" 2>/dev/null || true
	wait "$(cat "$WORK/freeradius.pid")" 2>/dev/null || true
}

# --- supplicants de test (eapol_test) ---------------------------------------
eapol_conf() {  # $1=identity $2=cert $3=key
	cat > "$WORK/eapol-$1.conf" <<EOF
network={
    eap=TLS
    eapol_flags=0
    key_mgmt=IEEE8021X
    identity="$1"
    ca_cert="$PKI/ca/ca.crt"
    client_cert="$2"
    private_key="$3"
}
EOF
}
eapol_conf endpoint-ok "$PKI/certs/endpoint-ok.crt" "$PKI/certs/endpoint-ok.key"
eapol_conf rogue "$WORK/foreign/rogue.crt" "$WORK/foreign/rogue.key"

start_radius
sleep 0.3

# --- 3. scénarios ------------------------------------------------------------
if "$EAPOL" -c "$WORK/eapol-endpoint-ok.conf" -a 127.0.0.1 -p "$PORT" \
		-s testing123 > "$WORK/eapol-ok.log" 2>&1 && \
	grep -q "SUCCESS" "$WORK/eapol-ok.log"; then
	ok "CRITÈRE: certificat de la PKI du handshake → Access-Accept (EAP-TLS)"
else
	fail "EAP-TLS endpoint-ok refusé — voir $WORK/eapol-ok.log"
fi

if "$EAPOL" -c "$WORK/eapol-rogue.conf" -a 127.0.0.1 -p "$PORT" \
		-s testing123 > "$WORK/eapol-rogue.log" 2>&1 && \
	grep -q "SUCCESS" "$WORK/eapol-rogue.log"; then
	fail "certificat de PKI étrangère ACCEPTÉ"
else
	grep -q "FAILURE" "$WORK/eapol-rogue.log" \
		|| fail "résultat inattendu pour rogue — voir $WORK/eapol-rogue.log"
	ok "CRITÈRE: certificat de PKI étrangère → Access-Reject (vers VLAN captif côté switch)"
fi

# --- 4. révocation : CRL régénérée, serveur rechargé, accès refusé ----------
sh "$SCRIPT_DIR/revoke_client.sh" endpoint-ok >/dev/null || fail "revoke endpoint-ok"
grep -q '"action":"revocation"' "$PKI/leaves.jsonl" \
	|| fail "pas de feuille revocation"
ok "révocation endpoint-ok + feuille registre"

cat "$PKI/ca/ca.crt" "$PKI/crl/ca.crl" > "$CONF/certs/ca.pem"
stop_radius
start_radius
sleep 0.3
if "$EAPOL" -c "$WORK/eapol-endpoint-ok.conf" -a 127.0.0.1 -p "$PORT" \
		-s testing123 > "$WORK/eapol-revoked.log" 2>&1 && \
	grep -q "SUCCESS" "$WORK/eapol-revoked.log"; then
	fail "certificat RÉVOQUÉ encore accepté (CRL non effective)"
else
	grep -q "FAILURE" "$WORK/eapol-revoked.log" \
		|| fail "résultat inattendu après révocation — voir $WORK/eapol-revoked.log"
	ok "CRITÈRE: certificat révoqué → Access-Reject (CRL effective)"
fi

# double enrôlement : refus explicite (jamais silencieux)
if sh "$SCRIPT_DIR/enroll_client.sh" endpoint-ok 2>"$WORK/err"; then
	fail "double enrôlement accepté"
fi
grep -q "déjà enrôlé" "$WORK/err" || fail "refus double enrôlement inattendu: $(cat "$WORK/err")"
ok "double enrôlement refusé (fail-closed, §1)"

stop_radius
echo
echo "TOUS LES TESTS T18 PASSENT"
