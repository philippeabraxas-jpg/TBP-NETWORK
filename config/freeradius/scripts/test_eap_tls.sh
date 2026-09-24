#!/bin/sh
# test_eap_tls.sh — validation RÉELLE du critère d'acceptation T18 (#18) et
# de la révocation sans redémarrage (issue #130) :
# FreeRADIUS + eapol_test (802.1X/EAP-TLS sans switch, le lab T19 viendra).
#
#   1. certificat de la PKI du handshake (§3) → Access-Accept ;
#   2. certificat d'une PKI ÉTRANGÈRE → Access-Reject (vers VLAN captif,
#      côté switch — ici on prouve le Reject) ;
#   3. certificat RÉVOQUÉ → Access-Reject, vérifié EN DIRECT par OCSP
#      (ocsp_responder.sh) SANS jamais redémarrer FreeRADIUS (issue #130 :
#      avant ce correctif, seule une CRL relue au redémarrage rendait la
#      révocation effective — ce test prouve maintenant qu'aucun
#      redémarrage de FreeRADIUS n'a lieu entre l'admission et le refus) ;
#   4. enrôlement et révocation ont chacun leur feuille (§4.1, hash-only §6.2).
#
# La configuration FreeRADIUS exercée ici est produite par render_config.sh
# (config/freeradius/scripts/) — le MÊME script que celui destiné à un
# déploiement réel (T19/T20) : tester ce fichier, c'est tester la
# configuration livrée, pas une logique parallèle inventée pour le test.
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
trap 'kill $(cat "$WORK/freeradius.pid" 2>/dev/null) 2>/dev/null || true; sh "$SCRIPT_DIR/ocsp_responder.sh" stop "$WORK/pki" 2>/dev/null || true; [ -n "${TBP_TEST_KEEP:-}" ] && { echo "WORK conservé: $WORK"; exit 0; }; rm -rf "$WORK"' EXIT
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

# --- 2. Configuration FreeRADIUS RÉELLE (render_config.sh — le MÊME
#        chemin de code qu'un déploiement T19/T20, pas une logique de
#        test séparée), plus le répondeur OCSP live (issue #130) ---------
OCSP_PORT=${TBP_OCSP_PORT:-18999}
CONF="$WORK/raddb"
sh "$SCRIPT_DIR/render_config.sh" "$RADDB_SRC" "$CONF" "$PKI" "http://127.0.0.1:$OCSP_PORT/" >/dev/null \
	|| fail "render_config.sh"
mkdir -p "$WORK/log" "$WORK/var/run/freeradius"

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

sh "$SCRIPT_DIR/ocsp_responder.sh" start "$PKI" "$OCSP_PORT" >/dev/null || fail "ocsp_responder.sh start"

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

# --- 4. révocation SANS redémarrage de FreeRADIUS (issue #130) --------------
# revoke_client.sh régénère la CRL sur disque (défense en profondeur, relue
# au prochain redémarrage naturel) ET recharge le répondeur OCSP en direct
# (ocsp_responder.sh restart — un processus léger, sans rapport avec
# FreeRADIUS). FreeRADIUS n'est JAMAIS arrêté ni relancé dans ce scénario :
# c'est précisément le comportement que #130 réclamait.
FR_PID_BEFORE_REVOKE=$(cat "$WORK/freeradius.pid")
sh "$SCRIPT_DIR/revoke_client.sh" endpoint-ok >/dev/null || fail "revoke endpoint-ok"
grep -q '"action":"revocation"' "$PKI/leaves.jsonl" \
	|| fail "pas de feuille revocation"
ok "révocation endpoint-ok + feuille registre"

kill -0 "$FR_PID_BEFORE_REVOKE" 2>/dev/null \
	|| fail "FreeRADIUS ne tourne plus après la révocation — ce scénario doit prouver qu'aucun redémarrage n'est nécessaire"
if "$EAPOL" -c "$WORK/eapol-endpoint-ok.conf" -a 127.0.0.1 -p "$PORT" \
		-s testing123 > "$WORK/eapol-revoked.log" 2>&1 && \
	grep -q "SUCCESS" "$WORK/eapol-revoked.log"; then
	fail "certificat RÉVOQUÉ encore accepté (OCSP non effectif)"
else
	grep -q "FAILURE" "$WORK/eapol-revoked.log" \
		|| fail "résultat inattendu après révocation — voir $WORK/eapol-revoked.log"
	ok "CRITÈRE (issue #130): certificat révoqué → Access-Reject via OCSP live, SANS redémarrer FreeRADIUS (pid $FR_PID_BEFORE_REVOKE inchangé)"
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
