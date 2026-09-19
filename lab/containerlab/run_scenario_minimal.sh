#!/bin/sh
# run_scenario_minimal.sh — scénario minimal P1 via containerlab (issue #21) :
# le « mur et l'aiguillage » (§5.1) de bout en bout.
#
#   endpoint-ok : 802.1X/EAP-TLS (cert T18) → VLAN 20 → broker joignable ;
#   endpoint-ko : cert étranger → rejet → VLAN 66 captif → seule route =
#                 enrôlement ; aucun chemin vers le serveur, même en forgeant
#                 des tags 802.1Q (§5.2) ; chaque décision NAC tracée (§4.1).
#
# Prérequis : docker + containerlab. Les images se construisent depuis
# images/*.Dockerfile. Sans docker, la même preuve est rejouable par
# tests/scenario_minimal_netns.sh (network namespaces).
#
# Env : CLAB_BIN (défaut containerlab), SKIP_BUILD=1 pour sauter le build.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"
CLAB=${CLAB_BIN:-containerlab}
PREFIX=clab-tbp-p1

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }
run() { local n=$1; shift; docker exec $PREFIX-$n "$@"; }
rund() { local n=$1; shift; docker exec -d $PREFIX-$n "$@"; }

cleanup() {
	$CLAB destroy -t p1.clab.yml >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- images + déploiement ------------------------------------------------------
if [ "${SKIP_BUILD:-0}" != 1 ]; then
	for img in router switch radius endpoint cell; do
		docker build -q -t tbp-lab/$img:bookworm -f images/$img.Dockerfile . \
			>/dev/null || { echo "build $img KO" >&2; exit 2; }
	done
	ok "images tbp-lab/* construites"
fi
rm -rf .runtime; mkdir -p .runtime/radius .runtime/nac .runtime/foreign
$CLAB deploy -t p1.clab.yml >/dev/null || { echo "containerlab deploy KO" >&2; exit 2; }
ok "containerlab deploy — topologie P1 en place"
sleep 2

# --- routeur : interfaces + VRAIE config du dépôt --------------------------------
run router ip link set eth1 up
for v in 10 20 66 99; do
	run router ip link add link eth1 name eth1.$v type vlan id $v
	run router ip link set eth1.$v up
done
run router ip addr add 10.10.10.1/24 dev eth1.10
run router ip addr add 10.20.20.1/24 dev eth1.20
run router ip addr add 10.66.66.1/24 dev eth1.66
run router ip addr add 10.99.99.1/24 dev eth1.99
run router env TBP_LAB=/tbp TBP_WORK=/run/tbp-p1 \
	sh /tbp/lab/containerlab/startup-configs/router/router-setup.sh \
	&& ok "routeur : charge config/sysctl + config/nftables/router-p1.nft (le mur)" \
	|| { bad "router-setup.sh"; exit 1; }

# --- switch : bridge + authenticator + hook d'aiguillage --------------------------
run switch sh /tbp/lab/containerlab/startup-configs/switch/bridge-setup.sh \
	&& ok "switch : bridge VLAN-aware (ports endpoints en captif 66)"

# --- cells / endpoints : adressage -------------------------------------------------
run cell-a ip link set eth1 up
run cell-a ip addr add 10.10.10.11/24 dev eth1
run cell-a ip route add default via 10.10.10.1
run cell-b ip link set eth1 up
run cell-b ip addr add 10.10.10.12/24 dev eth1
run cell-b ip route add default via 10.10.10.1
rund cell-a socat TCP4-LISTEN:9000,bind=10.10.10.11,reuseaddr,fork \
	SYSTEM:"echo TBP-BROKER-CELL-A"
run endpoint-ok ip link set eth1 up
run endpoint-ok ip addr add 10.66.66.11/24 dev eth1
run endpoint-ok ip route add default via 10.66.66.1
run endpoint-ko ip link set eth1 up
run endpoint-ko ip addr add 10.66.66.12/24 dev eth1
run endpoint-ko ip route add default via 10.66.66.1

# --- PKI du handshake (T18) + RADIUS ------------------------------------------------
run radius ip link set eth1 up
run radius ip addr add 10.99.99.3/24 dev eth1
run radius ip route add default via 10.99.99.1
run radius env TBP_PKI_HOME=/run/tbp-p1/pki TBP_NAC_HOME=/run/nac \
	sh /tbp/config/freeradius/scripts/ca_dev.sh >/dev/null
run radius env TBP_PKI_HOME=/run/tbp-p1/pki TBP_NAC_HOME=/run/nac \
	sh /tbp/config/freeradius/scripts/enroll_client.sh endpoint-ok >/dev/null \
	&& ok "PKI du handshake (T18) : CA + endpoint-ok enrôlé, feuille enrollment"

# PKI étrangère (attaque endpoint-ko) — générée dans le volume partagé
run radius sh -c '
	set -e; cd /run/tbp-p1/foreign 2>/dev/null || { mkdir -p /run/tbp-p1/foreign; cd /run/tbp-p1/foreign; }
	openssl genpkey -algorithm Ed25519 -out ca.key 2>/dev/null
	openssl req -x509 -new -key ca.key -days 30 -subj "/CN=foreign CA" -out ca.crt 2>/dev/null
	openssl genpkey -algorithm Ed25519 -out rogue.key 2>/dev/null
	openssl req -new -key rogue.key -subj "/CN=endpoint-ko" -out rogue.csr 2>/dev/null
	openssl x509 -req -in rogue.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
		-days 30 -out rogue.crt 2>/dev/null'
# recopie vers le volume de endpoint-ko
docker cp $PREFIX-radius:/run/tbp-p1/foreign/. .runtime/foreign/

run radius env TBP_WORK=/run/tbp-p1 TBP_PKI_HOME=/run/tbp-p1/pki \
	sh /tbp/lab/containerlab/startup-configs/radius/raddb-setup.sh >/dev/null \
	|| { bad "raddb-setup.sh"; exit 1; }
rund radius freeradius -f -d /run/tbp-p1/raddb -l /run/tbp-p1/log/radius.log
for i in $(seq 1 50); do
	docker exec $PREFIX-radius grep -q "Ready to process requests" \
		/run/tbp-p1/log/radius.log 2>/dev/null && break
	sleep 0.2
done
docker exec $PREFIX-radius grep -q "Ready to process requests" \
	/run/tbp-p1/log/radius.log \
	&& ok "FreeRADIUS écoute (PKI du handshake, EAP-TLS seul, check_crl=yes)" \
	|| { bad "freeradius ne démarre pas"; exit 1; }

# hostapd wired sur les ports endpoints + hook d'aiguillage local (§5.3)
for p in swp1 swp2; do
	run switch sh -c "mkdir -p /run/tbp-p1/hostapd-$p/ctrl"
	run switch sh -c "sed -e 's|@PORT@|$p|g' -e 's|@WORK@|/run/tbp-p1|g' \
		-e 's|@RADIUS_IP@|10.99.99.3|g' -e 's|@RADIUS_SECRET@|testing123|g' \
		/tbp/lab/containerlab/startup-configs/switch/hostapd-port.conf.tmpl \
		> /run/tbp-p1/hostapd-$p/hostapd.conf"
	docker exec -d $PREFIX-switch sh -c \
		"hostapd -t /run/tbp-p1/hostapd-$p/hostapd.conf > /run/tbp-p1/hostapd-$p/log 2>&1"
	rund switch env TBP_WORK=/run/tbp-p1 \
		sh /tbp/lab/containerlab/startup-configs/switch/switchd.sh $p 20
done
sleep 1
docker exec $PREFIX-switch sh -c \
	"grep -q 'INITIALIZING\|ENABLED' /run/tbp-p1/hostapd-swp1/log" \
	&& ok "hostapd wired actif (swp1, swp2) — authenticator 802.1X" \
	|| bad "hostapd ne démarre pas"

# --- supplicants ---------------------------------------------------------------------
run endpoint-ok sh -c "sed -e 's|@IDENTITY@|endpoint-ok|' \
	-e 's|@CA@|/run/nac/endpoint-ok/ca.crt|' \
	-e 's|@CERT@|/run/nac/endpoint-ok/client.crt|' \
	-e 's|@KEY@|/run/nac/endpoint-ok/client.key|' \
	/tbp/lab/containerlab/startup-configs/endpoint/wpa_supplicant.conf.tmpl \
	> /run/wpa-ok.conf"
run endpoint-ko sh -c "sed -e 's|@IDENTITY@|endpoint-ko|' \
	-e 's|@CA@|/run/foreign/ca.crt|' -e 's|@CERT@|/run/foreign/rogue.crt|' \
	-e 's|@KEY@|/run/foreign/rogue.key|' \
	/tbp/lab/containerlab/startup-configs/endpoint/wpa_supplicant.conf.tmpl \
	> /run/wpa-ko.conf"

# ============================ SCÉNARIO ============================================

# [1] pré-auth : endpoint-ok (captif) bloqué vers le broker
if run endpoint-ok ping -c1 -W1 10.10.10.11 >/dev/null 2>&1; then
	bad "pré-auth: endpoint-ok a joint le broker depuis le captif"
else
	ok "pré-auth : endpoint-ok (captif) bloqué vers le broker — mur fermé par défaut (§1)"
fi

# [2] endpoint-ok : 802.1X/EAP-TLS
rund endpoint-ok wpa_supplicant -B -Dwired -ieth1 -c /run/wpa-ok.conf \
	-f /run/wpa-ok.log -dd
for i in $(seq 1 50); do
	docker exec $PREFIX-endpoint-ok sh -c \
		"grep -q 'EAP: Completed successfully\|CTRL-EVENT-EAP-SUCCESS' /run/wpa-ok.log" \
		2>/dev/null && break
	sleep 0.2
done
docker exec $PREFIX-endpoint-ok sh -c \
	"grep -q 'EAP: Completed successfully\|CTRL-EVENT-EAP-SUCCESS' /run/wpa-ok.log" \
	&& ok "endpoint-ok : 802.1X/EAP-TLS réussi (certificat PKI du handshake)" \
	|| bad "endpoint-ok : échec EAP"
for i in $(seq 1 50); do
	docker exec $PREFIX-switch sh -c "bridge vlan show dev swp1 | grep -q '20.*PVID'" \
		2>/dev/null && break
	sleep 0.2
done
docker exec $PREFIX-switch sh -c "bridge vlan show dev swp1 | grep -q '20.*PVID'" \
	&& ok "switch : port swp1 basculé VLAN 20 par décision LOCALE (§5.3)" \
	|| bad "PVID swp1 non basculé"
run endpoint-ok ip addr replace 10.20.20.11/24 dev eth1
run endpoint-ok ip route replace default via 10.20.20.1

# [3] voie légitime
run endpoint-ok ping -c1 -W2 10.10.10.11 >/dev/null 2>&1 \
	&& ok "endpoint-ok (authentifié) → broker cell-a : PING OK via routeur" \
	|| bad "endpoint-ok ne joint pas le broker"
BANNER=$(run endpoint-ok nc -w2 10.10.10.11 9000 2>/dev/null)
[ "$BANNER" = "TBP-BROKER-CELL-A" ] \
	&& ok "endpoint-ok → broker cell-a : TCP 9000 OK (« $BANNER »)" \
	|| bad "broker injoignable en TCP"

# [4] endpoint-ko : PKI étrangère → rejet → captif
rund endpoint-ko wpa_supplicant -B -Dwired -ieth1 -c /run/wpa-ko.conf \
	-f /run/wpa-ko.log -dd
sleep 3
docker exec $PREFIX-endpoint-ko sh -c \
	"grep -q 'EAP: Completed successfully' /run/wpa-ko.log" 2>/dev/null \
	&& bad "endpoint-ko (PKI étrangère) AUTHENTIFIÉ — fail-open !" \
	|| ok "endpoint-ko (PKI étrangère) rejeté par le 802.1X"
docker exec $PREFIX-switch sh -c "bridge vlan show dev swp2 | grep -q '66.*PVID'" \
	&& ok "switch : port swp2 RESTE en VLAN 66 (captif)" \
	|| bad "swp2 a quitté le captif"

# [5] aucun chemin vers le serveur — ni routé, ni en forgeant les tags
run endpoint-ko ping -c1 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "endpoint-ko a joint le broker (routé)" \
	|| ok "endpoint-ko ne joint PAS le broker en routé (mur routeur)"
run endpoint-ko ip link add link eth1 name eth1.10 type vlan id 10
run endpoint-ko ip link set eth1.10 up
run endpoint-ko ip addr add 10.10.10.66/24 dev eth1.10
run endpoint-ko ping -c1 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "endpoint-ko a rejoint le VLAN serveur en forgeant des tags 802.1Q" \
	|| ok "endpoint-ko : trames taguées VLAN 10 forgées BLOQUÉES par le bridge (§5.2)"
run endpoint-ko ip link del eth1.10

# [6] captif : seule route = enrôlement
ENROLL=$(run endpoint-ko nc -w2 10.66.66.1 8080 2>/dev/null | head -1)
case "$ENROLL" in
	TBP-ENROLL*) ok "endpoint-ko : VLAN captif → seule voie = enrôlement (« $ENROLL »)" ;;
	*) bad "service d'enrôlement injoignable depuis le captif" ;;
esac

# [7] observabilité (§4.1, §5.3)
sleep 1
CFWD=$(docker exec $PREFIX-router sh -c \
	"nft list counter inet tbp_p1 mur_captif_serveur 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+'")
CLEG=$(docker exec $PREFIX-router sh -c \
	"nft list counter inet tbp_p1 voie_auth_serveur 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+'")
[ "${CFWD:-0}" -gt 0 ] \
	&& ok "compteur mur_captif_serveur = $CFWD (tentatives bloquées visibles, §5.3)" \
	|| bad "compteur mur à zéro"
[ "${CLEG:-0}" -gt 0 ] \
	&& ok "compteur voie_auth_serveur = $CLEG (voie légitime visible)" \
	|| bad "compteur voie légitime à zéro"
docker exec $PREFIX-radius grep -q '"action":"enrollment"' \
	/run/tbp-p1/pki/leaves.jsonl \
	&& ok "feuille enrollment (§4.1, hash-only §6.2) dans leaves.jsonl" \
	|| bad "pas de feuille enrollment"
docker exec $PREFIX-switch sh -c \
	"grep -q result=success /run/tbp-p1/nac-decisions.log && grep -q result=failure /run/tbp-p1/nac-decisions.log" \
	&& ok "chaque décision NAC tracée (succès swp1, échec swp2)" \
	|| bad "décisions NAC incomplètes"
docker exec $PREFIX-radius sh -c \
	"grep -q 'Login OK' /run/tbp-p1/log/radius.log && grep -q 'Login incorrect' /run/tbp-p1/log/radius.log" \
	&& ok "journal RADIUS : décisions d'authentification consignées" \
	|| bad "journal RADIUS incomplet"

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "SCÉNARIO MINIMAL P1 : VERT" || echo "SCÉNARIO MINIMAL P1 : ROUGE"
exit $FAILL
