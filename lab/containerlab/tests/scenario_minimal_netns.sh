#!/usr/bin/env bash
# scenario_minimal_netns.sh — réplique network-namespaces du scénario
# minimal P1 (issue #21), exécutable SANS docker ni matériel :
# mêmes topologie, configs (startup-configs/) et binaires que le lab
# containerlab. C'est la preuve sandbox de T19 ; `run_scenario_minimal.sh`
# rejoue le même scénario via `containerlab deploy`.
#
# Topologie (aucun lien direct endpoint -> cell, §5.1) :
#   endpoint-ok/ko -- swp1/swp2 [switch: bridge VLAN + hostapd wired] --
#   swp3 (trunk 10,20,66,99) -- routeur (nft = config/nftables/router-p1.nft)
#   switch: swp4 -> radius (VLAN 99), swp5/swp6 -> cell-a/cell-b (VLAN 10)
#
# Prérequis : binaires ip, bridge, nft, hostapd, wpa_supplicant, socat, nc,
# openssl, freeradius + arbre raddb stock, scripts T18 du dépôt. Tout peut
# provenir de paquets Debian épinglés extraits via dpkg -x (voir README).
#
# Env : TBP_LAB (racine du dépôt — défaut : ../../.. relatif au script)
#   IP_BIN BRIDGE_BIN NFT_BIN HOSTAPD_BIN WPA_BIN SOCAT_BIN NC_BIN FR_BIN
#   RADDB_SRC FR_LIBDIR TBP_WORK (défaut /tmp/tbp-p1-netns.XXXX)
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LAB=${TBP_LAB:-$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)}
SC=$LAB/lab/containerlab/startup-configs
W=$(mktemp -d "${TBP_WORK:-/tmp/tbp-p1-netns.XXXXXX}")
export TBP_LAB=$LAB TBP_WORK=$W

IP=${IP_BIN:-ip}
BR=${BRIDGE_BIN:-bridge}
NFT=${NFT_BIN:-nft}
HOSTAPD=${HOSTAPD_BIN:-hostapd}
WPA=${WPA_BIN:-wpa_supplicant}
NC=${NC_BIN:-nc}
FR=${FR_BIN:-freeradius}
RADDB_SRC=${RADDB_SRC:-/etc/freeradius/3.0}

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }

# --- nœuds : un netns persistant chacun --------------------------------------
declare -A NS
for n in sw rtr radius cella cellb epok epko; do
	unshare -n -- sleep 900 & NS[$n]=$!
done
sleep 0.5
run() { local n=$1; shift; nsenter -t ${NS[$n]} -n -- "$@"; }
cleanup() {
	[ -f $W/pids ] && kill $(cat $W/pids) 2>/dev/null
	for n in "${!NS[@]}"; do kill ${NS[$n]} 2>/dev/null; done
	pkill -x hostapd 2>/dev/null; pkill -x wpa_supplicant 2>/dev/null
	[ -n "${TBP_TEST_KEEP:-}" ] && echo "WORK conservé: $W" || rm -rf $W
}
trap cleanup EXIT
for n in sw rtr radius cella cellb epok epko; do run $n $IP link set lo up; done

# --- liens veth (endpoints -> switch, trunk routeur, mgmt radius, cells) -----
link() {
	$IP link add "$2" type veth peer name "$4.$$" || return 1
	$IP link set "$2" netns ${NS[$1]}
	$IP link set "$4.$$" netns ${NS[$3]}
	run $3 $IP link set "$4.$$" name "$4"
}
link epok   eth0 sw swp1
link epko   eth0 sw swp2
link rtr    eth0 sw swp3   # trunk VLANs 10/20/66/99
link radius eth0 sw swp4   # access VLAN 99 (mgmt)
link cella  eth0 sw swp5   # access VLAN 10 (serveur)
link cellb  eth0 sw swp6   # access VLAN 10 (serveur)

# --- switch : la vraie config du dépôt -----------------------------------------
run sw env IP_BIN=$IP BRIDGE_BIN=$BR sh $SC/switch/bridge-setup.sh \
	&& ok "switch : bridge VLAN-aware monté (startup-configs/switch/bridge-setup.sh)"

# --- routeur : VLANs, IPs, puis la vraie config du dépôt ------------------------
run rtr $IP link set eth0 up
for v in 10 20 66 99; do
	run rtr $IP link add link eth0 name eth0.$v type vlan id $v
	run rtr $IP link set eth0.$v up
done
run rtr $IP addr add 10.10.10.1/24 dev eth0.10
run rtr $IP addr add 10.20.20.1/24 dev eth0.20
run rtr $IP addr add 10.66.66.1/24 dev eth0.66
run rtr $IP addr add 10.99.99.1/24 dev eth0.99
if run rtr env NFT_BIN=$NFT IP_BIN=$IP sh $SC/router/router-setup.sh > $W/router-setup.log 2>&1; then
	ok "routeur : charge config/sysctl + config/nftables/router-p1.nft (le mur)"
	grep -q "partiellement" $W/router-setup.log \
		&& echo "note: sysctl partiellement appliqué (environnement restreint) — voir router-setup.log"
else
	bad "router-setup.sh"; cat $W/router-setup.log; exit 1
fi

# --- cells / radius / endpoints ------------------------------------------------
run cella  $IP link set eth0 up; run cella $IP addr add 10.10.10.11/24 dev eth0
run cella  $IP route add default via 10.10.10.1
run cellb  $IP link set eth0 up; run cellb $IP addr add 10.10.10.12/24 dev eth0
run cellb  $IP route add default via 10.10.10.1
run radius $IP link set eth0 up; run radius $IP addr add 10.99.99.3/24 dev eth0
run radius $IP route add default via 10.99.99.1
run epok   $IP link set eth0 up; run epok $IP addr add 10.66.66.11/24 dev eth0
run epok   $IP route add default via 10.66.66.1
run epko   $IP link set eth0 up; run epko $IP addr add 10.66.66.12/24 dev eth0
run epko   $IP route add default via 10.66.66.1

# broker cell-a (le « serveur » à atteindre)
nsenter -t ${NS[cella]} -n -- socat TCP4-LISTEN:9000,bind=10.10.10.11,reuseaddr,fork \
	SYSTEM:"echo TBP-BROKER-CELL-A" >/dev/null 2>&1 &
echo $! >> $W/pids

# --- PKI du handshake (T18) + RADIUS -------------------------------------------
export TBP_PKI_HOME=$W/pki TBP_NAC_HOME=$W/nac TBP_CELL=cell-alpha-01
sh $LAB/config/freeradius/scripts/ca_dev.sh >/dev/null || { bad ca_dev; exit 1; }
sh $LAB/config/freeradius/scripts/enroll_client.sh endpoint-ok >/dev/null \
	|| { bad enroll; exit 1; }
ok "PKI du handshake (T18) : CA + endpoint-ok enrôlé, feuille enrollment"

# PKI étrangère pour endpoint-ko (certificat valide mais hors PKI)
mkdir -p $W/foreign
openssl genpkey -algorithm Ed25519 -out $W/foreign/ca.key 2>/dev/null
openssl req -x509 -new -key $W/foreign/ca.key -days 30 -subj "/CN=foreign CA" \
	-out $W/foreign/ca.crt 2>/dev/null
openssl genpkey -algorithm Ed25519 -out $W/foreign/rogue.key 2>/dev/null
openssl req -new -key $W/foreign/rogue.key -subj "/CN=endpoint-ko" \
	-out $W/foreign/rogue.csr 2>/dev/null
openssl x509 -req -in $W/foreign/rogue.csr -CA $W/foreign/ca.crt \
	-CAkey $W/foreign/ca.key -CAcreateserial -days 30 \
	-out $W/foreign/rogue.crt 2>/dev/null

# config RADIUS via startup-configs/radius/raddb-setup.sh
RADDB_SRC=$RADDB_SRC FR_LIBDIR=${FR_LIBDIR:-} \
	sh $SC/radius/raddb-setup.sh >/dev/null || { bad raddb-setup; exit 1; }
nsenter -t ${NS[radius]} -n -- $FR -f -d $W/raddb -l $W/log/radius.log \
	>/dev/null 2>&1 &
echo $! >> $W/pids
for i in $(seq 1 50); do
	grep -q "Ready to process requests" $W/log/radius.log 2>/dev/null && break
	sleep 0.2
done
grep -q "Ready to process requests" $W/log/radius.log \
	|| { bad "freeradius ne démarre pas"; tail -5 $W/log/radius.log; exit 1; }
ok "FreeRADIUS écoute (PKI du handshake, EAP-TLS seul, check_crl=yes)"

# --- hostapd wired (authenticator) sur les ports endpoints ----------------------
for p in swp1 swp2; do
	mkdir -p $W/hostapd-$p/ctrl
	sed -e "s|@PORT@|$p|g" -e "s|@WORK@|$W|g" \
		-e "s|@RADIUS_IP@|10.99.99.3|g" -e "s|@RADIUS_SECRET@|testing123|g" \
		$SC/switch/hostapd-port.conf.tmpl > $W/hostapd-$p/hostapd.conf
	nsenter -t ${NS[sw]} -n -- $HOSTAPD -t $W/hostapd-$p/hostapd.conf \
		> $W/hostapd-$p/log 2>&1 &
	echo $! >> $W/pids
done
sleep 1
grep -q "INITIALIZING\|ENABLED" $W/hostapd-swp1/log \
	&& ok "hostapd wired actif (swp1, swp2) — authenticator 802.1X" \
	|| { bad "hostapd"; tail -5 $W/hostapd-swp1/log; exit 1; }

# --- hook d'aiguillage LOCAL (pas de VLAN RADIUS, §5.3) --------------------------
for p in swp1 swp2; do
	nsenter -t ${NS[sw]} -n -- env TBP_WORK=$W BRIDGE_BIN=$BR \
		sh $SC/switch/switchd.sh $p 20 >/dev/null 2>&1 &
	echo $! >> $W/pids
done

# --- supplicants (template du dépôt) ---------------------------------------------
sed -e "s|@IDENTITY@|endpoint-ok|" -e "s|@CA@|$W/pki/ca/ca.crt|" \
	-e "s|@CERT@|$W/pki/certs/endpoint-ok.crt|" \
	-e "s|@KEY@|$W/pki/certs/endpoint-ok.key|" \
	$SC/endpoint/wpa_supplicant.conf.tmpl > $W/wpa-ok.conf
sed -e "s|@IDENTITY@|endpoint-ko|" -e "s|@CA@|$W/foreign/ca.crt|" \
	-e "s|@CERT@|$W/foreign/rogue.crt|" -e "s|@KEY@|$W/foreign/rogue.key|" \
	$SC/endpoint/wpa_supplicant.conf.tmpl > $W/wpa-ko.conf

# ============================ SCÉNARIO ============================================

# [1] AVANT auth : endpoint-ok est en captif — le mur doit bloquer vers le serveur
if run epok ping -c1 -W1 10.10.10.11 >/dev/null 2>&1; then
	bad "pré-auth: endpoint-ok a joint le broker depuis le captif"
else
	ok "pré-auth : endpoint-ok (captif) bloqué vers le broker — mur fermé par défaut (§1)"
fi

# [2] endpoint-ok s'authentifie en 802.1X/EAP-TLS
nsenter -t ${NS[epok]} -n -- $WPA -B -Dwired -ieth0 -c $W/wpa-ok.conf \
	-f $W/wpa-ok.log -dd >/dev/null 2>&1
for i in $(seq 1 50); do
	grep -q "EAP: Completed successfully\|CTRL-EVENT-EAP-SUCCESS" $W/wpa-ok.log 2>/dev/null && break
	sleep 0.2
done
if grep -q "EAP: Completed successfully\|CTRL-EVENT-EAP-SUCCESS" $W/wpa-ok.log; then
	ok "endpoint-ok : 802.1X/EAP-TLS réussi (certificat PKI du handshake)"
else
	bad "endpoint-ok : échec EAP"; tail -20 $W/wpa-ok.log
fi
for i in $(seq 1 50); do
	run sw $BR vlan show dev swp1 | grep -q "20.*PVID" && break
	sleep 0.2
done
run sw $BR vlan show dev swp1 | grep -q "20.*PVID" \
	&& ok "switch : port swp1 basculé VLAN 20 par décision LOCALE (§5.3, pas de VLAN RADIUS)" \
	|| { bad "PVID swp1 non basculé"; run sw $BR vlan show dev swp1; }

# adressage post-auth (simule le DHCP du VLAN 20)
run epok $IP addr replace 10.20.20.11/24 dev eth0
run epok $IP route replace default via 10.20.20.1

# [3] endpoint-ok atteint le broker — la voie légitime, via le routeur
if run epok ping -c1 -W2 10.10.10.11 >/dev/null 2>&1; then
	ok "endpoint-ok (authentifié) → broker cell-a : PING OK via routeur"
else
	bad "endpoint-ok ne joint pas le broker"
fi
BANNER=$(run epok $NC -w2 10.10.10.11 9000 2>/dev/null)
[ "$BANNER" = "TBP-BROKER-CELL-A" ] \
	&& ok "endpoint-ok → broker cell-a : TCP 9000 OK (« $BANNER »)" \
	|| bad "broker injoignable en TCP ($BANNER)"

# [4] endpoint-ko : certificat étranger → rejeté → captif
nsenter -t ${NS[epko]} -n -- $WPA -B -Dwired -ieth0 -c $W/wpa-ko.conf \
	-f $W/wpa-ko.log -dd >/dev/null 2>&1
sleep 3
if grep -q "EAP: Completed successfully" $W/wpa-ko.log 2>/dev/null; then
	bad "endpoint-ko (PKI étrangère) AUTHENTIFIÉ — fail-open !"
else
	ok "endpoint-ko (PKI étrangère) rejeté par le 802.1X"
fi
run sw $BR vlan show dev swp2 | grep -q "66.*PVID" \
	&& ok "switch : port swp2 RESTE en VLAN 66 (captif)" \
	|| bad "swp2 a quitté le captif"

# [5] endpoint-ko ne peut PAS joindre le serveur — ni en routé, ni en direct
if run epko ping -c1 -W1 10.10.10.11 >/dev/null 2>&1; then
	bad "endpoint-ko a joint le broker (routé)"
else
	ok "endpoint-ko ne joint PAS le broker en routé (mur routeur)"
fi
# contournement L2 : trames forgées taguées VLAN 10 depuis le port captif (§5.2)
run epko $IP link add link eth0 name eth0.10 type vlan id 10
run epko $IP link set eth0.10 up
run epko $IP addr add 10.10.10.66/24 dev eth0.10
if run epko ping -c1 -W1 10.10.10.11 >/dev/null 2>&1; then
	bad "endpoint-ko a rejoint le VLAN serveur en forgeant des tags 802.1Q"
else
	ok "endpoint-ko : trames taguées VLAN 10 forgées BLOQUÉES par le bridge (§5.2)"
fi
run epko $IP link del eth0.10

# [6] captif : seule route = enrôlement
ENROLL=$(run epko $NC -w2 10.66.66.1 8080 2>/dev/null | head -1)
case "$ENROLL" in
	TBP-ENROLL*) ok "endpoint-ko : VLAN captif → seule voie = enrôlement (« $ENROLL »)" ;;
	*) bad "service d'enrôlement injoignable depuis le captif" ;;
esac

# [7] observabilité : compteurs du mur + décisions NAC + feuilles (§4.1, §5.3)
sleep 1
CFWD=$(run rtr $NFT list counter inet tbp_p1 mur_captif_serveur 2>/dev/null | grep -oE "packets [0-9]+" | grep -oE "[0-9]+")
CLEG=$(run rtr $NFT list counter inet tbp_p1 voie_auth_serveur 2>/dev/null | grep -oE "packets [0-9]+" | grep -oE "[0-9]+")
[ "${CFWD:-0}" -gt 0 ] \
	&& ok "compteur mur_captif_serveur = $CFWD (tentatives bloquées visibles, §5.3)" \
	|| bad "compteur mur à zéro"
[ "${CLEG:-0}" -gt 0 ] \
	&& ok "compteur voie_auth_serveur = $CLEG (voie légitime visible)" \
	|| bad "compteur voie légitime à zéro"
grep -q '"action":"enrollment"' $W/pki/leaves.jsonl \
	&& ok "feuille enrollment (§4.1, hash-only §6.2) dans leaves.jsonl" \
	|| bad "pas de feuille enrollment"
grep -q "result=success" $W/nac-decisions.log && grep -q "result=failure" $W/nac-decisions.log \
	&& ok "chaque décision NAC tracée (succès swp1, échec swp2)" \
	|| bad "décisions NAC incomplètes"
grep -q "Login OK" $W/log/radius.log && grep -q "Login incorrect" $W/log/radius.log \
	&& ok "journal RADIUS : décisions d'authentification consignées (Login OK / Login incorrect)" \
	|| { bad "journal RADIUS incomplet"; grep -E "Auth:" $W/log/radius.log | tail -4; }

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "SCÉNARIO MINIMAL P1 : VERT" || echo "SCÉNARIO MINIMAL P1 : ROUGE"
exit $FAILL
