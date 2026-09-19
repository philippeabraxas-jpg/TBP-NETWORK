#!/usr/bin/env bash
# lib_p1_netns.sh — bibliothèque commune des tests T20 (issue #17) :
# montage de la topologie P1 en network namespaces (sans docker), avec les
# mêmes startup-configs/ que le lab containerlab. Sourcée par les tests
# lab/tests/test_*.sh — ne pas exécuter directement.
#
# Fournit : p1_init, p1_link, p1_topo, p1_switch, p1_router, p1_radius,
# p1_restart_radius, p1_break_crl / p1_restore_crl, p1_cells, p1_hostapd,
# p1_switchd, p1_watchdog, p1_mabd, p1_wpa_conf, p1_canary_conf,
# p1_foreign_pki, run, p1_pvid.
#
# Env attendu (défauts PATH) : TBP_LAB (racine du dépôt), TBP_WORK,
# IP_BIN BRIDGE_BIN NFT_BIN HOSTAPD_BIN WPA_BIN FR_BIN EAPOL_TEST_BIN
# RADCLIENT_BIN SOCAT_BIN NC_BIN RADDB_SRC FR_LIBDIR RADIUS_SECRET
# WATCHDOG_INTERVAL MAB_INTERVAL

: "${TBP_LAB:?definir TBP_LAB (racine du depot)}"
SC=$TBP_LAB/lab/containerlab/startup-configs
W=$(mktemp -d "${TBP_WORK:-/tmp/tbp-t20-netns.XXXXXX}")
export TBP_WORK=$W

IP=${IP_BIN:-ip}
BR=${BRIDGE_BIN:-bridge}
NFT=${NFT_BIN:-nft}
HOSTAPD=${HOSTAPD_BIN:-hostapd}
WPA=${WPA_BIN:-wpa_supplicant}
FR=${FR_BIN:-freeradius}
EAPOL=${EAPOL_TEST_BIN:-eapol_test}
RADCLIENT=${RADCLIENT_BIN:-radclient}
RADDB_SRC=${RADDB_SRC:-/etc/freeradius/3.0}
RADIUS_SECRET=${RADIUS_SECRET:-testing123}

declare -A NS

p1_init() { # p1_init <node...> — un netns persistant par nœud + trap cleanup
	for n in "$@"; do
		unshare -n -- sleep 900 & NS[$n]=$!
	done
	sleep 0.5
	trap p1_cleanup EXIT
	for n in "$@"; do run $n $IP link set lo up; done
}

run() { local n=$1; shift; nsenter -t ${NS[$n]} -n -- "$@"; }

p1_cleanup() {
	[ -f $W/pids ] && kill $(cat $W/pids) 2>/dev/null
	for n in "${!NS[@]}"; do kill ${NS[$n]} 2>/dev/null; done
	pkill -x hostapd 2>/dev/null; pkill -x wpa_supplicant 2>/dev/null
	pkill -x freeradius 2>/dev/null
	[ -n "${TBP_TEST_KEEP:-}" ] && echo "WORK conservé: $W" || rm -rf $W
}

p1_link() { # p1_link <n1> <if1> <n2> <if2> — veth avec noms temporaires (revue T19)
	$IP link add "$2.$$" type veth peer name "$4.$$" || return 1
	$IP link set "$2.$$" netns ${NS[$1]}
	$IP link set "$4.$$" netns ${NS[$3]}
	run $1 $IP link set "$2.$$" name "$2"
	run $3 $IP link set "$4.$$" name "$4"
}

p1_topo() { # câblage standard : epok-swp1 eplate-swp2 [epiot-swp7 epunk-swp8]
	[ -n "${NS[epok]:-}" ] && p1_link epok   eth0 sw swp1
	[ -n "${NS[eplate]:-}" ] && p1_link eplate eth0 sw swp2
	[ -n "${NS[epiot]:-}" ] && p1_link epiot eth0 sw swp7
	[ -n "${NS[epunk]:-}" ] && p1_link epunk eth0 sw swp8
	p1_link rtr    eth0 sw swp3
	p1_link radius eth0 sw swp4
	p1_link cella  eth0 sw swp5
	p1_link cellb  eth0 sw swp6
}

p1_switch() { # bridge VLAN-aware (CAPTIVE_PORTS paramétrable)
	run sw env IP_BIN=$IP BRIDGE_BIN=$BR CAPTIVE_PORTS="${CAPTIVE_PORTS:-swp1 swp2}" \
		sh $SC/switch/bridge-setup.sh
}

p1_router() { # subifs VLANs (10/20/33/66/77/99) + mur + services hébergés
	run rtr $IP link set eth0 up
	for v in 10 20 33 66 77 99; do
		run rtr $IP link add link eth0 name eth0.$v type vlan id $v
		run rtr $IP link set eth0.$v up
	done
	run rtr $IP addr add 10.10.10.1/24 dev eth0.10
	run rtr $IP addr add 10.20.20.1/24 dev eth0.20
	run rtr $IP addr add 10.33.33.1/24 dev eth0.33
	run rtr $IP addr add 10.66.66.1/24 dev eth0.66
	run rtr $IP addr add 10.77.77.1/24 dev eth0.77
	run rtr $IP addr add 10.99.99.1/24 dev eth0.99
	run rtr env NFT_BIN=$NFT IP_BIN=$IP sh $SC/router/router-setup.sh \
		> $W/router-setup.log 2>&1
}

p1_cells() { # cells + broker factice sur cell-a
	run cella  $IP link set eth0 up; run cella $IP addr add 10.10.10.11/24 dev eth0
	run cella  $IP route add default via 10.10.10.1
	run cellb  $IP link set eth0 up; run cellb $IP addr add 10.10.10.12/24 dev eth0
	run cellb  $IP route add default via 10.10.10.1
	nsenter -t ${NS[cella]} -n -- socat TCP4-LISTEN:9000,bind=10.10.10.11,reuseaddr,fork \
		SYSTEM:"echo TBP-BROKER-CELL-A" >/dev/null 2>&1 &
	echo $! >> $W/pids
}

p1_radius() { # p1_radius <host_a_enroler...> — PKI T18 + raddb + freeradius
	export TBP_PKI_HOME=$W/pki TBP_NAC_HOME=$W/nac TBP_CELL=cell-alpha-01
	sh $TBP_LAB/config/freeradius/scripts/ca_dev.sh >/dev/null || return 1
	for h in "$@"; do
		sh $TBP_LAB/config/freeradius/scripts/enroll_client.sh "$h" >/dev/null || return 1
	done
	RADDB_SRC=$RADDB_SRC FR_LIBDIR=${FR_LIBDIR:-} TBP_MAB_FILE=${TBP_MAB_FILE:-} \
		sh $SC/radius/raddb-setup.sh >/dev/null || return 1
	run radius $IP link set eth0 up
	run radius $IP addr add 10.99.99.3/24 dev eth0
	run radius $IP route add default via 10.99.99.1
	p1_radius_start
}

p1_radius_start() {
	# readiness sur une ligne NOUVELLE (le log survit d'un run à l'autre)
	local n=0
	[ -f $W/log/radius.log ] && n=$(wc -l < $W/log/radius.log)
	nsenter -t ${NS[radius]} -n -- $FR -f -d $W/raddb -l $W/log/radius.log \
		>/dev/null 2>&1 &
	echo $! >> $W/pids
	for i in $(seq 1 50); do
		tail -n +$((n+1)) $W/log/radius.log 2>/dev/null \
			| grep -q "Ready to process requests" && return 0
		sleep 0.2
	done
	return 1
}

p1_radius_stop() {
	pkill -x freeradius 2>/dev/null
	sleep 0.5
}

p1_break_crl() { # simule CRL/OCSP injoignable : ca.pem SANS la CRL
	install -m 0444 $W/pki/ca/ca.crt $W/raddb/certs/ca.pem
}

p1_restore_crl() { # ca.pem = CA + CRL (état nominal)
	cat $W/pki/ca/ca.crt $W/pki/crl/ca.crl > $W/raddb/certs/ca.pem
}

p1_canary_conf() { # sonde du watchdog : certificat swprobe (enrôlé)
	cat > $W/canary.conf <<EOF
network={
	key_mgmt=IEEE8021X
	eap=TLS
	identity="swprobe"
	ca_cert="$W/pki/ca/ca.crt"
	client_cert="$W/pki/certs/swprobe.crt"
	private_key="$W/pki/certs/swprobe.key"
	eapol_flags=0
}
EOF
}

p1_hostapd() { # p1_hostapd <port...>
	for p in "$@"; do
		mkdir -p $W/hostapd-$p/ctrl
		sed -e "s|@PORT@|$p|g" -e "s|@WORK@|$W|g" \
			-e "s|@RADIUS_IP@|10.99.99.3|g" -e "s|@RADIUS_SECRET@|$RADIUS_SECRET|g" \
			$SC/switch/hostapd-port.conf.tmpl > $W/hostapd-$p/hostapd.conf
		nsenter -t ${NS[sw]} -n -- $HOSTAPD -t $W/hostapd-$p/hostapd.conf \
			> $W/hostapd-$p/log 2>&1 &
		echo $! >> $W/pids
	done
	sleep 1
}

p1_switchd() { # p1_switchd <port...>
	for p in "$@"; do
		nsenter -t ${NS[sw]} -n -- env TBP_WORK=$W BRIDGE_BIN=$BR \
			sh $SC/switch/switchd.sh $p 20 >/dev/null 2>&1 &
		echo $! >> $W/pids
	done
}

p1_watchdog() {
	nsenter -t ${NS[sw]} -n -- env TBP_WORK=$W RADIUS_SECRET=$RADIUS_SECRET \
		WATCHDOG_INTERVAL=${WATCHDOG_INTERVAL:-3} EAPOL_TEST_BIN=$EAPOL \
		sh $SC/switch/radius-watchdog.sh >/dev/null 2>&1 &
	echo $! >> $W/pids
}

p1_mabd() { # p1_mabd <port...>
	nsenter -t ${NS[sw]} -n -- env TBP_WORK=$W BRIDGE_BIN=$BR RADCLIENT_BIN=$RADCLIENT \
		RADIUS_SECRET=$RADIUS_SECRET MAB_INTERVAL=${MAB_INTERVAL:-2} \
		sh $SC/switch/mabd.sh "$@" >/dev/null 2>&1 &
	echo $! >> $W/pids
}

p1_wpa_conf() { # p1_wpa_conf <identity> <ca> <cert> <key> <outfile>
	sed -e "s|@IDENTITY@|$1|" -e "s|@CA@|$2|" -e "s|@CERT@|$3|" -e "s|@KEY@|$4|" \
		$SC/endpoint/wpa_supplicant.conf.tmpl > "$5"
}

p1_foreign_pki() { # PKI étrangère (attaque)
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
}

p1_pvid() { # p1_pvid <port> → vid PVID courant (vide si absent)
	run sw $BR vlan show dev $1 2>/dev/null | grep PVID | awk '{print $2}'
}

p1_wait() { # p1_wait <secondes_max> <cmd...> — 0 si cmd réussit à temps
	local max=$1; shift
	for i in $(seq 1 $((max*2))); do
		"$@" >/dev/null 2>&1 && return 0
		sleep 0.5
	done
	return 1
}
