#!/usr/bin/env bash
# test_radius_failclosed.sh — T20 (issue #17) : coupure RADIUS.
#
# Doctrine (§5.3, §9.1, D14) :
#  - fail-closed PAR CONSTRUCTION au switch : sans EAP-SUCCESS aucun port ne
#    sort du captif — RADIUS down ⇒ aucun NOUVEL accès, pas de fail-open ;
#  - jamais silencieux : le watchdog canari (radius-watchdog.sh) détecte la
#    coupure (timeout) → alarme + feuille ;
#  - politique sessions établies (v1, documentée lab/tests/README.md) : une
#    session authentifiée AVANT la coupure persiste jusqu'à déconnexion
#    (eap_reauth_period=0) ;
#  - rétablissement : le watchdog revient à « ok » et les nouvelles auth
#    redeviennent possibles — le tout tracé.
#
# Env : TBP_LAB + binaires (voir lib_p1_netns.sh). Sortie : PASS/FAIL + exit.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TBP_LAB=${TBP_LAB:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}
. "$SCRIPT_DIR/lib_p1_netns.sh"

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }

p1_init sw rtr radius cella cellb epok eplate
p1_topo
p1_switch && ok "switch : bridge VLAN-aware (ports endpoints captifs)" || { bad "switch"; exit 1; }
p1_router && ok "routeur : mur + services (config/ du dépôt)" || { bad "routeur"; cat $W/router-setup.log; exit 1; }
p1_cells
p1_radius endpoint-ok endpoint-late swprobe \
	&& ok "PKI T18 : endpoint-ok + endpoint-late + canari swprobe enrôlés" \
	|| { bad "radius setup"; exit 1; }
p1_canary_conf
p1_hostapd swp1 swp2
grep -q "INITIALIZING\|ENABLED" $W/hostapd-swp1/log \
	&& ok "hostapd wired actif (swp1, swp2)" || { bad hostapd; exit 1; }
p1_switchd swp1 swp2
p1_watchdog

# --- session établie AVANT la coupure ----------------------------------------
run epok $IP link set eth0 up
run eplate $IP link set eth0 up
p1_wpa_conf endpoint-ok $W/pki/ca/ca.crt $W/pki/certs/endpoint-ok.crt \
	$W/pki/certs/endpoint-ok.key $W/wpa-ok.conf
nsenter -t ${NS[epok]} -n -- $WPA -B -Dwired -ieth0 -c $W/wpa-ok.conf \
	-f $W/wpa-ok.log -dd >/dev/null 2>&1
p1_wait 10 grep -q "EAP: Completed successfully\\|CTRL-EVENT-EAP-SUCCESS" $W/wpa-ok.log \
	&& ok "endpoint-ok : 802.1X/EAP-TLS réussi (session établie)" \
	|| { bad "auth endpoint-ok"; exit 1; }
for i in $(seq 1 20); do [ "$(p1_pvid swp1)" = "20" ] && break; sleep 0.5; done
[ "$(p1_pvid swp1)" = "20" ] \
	&& ok "swp1 basculé VLAN 20 (décision locale)" || { bad "PVID swp1"; exit 1; }
run epok $IP addr replace 10.20.20.11/24 dev eth0
run epok $IP route replace default via 10.20.20.1
run epok ping -c1 -W2 10.10.10.11 >/dev/null 2>&1 \
	&& ok "endpoint-ok joint le broker (voie légitime)" || bad "broker injoignable"

# watchdog sain avant la coupure
p1_wait 15 grep -q '"state":"ok"' $W/nac-watchdog.jsonl \
	&& ok "watchdog : état « ok » tracé (canari sain)" || bad "watchdog pas sain"

# ============================ COUPURE RADIUS ==================================
p1_radius_stop
ok "RADIUS arrêté (coupure simulée)"

# [1] jamais silencieux : alarme + feuille
p1_wait 30 grep -q '"state":"radius-down"' $W/nac-watchdog.jsonl \
	&& ok "coupure DÉTECTÉE : feuille watchdog « radius-down » (§5.3, jamais silencieux)" \
	|| bad "coupure non détectée par le watchdog"
grep -q "WATCHDOG etat=radius-down" $W/nac-decisions.log \
	&& ok "alarme consignée dans nac-decisions.log" \
	|| bad "pas d'alarme dans nac-decisions.log"
[ ! -f $W/remediation.mode ] \
	&& ok "coupure ≠ dégradation : pas de mode remédiation (distinction D14/D15)" \
	|| bad "remediation.mode posé à tort"

# [2] politique sessions établies (D14) : la session persiste
run epok ping -c1 -W2 10.10.10.11 >/dev/null 2>&1 \
	&& ok "session établie AVANT coupure : préservée (politique documentée D14)" \
	|| bad "session établie coupée — politique non respectée"

# [3] fail-closed : AUCUN nouvel accès (certificat valide inclus)
p1_wpa_conf endpoint-late $W/pki/ca/ca.crt $W/pki/certs/endpoint-late.crt \
	$W/pki/certs/endpoint-late.key $W/wpa-late.conf
nsenter -t ${NS[eplate]} -n -- $WPA -B -Dwired -ieth0 -c $W/wpa-late.conf \
	-f $W/wpa-late.log -dd >/dev/null 2>&1
sleep 8
grep -q "EAP: Completed successfully\\|CTRL-EVENT-EAP-SUCCESS" $W/wpa-late.log 2>/dev/null \
	&& bad "endpoint-late authentifié SANS RADIUS — FAIL-OPEN !" \
	|| ok "endpoint-late (certificat valide) : AUCUNE auth possible RADIUS down — fail-closed"
[ "$(p1_pvid swp2)" = "66" ] \
	&& ok "swp2 RESTE captif (66) — fail-closed au switch, pas au RADIUS" \
	|| bad "swp2 a quitté le captif sans RADIUS"
run eplate $IP addr add 10.66.66.12/24 dev eth0 2>/dev/null
run eplate $IP route add default via 10.66.66.1 2>/dev/null
run eplate ping -c1 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "endpoint-late a joint le broker" \
	|| ok "endpoint-late ne joint PAS le broker"

# ============================ RÉTABLISSEMENT ==================================
p1_radius_start && ok "RADIUS redémarré" || { bad "redémarrage RADIUS"; exit 1; }
NLINES=$(wc -l < $W/nac-watchdog.jsonl)
p1_wait 30 sh -c "tail -n +$((NLINES+1)) $W/nac-watchdog.jsonl | grep -q '\"state\":\"ok\"'" \
	&& ok "rétablissement DÉTECTÉ : feuille watchdog « ok » (transition tracée)" \
	|| bad "rétablissement non détecté"
# wpa_supplicant réessaie seul : l'auth redevient possible
p1_wait 30 grep -q "EAP: Completed successfully\\|CTRL-EVENT-EAP-SUCCESS" $W/wpa-late.log \
	&& ok "endpoint-late : auth réussie après rétablissement" \
	|| bad "pas d'auth après rétablissement"
for i in $(seq 1 20); do [ "$(p1_pvid swp2)" = "20" ] && break; sleep 0.5; done
[ "$(p1_pvid swp2)" = "20" ] && ok "swp2 basculé VLAN 20 après rétablissement" \
	|| bad "swp2 pas basculé après rétablissement"
run eplate $IP addr replace 10.20.20.12/24 dev eth0
run eplate $IP route replace default via 10.20.20.1
run eplate ping -c1 -W2 10.10.10.11 >/dev/null 2>&1 \
	&& ok "endpoint-late joint le broker après rétablissement" \
	|| bad "broker injoignable après rétablissement"

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "TEST RADIUS FAIL-CLOSED : VERT" || echo "TEST RADIUS FAIL-CLOSED : ROUGE"
exit $FAILL
