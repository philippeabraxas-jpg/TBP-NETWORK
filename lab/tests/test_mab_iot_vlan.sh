#!/usr/bin/env bash
# test_mab_iot_vlan.sh — T20 (issue #17) : MAB = canal instrumenté.
#
# Doctrine (§5.3, §9.1, D16) : un équipement SANS 802.1X (IoT) est pris en
# charge par MAB LOCAL au switch (mabd.sh) : sa MAC est authentifiée par
# MAC-auth RADIUS ; Accept → VLAN IoT dédié (33), instrumenté (télémétrie
# uniquement) ; Reject → le port RESTE captif + alarme. Jamais de MAB
# silencieux vers un VLAN de production.
#
# Priorité 802.1X : une MAC n'est candidate au MAB qu'après quiétude
# (MAB_QUIET_POLLS scrutations) sur un port TOUJOURS captif.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TBP_LAB=${TBP_LAB:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}
. "$SCRIPT_DIR/lib_p1_netns.sh"

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }

MAC_IOT="aa:bb:cc:dd:ee:01"     # autorisée dans le fichier MAB
MAC_UNK="aa:bb:cc:dd:ee:99"     # inconnue

export CAPTIVE_PORTS="swp7 swp8"
p1_init sw rtr radius cella cellb epiot epunk
p1_topo
p1_switch && ok "switch : bridge VLAN-aware (swp7/swp8 captifs)" || { bad "switch"; exit 1; }
p1_router && ok "routeur : mur + collecteur télémétrie IoT" || { bad "routeur"; cat $W/router-setup.log; exit 1; }
p1_cells

# fichier MAB : seule la MAC de l'IoT est autorisée
printf '%s Cleartext-Password := "%s"\n' "$MAC_IOT" "$MAC_IOT" > $W/mab-authorize
TBP_MAB_FILE=$W/mab-authorize p1_radius \
	&& ok "RADIUS prêt (fichier MAB : 1 MAC autorisée)" || { bad radius; exit 1; }
p1_hostapd swp7 swp8
p1_switchd swp7 swp8
p1_mabd swp7 swp8

# --- équipement IoT sans 802.1X, MAC autorisée --------------------------------
run epiot $IP link set eth0 address $MAC_IOT up
run epiot $IP addr add 10.66.66.21/24 dev eth0
run epiot $IP route add default via 10.66.66.1
run epunk $IP link set eth0 address $MAC_UNK up
run epunk $IP addr add 10.66.66.22/24 dev eth0
run epunk $IP route add default via 10.66.66.1

# trafic captif → la MAC est apprise par le bridge (aucun 802.1X)
run epiot ping -c2 -W1 10.66.66.1 >/dev/null 2>&1
for i in $(seq 1 30); do [ "$(p1_pvid swp7)" = "33" ] && break; sleep 0.5; done
[ "$(p1_pvid swp7)" = "33" ] \
	&& ok "MAC autorisée : swp7 basculé VLAN IoT 33 par MAB LOCAL (D16)" \
	|| bad "swp7 pas basculé IoT (PVID=$(p1_pvid swp7))"
grep -q '"agent":"mabd".*"result":"success"' $W/mab-decisions.jsonl \
	&& ok "feuille MAB success (MAC hachée, §6.2)" || bad "pas de feuille MAB success"

# --- VLAN IoT : télémétrie OUI, production NON ---------------------------------
run epiot $IP addr replace 10.33.33.21/24 dev eth0
run epiot $IP route replace default via 10.33.33.1
BANNER=$(run epiot nc -w2 10.33.33.1 8888 2>/dev/null | head -1)
case "$BANNER" in
	TBP-TELEMETRY*) ok "IoT → collecteur télémétrie joignable (« $BANNER »)" ;;
	*) bad "collecteur télémétrie injoignable" ;;
esac
CTEL=$(run rtr $NFT list counter inet tbp_p1 voie_iot_telemetry 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+")
[ "${CTEL:-0}" -gt 0 ] \
	&& ok "compteur voie_iot_telemetry = $CTEL — canal INSTRUMENTÉ (§5.3)" \
	|| bad "télémétrie non comptée"
run epiot ping -c1 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "l'IoT a joint le broker — MAB vers la production !" \
	|| ok "IoT : AUCUN chemin vers le VLAN serveur (jamais de production)"
CIOT=$(run rtr $NFT list counter inet tbp_p1 mur_iot_serveur 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+")
[ "${CIOT:-0}" -gt 0 ] \
	&& ok "compteur mur_iot_serveur = $CIOT (tentative IoT→serveur visible)" \
	|| bad "compteur IoT à zéro"

# --- MAC inconnue : captif + alarme, jamais silencieux --------------------------
run epunk ping -c2 -W1 10.66.66.1 >/dev/null 2>&1
p1_wait 20 grep -q '"result":"failure"' $W/mab-decisions.jsonl \
	&& ok "MAC inconnue : feuille MAB failure — ALARME (jamais silencieux)" \
	|| bad "pas de feuille failure pour MAC inconnue"
sleep 2
[ "$(p1_pvid swp8)" = "66" ] \
	&& ok "MAC inconnue : swp8 RESTE captif (66)" \
	|| bad "swp8 a quitté le captif pour une MAC inconnue"
run epunk ping -c1 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "MAC inconnue a joint le broker" \
	|| ok "MAC inconnue : aucun accès serveur"
BANNER=$(run epunk nc -w2 10.66.66.1 8080 2>/dev/null | head -1)
case "$BANNER" in
	TBP-ENROLL*) ok "MAC inconnue : seule voie = enrôlement (captif fonctionnel)" ;;
	*) bad "enrôlement injoignable depuis le captif" ;;
esac

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "TEST MAB VLAN IoT : VERT" || echo "TEST MAB VLAN IoT : ROUGE"
exit $FAILL
