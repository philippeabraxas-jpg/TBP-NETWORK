#!/usr/bin/env bash
# test_ocsp_remediation.sh — T20 (issue #17) : OCSP/CRL injoignable.
#
# Doctrine (§5.3, §9.1, D15) : quand la couche de vérification est DÉGRADÉE
# (CRL/OCSP injoignable), un endpoint même porteur d'un certificat VALIDE ne
# peut être vérifié — il part en VLAN de REMÉDIATION (77) AVEC FEEDBACK
# explicite, jamais de rejet aveugle, jamais d'accès production.
#
# Mécanisme (Exp C du plan T20) : le watchdog canari distingue
# « RADIUS down » (timeout) de « vérification dégradée » (rejet explicite du
# canari sain). En mode dégradé, switchd envoie les EAP-FAILURE en VLAN 77.
# Simulation de la panne : ca.pem amputé de la CRL avec check_crl=yes
# (toute vérification échoue « unable to get certificate CRL »).
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TBP_LAB=${TBP_LAB:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}
. "$SCRIPT_DIR/lib_p1_netns.sh"

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }

export CAPTIVE_PORTS="swp1"
p1_init sw rtr radius cella cellb epok
p1_topo
p1_switch && ok "switch : bridge VLAN-aware" || { bad "switch"; exit 1; }
p1_router && ok "routeur : mur + services (remédiation incluse)" || { bad "routeur"; cat $W/router-setup.log; exit 1; }
p1_cells
p1_radius endpoint-ok swprobe \
	&& ok "PKI T18 : endpoint-ok + canari enrôlés, CRL saine" \
	|| { bad "radius setup"; exit 1; }
p1_canary_conf
p1_hostapd swp1
p1_switchd swp1
p1_watchdog
p1_wait 15 grep -q '"state":"ok"' $W/nac-watchdog.jsonl \
	&& ok "watchdog sain (CRL joignable, canari authentifié)" \
	|| { bad "watchdog pas sain au départ"; exit 1; }

# ====================== CRL/OCSP INJOIGNABLE ==================================
p1_break_crl
p1_radius_stop
p1_radius_start && ok "CRL injoignable simulée (ca.pem sans CRL, check_crl=yes)" \
	|| { bad "redémarrage RADIUS"; exit 1; }

# [1] le watchdog distingue dégradation et coupure
p1_wait 30 grep -q '"state":"verification-degraded"' $W/nac-watchdog.jsonl \
	&& ok "dégradation DÉTECTÉE : feuille « verification-degraded » (≠ radius-down)" \
	|| bad "dégradation non détectée"
[ -f $W/remediation.mode ] \
	&& ok "mode remédiation ARMÉ sur le switch (décision locale, §5.3)" \
	|| bad "remediation.mode absent"

# [2] endpoint à certificat VALIDE mais invérifiable → REMÉDIATION
run epok $IP link set eth0 up
p1_wpa_conf endpoint-ok $W/pki/ca/ca.crt $W/pki/certs/endpoint-ok.crt \
	$W/pki/certs/endpoint-ok.key $W/wpa-ok.conf
nsenter -t ${NS[epok]} -n -- $WPA -B -Dwired -ieth0 -c $W/wpa-ok.conf \
	-f $W/wpa-ok.log -dd >/dev/null 2>&1
p1_wait 15 grep -q "result=remediation" $W/nac-decisions.log \
	&& ok "échec d'auth en mode dégradé → décision « remediation » tracée (§4.1)" \
	|| bad "pas de décision remediation"
for i in $(seq 1 20); do [ "$(p1_pvid swp1)" = "77" ] && break; sleep 0.5; done
[ "$(p1_pvid swp1)" = "77" ] \
	&& ok "swp1 basculé VLAN 77 (remédiation) — pas de rejet aveugle en captif" \
	|| bad "swp1 pas en remédiation (PVID=$(p1_pvid swp1))"
grep -q "EAP: Completed successfully\\|CTRL-EVENT-EAP-SUCCESS" $W/wpa-ok.log 2>/dev/null \
	&& bad "certificat INVÉRIFIABLE authentifié — fail-open !" \
	|| ok "aucune auth sans vérification (§9.1 : échec vers le déni)"

# [3] remédiation : feedback OUI, production NON
run epok $IP addr replace 10.77.77.11/24 dev eth0
run epok $IP route replace default via 10.77.77.1
run epok ping -c1 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "la remédiation a joint le broker !" \
	|| ok "remédiation : AUCUN accès au broker (quarantaine réelle)"
BANNER=$(run epok nc -w2 10.77.77.1 8080 2>/dev/null | head -1)
case "$BANNER" in
	TBP-REMEDIATION*) ok "feedback explicite joignable (« $BANNER »)" ;;
	*) bad "pas de feedback de remédiation" ;;
esac
CFWD=$(run rtr $NFT list counter inet tbp_p1 mur_rem_serveur 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+")
[ "${CFWD:-0}" -gt 0 ] \
	&& ok "compteur mur_rem_serveur = $CFWD (tentatives bloquées visibles, §5.3)" \
	|| bad "compteur remédiation à zéro"

# ====================== RÉTABLISSEMENT CRL ====================================
p1_restore_crl
p1_radius_stop
p1_radius_start && ok "CRL rétablie" || { bad "redémarrage RADIUS"; exit 1; }
NLINES=$(wc -l < $W/nac-watchdog.jsonl)
p1_wait 30 sh -c "tail -n +$((NLINES+1)) $W/nac-watchdog.jsonl | grep -q '\"state\":\"ok\"'" \
	&& ok "rétablissement tracé : feuille « ok »" \
	|| bad "rétablissement non tracé"
[ ! -f $W/remediation.mode ] \
	&& ok "mode remédiation DÉSARMÉ au rétablissement" \
	|| bad "remediation.mode résiduel"

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "TEST OCSP/CRL REMÉDIATION : VERT" || echo "TEST OCSP/CRL REMÉDIATION : ROUGE"
exit $FAILL
