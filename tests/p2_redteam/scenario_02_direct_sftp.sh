#!/usr/bin/env bash
# scenario_02_direct_sftp.sh — T28 (issue #28), S2 : SFTP direct (§5.2).
#
# Attaque : contourner le broker — ouvrir une session SFTP/SSH DIRECTE
# vers une cellule, (a) depuis le captif, (b) depuis un endpoint
# authentifié, (c) en forgeant des tags 802.1Q du VLAN serveur.
# Attente doctrinale (§5.2 « no direct client → server path ») :
#   - captif → cellule : le mur jette, compte (§5.3) ;
#   - authentifié → cellule:22 : AUCUN service SFTP/SSH exposé — la voie
#     L3 légitime (VLAN 20 → 10) ne porte que le broker/PEP ; la donnée
#     ne passe que par passeport, jamais par une session directe ;
#   - tag 802.1Q forgé vers le VLAN 10 : le port du switch n'est pas
#     membre — la trame meurt au bridge, sans réponse.
#
# Preuve (D93) : évidence leafée via `runner leaf-evidence` (§6.2).
#
# Exécution : LAB uniquement (netns — cf. en-tête scenario_01).
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TBP_LAB=${TBP_LAB:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}
. "$TBP_LAB/lab/tests/lib_p1_netns.sh"

OUT=${TBP_P2_OUT:-$TBP_LAB/tests/p2_redteam/out}
CELL=${TBP_P2_CELL:-tbp-cell-redteam}
mkdir -p "$OUT"

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }

# --- topologie : un endpoint authentifié + un captif ---------------------------
export CAPTIVE_PORTS="swp1 swp2"
p1_init sw rtr radius cella cellb epok epko
p1_topo
p1_switch && ok "switch : ports endpoints captifs au départ" || { bad "switch"; exit 1; }
p1_router && ok "routeur : mur chargé" || { bad "routeur"; cat $W/router-setup.log; exit 1; }
p1_cells
p1_radius epok || { bad "radius"; exit 1; }   # seul epok est enrôlé (PKI T18)
p1_hostapd swp1 swp2
p1_switchd swp1 swp2

# --- contrôle : l'endpoint légitime s'authentifie et est aiguillé (VLAN 20) ---
p1_wpa_conf "epok" "$W/pki/ca/ca.crt" "$W/pki/certs/epok.crt" "$W/pki/certs/epok.key" "$W/epok.conf"
run epok $IP link set eth0 up
nsenter -t ${NS[epok]} -n -- $WPA -B -i eth0 -c $W/epok.conf >/dev/null 2>&1
echo $! >> $W/pids
p1_wait 20 test "$(p1_pvid swp1)" = "20" \
	&& ok "epok authentifié 802.1X/EAP-TLS → aiguillé VLAN 20 (contrôle)" \
	|| { bad "epok jamais aiguillé (PVID=$(p1_pvid swp1))"; exit 1; }
run epok $IP addr add 10.20.20.21/24 dev eth0
run epok $IP route add default via 10.20.20.1

# --- (a) captif → SFTP direct : le mur -----------------------------------------
run epko $IP link set eth0 up
run epko $IP addr add 10.66.66.23/24 dev eth0
run epko $IP route add default via 10.66.66.1
CMUR0=$(run rtr $NFT list counter inet tbp_p1 mur_captif_serveur 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+"); CMUR0=${CMUR0:-0}
run epko nc -w2 10.10.10.11 22 </dev/null >/dev/null 2>&1 \
	&& bad "SFTP direct depuis le captif : CONNECTÉ — le mur est tombé (§5.2)" \
	|| ok "captif → cellule:22 : bloqué (pas de chemin direct)"
CMUR1=$(run rtr $NFT list counter inet tbp_p1 mur_captif_serveur 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+"); CMUR1=${CMUR1:-0}
[ "$CMUR1" -gt "$CMUR0" ] \
	&& ok "tentative SFTP captive comptée au mur ($CMUR0 → $CMUR1)" \
	|| bad "tentative SFTP captive non comptée"

# --- (b) authentifié → SFTP direct : aucun service direct exposé ----------------
SFTP_DIRECT=$(run epok nc -w2 10.10.10.11 22 </dev/null 2>&1 | head -1)
if [ -z "$SFTP_DIRECT" ]; then
	ok "authentifié → cellule:22 : AUCUN service SFTP/SSH — la voie L3 ne porte que le broker (§5.2)"
else
	bad "service direct exposé sur la cellule (« $SFTP_DIRECT ») — contournement du broker possible"
fi
BROKER=$(run epok nc -w2 10.10.10.11 9000 2>/dev/null | head -1)
case "$BROKER" in
	TBP-BROKER*) ok "contrôle : la voie légitime (broker) répond — « $BROKER »" ;;
	*) bad "le broker légitime ne répond pas — le lab est cassé, pas l'attaque" ;;
esac

# --- (c) tag 802.1Q forgé vers le VLAN serveur -----------------------------------
run epok $IP link add link eth0 name eth0.10 type vlan id 10 2>/dev/null
run epok $IP link set eth0.10 up 2>/dev/null
run epok $IP addr add 10.10.10.99/24 dev eth0.10 2>/dev/null
run epok ping -c2 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "tag 802.1Q forgé : la cellule RÉPOND — confinement VLAN mort (§5.2)" \
	|| ok "tag 802.1Q forgé vers VLAN 10 : aucune réponse (port non membre — confinement bridge)"

# --- preuve leafée (D93) ---------------------------------------------------------
EV=$W/evidence-s2.json
cat > "$EV" <<EOF
{"scenario":"S2","attack":"SFTP direct captif + authentifié + tag 802.1Q forgé",
 "mur_captif_serveur_avant":$CMUR0,"mur_captif_serveur_apres":$CMUR1,
 "service_sftp_direct":"${SFTP_DIRECT:-aucun}","voie_broker":"$BROKER",
 "asserts_ok":$PASS,"asserts_ko":$FAILL}
EOF
if command -v go >/dev/null 2>&1; then
	(cd "$TBP_LAB" && go run ./tests/p2_redteam/runner leaf-evidence \
		-out "$OUT" -cell "$CELL" -scenario S2 -evidence "$EV") \
		&& ok "évidence S2 leafée (KindTelemetry, hash salé §6.2)" \
		|| bad "feuille d'évidence S2 impossible"
else
	cp "$EV" "$OUT/evidence-S2.json"
	echo "note: go absent — évidence copiée dans $OUT/evidence-S2.json ; la leafer au retour (leaf-evidence -scenario S2)"
fi

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "S2 SFTP direct : VERT" || echo "S2 SFTP direct : ROUGE"
exit $FAILL
