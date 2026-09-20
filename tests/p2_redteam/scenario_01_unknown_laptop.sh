#!/usr/bin/env bash
# scenario_01_unknown_laptop.sh — T28 (issue #28), S1 : laptop inconnu (§5.1).
#
# Attaque : Michel branche un laptop inconnu — certificat d'une PKI
# ÉTRANGÈRE (forge complète, p1_foreign_pki) — et tente le 802.1X du port.
# Attente doctrinale : l'authentification échoue, le port RESTE dans le
# VLAN captif (66), aucune route vers les serveurs — la seule voie est
# l'enrôlement (8080). Chaque tentative captif→serveur est comptée par le
# mur (§5.3 monitor) et le journal NAC porte le refus.
#
# Preuve (D93) : l'évidence observée (compteurs avant/après, journal NAC,
# sondes) est inscrite en feuille KindTelemetry du registre du run via
# `runner leaf-evidence` (hash salé, sel local §6.2) — un scénario qui
# « passe » sans trace vérifiable n'a rien prouvé.
#
# Exécution : LAB uniquement (network namespaces — le sandbox CI ne monte
# pas de namespaces : `unshare -n` → Operation not permitted). Mêmes
# startup-configs que le lab containerlab, via lab/tests/lib_p1_netns.sh.
#
# Env : TBP_LAB (racine du dépôt), TBP_P2_OUT (répertoire du run — défaut
# tests/p2_redteam/out), + les *_BIN de lib_p1_netns.sh.
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

MAC_ROGUE="aa:bb:cc:dd:ee:66"

# --- topologie : le laptop inconnu seul (pas d'endpoint légitime requis) ----
export CAPTIVE_PORTS="swp8"
p1_init sw rtr radius cella cellb epunk
p1_topo
p1_switch && ok "switch : swp8 captif (66) par défaut" || { bad "switch"; exit 1; }
p1_router && ok "routeur : mur nftables chargé" || { bad "routeur"; cat $W/router-setup.log; exit 1; }
p1_cells
p1_radius || { bad "radius"; exit 1; }   # PKI T18 légitime — le rogue n'y est PAS enrôlé
p1_hostapd swp8
p1_switchd swp8

# --- l'attaque : certificat étranger, 802.1X complet --------------------------
p1_foreign_pki
p1_wpa_conf "endpoint-ko" "$W/foreign/ca.crt" "$W/foreign/rogue.crt" "$W/foreign/rogue.key" "$W/rogue.conf"
run epunk $IP link set eth0 address $MAC_ROGUE up
nsenter -t ${NS[epunk]} -n -- $WPA -B -i eth0 -c $W/rogue.conf >/dev/null 2>&1
echo $! >> $W/pids
sleep 3

# Attente doctrinale 1 : le port ne quitte JAMAIS le captif.
sleep 3
PVID=$(p1_pvid swp8)
[ "$PVID" = "66" ] \
	&& ok "PKI étrangère : swp8 RESTE captif (PVID=66) après la tentative 802.1X" \
	|| bad "swp8 a quitté le captif (PVID=$PVID) — aiguillage compromis (§5.1)"

# Attente doctrinale 2 : le refus est journalisé (jamais silencieux, §5.3).
p1_wait 10 grep -q '"result":"failure"' $W/nac-decisions.log \
	&& ok "journal NAC : refus tracé (nac-decisions.log)" \
	|| bad "aucun refus tracé au journal NAC — rejet silencieux"

# --- sondes depuis le captif : aucune route serveur, enrôlement seul ----------
run epunk $IP addr add 10.66.66.22/24 dev eth0 2>/dev/null
run epunk $IP route add default via 10.66.66.1 2>/dev/null
CMUR0=$(run rtr $NFT list counter inet tbp_p1 mur_captif_serveur 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+"); CMUR0=${CMUR0:-0}
run epunk ping -c2 -W1 10.10.10.11 >/dev/null 2>&1 \
	&& bad "le captif a joint la cellule — le mur est tombé (§5.1)" \
	|| ok "captif → cellule : injoignable (aucune route serveur)"
CMUR1=$(run rtr $NFT list counter inet tbp_p1 mur_captif_serveur 2>/dev/null \
	| grep -oE "packets [0-9]+" | grep -oE "[0-9]+"); CMUR1=${CMUR1:-0}
[ "$CMUR1" -gt "$CMUR0" ] \
	&& ok "compteur mur_captif_serveur $CMUR0 → $CMUR1 (tentative VISIBLE, §5.3)" \
	|| bad "tentative captif→serveur non comptée"
BANNER=$(run epunk nc -w2 10.66.66.1 8080 2>/dev/null | head -1)
case "$BANNER" in
	TBP-ENROLL*) ok "seule voie du captif = enrôlement (« $BANNER »)" ;;
	*) bad "enrôlement injoignable depuis le captif" ;;
esac

# --- preuve : l'observation est leafée (D93) -----------------------------------
EV=$W/evidence-s1.json
cat > "$EV" <<EOF
{"scenario":"S1","attack":"802.1X PKI étrangère + sondes captives","pvid_apres":"$PVID",
 "mur_captif_serveur_avant":$CMUR0,"mur_captif_serveur_apres":$CMUR1,
 "banniere_enrolement":"$BANNER","asserts_ok":$PASS,"asserts_ko":$FAILL}
EOF
if command -v go >/dev/null 2>&1; then
	(cd "$TBP_LAB" && go run ./tests/p2_redteam/runner leaf-evidence \
		-out "$OUT" -cell "$CELL" -scenario S1 -evidence "$EV") \
		&& ok "évidence S1 leafée (KindTelemetry, hash salé §6.2)" \
		|| bad "feuille d'évidence S1 impossible"
else
	cp "$EV" "$OUT/evidence-S1.json"
	echo "note: go absent — évidence copiée dans $OUT/evidence-S1.json ; la leafer au retour (leaf-evidence -scenario S1)"
fi

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "S1 laptop inconnu : VERT" || echo "S1 laptop inconnu : ROUGE"
exit $FAILL
