#!/bin/sh
# mabd.sh <port...> — MAB (MAC Authentication Bypass) LOCAL au switch, pour
# les équipements sans 802.1X (IoT). Jamais silencieux (§5.3) : chaque MAC
# apprise sur un port captif est authentifiée par MAC-auth RADIUS
# (User-Name = User-Password = MAC ; entrées du module files) :
#   Accept → le port bascule en VLAN IoT (33), instrumenté (télémétrie
#            uniquement, compteur voie_iot_telemetry) + feuille success ;
#   Reject → le port RESTE captif + feuille failure + alarme — jamais de
#            MAB silencieux vers un VLAN de production (§5.3, §9.1).
#
# Priorité 802.1X (D16) : une MAC n'est candidate au MAB qu'après avoir été
# vue sur MAB_QUIET_POLLS scrutations consécutives (laisse le 802.1X se
# dérouler d'abord) et uniquement si le port est TOUJOURS en PVID captif.
#
# Usage : mabd.sh swp1 swp2 &
# Env : TBP_WORK, BRIDGE_BIN, RADCLIENT_BIN (défaut radclient), RADIUS_IP
# (défaut 10.99.99.3), RADIUS_PORT (1812), RADIUS_SECRET,
# IOT_VLAN (défaut 33), CAPTIVE_VLAN (défaut 66), MAB_INTERVAL (défaut 2s),
# MAB_QUIET_POLLS (défaut 3).
set -u

[ $# -ge 1 ] || { echo "usage: mabd.sh <port...>" >&2; exit 2; }
PORTS="$*"
WORK=${TBP_WORK:-/run/tbp-p1}
BR=${BRIDGE_BIN:-bridge}
RADCLIENT=${RADCLIENT_BIN:-radclient}
RADIUS_IP=${RADIUS_IP:-10.99.99.3}
RADIUS_PORT=${RADIUS_PORT:-1812}
SECRET=${RADIUS_SECRET:-testing123}
VLAN_IOT=${IOT_VLAN:-33}
VLAN_CAPT=${CAPTIVE_VLAN:-66}
EVERY=${MAB_INTERVAL:-2}
QUIET=${MAB_QUIET_POLLS:-3}
LEAVES=$WORK/mab-decisions.jsonl
DECISIONS=$WORK/nac-decisions.log
SEEN_DIR=$WORK/mab-seen
mkdir -p "$SEEN_DIR"

mab_leaf() { # mab_leaf <mac> <result>
	printf '{"v":1,"agent":"mabd","mac_sha256":"%s","result":"%s","ts":%s}\n' \
		"$(echo "$1" | sha256sum | cut -d' ' -f1)" "$2" "$(date +%s)" >> $LEAVES
	echo "$(date +%s) MAB mac=$1 result=$2" >> $DECISIONS
}

while :; do
	for PORT in $PORTS; do
		# le port n'est éligible au MAB que s'il est TOUJOURS captif
		$BR vlan show dev $PORT 2>/dev/null | grep -q "$VLAN_CAPT.*PVID" || continue
		# MACs apprises sur ce port (hors self/permanent)
		for MAC in $($BR fdb show dev $PORT 2>/dev/null \
				| grep -v "self\|permanent" | awk '{print $1}' | sort -u); do
			F=$SEEN_DIR/$(echo "$MAC" | tr ':' '-')
			if [ -f "$F.done" ]; then continue; fi
			N=$(cat "$F.count" 2>/dev/null || echo 0)
			N=$((N+1)); echo $N > "$F.count"
			[ $N -lt $QUIET ] && continue
			# re-vérifier que le port est resté captif pendant la quiétude
			$BR vlan show dev $PORT 2>/dev/null | grep -q "$VLAN_CAPT.*PVID" \
				|| { : > "$F.done"; continue; }
			RESP=$(printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$MAC" "$MAC" \
				| $RADCLIENT -x $RADIUS_IP:$RADIUS_PORT auth "$SECRET" 2>&1)
			# « Received Access-Accept » uniquement : une ligne « Expected
			# Access-Accept got Access-Reject » (rejet) contient la sous-
			# chaîne « Access-Accept » — le grep doit être ancré sur le
			# paquet REÇU, sous peine de fail-open (constaté au test T20).
			if echo "$RESP" | grep -q "Received Access-Accept"; then
				$BR vlan add vid $VLAN_IOT pvid untagged dev $PORT
				$BR vlan del vid $VLAN_CAPT dev $PORT 2>/dev/null || true
				mab_leaf "$MAC" success
			else
				mab_leaf "$MAC" failure   # alarme : jamais silencieux
			fi
			: > "$F.done"
		done
	done
	sleep $EVERY
done
