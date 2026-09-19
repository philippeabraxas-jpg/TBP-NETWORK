#!/bin/sh
# switchd.sh <port> <vlan_succes> — l'aiguillage du §5.1, exécuté
# LOCALEMENT par le switch : sur EAP-SUCCESS le port bascule du VLAN
# captif (66) vers le VLAN des endpoints authentifiés (20) ; sur
# EAP-FAILURE il RESTE en captif. Chaque décision est tracée dans
# $TBP_WORK/nac-decisions.log (une décision = une trace, §4.1).
#
# Env : TBP_WORK (défaut /run/tbp-p1), BRIDGE_BIN (défaut bridge)
set -eu

[ $# -eq 2 ] || { echo "usage: switchd.sh <port> <vlan_succes>" >&2; exit 2; }
PORT=$1; VLAN_OK=$2
WORK=${TBP_WORK:-/run/tbp-p1}
BR=${BRIDGE_BIN:-bridge}
LOG=$WORK/hostapd-$PORT/log

[ -f "$LOG" ] || { echo "erreur: log hostapd absent: $LOG" >&2; exit 1; }

tail -F -n0 "$LOG" 2>/dev/null | while read -r line; do
	case "$line" in
	*EAP-SUCCESS*)
		echo "$(date +%s) DECISION port=$PORT result=success vlan=$VLAN_OK" \
			>> $WORK/nac-decisions.log
		$BR vlan add vid $VLAN_OK pvid untagged dev $PORT
		$BR vlan del vid 66 dev $PORT ;;
	*EAP-FAILURE*)
		echo "$(date +%s) DECISION port=$PORT result=failure vlan=66" \
			>> $WORK/nac-decisions.log ;;
	esac
done
