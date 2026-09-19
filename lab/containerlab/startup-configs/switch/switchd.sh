#!/bin/sh
# switchd.sh <port> <vlan_succes> — l'aiguillage du §5.1, exécuté
# LOCALEMENT par le switch : sur EAP-SUCCESS le port bascule du VLAN
# captif (66) vers le VLAN des endpoints authentifiés (20) ; sur
# EAP-FAILURE il RESTE en captif — SAUF si le watchdog (radius-watchdog.sh)
# signale une vérification dégradée (CRL/OCSP injoignable) : l'échec est
# alors INVIOLABLE d'un certificat invalide, et le port part en VLAN de
# REMÉDIATION (77) avec feedback, jamais de rejet aveugle (§5.3, D15).
# Chaque décision est tracée dans $TBP_WORK/nac-decisions.log (§4.1).
#
# Env : TBP_WORK (défaut /run/tbp-p1), BRIDGE_BIN (défaut bridge),
# REMEDIATION_VLAN (défaut 77)
set -eu

[ $# -eq 2 ] || { echo "usage: switchd.sh <port> <vlan_succes>" >&2; exit 2; }
PORT=$1; VLAN_OK=$2
WORK=${TBP_WORK:-/run/tbp-p1}
BR=${BRIDGE_BIN:-bridge}
VLAN_REM=${REMEDIATION_VLAN:-77}
LOG=$WORK/hostapd-$PORT/log
MODE=$WORK/remediation.mode   # créé/retiré par radius-watchdog.sh

[ -f "$LOG" ] || { echo "erreur: log hostapd absent: $LOG" >&2; exit 1; }

tail -F -n0 "$LOG" 2>/dev/null | while read -r line; do
	case "$line" in
	*EAP-SUCCESS*)
		echo "$(date +%s) DECISION port=$PORT result=success vlan=$VLAN_OK" \
			>> $WORK/nac-decisions.log
		$BR vlan add vid $VLAN_OK pvid untagged dev $PORT 2>/dev/null || true
		$BR vlan del vid 66 dev $PORT 2>/dev/null || true
		$BR vlan del vid $VLAN_REM dev $PORT 2>/dev/null || true ;;
	*EAP-FAILURE*)
		if [ -f "$MODE" ]; then
			# vérification dégradée : quarantaine AVEC feedback (§5.3)
			echo "$(date +%s) DECISION port=$PORT result=remediation vlan=$VLAN_REM" \
				>> $WORK/nac-decisions.log
			$BR vlan add vid $VLAN_REM pvid untagged dev $PORT 2>/dev/null || true
			$BR vlan del vid 66 dev $PORT 2>/dev/null || true
		else
			echo "$(date +%s) DECISION port=$PORT result=failure vlan=66" \
				>> $WORK/nac-decisions.log
		fi ;;
	esac
done
