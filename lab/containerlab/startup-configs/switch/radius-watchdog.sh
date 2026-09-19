#!/bin/sh
# radius-watchdog.sh — le « monitor » du §5.3 côté switch : vérifie
# périodiquement la SANTÉ de l'authentification en authentifiant un
# certificat canari (swprobe, enrôlé via T18) directement contre le RADIUS.
#
# Trois états distingués côté switch (Exp C, T20) :
#   SUCCESS              → sain (sortie de mode remédiation le cas échéant) ;
#   FAILURE + « timed out » → RADIUS DOWN : fail-closed structurel (aucun
#                          EAP-SUCCESS possible, les ports restent captifs) —
#                          le watchdog ALARME : jamais silencieux ;
#   FAILURE sans timeout → vérification DÉGRADÉE (ex. CRL/OCSP injoignable) :
#                          pose $TBP_WORK/remediation.mode → switchd envoie
#                          les échecs en VLAN remédiation (feedback, §5.3).
#
# Chaque TRANSITION d'état est une feuille JSONL hash-only (§4.1, §6.2) dans
# $TBP_WORK/nac-watchdog.jsonl + un événement dans nac-decisions.log.
#
# Usage : radius-watchdog.sh &  (boucle infinie)
# Env : TBP_WORK, RADIUS_IP (défaut 10.99.99.3), RADIUS_PORT (1812),
# RADIUS_SECRET, CANARY_CONF (défaut $TBP_WORK/canary.conf),
# WATCHDOG_INTERVAL (défaut 5s), EAPOL_TEST_BIN (défaut eapol_test).
set -u

WORK=${TBP_WORK:-/run/tbp-p1}
RADIUS_IP=${RADIUS_IP:-10.99.99.3}
RADIUS_PORT=${RADIUS_PORT:-1812}
SECRET=${RADIUS_SECRET:-testing123}
CANARY=${CANARY_CONF:-$WORK/canary.conf}
EVERY=${WATCHDOG_INTERVAL:-5}
EAPOL=${EAPOL_TEST_BIN:-eapol_test}
MODE=$WORK/remediation.mode
LEAVES=$WORK/nac-watchdog.jsonl
DECISIONS=$WORK/nac-decisions.log

STATE=unknown
leaf() { # leaf <etat> — feuille de transition (hash-only : état + sonde, pas de secret)
	printf '{"v":1,"agent":"nac-watchdog","state":"%s","probe":"swprobe","ts":%s}\n' \
		"$1" "$(date +%s)" >> $LEAVES
	echo "$(date +%s) WATCHDOG etat=$1" >> $DECISIONS
}

while :; do
	OUT=$($EAPOL -c "$CANARY" -a $RADIUS_IP -p $RADIUS_PORT -s "$SECRET" -t 3 2>&1)
	if echo "$OUT" | grep -q "^SUCCESS"; then
		NEW=ok
	elif echo "$OUT" | grep -q "timed out"; then
		NEW=radius-down
	else
		NEW=verification-degraded
	fi
	if [ "$NEW" != "$STATE" ]; then
		leaf "$NEW"
		case "$NEW" in
		verification-degraded) : > "$MODE" ;;   # → switchd : échecs → VLAN 77
		*) rm -f "$MODE" ;;
		esac
		STATE=$NEW
	fi
	sleep $EVERY
done
