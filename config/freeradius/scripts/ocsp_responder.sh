#!/bin/sh
# ocsp_responder.sh — répondeur OCSP de DEV/TEST adossé à la base openssl ca
# (index.txt) de ca_dev.sh (issue #130) : FreeRADIUS interroge ce répondeur
# EN DIRECT à chaque authentification EAP-TLS (mods-available/eap, bloc
# ocsp — voir render_config.sh), au lieu de ne relire la CRL qu'à son
# (re)démarrage — la révocation devient effective sans jamais redémarrer
# FreeRADIUS lui-même (aucune interruption du service RADIUS).
#
# Limite vérifiée (openssl 3.0.13, comportement documenté du répondeur de
# référence) : `openssl ocsp -index` charge la base UNE FOIS au démarrage,
# jamais relue par requête — un `restart` de CE processus, léger et sans
# rapport avec FreeRADIUS, est donc nécessaire après chaque révocation.
# revoke_client.sh l'appelle automatiquement (best-effort) : la fenêtre
# d'exposition est le temps d'un redémarrage de processus (< 1 s), jamais
# le redémarrage du service RADIUS.
#
# ⚠ DEV/TEST UNIQUEMENT — même doctrine que ca_dev.sh : le répondeur signe
# ici avec la clé de CA elle-même (jamais un certificat OCSP délégué). En
# production : un répondeur OCSP réel adossé à la même base openssl ca (ou
# un service managé), avec un certificat de signature OCSP délégué (EKU
# OCSPSigning) dont la clé ne quitte jamais son HSM — jamais la clé de CA
# pour signer des réponses de masse.
#
# Usage :
#   ocsp_responder.sh start   [pki_home] [port]   (idempotent : stop puis start)
#   ocsp_responder.sh restart [pki_home] [port]   (alias de start)
#   ocsp_responder.sh stop    [pki_home]
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CMD=${1:-}
PKI_ARG=${2:-"${SCRIPT_DIR}/../certs/dev"}
PORT_ARG=${3:-}

stop_one() {
	pki=$1
	pidfile="$pki/ocsp.pid"
	if [ -f "$pidfile" ]; then
		kill "$(cat "$pidfile")" 2>/dev/null || true
		wait "$(cat "$pidfile")" 2>/dev/null || true
		rm -f "$pidfile"
	fi
}

case "$CMD" in
start | restart)
	[ -d "$PKI_ARG" ] || { echo "erreur: PKI introuvable dans $PKI_ARG — lancer ca_dev.sh d'abord" >&2; exit 1; }
	PKI=$(CDPATH= cd -- "$PKI_ARG" && pwd)
	[ -f "$PKI/index.txt" ] && [ -f "$PKI/ca/ca.crt" ] || {
		echo "erreur: base openssl ca introuvable dans $PKI (index.txt/ca/ca.crt) — lancer ca_dev.sh d'abord" >&2
		exit 1
	}
	# Port explicite > port déjà en service (fichier écrit ci-dessous au
	# premier start) > défaut 8888. Sans ce fichier, un `restart` appelé
	# SANS port explicite (revoke_client.sh, qui ne connaît que le
	# répertoire PKI) retomberait sur le défaut 8888 même si le répondeur
	# tournait sur un autre port — constaté à l'exécution : la révocation
	# semblait « rechargée » mais interrogeait un processus fantôme sur le
	# mauvais port, l'ancien ayant déjà été arrêté par stop_one ci-dessous.
	if [ -n "$PORT_ARG" ]; then
		PORT=$PORT_ARG
	elif [ -f "$PKI/ocsp.port" ]; then
		PORT=$(cat "$PKI/ocsp.port")
	else
		PORT=8888
	fi
	stop_one "$PKI" # idempotent : toute instance déjà en écoute charge une base figée
	# nohup + stdin fermé + flux redirigés : ce script est typiquement
	# appelé depuis un AUTRE script de courte durée (revoke_client.sh) —
	# sans détachement explicite, le processus en arrière-plan reçoit
	# SIGHUP et meurt dès que SON appelant direct se termine, avant même
	# d'avoir servi une seule requête (constaté à l'exécution : le
	# répondeur démarrait puis disparaissait silencieusement au retour de
	# revoke_client.sh).
	nohup openssl ocsp -index "$PKI/index.txt" -CA "$PKI/ca/ca.crt" \
		-rsigner "$PKI/ca/ca.crt" -rkey "$PKI/ca/ca.key" \
		-port "$PORT" -text -out "$PKI/ocsp.log" \
		>"$PKI/ocsp.out" 2>&1 </dev/null &
	echo $! >"$PKI/ocsp.pid"
	disown 2>/dev/null || true
	# openssl ocsp n'a pas de témoin "prêt" explicite dans son log — une
	# courte pause suffit pour le cas d'usage de ce dépôt (dev/lab, jamais
	# un service de production dont la disponibilité serait sondée ainsi).
	sleep 0.2
	if ! kill -0 "$(cat "$PKI/ocsp.pid")" 2>/dev/null; then
		echo "erreur: le répondeur OCSP n'a pas démarré — voir $PKI/ocsp.out" >&2
		exit 1
	fi
	echo "$PORT" >"$PKI/ocsp.port"
	echo "répondeur OCSP de dev démarré (pid $(cat "$PKI/ocsp.pid"), port $PORT) — $PKI/ocsp.log"
	;;
stop)
	[ -d "$PKI_ARG" ] || exit 0
	PKI=$(CDPATH= cd -- "$PKI_ARG" && pwd)
	stop_one "$PKI"
	;;
*)
	echo "usage: ocsp_responder.sh start|restart|stop [pki_home] [port]" >&2
	exit 2
	;;
esac
