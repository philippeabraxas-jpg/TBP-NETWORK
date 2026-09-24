#!/bin/sh
# disconnect_client.sh <hostname> — termine IMMÉDIATEMENT une session déjà
# authentifiée d'un endpoint révoqué, via RADIUS CoA/Disconnect-Request
# (RFC 5176) — issue #130, second mécanisme nommé par le correctif attendu
# ("rechargement à chaud, CoA RADIUS, ou équivalent") : l'OCSP live
# (ocsp_responder.sh, appelé par revoke_client.sh) empêche une RÉ-
# authentification avec le certificat révoqué, mais ne coupe pas une
# session DÉJÀ établie avant la révocation — seul un Disconnect-Message
# envoyé au NAS (switch) le fait.
#
# Best-effort et OPTIONNEL : nécessite un NAS qui écoute effectivement le
# port CoA (RFC 5176 — souvent 3799) et l'accepte comme client CoA
# (clients.conf du NAS, pas de ce dépôt) ; aucun NAS de ce genre n'existe
# dans les environnements dev/lab de ce dépôt, donc CE SCRIPT N'EST PAS
# EXERCÉ EN CI — seule la CORRECTION du paquet RADIUS émis (code 40, attribut
# d'identification présent) est vérifiable ici (voir test_eap_tls.sh, témoin
# "paquet Disconnect-Request bien formé").
#
# Usage :
#   disconnect_client.sh <hostname>
# Variables :
#   TBP_NAC_COA_NAS      <host>:<port> du NAS (port CoA, RFC 5176 : 3799
#                        par défaut) — ABSENT ⇒ le script ne fait rien
#                        (silencieux, jamais une erreur : tous les
#                        déploiements n'ont pas encore de NAS avec CoA
#                        activé, cf. T19/T20)
#   TBP_NAC_COA_SECRET   secret partagé CoA du NAS — requis si NAS défini
#   TBP_NAC_HOME         défaut /etc/tbp/nac (déploiement des certificats
#                        clients, voir enroll_client.sh) — sert à retrouver
#                        l'identité RADIUS de l'endpoint (Calling-Station-Id
#                        = son nom, convention de ce dépôt)
set -eu

HOST=${1:-}
[ -n "$HOST" ] || { echo "usage: disconnect_client.sh <hostname>" >&2; exit 2; }

NAS=${TBP_NAC_COA_NAS:-}
if [ -z "$NAS" ]; then
	echo "  CoA: TBP_NAC_COA_NAS non défini — pas de NAS à déconnecter (T19/T20), rien à faire"
	exit 0
fi
SECRET=${TBP_NAC_COA_SECRET:-}
[ -n "$SECRET" ] || { echo "erreur: TBP_NAC_COA_SECRET requis avec TBP_NAC_COA_NAS" >&2; exit 1; }
command -v radclient >/dev/null 2>&1 || {
	echo "erreur: radclient introuvable (paquet freeradius-utils)" >&2
	exit 1; }

# Convention de ce dépôt (enroll_client.sh) : l'identité RADIUS de
# l'endpoint est son hostname — Calling-Station-Id est l'attribut le plus
# largement supporté par les NAS pour cibler une session par Disconnect
# (RFC 5176 §3) ; User-Name en défense en profondeur si le NAS l'indexe
# plutôt.
printf 'Calling-Station-Id = "%s"\nUser-Name = "%s"\n' "$HOST" "$HOST" \
	| radclient -x "$NAS" disconnect "$SECRET" \
	&& echo "  CoA: Disconnect-Request envoyé pour $HOST à $NAS (best-effort — voir accusé du NAS)" \
	|| echo "  AVERTISSEMENT: Disconnect-Request pour $HOST échoué (NAS injoignable ou CoA non activé côté NAS, T19/T20) — la session déjà établie peut persister jusqu'à sa ré-authentification périodique" >&2
