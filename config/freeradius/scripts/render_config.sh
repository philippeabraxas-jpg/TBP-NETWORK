#!/bin/sh
# render_config.sh — applique le profil TBP (§5.1, issue #130 : "le NAC
# reste une intention documentée, pas un artefact déployable") sur un
# arbre FreeRADIUS STOCK : EAP-TLS seul sur la PKI du handshake (§3),
# révocation vérifiée EN DIRECT par OCSP (ocsp_responder.sh — voir cette
# issue, seconde moitié : jamais un rechargement qui n'a lieu qu'au
# redémarrage), CRL en défense en profondeur si l'OCSP est injoignable
# (§5.3 : jamais un soft-fail silencieux — c'est FreeRADIUS/le switch qui
# route vers la remédiation dans ce cas, pas ce script).
#
# Ne DUPLIQUE jamais la configuration stock à la main : elle dérive à
# chaque version de FreeRADIUS (mods-available/eap fait ~1000 lignes,
# essentiellement documentées par le paquet lui-même). Même doctrine que
# policies/gen_capabilities.sh (jamais un capabilities.json figé à la
# main) — ce script part du paquet RÉELLEMENT installé et n'y touche que
# ce qui doit changer. C'est le même chemin de code que test_eap_tls.sh
# valide de bout en bout (EAP-TLS réel, CA/PKI réelles, refus réel d'un
# certificat étranger ou révoqué) : le tester, c'est tester ce script.
#
# Usage :
#   render_config.sh <raddb_stock> <raddb_sortie> [pki_home] [ocsp_url]
#
#   <raddb_stock>   arbre FreeRADIUS stock (ex. /etc/freeradius/3.0 sur
#                   Debian/Ubuntu) — jamais modifié par ce script.
#   <raddb_sortie>  répertoire de sortie. DIFFÉRENT de <raddb_stock> pour
#                   un essai jetable (copie complète, symlinks
#                   mods-enabled/sites-enabled recréés comme le ferait le
#                   postinst du paquet) ; IDENTIQUE à <raddb_stock> pour
#                   une production réelle déjà installée par le paquet —
#                   ce script ne touche alors QUE mods-available/eap et
#                   certs/, jamais clients.conf ni sites-enabled.
#   pki_home        défaut ../certs/dev (ca_dev.sh) — EN PRODUCTION :
#                   pointer vers la PKI réelle (jamais le dev), la clé de
#                   CA vivant dans un HSM (§12), pas dans un fichier.
#   ocsp_url        défaut http://127.0.0.1:8888/ — doit correspondre au
#                   port du répondeur lancé par ocsp_responder.sh.
#
# Ce que ce script NE fait PAS (D99 : à adapter, jamais à copier tel
# quel) :
#   - clients.conf (secrets des switches) — voir clients.conf.example,
#     spécifique à chaque déploiement, jamais généré ici ;
#   - la politique VLAN côté switch (captif/remédiation, T20) ;
#   - le choix production vs lab de l'emplacement de la PKI/HSM.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RADDB_SRC=${1:-}
RADDB_OUT=${2:-}
PKI_ARG=${3:-"${SCRIPT_DIR}/../certs/dev"}
OCSP_URL=${4:-"http://127.0.0.1:8888/"}

[ -n "$RADDB_SRC" ] && [ -n "$RADDB_OUT" ] || {
	echo "usage: render_config.sh <raddb_stock> <raddb_sortie> [pki_home] [ocsp_url]" >&2
	exit 2
}
[ -d "$RADDB_SRC" ] || { echo "erreur: raddb stock introuvable: $RADDB_SRC" >&2; exit 1; }
[ -f "$RADDB_SRC/mods-available/eap" ] || {
	echo "erreur: $RADDB_SRC ne ressemble pas à un raddb FreeRADIUS (mods-available/eap absent)" >&2
	exit 1
}
[ -d "$PKI_ARG" ] || { echo "erreur: PKI introuvable dans $PKI_ARG — lancer ca_dev.sh d'abord" >&2; exit 1; }
PKI=$(CDPATH= cd -- "$PKI_ARG" && pwd)
[ -f "$PKI/ca/ca.crt" ] && [ -f "$PKI/certs/radius.crt" ] || {
	echo "erreur: PKI incomplète dans $PKI (ca/ca.crt, certs/radius.*) — lancer ca_dev.sh d'abord" >&2
	exit 1
}

if [ "$RADDB_SRC" != "$RADDB_OUT" ]; then
	mkdir -p "$RADDB_OUT"
	cp -a "$RADDB_SRC"/. "$RADDB_OUT"/
	chmod -R u+w "$RADDB_OUT"
	# Un arbre issu de « dpkg -x » (jamais dpkg -i) n'a pas les symlinks
	# créés par le postinst Debian — les recréer pour les modules/sites
	# nécessaires à EAP-TLS. Sans effet sur une sortie déjà installée par
	# le paquet (les liens existent déjà, la boucle est un no-op).
	for m in always attr_filter cache_eap chap date detail detail.log digest \
		dynamic_clients eap echo exec expiration expr files linelog \
		logintime mschap ntlm_auth pap passwd preprocess radutmp realm \
		replicate sradutmp totp unix unpack utf8; do
		[ -e "$RADDB_OUT/mods-available/$m" ] && [ ! -e "$RADDB_OUT/mods-enabled/$m" ] &&
			ln -sf "../mods-available/$m" "$RADDB_OUT/mods-enabled/$m"
	done
	for s in default inner-tunnel; do
		[ -e "$RADDB_OUT/sites-available/$s" ] && [ ! -e "$RADDB_OUT/sites-enabled/$s" ] &&
			ln -sf "../sites-available/$s" "$RADDB_OUT/sites-enabled/$s"
	done
fi

# --- Certificats : serveur RADIUS (profil nac-server), CA+CRL combinés -----
mkdir -p "$RADDB_OUT/certs"
install -m 0400 "$PKI/certs/radius.key" "$RADDB_OUT/certs/server.key"
install -m 0444 "$PKI/certs/radius.crt" "$RADDB_OUT/certs/server.pem"
cat "$PKI/ca/ca.crt" "$PKI/crl/ca.crl" >"$RADDB_OUT/certs/ca.pem"

# --- module eap : TLS seul (§1 : une seule voie d'authentification, pas de
# PEAP/MSCHAPv2 en parallèle), CA du handshake, OCSP live (issue #130) +
# CRL en défense en profondeur -----------------------------------------
EAP="$RADDB_OUT/mods-available/eap"
sed -i \
	-e "s|private_key_file = .*|private_key_file = \${certdir}/server.key|" \
	-e "s|certificate_file = .*|certificate_file = \${certdir}/server.pem|" \
	-e "s|ca_file = .*|ca_file = \${certdir}/ca.pem|" \
	-e "s|^[[:space:]#]*check_crl = .*|\t\tcheck_crl = yes|" \
	-e "s|default_eap_type = md5|default_eap_type = tls|" \
	"$EAP"
# Bloc 'ocsp { enable = no ... }' : SEULE occurrence de "enable = no" entre
# "ocsp {" et "override_cert_url" dans le fichier stock (vérifié contre
# FreeRADIUS 3.2.5 réel) — un autre "enable = no" existe plus haut, pour
# la mise en cache de session, jamais touché ici.
sed -i \
	-e "/ocsp {/,/override_cert_url/ s/^\([[:space:]]*\)enable = no/\1enable = yes/" \
	-e "s|url = \"http://127.0.0.1/ocsp/\"|url = \"$OCSP_URL\"|" \
	"$EAP"
awk '/ocsp \{/{f=1} f&&/enable = yes/{found=1} f&&/override_cert_url/{exit} END{exit !found}' "$EAP" ||
	{ echo "erreur: le bloc ocsp de $EAP n'a pas été activé — structure du fichier inattendue (version de FreeRADIUS différente ?)" >&2; exit 1; }

echo "configuration TBP appliquée : $RADDB_OUT"
echo "  EAP-TLS seul, CRL: $RADDB_OUT/certs/ca.pem, OCSP live: $OCSP_URL"
echo "rappel (D99, à adapter — jamais à copier tel quel) : clients.conf"
echo "  (secrets des switches, voir clients.conf.example) et la politique"
echo "  VLAN côté switch (T20) restent spécifiques à ce déploiement"
