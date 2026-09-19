#!/bin/sh
# router-setup.sh — routeur Debian du pilote P1 : durcissement sysctl +
# « mur » nftables + service d'enrôlement (seule voie du captif, §5.1).
#
# Le routeur charge RÉELLEMENT les configs du dépôt :
#   $TBP_LAB/config/sysctl/99-tbp-hardening.conf
#   $TBP_LAB/config/nftables/router-p1.nft
#
# Env : TBP_LAB (racine du dépôt, défaut /tbp), TBP_WORK (défaut
# /run/tbp-p1), NFT_BIN / IP_BIN. Le sysctl est best-effort : en environnement
# à /proc/sys restreint (conteneur sans cap), les clés non applicables sont
# journalisées, pas masquées — mais ip_forward est un PRÉREQUIS dur.
set -eu

LAB=${TBP_LAB:-/tbp}
WORK=${TBP_WORK:-/run/tbp-p1}
NFT=${NFT_BIN:-nft}
IP=${IP_BIN:-ip}

mkdir -p "$WORK"

# --- durcissement sysctl (config/ du dépôt) ------------------------------------
# -e : ignorer les clés inconnues ; les refus (ex. /proc/sys read-only en
# sandbox) sont consignés dans sysctl.log — visibles, jamais silencieux.
if sysctl -e -p "$LAB/config/sysctl/99-tbp-hardening.conf" > "$WORK/sysctl.log" 2>&1; then
	echo "router-setup: sysctl 99-tbp-hardening.conf appliqué"
else
	echo "router-setup: sysctl partiellement appliqué — voir $WORK/sysctl.log" >&2
fi

# ip_forward est le pré-requis dur du routeur : sans lui, pas de pilote.
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
	sysctl -w net.ipv4.ip_forward=1 || {
		echo "erreur: ip_forward impossible (pré-requis routeur)" >&2; exit 1; }
fi

# --- le mur (config/nftables/router-p1.nft du dépôt) -----------------------------
# Le jeu de règles chargé est celui du dépôt ; seuls les NOMS d'interfaces sont
# liés au déploiement : le trunk est l'unique interface data du routeur (eth0
# dans le harnais netns, eth1 sous containerlab) — détection auto, surcharge
# possible par TRUNK_IF.
# `ip -o link show` affiche un veth inter-netns (le cas normal, netns comme
# containerlab) sous la forme « eth0@if22 » : le « .* » ne coupe qu'après un
# point (suffixe VLAN), pas après le « @ » — sans quoi TRUNK vaut littéralement
# « eth0@if22 » et le nft généré ci-dessous échoue au chargement (interface
# invalide) alors que router-setup.sh remonte quand même un succès.
TRUNK=${TRUNK_IF:-$($IP -o link show | awk -F': ' '$2 != "lo" { sub(/[@.].*/, "", $2); print $2; exit }')}
RUNNFT="$WORK/router-p1.nft"
sed -e "s/= eth0\.10/= $TRUNK.10/" -e "s/= eth0\.20/= $TRUNK.20/" \
	-e "s/= eth0\.66/= $TRUNK.66/" -e "s/= eth0\.99/= $TRUNK.99/" \
	"$LAB/config/nftables/router-p1.nft" > "$RUNNFT"
$NFT -f "$RUNNFT"
echo "router-setup: mur nftables chargé (router-p1.nft, trunk $TRUNK)"

# --- service d'enrôlement : la SEULE voie offerte au captif ----------------------
# bannière lue depuis un fichier (socat SYSTEM avec un message quoté
# multi-mots échoue silencieusement — constaté au test).
echo "TBP-ENROLL: presentez la machine a l enrolement (PKI du handshake)" \
	> "$WORK/enroll-banner.txt"
socat TCP4-LISTEN:8080,bind=10.66.66.1,reuseaddr,fork \
	SYSTEM:"cat $WORK/enroll-banner.txt" >/dev/null 2>&1 &
echo $! >> "$WORK/pids"
echo "router-setup: service d'enrôlement sur 10.66.66.1:8080 (VLAN captif)"
