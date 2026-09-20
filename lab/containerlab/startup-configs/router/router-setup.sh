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
SEDEXPR=
for v in 10 20 33 66 77 99; do
	SEDEXPR="$SEDEXPR;s/= eth0\\.$v/= $TRUNK.$v/"
done
sed -e "${SEDEXPR#;}" "$LAB/config/nftables/router-p1.nft" > "$RUNNFT"
$NFT -f "$RUNNFT"
echo "router-setup: mur nftables chargé (router-p1.nft, trunk $TRUNK)"

# --- services hébergés : les SEULES voies offertes aux VLANs fermés ------------
# bannière lue depuis un fichier (socat SYSTEM avec un message quoté
# multi-mots échoue silencieusement — constaté au test).
banner() { # banner <fichier> <message>
	echo "$2" > "$WORK/$1"
}
banner enroll-banner.txt "TBP-ENROLL: presentez la machine a l enrolement (PKI du handshake)"
banner rem-banner.txt "TBP-REMEDIATION: verification du certificat indisponible (CRL/OCSP) — contactez l exploitant, aucun acces production"
banner telemetry-banner.txt "TBP-TELEMETRY: collecteur IoT (placeholder T21)"
serve() { # serve <ip> <port> <fichier>
	socat TCP4-LISTEN:$2,bind=$1,reuseaddr,fork \
		SYSTEM:"cat $WORK/$3" >/dev/null 2>&1 &
	echo $! >> "$WORK/pids"
}
# captif → enrôlement ; remédiation → feedback explicite (§5.3) ;
# IoT → télémétrie uniquement (canal instrumenté, jamais silencieux).
serve 10.66.66.1 8080 enroll-banner.txt
serve 10.77.77.1 8080 rem-banner.txt
serve 10.33.33.1 8888 telemetry-banner.txt
echo "router-setup: enrôlement 10.66.66.1:8080, remédiation 10.77.77.1:8080, télémétrie IoT 10.33.33.1:8888"
