#!/usr/bin/env bash
# verify_network_isolation.sh — vérifie, ACTIVEMENT, qu'aucune route de sortie autre que TBP
# n'existe depuis le contexte réseau d'un agent de la cellule (issue #186).
#
# Pourquoi : « l'agent ne peut pas contourner TBP pour sortir » n'est pas une propriété du code de
# TBP, c'est une propriété du déploiement (VLAN dédié, nftables qui force toute sortie vers le proxy
# bloquant du PEP). Une IA prendra la route hors TBP si elle existe : la garantie ne peut pas reposer
# sur une configuration SUPPOSÉE correcte, elle se teste, à chaque déploiement.
#
# Ce qui est vérifié :
#   1. CONTRÔLE POSITIF — la destination autorisée (le proxy bloquant du PEP) est JOIGNABLE depuis ce
#      contexte. Sans lui, « tout échoue » ne prouve rien (réseau simplement tombé) : erreur (2),
#      jamais un faux « conforme ».
#   2. SONDES NÉGATIVES — des connexions TCP vers des destinations arbitraires (IP internet v4 et
#      v6, un nom DNS) doivent TOUTES échouer. Une connexion qui aboutit = route de sortie = violation.
#   3. RÈGLES CHARGÉES — le noyau a réellement la table nftables attendue, avec au moins une règle
#      qui bloque ou redirige (pas seulement un fichier .nft sur le disque).
#
# Où l'exécuter : DEPUIS le contexte réseau de l'agent (c'est ce contexte qu'on éprouve).
#   --netns NOM    exécute les sondes via « ip netns exec NOM »
#   --pid PID      exécute les sondes via « nsenter -t PID -n » (conteneur, unit systemd)
#   --as-user U    exécute les sondes sous l'utilisateur U (règles nftables « meta skuid »)
#   sans option    le contexte courant
#
# Usage :
#   verify_network_isolation.sh --allow 127.0.0.1:9443 [--mode report|strict]
#       [--probe HOTE:PORT]… [--table inet:tbp_pep] [--no-nft] [--timeout 3]
#       [--netns NOM | --pid PID] [--as-user U]
#   verify_network_isolation.sh --fixture DIR --allow … # tests/CI : lit DIR/ruleset au lieu de nft
#
# Modes (cohérents avec « monitor avant closed », §5.3) :
#   report  (défaut)  affiche tout, sort 0 même s'il y a des violations — calibration d'un déploiement
#   strict            toute violation sort 1 — à brancher comme garde de déploiement
# Codes de sortie (comme audit_confinement.sh) : 0 = conforme (ou rapport seul), 1 = violation,
# 2 = erreur d'usage ou d'environnement (dont contrôle positif échoué, règles illisibles en strict).
#
# Limites, dites ici pour ne pas être lues comme une garantie : seules les connexions TCP sont
# sondées (pas UDP, pas ICMP, pas les canaux couverts : DNS-sur-HTTPS vers un hôte autorisé…) ; un
# échec de sonde n'est pas la preuve d'une règle (un hôte peut être simplement éteint) — d'où la
# liste de sondes variée et le contrôle positif ; cela atteste l'état AU MOMENT de l'exécution.

set -uo pipefail

MODE=report
ALLOW=""
PROBES=()
TABLE="inet:tbp_pep"
CHECK_NFT=1
TIMEOUT=3
FIXTURE=""
PREFIX=()

DEFAULT_PROBES=("1.1.1.1:443" "9.9.9.9:443" "8.8.8.8:53" "[2606:4700:4700::1111]:443" "example.com:443")

usage() { sed -n '2,38p' "$0"; exit 2; }
die() { echo "verify_network_isolation: $1" >&2; exit 2; }

while [ $# -gt 0 ]; do
	case "$1" in
	--mode) MODE="${2:?--mode exige report|strict}"; shift 2 ;;
	--allow) ALLOW="${2:?--allow exige HOTE:PORT}"; shift 2 ;;
	--probe) PROBES+=("${2:?--probe exige HOTE:PORT}"); shift 2 ;;
	--table) TABLE="${2:?--table exige FAMILLE:NOM}"; shift 2 ;;
	--no-nft) CHECK_NFT=0; shift ;;
	--timeout) TIMEOUT="${2:?--timeout exige des secondes}"; shift 2 ;;
	--fixture) FIXTURE="${2:?--fixture exige un répertoire}"; shift 2 ;;
	--netns) PREFIX=(ip netns exec "${2:?--netns exige un nom}"); shift 2 ;;
	--pid) PREFIX=(nsenter -t "${2:?--pid exige un pid}" -n); shift 2 ;;
	--as-user) PREFIX+=(runuser -u "${2:?--as-user exige un nom}" --); shift 2 ;;
	-h | --help) usage ;;
	*) echo "argument inconnu : $1" >&2; usage ;;
	esac
done

case "$MODE" in report | strict) ;; *) die "--mode : report ou strict" ;; esac
[ -n "$ALLOW" ] || die "--allow HOTE:PORT requis (le proxy bloquant du PEP : sans contrôle positif, un test réseau ne prouve rien)"
case "$TIMEOUT" in '' | *[!0-9]*) die "--timeout : entier de secondes" ;; esac
[ ${#PROBES[@]} -gt 0 ] || PROBES=("${DEFAULT_PROBES[@]}")
command -v timeout >/dev/null || die "« timeout » (coreutils) requis"

FAILS=0
ok() { echo "  OK   $1"; }
warn() { echo "  WARN $1"; }
ko() { echo "  FAIL $1"; FAILS=$((FAILS + 1)); }

# split_hostport HOTE:PORT ou [v6]:PORT → HOST et PORT
split_hostport() {
	local hp=$1
	case "$hp" in
	\[*\]:*) HOST=${hp%%]:*}; HOST=${HOST#[}; PORT=${hp##*]:} ;;
	*:*) HOST=${hp%:*}; PORT=${hp##*:} ;;
	*) return 1 ;;
	esac
	case "$PORT" in '' | *[!0-9]*) return 1 ;; esac
	[ -n "$HOST" ]
}

# can_connect HOTE:PORT → 0 si une connexion TCP aboutit depuis le contexte réseau choisi
can_connect() {
	split_hostport "$1" || die "destination mal formée : $1 (HOTE:PORT ou [v6]:PORT)"
	${PREFIX[@]+"${PREFIX[@]}"} timeout "$TIMEOUT" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$HOST" "$PORT" >/dev/null 2>&1
}

echo "verify_network_isolation — mode $MODE ; autorisé : $ALLOW ; contexte : ${PREFIX[*]:-courant}"

# --- 1. contrôle positif ------------------------------------------------------------------------
if can_connect "$ALLOW"; then
	ok "contrôle positif : $ALLOW joignable (le test réseau est valide)"
else
	echo "  ERR  contrôle positif : $ALLOW INJOIGNABLE depuis ce contexte — « tout échoue » ne prouverait rien (réseau tombé, mauvais contexte, proxy éteint ?)" >&2
	exit 2
fi

# --- 2. sondes négatives -------------------------------------------------------------------------
for p in "${PROBES[@]}"; do
	if [ "$p" = "$ALLOW" ]; then continue; fi
	if can_connect "$p"; then
		ko "route de sortie : connexion à $p ABOUTIE hors du proxy TBP"
	else
		ok "sortie refusée : $p"
	fi
done

# --- 3. règles chargées dans le noyau ------------------------------------------------------------
if [ "$CHECK_NFT" = 1 ]; then
	family=${TABLE%%:*}; tname=${TABLE#*:}
	rules=""; rules_ok=0
	if [ -n "$FIXTURE" ]; then
		[ -f "$FIXTURE/ruleset" ] || die "fixture : $FIXTURE/ruleset absent"
		rules=$(cat "$FIXTURE/ruleset"); rules_ok=1
	elif command -v nft >/dev/null && rules=$(nft list table "$family" "$tname" 2>/dev/null); then
		rules_ok=1
	elif command -v nft >/dev/null && nft list ruleset >/dev/null 2>&1; then
		rules_ok=1; rules=""   # lisible mais la table attendue n'y est pas
	fi
	if [ "$rules_ok" = 0 ]; then
		if [ "$MODE" = strict ]; then
			echo "  ERR  règles nftables illisibles (nft absent ou droits insuffisants) : non vérifiable en mode strict — --no-nft pour l'assumer" >&2
			exit 2
		fi
		warn "règles nftables illisibles (nft absent ou droits insuffisants) — non vérifiées"
	elif [ -z "$rules" ]; then
		ko "table nftables $family $tname ABSENTE du noyau (un fichier .nft sur le disque n'est pas une règle chargée)"
	else
		# une règle ACTIVE (non commentée) qui bloque ou redirige, ou une chaîne en policy drop
		active=$(printf '%s\n' "$rules" | sed 's/#.*//')
		if printf '%s\n' "$active" | grep -Eq '(^|[[:space:]])(redirect|drop|reject)([[:space:]]|$)|policy[[:space:]]+drop'; then
			ok "table nftables $family $tname chargée, avec au moins une règle qui bloque ou redirige"
		else
			ko "table nftables $family $tname chargée mais SANS règle active qui bloque ou redirige (squelette non calibré ?)"
		fi
	fi
else
	warn "règles nftables non vérifiées (--no-nft)"
fi

# --- verdict -------------------------------------------------------------------------------------
if [ "$FAILS" -eq 0 ]; then
	echo "verdict : CONFORME — aucune route de sortie hors TBP détectée (TCP, ${#PROBES[@]} sondes)"
	exit 0
fi
if [ "$MODE" = report ]; then
	echo "verdict : $FAILS VIOLATION(S) — mode report : sortie 0 (calibration). Passer en --mode strict avant de déclarer la cellule fermée."
	exit 0
fi
echo "verdict : $FAILS VIOLATION(S) — mode strict"
exit 1
