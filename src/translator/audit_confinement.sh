#!/usr/bin/env bash
# audit_confinement.sh — vérification post-déploiement du confinement du
# traducteur (T24, issue #23, spec §4.5). À brancher dans la CI de
# déploiement et à rejouer après toute mise à jour de la pile vLLM/PyTorch.
#
# Vérifié ici (preuves lues dans /proc et systemd) :
#   - processus non-root dédié (Uid réel/effectif = utilisateur attendu) ;
#   - capabilities effectives VIDES (CapEff == 0) ;
#   - no_new_privs actif ; seccomp en mode filtre (Seccomp == 2) ;
#   - propriétés systemd de l'unit (ProtectSystem, familles d'adresses, …)
#     quand systemd est disponible ;
#   - dépendance réseau HONNÊTE : si le processus partage le netns de l'hôte,
#     le déni d'égress n'est PAS prouvé par le confinement — il reste porté
#     par nftables (config/nftables/) et cet audit le RAPPORTE en
#     avertissement au lieu de le prétendre fermé (§5.3). Si le processus a
#     un netns dédié, une route par défaut y est un ÉCHEC.
#
# Usage :
#   audit_confinement.sh --unit tbp-translator          # via systemctl (défaut)
#   audit_confinement.sh --pid <PID> [--user tbp-translator]
#   audit_confinement.sh --fixture <DIR> --uid <UID>    # CI hors systemd
#
# Codes de sortie : 0 = conforme (avertissements possibles), 1 = violation,
# 2 = erreur d'usage ou d'environnement.
#
# Mode fixture (tests offline et CI sans systemd) : DIR contient
#   status     — copie d'un /proc/<pid>/status
#   route      — copie d'un /proc/<pid>/net/route
#   route6     — copie d'un /proc/<pid>/net/ipv6_route
#   netns_pid  — chaîne « net:[NNN] » du namespace du processus
#   netns_init — chaîne « net:[NNN] » du namespace d'init

set -euo pipefail

UNIT=tbp-translator
USER_EXPECTED=tbp-translator
PID=""
FIXTURE=""
UID_EXPECTED=""
FAILS=0
WARNS=0

usage() {
	sed -n '2,30p' "$0"
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--unit) UNIT="${2:?--unit exige un nom}"; shift 2 ;;
	--pid) PID="${2:?--pid exige un pid}"; shift 2 ;;
	--user) USER_EXPECTED="${2:?--user exige un nom}"; shift 2 ;;
	--uid) UID_EXPECTED="${2:?--uid exige un entier}"; shift 2 ;;
	--fixture) FIXTURE="${2:?--fixture exige un répertoire}"; shift 2 ;;
	-h | --help) usage ;;
	*) echo "argument inconnu : $1" >&2; usage ;;
	esac
done

ok() { echo "  OK   $1"; }
warn() { echo "  WARN $1"; WARNS=$((WARNS + 1)); }
ko() { echo "  FAIL $1"; FAILS=$((FAILS + 1)); }

# --- lecture des sources (réel ou fixture) ---------------------------------

if [ -n "$FIXTURE" ]; then
	[ -f "$FIXTURE/status" ] || { echo "fixture : $FIXTURE/status absent" >&2; exit 2; }
	[ -n "$UID_EXPECTED" ] || { echo "--fixture exige --uid (pas de résolution de nom hors système)" >&2; exit 2; }
	STATUS=$FIXTURE/status
else
	if [ -z "$PID" ]; then
		command -v systemctl >/dev/null || { echo "systemctl absent : utiliser --pid ou --fixture" >&2; exit 2; }
		PID=$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null) \
			|| { echo "unit $UNIT illisible" >&2; exit 2; }
		[ "$PID" != "0" ] && [ -n "$PID" ] || { echo "unit $UNIT sans processus (inactive ?)" >&2; exit 2; }
	fi
	[ -r "/proc/$PID/status" ] || { echo "processus $PID illisible" >&2; exit 2; }
	STATUS=/proc/$PID/status
fi

field() { # field <NomChamp> → valeur(s) du champ dans status
	awk -v k="$1:" '$1 == k {sub(/^[^ \t]+[ \t]+/, ""); print; exit}' "$STATUS"
}

if [ -z "$UID_EXPECTED" ]; then
	UID_EXPECTED=$(id -u "$USER_EXPECTED" 2>/dev/null) \
		|| { echo "utilisateur $USER_EXPECTED inexistant" >&2; exit 2; }
fi

echo "audit_confinement — cible : ${FIXTURE:-pid $PID} ; uid attendu : $UID_EXPECTED ($USER_EXPECTED)"

# --- 1. utilisateur non-root dédié (§4.5) -----------------------------------

uids=$(field Uid) || true
set -- $uids
if [ "${1:-}" = "$UID_EXPECTED" ] && [ "${2:-}" = "$UID_EXPECTED" ] && [ "$UID_EXPECTED" != "0" ]; then
	ok "Uid réel/effectif = $UID_EXPECTED (non-root dédié)"
else
	ko "Uid '$uids' — attendu $UID_EXPECTED/$UID_EXPECTED, non-root (§4.5)"
fi

# --- 2. capabilities effectives vides (CAP_DROP_ALL) ------------------------

capeff=$(field CapEff) || true
if [ "$capeff" = "0000000000000000" ]; then
	ok "CapEff = 0 (toutes les capabilities sont tombées)"
else
	ko "CapEff = $capeff — attendu 0000000000000000 (CAP_DROP_ALL, §4.5)"
fi

# --- 3. no_new_privs ---------------------------------------------------------

nnp=$(field NoNewPrivs) || true
if [ "$nnp" = "1" ]; then
	ok "NoNewPrivs = 1"
else
	ko "NoNewPrivs = '$nnp' — attendu 1 (NoNewPrivileges=yes)"
fi

# --- 4. seccomp en mode filtre ----------------------------------------------

seccomp=$(field Seccomp) || true
case "$seccomp" in
2) ok "Seccomp = 2 (mode filtre strict)" ;;
1) ko "Seccomp = 1 (mode strict legacy, pas le filtre attendu)" ;;
*) ko "Seccomp = '$seccomp' — attendu 2 (seccomp strict, §4.5)" ;;
esac

# --- 5. propriétés systemd (si disponible, hors fixture) ---------------------

# systemd_usable : le binaire systemctl peut être présent (image minimale,
# CI, chroot) sans qu'un systemd tourne en PID 1 — « command -v systemctl »
# seul ne le détecte pas. Appelée UNIQUEMENT en position de condition (if) :
# sous set -e, un $(sous-shell) qui échoue hors condition/||/&& fait
# avorter tout le script (vérifié empiriquement) — ce qui, en pratique,
# faisait sauter silencieusement toute la section 6 (l'honnêteté netns) et
# le verdict final dès la 1ère propriété interrogée sur un hôte sans
# systemd fonctionnel, avec un code de sortie confondant crash d'outil et
# violation réelle (contrat documenté en tête de fichier : 2 = erreur
# d'environnement, pas 1).
systemd_usable() { systemctl show -p Id --value "$UNIT" >/dev/null 2>&1; }

if [ -z "$FIXTURE" ] && command -v systemctl >/dev/null && systemd_usable; then
	# 2>/dev/null || true : défense en profondeur — même la garde ci-dessus
	# passée, une requête de propriété individuelle ne doit jamais faire
	# avorter le script sous set -e (même raison que systemd_usable).
	show() { systemctl show -p "$1" --value "$UNIT" 2>/dev/null || true; }
	check_prop() { # check_prop <Propriété> <attendu>
		local got; got=$(show "$1")
		if [ "$got" = "$2" ]; then ok "$1=$2"; else ko "$1='$got' — attendu '$2'"; fi
	}
	check_prop ProtectSystem strict
	check_prop ProtectHome yes
	check_prop PrivateTmp yes
	check_prop NoNewPrivileges yes
	check_prop SystemCallArchitectures native
	caps=$(show CapabilityBoundingSet)
	if [ "$caps" = "0" ] || [ -z "$caps" ]; then
		ok "CapabilityBoundingSet vide"
	else
		ko "CapabilityBoundingSet='$caps' — attendu vide (CAP_DROP_ALL)"
	fi
	fam=$(show RestrictAddressFamilies)
	case "$fam" in
	*"AF_NETLINK"* | *"AF_PACKET"* | *"AF_BLUETOOTH"*)
		ko "RestrictAddressFamilies='$fam' — famille non prévue (v1 : AF_UNIX AF_INET AF_INET6)" ;;
	*"AF_UNIX"* | *"AF_INET"*)
		ok "RestrictAddressFamilies='$fam'" ;;
	*) ko "RestrictAddressFamilies='$fam' — restriction absente ou illisible" ;;
	esac
	mdwe=$(show MemoryDenyWriteExecute)
	if [ "$mdwe" = "yes" ]; then
		ok "MemoryDenyWriteExecute=yes (W^X, rendu possible par --enforce-eager)"
	else
		warn "MemoryDenyWriteExecute='$mdwe' — exception JIT ? Elle DOIT être documentée et justifiée (README src/translator/)"
	fi
elif [ -n "$FIXTURE" ]; then
	echo "  (fixture : propriétés systemd non vérifiées — par construction)"
else
	warn "systemctl absent ou non fonctionnel (pas de systemd en PID 1) : propriétés d'unit non vérifiées (seules les preuves /proc le sont)"
fi

# --- 6. netns et routes — honnêteté sur l'égress ----------------------------

if [ -n "$FIXTURE" ]; then
	NS_PID=$(cat "$FIXTURE/netns_pid" 2>/dev/null || echo "")
	NS_INIT=$(cat "$FIXTURE/netns_init" 2>/dev/null || echo "")
	ROUTE=$FIXTURE/route
	ROUTE6=$FIXTURE/route6
else
	NS_PID=$(readlink "/proc/$PID/ns/net" 2>/dev/null || echo "")
	NS_INIT=$(readlink /proc/1/ns/net 2>/dev/null || echo "")
	ROUTE=/proc/$PID/net/route
	ROUTE6=/proc/$PID/net/ipv6_route
fi

default_route_v4() { # 0 si une route par défaut IPv4 existe
	[ -f "$1" ] || return 1
	awk 'NR > 1 && $2 == "00000000" {found=1} END {exit !found}' "$1"
}
default_route_v6() { # 0 si une route par défaut IPv6 (::/0) existe
	[ -f "$1" ] || return 1
	awk '$1 == "00000000000000000000000000000000" && $2 == "00" {found=1} END {exit !found}' "$1"
}

if [ -n "$NS_PID" ] && [ -n "$NS_INIT" ] && [ "$NS_PID" != "$NS_INIT" ]; then
	# netns dédié : le confinement réseau est alors mesurable ici.
	if default_route_v4 "$ROUTE" || default_route_v6 "$ROUTE6"; then
		ko "netns dédié avec route par défaut — sortie possible (le service doit être local, §4.5)"
	else
		ok "netns dédié sans route par défaut (pas de sortie)"
	fi
else
	# netns partagé avec l'hôte (cas v1 de l'unit) : l'absence de route par
	# défaut dans /proc/<pid>/net/route ne prouverait rien — c'est la table
	# de l'hôte. On rapporte la dépendance au lieu de la prétendre fermée.
	warn "netns partagé avec l'hôte : le déni d'égress n'est PAS garanti par le confinement — il est porté par nftables (config/nftables/) ; vérifier la chaîne de sortie de l'hôte séparément (§5.3)"
fi

# --- verdict -----------------------------------------------------------------

echo "audit_confinement — $FAILS violation(s), $WARNS avertissement(s)"
[ "$FAILS" -eq 0 ]
