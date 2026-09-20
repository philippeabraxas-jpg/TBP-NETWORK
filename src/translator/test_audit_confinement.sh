#!/usr/bin/env bash
# test_audit_confinement.sh — test offline de audit_confinement.sh (T24,
# issue #23). Doctrine maison : chaque assertion de l'audit doit pouvoir
# ÉCHOUER — chaque mutation de fixture ci-dessous vise une assertion et
# vérifie qu'elle la détecte (non-vacuité), puis deux tests réels prouvent
# les assertions contre /proc (processus non confiné ; processus setpriv).
#
# Aucun systemd, aucun vLLM requis : le mode --fixture de l'audit est la
# couture de test. Usage : bash test_audit_confinement.sh

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
AUDIT=$HERE/audit_confinement.sh
W=$(mktemp -d /tmp/tbp-t24-audit.XXXXXX)
trap 'rm -rf "$W"' EXIT

PASS=0
FAIL=0

check() { # check <nom> <rc attendu> <sortie> [sous-chaîne attendue]
	local name=$1 want=$2 out=$3 needle=${4:-}
	local rc_ok=1 sub_ok=0
	if [ "$want" = "0" ]; then [ "$RC" = "0" ] && rc_ok=0; else [ "$RC" != "0" ] && rc_ok=0; fi
	if [ -n "$needle" ]; then printf '%s' "$out" | grep -q -- "$needle" && sub_ok=0 || sub_ok=1; fi
	if [ $rc_ok = 0 ] && [ $sub_ok = 0 ]; then
		echo "ok   $name"; PASS=$((PASS + 1))
	else
		echo "FAIL $name (rc=$RC, attendu $want ; motif '$needle')" ; echo "$out" | sed 's/^/     /'
		FAIL=$((FAIL + 1))
	fi
}

# mkfixture <dir> — fixture CONFORME : uid 4242 non-root, caps vides,
# no_new_privs, seccomp filtre, netns dédié sans route par défaut.
mkfixture() {
	local d=$1
	mkdir -p "$d"
	cat > "$d/status" <<'EOF'
Name:	vllm
Umask:	0077
State:	S (sleeping)
Pid:	4242
PPid:	1
Uid:	4242	4242	4242	4242
Gid:	4242	4242	4242	4242
NoNewPrivs:	1
Seccomp:	2
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
EOF
	# table de routage sans route par défaut (en-tête réel + route lien-local)
	printf 'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n' > "$d/route"
	printf 'eth0\t000011AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n' >> "$d/route"
	# ipv6 : uniquement une route /64 non par défaut
	printf 'fe8000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n' > "$d/route6"
	echo 'net:[4026535000]' > "$d/netns_pid"
	echo 'net:[4026531992]' > "$d/netns_init"
}

run_audit() { # run_audit <args...> — pose RC et OUT sans casser set -e
	set +e
	OUT=$(bash "$AUDIT" "$@" 2>&1)
	RC=$?
	set -e
}

echo "== fixtures : conforme puis mutations (non-vacuité de chaque assertion) =="

mkfixture "$W/base"
run_audit --fixture "$W/base" --uid 4242
check "fixture conforme acceptée" 0 "$OUT"

# Mutation : root
sed 's/^Uid:.*/Uid:\t0\t0\t0\t0/' "$W/base/status" > "$W/base/status.root"
mkdir -p "$W/m-root"; cp "$W/base/route" "$W/base/route6" "$W/base/netns_pid" "$W/base/netns_init" "$W/m-root/"; mv "$W/base/status.root" "$W/m-root/status"
run_audit --fixture "$W/m-root" --uid 4242
check "uid root détecté" 1 "$OUT" "Uid"

# Mutation : capabilities non vides
mkdir -p "$W/m-caps"; cp "$W/base/"* "$W/m-caps/"
sed -i 's/^CapEff:.*/CapEff:\t00000000a80425fb/' "$W/m-caps/status"
run_audit --fixture "$W/m-caps" --uid 4242
check "CapEff non vide détectée" 1 "$OUT" "CapEff"

# Mutation : no_new_privs absent
mkdir -p "$W/m-nnp"; cp "$W/base/"* "$W/m-nnp/"
sed -i 's/^NoNewPrivs:.*/NoNewPrivs:\t0/' "$W/m-nnp/status"
run_audit --fixture "$W/m-nnp" --uid 4242
check "NoNewPrivs=0 détecté" 1 "$OUT" "NoNewPrivs"

# Mutation : pas de filtre seccomp
mkdir -p "$W/m-seccomp"; cp "$W/base/"* "$W/m-seccomp/"
sed -i 's/^Seccomp:.*/Seccomp:\t0/' "$W/m-seccomp/status"
run_audit --fixture "$W/m-seccomp" --uid 4242
check "Seccomp=0 détecté" 1 "$OUT" "Seccomp"

# Mutation : seccomp mode legacy (1) — pas le filtre attendu
mkdir -p "$W/m-seccomp1"; cp "$W/base/"* "$W/m-seccomp1/"
sed -i 's/^Seccomp:.*/Seccomp:\t1/' "$W/m-seccomp1/status"
run_audit --fixture "$W/m-seccomp1" --uid 4242
check "Seccomp=1 (legacy) détecté" 1 "$OUT" "Seccomp"

# Mutation : netns dédié AVEC route par défaut IPv4 → échec
mkdir -p "$W/m-route"; cp "$W/base/"* "$W/m-route/"
printf 'eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n' >> "$W/m-route/route"
run_audit --fixture "$W/m-route" --uid 4242
check "route par défaut v4 en netns dédié détectée" 1 "$OUT" "route par défaut"

# Mutation : route par défaut IPv6 (::/0) en netns dédié → échec
mkdir -p "$W/m-route6"; cp "$W/base/"* "$W/m-route6/"
printf '00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000100 00000001 00000000 00000001 eth0\n' >> "$W/m-route6/route6"
run_audit --fixture "$W/m-route6" --uid 4242
check "route par défaut v6 en netns dédié détectée" 1 "$OUT" "route par défaut"

# Fixture netns PARTAGÉ (pid == init) : avertissement honnêteté, pas d'échec
mkdir -p "$W/m-shared"; cp "$W/base/"* "$W/m-shared/"
cp "$W/base/netns_init" "$W/m-shared/netns_pid"
printf 'eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n' >> "$W/m-shared/route"
run_audit --fixture "$W/m-shared" --uid 4242
check "netns partagé → avertissement nftables, pas d'échec" 0 "$OUT" "nftables"

# Usage fautif : fixture sans --uid
run_audit --fixture "$W/base"
check "fixture sans --uid → usage (rc 2)" 2 "$OUT"
[ "$RC" = 2 ] || { echo "FAIL rc fixture sans uid = $RC, veut 2"; FAIL=$((FAIL + 1)); }

echo "== tests réels contre /proc (preuves non simulées) =="

# Processus NON confiné (ce shell, root dans la CI de dev) : l'audit doit
# échouer — preuve que les assertions lisent bien /proc et mordent.
sleep 60 & LOOSE=$!
run_audit --pid $LOOSE --user "$(id -un)"
kill $LOOSE 2>/dev/null || true
if [ "$(id -u)" = "0" ]; then
	check "processus root non confiné rejeté" 1 "$OUT" "Uid"
else
	# non-root mais non confiné : CapEff/Seccomp doivent mordre
	check "processus non-root non confiné rejeté" 1 "$OUT"
fi
# Preuve que le script va JUSQU'AU BOUT (section 6 + verdict), pas
# seulement jusqu'à la 1re assertion qui mord. Trouvé en revue de #64 :
# sur un hôte où `systemctl` est présent mais non fonctionnel (systemd pas
# en PID 1 — image minimale, CI, chroot ; cas fréquent, distinct de
# « systemctl absent » qui était déjà géré), la section 5 (propriétés
# systemd) faisait avorter tout le script via set -e à la toute première
# requête `systemctl show`, AVANT la section 6 (l'honnêteté netns/egress —
# la contribution la plus spécifique de cet outil) et avant la ligne de
# verdict — silencieusement, avec un code de sortie qui ressemble à
# « violation trouvée » (1) sans l'être (contrat documenté : 2 = erreur
# d'environnement). Cette assertion aurait échoué avant le correctif.
check "le script va jusqu'au verdict final (pas de crash mi-parcours)" 1 "$OUT" "violation(s)"
case "$OUT" in
*"netns partagé"* | *"netns dédié"*)
	echo "ok   section 6 (netns/egress) atteinte" ; PASS=$((PASS + 1)) ;;
*)
	echo "FAIL section 6 (netns/egress) jamais atteinte — le script s'est arrêté avant"
	FAIL=$((FAIL + 1)) ;;
esac

# Processus setpriv : non-root, caps vidées, no_new_privs — tout doit passer
# SAUF Seccomp (=0 : setpriv ne pose pas de filtre). Preuve que l'assertion
# seccomp est indépendante des autres et détecte l'absence réelle de filtre.
if command -v setpriv >/dev/null && [ "$(id -u)" = "0" ]; then
	setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
		--inh-caps=-all --ambient-caps=-all --bounding-set=-all sleep 60 &
	SP=$!
	run_audit --pid $SP --uid 65534 --user nobody
	kill $SP 2>/dev/null || true
	check "setpriv : confinement partiel reconnu, seccomp absent détecté" 1 "$OUT" "Seccomp"
	case "$OUT" in
	*"FAIL CapEff"*) echo "FAIL test setpriv : CapEff aurait dû passer"; FAIL=$((FAIL + 1)) ;;
	*) echo "ok   setpriv : CapEff vide confirmée en réel"; PASS=$((PASS + 1)) ;;
	esac
	case "$OUT" in
	*"OK   NoNewPrivs"*) echo "ok   setpriv : NoNewPrivs confirmé en réel"; PASS=$((PASS + 1)) ;;
	*) echo "FAIL test setpriv : NoNewPrivs aurait dû passer"; FAIL=$((FAIL + 1)) ;;
	esac
else
	echo "skip setpriv (non-root ou setpriv absent) — fixtures seules"
fi

echo "test_audit_confinement — $PASS ok, $FAIL échec(s)"
[ "$FAIL" -eq 0 ]
