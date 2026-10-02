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
	# « any » : seul le motif compte (le code de sortie dépend de l'utilisateur qui lance le test : root ⇒ violation Uid)
	if [ "$want" = "any" ]; then rc_ok=0
	elif [ "$want" = "0" ]; then [ "$RC" = "0" ] && rc_ok=0; else [ "$RC" != "0" ] && rc_ok=0; fi
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
Seccomp_filters:	1
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

# wait_comm <pid> <nom> : attend que le processus ait fait son exec (comm = nom). Sans cela, l'audit lit /proc d'un
# setpriv ENCORE root et plein de capabilities (course préexistante : les assertions « CapEff vide » passaient
# ou échouaient selon l'ordonnancement).
wait_comm() {
	local i
	for i in $(seq 1 100); do
		[ "$(cat "/proc/$1/comm" 2>/dev/null)" = "$2" ] && return 0
		sleep 0.05
	done
	echo "FAIL le processus $1 n'a pas atteint l'exec de '$2' (comm='$(cat "/proc/$1/comm" 2>/dev/null)')"
	FAIL=$((FAIL + 1))
	return 1
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
# Revue tierce 4.8 : « Seccomp = 2 » ne dit pas QUEL filtre — l'audit hors unit le rapporte au lieu de le prétendre
check "fixture : l'origine du filtre seccomp n'est PAS prétendue établie" 0 "$OUT" "origine du filtre seccomp NON établie"
check "fixture : le nombre de filtres attachés est rapporté" 0 "$OUT" "1 filtre(s) attaché(s)"

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
#
# Dans un CONTENEUR (revue tierce 4.8), le runtime pose déjà un filtre seccomp que setpriv hérite : le processus
# est alors « Seccomp: 2 » sans que personne ne l'ait voulu, et « l'absence de filtre » ne peut pas être éprouvée.
# Le test le DÉTECTE (état ambiant lu dans /proc/self/status) et saute cette seule assertion, dite à voix haute —
# au lieu d'échouer pour une raison qui n'est pas un défaut de l'audit.
if command -v setpriv >/dev/null && [ "$(id -u)" = "0" ]; then
	AMBIENT_SECCOMP=$(awk '$1 == "Seccomp:" {print $2}' /proc/self/status)
	setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
		--inh-caps=-all --ambient-caps=-all --bounding-set=-all sleep 60 &
	SP=$!
	wait_comm $SP sleep || true
	run_audit --pid $SP --uid 65534 --user nobody
	kill $SP 2>/dev/null || true
	if [ "$AMBIENT_SECCOMP" = "2" ]; then
		echo "skip setpriv/seccomp : filtre seccomp hérité de l'environnement (conteneur) — l'absence de filtre ne peut pas être éprouvée ici ; l'audit rapporte l'origine non établie :"
		check "setpriv (filtre hérité) : le filtre est vu, mais son ORIGINE n'est pas prétendue établie" 0 "$OUT" "origine du filtre seccomp NON établie"
	else
		check "setpriv : confinement partiel reconnu, seccomp absent détecté" 1 "$OUT" "Seccomp"
	fi
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

echo "== origine du filtre seccomp : unit systemd simulée (systemctl de substitution dans le PATH) =="

# systemctl de substitution : MainPID et SystemCallFilter pilotés par l'environnement du test. Il ne simule QUE
# les requêtes `show -p <prop> --value <unit>` que l'audit émet.
mkdir -p "$W/bin"
cat > "$W/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
[ "${1:-}" = show ] || exit 1
prop=$3
case "$prop" in
Id) echo "tbp-translator.service" ;;
MainPID) echo "${STUB_MAINPID:-0}" ;;
SystemCallFilter) printf '%s\n' "${STUB_SCF-@system-service}" ;;
ProtectSystem) echo strict ;;
ProtectHome) echo yes ;;
PrivateTmp) echo yes ;;
NoNewPrivileges) echo yes ;;
SystemCallArchitectures) echo native ;;
CapabilityBoundingSet) echo "" ;;
RestrictAddressFamilies) echo "AF_UNIX AF_INET AF_INET6" ;;
MemoryDenyWriteExecute) echo yes ;;
*) echo "" ;;
esac
STUB
chmod +x "$W/bin/systemctl"

# un processus réellement filtré (Seccomp: 2) : python3 pose un filtre « tout autoriser » via prctl, puis dort. C'est
# lui que l'on audite — l'avertissement d'origine ne se lit que sur un processus qui a un filtre.
python3 - <<'PY' &
import ctypes, struct, time
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(38, 1, 0, 0, 0) == 0                       # PR_SET_NO_NEW_PRIVS
buf = ctypes.create_string_buffer(struct.pack("HBBI", 0x06, 0, 0, 0x7fff0000))  # BPF_RET | SECCOMP_RET_ALLOW
class Prog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
prog = Prog(1, ctypes.addressof(buf))
assert libc.prctl(22, 2, ctypes.byref(prog)) == 0             # PR_SET_SECCOMP, SECCOMP_MODE_FILTER
time.sleep(60)
PY
TARGET=$!
for _ in $(seq 1 100); do [ "$(awk '$1 == "Seccomp:" {print $2}' /proc/$TARGET/status 2>/dev/null)" = "2" ] && break; sleep 0.05; done
[ "$(awk '$1 == "Seccomp:" {print $2}' /proc/$TARGET/status 2>/dev/null)" = "2" ] \
	|| { echo "FAIL le processus de test n'a pas de filtre seccomp (prctl refusé ?)"; FAIL=$((FAIL + 1)); }
audit_unit() { # audit_unit <MainPID> <SystemCallFilter> — le processus audité est TARGET
	set +e
	OUT=$(PATH="$W/bin:$PATH" STUB_MAINPID="$1" STUB_SCF="$2" bash "$AUDIT" --pid $TARGET --uid "$(id -u)" --user "$(id -un)" 2>&1)
	RC=$?
	set -e
}

# unit conforme : le processus EST le MainPID et l'unit déclare le filtre → origine établie, pas d'avertissement
audit_unit "$TARGET" "@system-service"
check "unit : SystemCallFilter déclaré (@system-service) vu" any "$OUT" "OK   SystemCallFilter déclaré"
case "$OUT" in
*"origine du filtre seccomp NON établie"*) echo "FAIL unit conforme : l'origine aurait dû être établie"; FAIL=$((FAIL + 1)) ;;
*) echo "ok   unit conforme : l'origine du filtre est établie (MainPID + SystemCallFilter)"; PASS=$((PASS + 1)) ;;
esac

# mutation : l'unit ne déclare AUCUN filtre → échec (le « Seccomp = 2 » ne serait pas celui du traducteur)
audit_unit "$TARGET" ""
check "unit sans SystemCallFilter : échec" 1 "$OUT" "SystemCallFilter vide"

# mutation : le processus audité n'est PAS le MainPID de l'unit → l'origine n'est pas établie
audit_unit "1" "@system-service"
check "processus ≠ MainPID de l'unit : origine non établie" any "$OUT" "origine du filtre seccomp NON établie"

# mutation : filtre déclaré mais autre profil → avertissement, l'origine reste établie par le MainPID
audit_unit "$TARGET" "@raw-io"
check "SystemCallFilter d'un autre profil : avertissement" any "$OUT" "ne mentionne pas @system-service"
kill $TARGET 2>/dev/null || true

echo "test_audit_confinement — $PASS ok, $FAIL échec(s)"
[ "$FAIL" -eq 0 ]
