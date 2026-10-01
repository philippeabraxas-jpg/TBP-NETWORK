#!/usr/bin/env bash
# test_verify_network_isolation.sh — test hors-ligne de verify_network_isolation.sh (issue #186).
# Doctrine maison : chaque assertion du script doit pouvoir ÉCHOUER. On l'éprouve avec de vrais
# écouteurs TCP locaux : « autorisé » = un écouteur, « route de sortie » = un autre écouteur (la
# connexion aboutit), « sortie refusée » = un port fermé. Aucun accès réseau externe.
# Usage : bash deploy/test_verify_network_isolation.sh

set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
V=$HERE/verify_network_isolation.sh
W=$(mktemp -d /tmp/tbp-186.XXXXXX)
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT

PASS=0; FAIL=0
check() { # check <nom> <rc attendu> <motif attendu ou ''> <rc réel> <sortie>
	local name=$1 want=$2 needle=$3 rc=$4 out=$5 good=1
	[ "$rc" = "$want" ] && good=0
	if [ -n "$needle" ] && ! printf '%s' "$out" | grep -q -- "$needle"; then good=1; fi
	if [ $good = 0 ]; then echo "ok   $name"; PASS=$((PASS + 1))
	else echo "FAIL $name (rc=$rc, attendu $want ; motif '$needle')"; printf '%s\n' "$out" | sed 's/^/     /'; FAIL=$((FAIL + 1)); fi
}

# écouteur(s) locaux : ports libres choisis par le noyau
listen() { # listen <fichier-port> : lance un écouteur, écrit son port
	python3 - "$1" <<'PY' &
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
while True:
    c, _ = s.accept(); c.close()
PY
	PIDS+=($!)
	for _ in $(seq 50); do [ -s "$1" ] && return 0; sleep 0.1; done
	echo "écouteur non démarré" >&2; exit 2
}
listen "$W/allow.port"; listen "$W/leak.port"
ALLOW=127.0.0.1:$(cat "$W/allow.port"); LEAK=127.0.0.1:$(cat "$W/leak.port")
# un port fermé : on lie puis on ferme
CLOSED_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
CLOSED=127.0.0.1:$CLOSED_PORT

run() { OUT=$("$@" 2>&1); RC=$?; }

# 1. conforme : autorisé joignable, sondes toutes refusées
run bash "$V" --allow "$ALLOW" --probe "$CLOSED" --no-nft --mode strict --timeout 2
check "conforme : autorisé joignable, sortie refusée" 0 "CONFORME" "$RC" "$OUT"

# 2. route de sortie (le « leak » aboutit) : strict → 1, report → 0 mais VIOLATION affichée
run bash "$V" --allow "$ALLOW" --probe "$LEAK" --probe "$CLOSED" --no-nft --mode strict --timeout 2
check "strict : une route de sortie est une violation" 1 "route de sortie" "$RC" "$OUT"
run bash "$V" --allow "$ALLOW" --probe "$LEAK" --no-nft --mode report --timeout 2
check "report : violation affichée mais sortie 0 (calibration)" 0 "VIOLATION" "$RC" "$OUT"

# 3. contrôle positif échoué : « tout échoue » ne doit jamais passer pour conforme
run bash "$V" --allow "$CLOSED" --probe "$CLOSED" --no-nft --mode strict --timeout 2
check "contrôle positif injoignable → erreur 2, pas « conforme »" 2 "INJOIGNABLE" "$RC" "$OUT"

# 4. la destination autorisée n'est pas comptée comme fuite quand elle figure aussi parmi les sondes
run bash "$V" --allow "$ALLOW" --probe "$ALLOW" --probe "$CLOSED" --no-nft --mode strict --timeout 2
check "l'autorisé parmi les sondes n'est pas une fuite" 0 "CONFORME" "$RC" "$OUT"

# 5. usage
run bash "$V" --probe "$CLOSED"
check "sans --allow : erreur d'usage (2)" 2 "--allow" "$RC" "$OUT"
run bash "$V" --allow "pas-un-hote" --no-nft
check "destination mal formée : erreur (2)" 2 "mal formée" "$RC" "$OUT"
run bash "$V" --allow "$ALLOW" --mode lax
check "mode inconnu : erreur (2)" 2 "report ou strict" "$RC" "$OUT"

# 6. règles nftables (fixture : copie d'un « nft list table »)
mkdir -p "$W/fx"
cat > "$W/fx/ruleset" <<'RS'
table inet tbp_pep {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 10.20.0.0/24 tcp dport { 80, 443 } redirect to :8443
	}
}
RS
run bash "$V" --allow "$ALLOW" --probe "$CLOSED" --fixture "$W/fx" --mode strict --timeout 2
check "règle redirect active chargée : conforme" 0 "chargée, avec au moins une règle" "$RC" "$OUT"

# squelette non calibré : la règle est COMMENTÉE (comme config/nftables/pep-redirect.nft) → violation
cat > "$W/fx/ruleset" <<'RS'
table inet tbp_pep {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		# ip daddr <VLAN_SERVEURS_CIDR> tcp dport { 80, 443 } redirect to :$PEP_PORT
	}
}
RS
run bash "$V" --allow "$ALLOW" --probe "$CLOSED" --fixture "$W/fx" --mode strict --timeout 2
check "squelette dont la règle est commentée : violation" 1 "SANS règle active" "$RC" "$OUT"

: > "$W/fx/ruleset"
run bash "$V" --allow "$ALLOW" --probe "$CLOSED" --fixture "$W/fx" --mode strict --timeout 2
check "table absente du noyau : violation" 1 "ABSENTE" "$RC" "$OUT"

# policy drop sur la chaîne de sortie : accepté
cat > "$W/fx/ruleset" <<'RS'
table inet tbp_pep {
	chain output { type filter hook output priority filter; policy drop; }
}
RS
run bash "$V" --allow "$ALLOW" --probe "$CLOSED" --fixture "$W/fx" --mode strict --timeout 2
check "policy drop : conforme" 0 "CONFORME" "$RC" "$OUT"

# 7. règles illisibles : strict refuse de conclure (2) ; report avertit
FAKEBIN=$W/bin; mkdir -p "$FAKEBIN"; printf '#!/bin/sh\nexit 1\n' > "$FAKEBIN/nft"; chmod +x "$FAKEBIN/nft"
run env PATH="$FAKEBIN:$PATH" bash "$V" --allow "$ALLOW" --probe "$CLOSED" --mode strict --timeout 2
check "nft illisible en strict : erreur (2), pas « conforme »" 2 "illisibles" "$RC" "$OUT"
run env PATH="$FAKEBIN:$PATH" bash "$V" --allow "$ALLOW" --probe "$CLOSED" --mode report --timeout 2
check "nft illisible en report : avertissement" 0 "WARN" "$RC" "$OUT"

# 8. IPv6 : le format [v6]:port est analysé (pas de route v6 ici : refusé, sans erreur de format)
run bash "$V" --allow "$ALLOW" --probe "[::1]:$CLOSED_PORT" --no-nft --mode strict --timeout 2
check "sonde IPv6 bien formée" 0 "CONFORME" "$RC" "$OUT"

echo; echo "verify_network_isolation : $PASS ok, $FAIL en échec"
[ "$FAIL" -eq 0 ]
