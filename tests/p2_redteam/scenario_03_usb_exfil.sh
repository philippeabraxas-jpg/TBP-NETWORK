#!/usr/bin/env bash
# scenario_03_usb_exfil.sh — T28 (issue #28), S3 : exfiltration USB (§5.2).
#
# Doctrine : l'USB est HORS portée réseau — la prévention est une
# compensation ENDPOINT (USBGuard / GPO / BIOS-IOMMU), pas un mécanisme
# TBP. Ce script est un CONSTAT, pas un faux test :
#   1. il recherche la compensation endpoint dans le dépôt ;
#   2. il inscrit le constat comme feuille d'évidence (D93) — y compris
#      quand la compensation est ABSENTE : le trou est déclaré, compté,
#      jamais maquillé en vert (« holes counted, never ignored »).
#
# Exécutable partout (aucun netns requis).
#
# Env : TBP_LAB (racine du dépôt), TBP_P2_OUT, TBP_P2_CELL.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export TBP_LAB=${TBP_LAB:-$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)}
OUT=${TBP_P2_OUT:-$TBP_LAB/tests/p2_redteam/out}
CELL=${TBP_P2_CELL:-tbp-cell-redteam}
mkdir -p "$OUT"

PASS=0; FAILL=0
ok()  { echo "ok: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*" >&2; FAILL=$((FAILL+1)); }

# --- constat : la compensation endpoint existe-t-elle dans le dépôt ? ----------
FOUND=""
for p in config/usbguard policies/usbguard usbguard; do
	[ -e "$TBP_LAB/$p" ] && FOUND="$FOUND $p"
done

if [ -n "$FOUND" ]; then
	ok "compensation endpoint présente :$FOUND"
	COMPENSATION="presente:$FOUND"
else
	# Ce n'est PAS un échec du scénario : c'est le constat honnête d'un
	# trou résiduel — déclaré dans run_report.json (S3-usb) et leafé ici.
	echo "constat: AUCUNE compensation USB (USBGuard/GPO/BIOS-IOMMU) dans le dépôt"
	echo "         → trou résiduel DÉCLARÉ (S3-usb) — compté, jamais ignoré"
	COMPENSATION="absente"
fi

# --- le constat est leafé : un trou déclaré est une preuve, pas un silence -----
EV=${TMPDIR:-/tmp}/t28-evidence-s3.$$.json
cat > "$EV" <<EOF
{"scenario":"S3","constat":"exfiltration USB hors portée réseau (§5.2)",
 "compensation_endpoint":"$COMPENSATION",
 "statut":"trou résiduel déclaré — la prévention USB est endpoint (USBGuard/GPO/BIOS-IOMMU), jamais un mécanisme réseau TBP"}
EOF
if command -v go >/dev/null 2>&1; then
	(cd "$TBP_LAB" && go run ./tests/p2_redteam/runner leaf-evidence \
		-out "$OUT" -cell "$CELL" -scenario S3 -evidence "$EV") \
		&& ok "constat S3 leafé (KindTelemetry, hash salé §6.2)" \
		|| bad "feuille de constat S3 impossible"
else
	cp "$EV" "$OUT/evidence-S3.json"
	echo "note: go absent — constat copié dans $OUT/evidence-S3.json ; le leafer au retour (leaf-evidence -scenario S3)"
fi
rm -f "$EV"

echo
echo "PASS=$PASS FAIL=$FAILL"
[ $FAILL -eq 0 ] && echo "S3 USB : VERT (constat leafé — trou déclaré, pas masqué)" || echo "S3 USB : ROUGE"
exit $FAILL
