#!/usr/bin/env bash
# selftest.sh — T35 (issue #61) : auto-vérification complète des guides de
# déploiement. À lancer depuis la racine du dépôt :
#
#     bash deploy/selftest/selftest.sh
#
# Prérequis vérifiables : binaires `go` (≥ 1.24) et `opa` (≥ 1.0) dans le
# PATH, python3. En cas d'absence : STOP — le script sort en erreur avant
# tout test (fail-closed, pas de « skipped » silencieux).
#
# Effets :
#   1. selftest Go (mono réel + scale1 + scale2 + fencing 2-cellules in-process + daemons
#      brokerd/supervisord réels, T37) — rapport JSON dans
#      deploy/selftest/out/selftest-report.json (gitignoré) ;
#   2. vérification formelle des guides (D96/D99) par check_steps.py ;
#   3. tests unitaires du vérificateur (non-vacuité : mutations prises) ;
#   4. test du script d'isolation réseau (#186) contre de vrais écouteurs locaux.
#
# Code de sortie : 1 dès qu'un contrôle échoue.

set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$REPO_ROOT"

command -v go  >/dev/null 2>&1 || { echo "erreur: binaire 'go' introuvable — STOP" >&2; exit 1; }
command -v opa >/dev/null 2>&1 || { echo "erreur: binaire 'opa' introuvable — STOP" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "erreur: binaire 'python3' introuvable — STOP" >&2; exit 1; }

echo "== 1/4 selftest Go (mono + scale1 + scale2 + fencing + daemons) =="
go run ./deploy/selftest -phase all "$@"

echo "== 2/4 vérification formelle des guides (D96/D99) =="
python3 deploy/selftest/check_steps.py \
    deploy/README.md \
    deploy/router-debian.md \
    deploy/scale-1.md \
    deploy/scale-2.md \
    deploy/cellule.md \
    deploy/serveur.md \
    deploy/superviseur.md \
    deploy/monitor-to-closed.md

echo "== 3/4 non-vacuité du vérificateur =="
(cd deploy/selftest && python3 test_check_steps.py)

echo "== 4/4 vérification d'isolation réseau (#186) : le script est éprouvé par mutation =="
bash deploy/test_verify_network_isolation.sh

echo "selftest.sh: tout est vert"
