#!/bin/sh
# scripts/genesis/genesis_dev.sh — T3 (issue #2)
#
# ⚠ DEV/TEST UNIQUEMENT. SoftHSM n'est jamais une racine de confiance de
# gouvernance (spec §12). La cérémonie de genèse réelle est PROCÉDURALE,
# pas du code : quorum de contrôleurs humains, HSM véritables, canal
# hors-bande authentifié (§3.2, §7.2) — voir README.md de ce répertoire.
#
# Ce script prépare un environnement de développement complet :
#   1. initialise un token SoftHSM « tbp-genesis-dev » (si absent) ;
#   2. génère n paires Ed25519 de contrôleurs dans le token (§12 :
#      Ed25519 partout) ;
#   3. signe le jeton d'epoch 0 à m-of-n (§7.2 : (N, authority, ~60 s)) ;
#   4. écrit un ancrage hors-bande SIMULÉ (fichier séparé — en réel, un
#      canal authentifié indépendant) ;
#   5. vérifie le tout (quorum de signataires distincts + ancrage).
#
# Usage :
#   scripts/genesis/genesis_dev.sh
# Variables (toutes optionnelles, valeurs de dev) :
#   N=3 M=2 AUTHORITY=cell-a GENESIS_HOME=scripts/genesis/out
#   TBP_DEV_PIN=0000 TBP_DEV_SOPIN=1234
#   SOFTHSM2_MODULE=/chemin/libsofthsm2.so   (détection automatique sinon)

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

N=${N:-3}
M=${M:-2}
AUTHORITY=${AUTHORITY:-cell-a}
GENESIS_HOME=${GENESIS_HOME:-"${SCRIPT_DIR}/out"}
TBP_DEV_PIN=${TBP_DEV_PIN:-0000}
TBP_DEV_SOPIN=${TBP_DEV_SOPIN:-1234}
export TBP_DEV_PIN

echo "=== genesis_dev — DEV/TEST UNIQUEMENT (SoftHSM, spec §12) ==="

# --- Pré-requis ------------------------------------------------------------
command -v softhsm2-util >/dev/null 2>&1 || {
    echo "erreur: softhsm2-util introuvable (paquet softhsm2)" >&2; exit 1; }
command -v go >/dev/null 2>&1 || {
    echo "erreur: go introuvable" >&2; exit 1; }

# --- Module PKCS#11 ----------------------------------------------------------
if [ -z "${SOFTHSM2_MODULE:-}" ]; then
    for c in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        [ -f "$c" ] && SOFTHSM2_MODULE=$c && break
    done
fi
[ -n "${SOFTHSM2_MODULE:-}" ] && [ -f "$SOFTHSM2_MODULE" ] || {
    echo "erreur: libsofthsm2.so introuvable — renseigner SOFTHSM2_MODULE" >&2; exit 1; }
export SOFTHSM2_MODULE

# --- Configuration SoftHSM isolée (rien hors de GENESIS_HOME) --------------
mkdir -p "${GENESIS_HOME}/tokens"
SOFTHSM2_CONF="${GENESIS_HOME}/softhsm2.conf"
export SOFTHSM2_CONF
cat > "$SOFTHSM2_CONF" <<EOF
# Généré par genesis_dev.sh — configuration SoftHSM de dev isolée
directories.tokendir = ${GENESIS_HOME}/tokens
objectstore.backend = file
log.level = ERROR
slots.removable = false
EOF

# --- 1. Token ----------------------------------------------------------------
if softhsm2-util --show-slots 2>/dev/null | grep -q "tbp-genesis-dev"; then
    echo "token tbp-genesis-dev déjà initialisé — réutilisation"
else
    softhsm2-util --init-token --slot 0 --label tbp-genesis-dev \
        --so-pin "$TBP_DEV_SOPIN" --pin "$TBP_DEV_PIN" >/dev/null
    echo "token tbp-genesis-dev initialisé (PIN de dev — jamais en réel)"
fi

# --- 2-5. keygen → sign → anchor → verify ------------------------------------
BIN="${GENESIS_HOME}/genesis-bin"
(cd "$SCRIPT_DIR" && CGO_ENABLED=1 go build -o "$BIN" .)

"$BIN" keygen  -n "$N" -out "$GENESIS_HOME"
"$BIN" sign    -m "$M" -n "$N" -authority "$AUTHORITY" -out "$GENESIS_HOME"
"$BIN" anchor  -out "$GENESIS_HOME"
"$BIN" verify  -m "$M" -out "$GENESIS_HOME"

echo "=== genèse dev complète dans ${GENESIS_HOME} ==="
echo "rappel : epoch 0 réel = cérémonie procédurale (quorum humain, HSM, canal"
echo "hors-bande authentifié) — rien ici ne s'y substitue (§3.2, §7.2, §12)"
