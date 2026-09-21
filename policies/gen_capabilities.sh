#!/bin/sh
# policies/gen_capabilities.sh — T1 (issue #3)
#
# Génère policies/capabilities.json depuis LA version d'OPA déployée, en
# retirant les built-ins interdits par la doctrine (spec §12,
# policies/README.md) :
#   - http.send          pas d'appel réseau sortant depuis une règle
#   - net.lookup_ip_addr même raison
#   - time.now_ns        le temps vient du broker/NTS, pas de l'horloge
#                        locale d'OPA (§6.2)
#   - opa.runtime        sauf usage déjà audité et justifié (ex. lire un
#                        token d'environnement) — jamais pour de l'I/O
#
# Ne JAMAIS écrire capabilities.json à la main : la liste des built-ins
# change entre versions d'OPA. Un fichier figé serait faux ou obsolète dès
# la prochaine mise à jour — croire http.send bloqué alors qu'il ne l'est
# plus est pire que de ne pas avoir de fichier du tout.
#
# Usage : policies/gen_capabilities.sh
# Effets : écrit policies/capabilities.json, puis vérification négative
#          (une règle appelant http.send doit être refusée au chargement).

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="${SCRIPT_DIR}/capabilities.json"
NEG_RULE="${SCRIPT_DIR}/testdata/rule_http_send.rego"

FORBIDDEN="http.send net.lookup_ip_addr time.now_ns opa.runtime"

# --- Pré-requis ------------------------------------------------------------
command -v opa >/dev/null 2>&1 || { echo "erreur: binaire 'opa' introuvable" >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "erreur: binaire 'jq' introuvable" >&2; exit 1; }

OPA_VERSION=$(opa version 2>/dev/null | sed -n 's/^Version: //p')
echo "OPA déployé : ${OPA_VERSION:-version inconnue} — capabilities générées depuis CE binaire"

# --- 1. Liste complète des built-ins de la version déployée ----------------
#    'opa capabilities' SANS argument liste les noms de version connus
#    (texte, pas JSON) — c'est '--current' qui imprime le document JSON de
#    CETTE version. Sans ce flag, jq échoue à parser dès la ligne 1 : le
#    script échouait donc à 100% avant ce correctif, sur toute version d'OPA.
TMP=$(mktemp)
# Même répertoire que $OUT : le 'mv' final (étape 3-4) doit être atomique,
# ce qu'un rename cross-filesystem ne garantit pas.
OUT_TMP=$(mktemp "${SCRIPT_DIR}/capabilities.json.XXXXXX")
trap 'rm -f "$TMP" "$OUT_TMP"' EXIT

opa capabilities --current > "$TMP"

# --- 2. Chaque built-in interdit doit être PRÉSENT avant retrait -----------
#    Sinon la liste a changé (mise à jour d'OPA) : arrêt explicite. On ne
#    continue pas aveuglément — c'est exactement le risque que ce script
#    existe pour prévenir.
missing=0
for b in $FORBIDDEN; do
    if ! jq -e --arg b "$b" '[.builtins[] | select(.name == $b)] | length > 0' "$TMP" >/dev/null; then
        echo "erreur: built-in interdit '$b' absent de la liste générée —" >&2
        echo "        la version d'OPA a changé, revoir la liste FORBIDDEN" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

# --- 3. Retrait --------------------------------------------------------
#    Écrit dans un fichier temporaire, PAS directement dans $OUT : tant que
#    la vérification négative (étape 4) n'a pas confirmé que ce fichier
#    bloque bien http.send, il ne doit jamais remplacer un capabilities.json
#    existant — un fichier non vérifié qui échoue silencieusement à filtrer
#    est exactement le risque documenté en tête de ce script.
FORBIDDEN_JSON=$(printf '%s\n' $FORBIDDEN | jq -R . | jq -sc .)
jq --argjson forbidden "$FORBIDDEN_JSON" \
   '.builtins |= map(select(.name as $n | ($forbidden | index($n)) | not))' \
   "$TMP" > "$OUT_TMP"

echo "généré (non écrit tant que non vérifié) : $(jq '.builtins | length' "$OUT_TMP") built-ins retenus"

# --- 4. Vérification négative -------------------------------------------
#    Une règle appelant http.send DOIT être refusée au chargement avec le
#    fichier restreint. Si elle passe, le filtrage a échoué → arrêt SANS
#    toucher à $OUT (le fichier précédent, s'il existe, reste en place).
if opa check --capabilities "$OUT_TMP" "$NEG_RULE" >/dev/null 2>&1; then
    echo "erreur: $NEG_RULE a été ACCEPTÉE alors qu'elle appelle http.send —" >&2
    echo "        le filtrage de capabilities.json a échoué ; $OUT non modifié" >&2
    exit 1
fi
echo "vérification négative OK: une règle appelant http.send est refusée au chargement"

mv -- "$OUT_TMP" "$OUT"
echo "écrit: $OUT"

# OPA ≥ 1.0 : 'opa run' n'a PLUS de flag --capabilities (retiré). La voie
# supportée : compiler un bundle AVEC le fichier restreint (les built-ins
# interdits sont alors rejetés au build), puis exécuter ce bundle.
echo "rappel: OPA ≥ 1.0 — compiler un bundle avec le fichier restreint :"
echo "          opa build --capabilities $OUT policies/rego/ -o bundle.tar.gz"
echo "        puis démarrer : opa run --server bundle.tar.gz"
echo "        le circuit-breaker 5 ms = deny reste à implémenter côté PEP"
echo "        (issue #12) — ce n'est pas un mécanisme natif d'OPA (§12)"
