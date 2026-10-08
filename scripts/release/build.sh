#!/usr/bin/env bash
# build.sh — compile les binaires d'une release (démons et outils d'opérateur).
#
#     bash scripts/release/build.sh [DOSSIER]        # défaut : dist
#
# UNE seule liste, deux usages : le workflow `release` (tag vX.Y.Z) la compile pour la
# provenance SLSA, et le job `go` de la CI la compile à CHAQUE PR. Un binaire qui disparaît, change de
# chemin ou ne compile plus casse la PR, pas le jour du tag.
#
# Cible : linux/amd64, Debian 12 (cf. deploy/). -trimpath, symboles retirés. CGO RESTE ACTIVÉ : brokerd en a
# besoin (PKCS#11 pour la clé d'émetteur en HSM, miekg/pkcs11), donc les binaires sont liés dynamiquement à la
# glibc de la machine de build. Pour qu'ils tournent sur Debian 12 (glibc 2.36), la version de glibc qu'ils
# exigent est VÉRIFIÉE ci-dessous : un build qui exige plus récent échoue au lieu de produire une release
# qui ne démarre pas chez l'opérateur. GOOS/GOARCH peuvent être surchargés.

set -euo pipefail

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$REPO_ROOT"

command -v go >/dev/null 2>&1 || { echo "erreur: binaire 'go' introuvable — STOP" >&2; exit 1; }

dist=${1:-dist}
mkdir -p "$dist"

# nom=chemin — démons (pepd, brokerd, anod, supervisord, opawatchdog) et outils d'opérateur
# (quorumproof : preuves et approbations signées ; tbp-audit : vérification du journal).
binaries=(
  "pepd=./src/pep/cmd/pepd"
  "brokerd=./src/broker/cmd/brokerd"
  "anod=./src/ano/cmd/anod"
  "supervisord=./src/supervision/cmd/supervisord"
  "opawatchdog=./src/supervision/cmd/opawatchdog"
  "quorumproof=./src/pep/cmd/quorumproof"
  "tbp-audit=./src/registry/cmd/tbp-audit"
)

export GOOS=${GOOS:-linux}
export GOARCH=${GOARCH:-amd64}

# glibc maximale que les binaires peuvent exiger : celle de Debian 12 (bookworm).
max_glibc=2.36

for entry in "${binaries[@]}"; do
  name=${entry%%=*}
  path=${entry#*=}
  [ -d "$path" ] || { echo "erreur: $path n'existe pas (binaire $name) — STOP" >&2; exit 1; }
  go build -trimpath -ldflags="-s -w" -o "$dist/$name" "$path"
  need=""
  if command -v objdump >/dev/null 2>&1; then
    need=$(objdump -T "$dist/$name" 2>/dev/null | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/GLIBC_//' | sort -uV | tail -1 || true)
    if [ -n "$need" ] && [ "$(printf '%s\n%s\n' "$need" "$max_glibc" | sort -V | tail -1)" != "$max_glibc" ]; then
      echo "erreur: $name exige GLIBC_$need, au-delà de $max_glibc (Debian 12) — la release ne démarrerait pas chez l'opérateur — STOP" >&2
      exit 1
    fi
  else
    echo "avert. objdump absent : version de glibc exigée par $name non vérifiée" >&2
  fi
  echo "ok   $name  ($path)${need:+  glibc ≤ $need}"
done
