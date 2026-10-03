#!/usr/bin/env python3
"""check_pinned_actions.py — issue #193 (SLSA / OWASP SCVS « build environment »).

Une action référencée par TAG (`actions/checkout@v4`) est mutable : quiconque
contrôle le dépôt amont, ou y vole un jeton, peut déplacer le tag vers du code
qui s'exécute dans NOTRE CI avec NOS jetons. Une référence par SHA de commit est
immuable. Ce vérificateur fait échouer la CI dès qu'un `uses:` n'est pas épinglé
par un SHA de 40 hexadécimaux, sauf exceptions listées ci-dessous, chacune avec
sa raison.

Même vérificateur, deuxième volet (#193, point 4) : chaque workflow déclare des `permissions:` — au
niveau du workflow, ou à défaut sur CHAQUE job — et aucune n'est `write-all`. Un workflow sans bloc
hérite des droits par défaut du dépôt, réglables hors du code et souvent en écriture.

Usage : python3 .github/scripts/check_pinned_actions.py [fichier.yml …]
        (sans argument : .github/workflows/*.yml)
"""

from __future__ import annotations

import glob
import re
import sys

# Exceptions : (sous-chaîne de la référence) -> raison.
EXCEPTIONS = {
    "slsa-framework/slsa-github-generator/": (
        "le vérificateur de provenance (slsa-verifier) exige que le générateur "
        "réutilisable soit référencé par un TAG de version (v2.1.0), jamais par un "
        "SHA : c'est le tag qui prouve l'identité du constructeur de confiance"
    ),
}

USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)")
SHA_RE = re.compile(r"@[0-9a-f]{40}$")


def check_file(path: str) -> list[str]:
    errors: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue  # commentaire, pas une référence
            m = USES_RE.match(line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith("./"):
                continue  # action locale du dépôt
            if SHA_RE.search(ref):
                continue
            if any(key in ref for key in EXCEPTIONS):
                continue
            errors.append(f"{path}:{n}: « {ref} » n'est pas épinglé par un SHA de commit (#193)")
    return errors


TOP_PERMS_RE = re.compile(r"^permissions:")
JOB_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(?:#.*)?$")
JOB_PERMS_RE = re.compile(r"^    permissions:")
WRITE_ALL_RE = re.compile(r"^\s*(?:permissions:\s*)?write-all\b|^\s*permissions:\s*write-all\b")


def check_permissions(path: str) -> list[str]:
    """Chaque workflow : `permissions:` en tête, ou sur chaque job ; jamais `write-all`."""
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    errors: list[str] = []
    for n, line in enumerate(lines, 1):
        if not line.lstrip().startswith("#") and WRITE_ALL_RE.search(line):
            errors.append(f"{path}:{n}: « write-all » interdit — déclarer les droits nécessaires un par un (#193)")
    if any(TOP_PERMS_RE.match(line) for line in lines):
        return errors
    jobs: dict[str, bool] = {}
    in_jobs, cur = False, None
    for line in lines:
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            break  # fin du bloc jobs
        m = JOB_RE.match(line)
        if m:
            cur = m.group(1)
            jobs[cur] = False
        elif cur is not None and JOB_PERMS_RE.match(line):
            jobs[cur] = True
    if not jobs:
        errors.append(f"{path}: aucun job reconnu et pas de `permissions:` en tête (#193)")
    for name, has in jobs.items():
        if not has:
            errors.append(f"{path}: le job « {name} » n'a pas de `permissions:` et le workflow n'en déclare pas en tête (#193)")
    return errors


def main(argv: list[str]) -> int:
    files = argv[1:] or sorted(glob.glob(".github/workflows/*.yml"))
    if not files:
        print("check_pinned_actions: aucun workflow trouvé — STOP", file=sys.stderr)
        return 2
    errors: list[str] = []
    for f in files:
        errors += check_file(f)
        errors += check_permissions(f)
    for e in errors:
        print(f"[FAIL] {e}")
    if errors:
        print(f"check_pinned_actions: {len(errors)} faute(s) de chaîne de build (#193)")
        return 1
    print(f"check_pinned_actions: {len(files)} workflow(s), actions épinglées par SHA, permissions déclarées")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
