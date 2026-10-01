#!/usr/bin/env python3
"""check_pinned_actions.py — issue #193 (SLSA / OWASP SCVS « build environment »).

Une action référencée par TAG (`actions/checkout@v4`) est mutable : quiconque
contrôle le dépôt amont, ou y vole un jeton, peut déplacer le tag vers du code
qui s'exécute dans NOTRE CI avec NOS jetons. Une référence par SHA de commit est
immuable. Ce vérificateur fait échouer la CI dès qu'un `uses:` n'est pas épinglé
par un SHA de 40 hexadécimaux, sauf exceptions listées ci-dessous, chacune avec
sa raison.

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


def main(argv: list[str]) -> int:
    files = argv[1:] or sorted(glob.glob(".github/workflows/*.yml"))
    if not files:
        print("check_pinned_actions: aucun workflow trouvé — STOP", file=sys.stderr)
        return 2
    errors: list[str] = []
    for f in files:
        errors += check_file(f)
    for e in errors:
        print(f"[FAIL] {e}")
    if errors:
        print(f"check_pinned_actions: {len(errors)} référence(s) mutable(s)")
        return 1
    print(f"check_pinned_actions: {len(files)} workflow(s), toutes les actions sont épinglées par SHA")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
