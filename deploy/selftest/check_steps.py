#!/usr/bin/env python3
"""check_steps.py — T35 (issue #61), décisions D96/D99.

Vérificateur formel et non-vacuole des guides de deploy/. Un guide qui
dérive du format convenu casse ici, pas chez l'opérateur :

  D96 — chaque étape « #### Étape N — … » porte les QUATRE blocs
        obligatoires, dans l'ordre :
          **Prérequis vérifiable** :
          **Commande** :
          **Critère de succès observable** :
          **En cas d'échec : STOP**
  D99 — toute ligne citant « config/ » explicite « adapter » (le dossier
        config/ est un point de départ à adapter, jamais copié tel quel).

Usage : python3 deploy/selftest/check_steps.py deploy/README.md […]
Sortie : un verdict par fichier ; code de sortie 1 dès qu'une règle casse.
"""

from __future__ import annotations

import re
import sys

REQUIRED_BLOCKS = [
    "**Prérequis vérifiable**",
    "**Commande**",
    "**Critère de succès observable**",
    "**En cas d'échec : STOP**",
]

STEP_RE = re.compile(r"^#### Étape \d+")
HEADING_RE = re.compile(r"^#{1,4} ")


def structural_lines(text: str) -> list[str]:
    """Lignes hors blocs de code : un commentaire bash « # … » dans une
    fence n'est PAS un titre Markdown. Sans cela, le parseur tronquait les
    étapes au premier commentaire de commande (faux positifs massifs)."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            out.append("")
        elif in_fence:
            out.append("")
        else:
            out.append(line)
    return out


def check_file(path: str) -> list[str]:
    """Rend la liste des violations (vide = conforme)."""
    errors: list[str] = []
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    lines = structural_lines(text)

    # D96 — format des étapes (structure lue hors fences).
    steps = [i for i, line in enumerate(lines) if STEP_RE.match(line)]
    if not steps:
        errors.append(f"{path}: aucune étape « #### Étape N » — le guide doit être exécutable étape par étape (D96)")
        return errors  # pas d'étape ⇒ les blocs ne peuvent pas être vérifiés
    for k, start in enumerate(steps):
        title = lines[start].strip()
        end = len(lines)
        for j in range(start + 1, len(lines)):
            if HEADING_RE.match(lines[j]):
                end = j
                break
        body = "\n".join(lines[start:end])
        pos = -1
        for block in REQUIRED_BLOCKS:
            found = body.find(block)
            if found == -1:
                errors.append(f"{path}: {title} — bloc obligatoire manquant : {block}")
            elif found < pos:
                errors.append(f"{path}: {title} — bloc « {block} » hors ordre (D96)")
            else:
                pos = found

    # D99 — config/ toujours cité « à adapter ».
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "config/" in line and "adapt" not in line.lower():
            errors.append(f"{path}:{lineno}: référence à config/ sans « adapter » (D99) : {line.strip()[:100]}")

    return errors


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_steps.py <guide.md> […]", file=sys.stderr)
        return 2
    total = 0
    for path in argv[1:]:
        errors = check_file(path)
        if errors:
            total += len(errors)
            for e in errors:
                print(f"[FAIL] {e}")
        else:
            print(f"[ ok ] {path}")
    if total:
        print(f"check_steps: {total} violation(s)")
        return 1
    print(f"check_steps: {len(argv) - 1} guide(s) conformes (D96/D99)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
