#!/usr/bin/env python3
"""Vérifie que les liens et images RELATIFS des documents suivis existent (revue externe du 11/10 : 17 figures des
specs pointaient vers figs/… au lieu de ../figs/…, invisible tant que personne n'ouvrait le rendu).

Ne vérifie que des chemins du dépôt : pas de réseau, pas d'ancre (#…), pas de lien absolu ni de schéma (http:, mailto:).
Les blocs de code (``` … ```) sont ignorés : un exemple n'est pas un lien.

Usage : python3 .github/scripts/check_doc_links.py [fichier.md ...]      (sans argument : les documents suivis)
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT = ["README.md", "docs/*.md", "deploy/dev-test/*.md", "tbp-compliance/*.md"]
LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def links(text):
    in_code = False
    for n, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        line = re.sub(r"`[^`]*`", "", line)  # le code en ligne n'est pas un lien
        for m in LINK.finditer(line):
            yield n, m.group(1)


def check(path):
    bad = []
    base = os.path.dirname(path)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for n, target in links(text):
        if re.match(r"^([a-z][a-z0-9+.-]*:|#|/|<)", target, re.I):
            continue
        target = target.split("#", 1)[0].split("?", 1)[0]
        if target.startswith("tbp4.2.1/"):  # le sous-module du protocole : absent d'un checkout sans --recurse-submodules
            continue
        if target and not os.path.exists(os.path.normpath(os.path.join(base, target))):
            bad.append((n, target))
    return bad


def main(argv):
    files = argv or [f for pat in DEFAULT for f in sorted(glob.glob(os.path.join(ROOT, pat)))]
    failed = 0
    for f in files:
        f = os.path.abspath(f)
        for n, target in check(f):
            print(f"{os.path.relpath(f, ROOT)}:{n}: lien relatif cassé : {target}")
            failed += 1
    if failed:
        print(f"\n{failed} lien(s) relatif(s) cassé(s).")
        return 1
    print("liens relatifs : ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
