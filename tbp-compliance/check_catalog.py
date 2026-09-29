#!/usr/bin/env python3
"""Vérifie la cohérence du catalogue de conformité (tbp-compliance/).

Le catalogue est un actif vivant : chaque ligne est ✅ couverte, 🔴 trou réel à
fermer (avec l'issue qui le suit), ou ⚪ hors périmètre (avec son motif et, pour
un déploiement, ce que l'utilisateur fait pour le fermer). Ce script échoue si
le catalogue dérive :

  1. plus aucune ligne 🟡 (partiel) ni 🟢 (à faire en Rego) : un partiel doit
     être tranché en couvert, rouge ou gris ;
  2. toute ligne 🔴 renvoie à une issue (#NNN) ;
  3. toute ligne ⚪ a un motif non vide (« Why grey » ou une raison d'une ligne) ;
  4. l'état de chaque fiche (Full / Partial) découle de ses lignes : Partial si et
     seulement si au moins une ligne 🔴 ;
  5. le tableau du README reprend l'état de chaque fiche ;
  6. chaque fiche porte une date « Last verified ».

Usage : python3 tbp-compliance/check_catalog.py
"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS_EMOJI = ("✅", "🟡", "🔴", "🟢", "⚪")
errors = []


def err(fname, msg):
    errors.append(f"{fname}: {msg}")


def split_row(line):
    return [c.strip() for c in line.strip().strip("|").split(" | ")]


def status_cell(cells):
    """La cellule de statut est la première qui COMMENCE par un émoji de statut."""
    for k, c in enumerate(cells):
        if c.startswith(STATUS_EMOJI):
            return k
    return None


fiches = sorted(glob.glob(os.path.join(HERE, "1[4-6][0-9]-*.md")))
if len(fiches) != 21:
    errors.append(f"attendu 21 fiches (142–162), trouvé {len(fiches)}")

header_status = {}
for path in fiches:
    fname = os.path.basename(path)
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")

    m = re.match(r"\*\*Status: (Full|Partial|Not applicable)", lines[2] if len(lines) > 2 else "")
    if not m:
        err(fname, "ligne 3 : « **Status: Full|Partial|Not applicable** » attendu")
        continue
    header_status[fname] = m.group(1)

    if not any(re.match(r"\*\*Last verified\*\*: \d{4}-\d{2}-\d{2}", l) for l in lines[:10]):
        err(fname, "« **Last verified**: AAAA-MM-JJ » manquant dans l'en-tête")

    red_rows = 0
    for n, line in enumerate(lines, 1):
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = split_row(line)
        k = status_cell(cells)
        if k is None:
            continue
        st, detail = cells[k], " ".join(cells[k + 1:])
        if "🟡" in st or "🟢" in st:
            err(fname, f"ligne {n} : statut partiel/à-faire « {st} » — trancher en ✅, 🔴 ou ⚪")
        if "🔴" in st:
            red_rows += 1
            if not re.search(r"#\d+", detail):
                err(fname, f"ligne {n} : ligne 🔴 sans issue de suivi (#NNN)")
        if "⚪" in st and len(detail.strip()) < 5:
            err(fname, f"ligne {n} : ligne ⚪ sans motif")

    if m.group(1) == "Not applicable":
        continue
    if red_rows and m.group(1) == "Full":
        err(fname, f"état Full alors que {red_rows} ligne(s) 🔴 subsistent")
    if not red_rows and m.group(1) == "Partial":
        err(fname, "état Partial alors qu'aucune ligne 🔴 ne subsiste")

readme = open(os.path.join(HERE, "README.md"), encoding="utf-8").read()
for fname, st in header_status.items():
    row = next((l for l in readme.split("\n") if f"]({fname})" in l), None)
    if row is None:
        err("README.md", f"aucune ligne pour {fname}")
        continue
    cells = split_row(row)
    if len(cells) < 3 or not cells[1].startswith(st):
        err("README.md", f"état de {fname} : « {cells[1] if len(cells) > 1 else '?'} », la fiche dit « {st} »")

if errors:
    print("\n".join(errors))
    print(f"\n{len(errors)} incohérence(s) dans le catalogue.")
    sys.exit(1)
print(f"catalogue cohérent : {len(fiches)} fiches")
