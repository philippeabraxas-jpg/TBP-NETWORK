#!/usr/bin/env python3
"""Vérifie la cohérence du catalogue de conformité (tbp-compliance/).

Le catalogue est un actif vivant : chaque ligne est ✅ couverte, 🔴 trou réel à
fermer (avec l'issue qui le suit), ou ⚪ hors périmètre (avec son motif et, pour
un déploiement, ce que l'utilisateur fait pour le fermer). Ce script échoue si
le catalogue dérive :

  1. plus aucun 🟡 (partiel) ni 🟢 (à faire en Rego) NULLE PART dans une fiche —
     ni dans une ligne, ni dans la légende, ni dans la prose d'un résumé : un
     partiel est tranché en couvert, rouge ou gris (le README les définit) ;
  2. toute ligne 🔴 renvoie à une issue (#NNN) ;
  3. toute ligne ⚪ a un motif non vide (« Why grey » ou une raison d'une ligne) ;
  4. l'état de chaque fiche (« No code gap » / « Open code gaps ») découle de ses lignes :
     « Open code gaps » si et seulement si au moins une ligne 🔴 ;
  5. les tableaux du README du catalogue ET du README RACINE reprennent l'état et les
     COMPTEURS (lignes ✅ / 🔴 / ⚪) de chaque fiche, recalculés ici — jamais écrits à la
     main, jamais une note « Full » : un règlement n'est pas « complet » parce qu'aucune
     ligne n'est rouge (des lignes ⚪ restent à la charge du déploiement) ;
  6. chaque fiche porte une date « Last verified » ;
  7. chaque issue citée par une ligne 🔴 figure dans « Open gaps that need code ».

Une ligne à statut combiné (« ✅ files · ⚪ other backends ») compte sous CHACUN de ses statuts :
une ligne qui contient un 🔴 compte dans les 🔴, comme dans l'état « Open code gaps » de la fiche.

Usage : python3 tbp-compliance/check_catalog.py            # vérifie
        python3 tbp-compliance/check_catalog.py --update   # réécrit les compteurs des README
"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_README = os.path.join(os.path.dirname(HERE), "README.md")
UPDATE = "--update" in sys.argv
TOTALS_RE = re.compile(r"<!-- catalogue-totals -->.*?<!-- /catalogue-totals -->", re.S)
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
counts = {}
red_issues = {}
for path in fiches:
    fname = os.path.basename(path)
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")

    m = re.match(r"\*\*Status: (No code gap|Open code gaps|Not applicable)", lines[2] if len(lines) > 2 else "")
    if not m:
        err(fname, "ligne 3 : « **Status: No code gap|Open code gaps|Not applicable** » attendu (jamais « Full »)")
        continue
    header_status[fname] = m.group(1)

    if not any(re.match(r"\*\*Last verified\*\*: \d{4}-\d{2}-\d{2}", l) for l in lines[:10]):
        err(fname, "« **Last verified**: AAAA-MM-JJ » manquant dans l'en-tête")

    red_rows = 0
    counts[fname] = {"✅": 0, "🔴": 0, "⚪": 0}
    for n, line in enumerate(lines, 1):
        if "🟡" in line or "🟢" in line:
            err(fname, f"ligne {n} : statut retiré (🟡/🟢) — trancher en ✅, 🔴 ou ⚪, y compris dans la légende et les résumés")
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = split_row(line)
        k = status_cell(cells)
        if k is None:
            continue
        st, detail = cells[k], " ".join(cells[k + 1:])
        for emoji in counts[fname]:  # une ligne partagée entre statuts compte sous chacun
            if emoji in st:
                counts[fname][emoji] += 1
        if "🟡" in st or "🟢" in st:
            err(fname, f"ligne {n} : statut partiel/à-faire « {st} » — trancher en ✅, 🔴 ou ⚪")
        if "🔴" in st:
            red_rows += 1
            if not re.search(r"#\d+", detail):
                err(fname, f"ligne {n} : ligne 🔴 sans issue de suivi (#NNN)")
            for num in re.findall(r"/issues/(\d+)", detail):  # l'issue de SUIVI : un lien d'issue, pas un renvoi au passage
                red_issues.setdefault(num, set()).add(fname)
        if "⚪" in st and len(detail.strip()) < 5:
            err(fname, f"ligne {n} : ligne ⚪ sans motif")

    if m.group(1) == "Not applicable":
        continue
    if red_rows and m.group(1) == "No code gap":
        err(fname, f"état « No code gap » alors que {red_rows} ligne(s) 🔴 subsistent")
    if not red_rows and m.group(1) == "Open code gaps":
        err(fname, "état « Open code gaps » alors qu'aucune ligne 🔴 ne subsiste")

def counter_cells(fname):
    c = counts[fname]
    return c["✅"], c["🔴"], c["⚪"]


def fix_or_check(path, label, text, row_match, want_cells, first_cell):
    """Vérifie (ou, avec --update, réécrit) les cellules de compteurs de la ligne de chaque fiche."""
    out = []
    changed = False
    for line in text.split("\n"):
        fname = row_match(line)
        if fname is not None and line.startswith("|"):
            cells = split_row(line)
            want = want_cells(fname)
            have = cells[first_cell:first_cell + len(want)]
            if have != want:
                if UPDATE:
                    cells[first_cell:first_cell + len(want)] = want
                    line = "| " + " | ".join(cells) + " |"
                    changed = True
                else:
                    err(label, f"compteurs de {fname} : « {' | '.join(have)} », les lignes de la fiche donnent « {' | '.join(want)} »")
        out.append(line)
    return "\n".join(out), changed


# README du catalogue : | Standard | Status | Rows | File |
cat_path = os.path.join(HERE, "README.md")
readme = open(cat_path, encoding="utf-8").read()
for fname, st in header_status.items():
    row = next((l for l in readme.split("\n") if f"]({fname})" in l), None)
    if row is None:
        err("README.md", f"aucune ligne pour {fname}")
        continue
    cells = split_row(row)
    if len(cells) < 4 or not cells[1].startswith(st):
        if UPDATE and len(cells) >= 4:
            continue
        err("README.md", f"état de {fname} : « {cells[1] if len(cells) > 1 else '?'} », la fiche dit « {st} »")
for fname, st in header_status.items():
    if UPDATE:
        lines = readme.split("\n")
        for i, l in enumerate(lines):
            if l.startswith("|") and f"]({fname})" in l:
                cells = split_row(l)
                if len(cells) >= 4 and not cells[1].startswith(st):
                    suffix = cells[1][len(cells[1].split(" (")[0]):] if " (" in cells[1] else ""
                    cells[1] = st + suffix
                    lines[i] = "| " + " | ".join(cells) + " |"
        readme = "\n".join(lines)
cat_new, ch1 = fix_or_check(
    cat_path, "README.md", readme,
    lambda l: next((f for f in header_status if f"]({f})" in l), None),
    lambda f: ["✅ %d · 🔴 %d · ⚪ %d" % counter_cells(f)], 2)

# README racine : | Standard | ✅ | 🔴 | ⚪ | Detail |
root = open(ROOT_README, encoding="utf-8").read()
root_new, ch2 = fix_or_check(
    ROOT_README, "../README.md", root,
    lambda l: next((f for f in header_status if f"tbp-compliance/{f}" in l), None),
    lambda f: [str(n) for n in counter_cells(f)], 1)
tot = [sum(counts[f][k] for f in counts) for k in ("✅", "🔴", "⚪")]
totals_text = ("<!-- catalogue-totals -->**%d ✅ covered, %d 🔴 real gaps (each with its issue), %d ⚪ not TBP's concern**"
               " — rows counted over the %d sheets (a row split between statuses counts under each)<!-- /catalogue-totals -->") % (tot[0], tot[1], tot[2], len(fiches))
m = TOTALS_RE.search(root_new)
if not m:
    err("../README.md", "le marqueur <!-- catalogue-totals --> manque (ligne de totaux du catalogue)")
elif m.group(0) != totals_text:
    if UPDATE:
        root_new = root_new.replace(m.group(0), totals_text)
        ch2 = True
    else:
        err("../README.md", "totaux du catalogue périmés : lancer `python3 tbp-compliance/check_catalog.py --update`")
for gone in ("Full", "Partial"):
    for l in root_new.split("\n"):
        if re.search(r"tbp-compliance/1[4-6]\d-", l) and re.search(rf"\b{gone}\b", l):
            err("../README.md", f"« {gone} » à côté d'un standard : des compteurs, pas une note — {l[:80]}")

# 7. toute issue citée par une ligne 🔴 est dans « Open gaps that need code »
gaps = readme.split("## Open gaps that need code", 1)[1].split("\n## ", 1)[0] if "## Open gaps that need code" in readme else ""
for num, files in sorted(red_issues.items()):
    if f"/issues/{num})" not in gaps:
        err("README.md", f"l'issue #{num} (ligne 🔴 de {', '.join(sorted(files))}) manque dans « Open gaps that need code »")

if UPDATE:
    if ch1 or cat_new != readme:
        open(cat_path, "w", encoding="utf-8").write(cat_new)
    if ch2:
        open(ROOT_README, "w", encoding="utf-8").write(root_new)

if errors:
    print("\n".join(errors))
    print(f"\n{len(errors)} incohérence(s) dans le catalogue.")
    sys.exit(1)
print(f"catalogue cohérent : {len(fiches)} fiches")
