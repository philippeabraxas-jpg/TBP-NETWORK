#!/usr/bin/env python3
"""assert_logged.py — T28 (issue #28), D94 : vérificateur transversal
« feuille présente » de la campagne red-team P2.

Métrique non négociable : **zéro action dangereuse non journalisée**.
Le vérificateur ne fait pas confiance à l'auto-contrôle du runner : il
recoupe indépendamment run_report.json contre le scan vérifié du registre
(leaves_export.json, produit par ChainWatcher) :

  1. tout scénario exécuté doit être TENU — sinon trou non déclaré ;
  2. pour chaque scénario exécuté, les comptes de feuilles par kind
     déclarés doivent égaler le scan sur [leaf_first, leaf_last] ;
  3. les plages des scénarios exécutés doivent couvrir le registre SANS
     trou ni recouvrement ;
  4. les scénarios réseau (lab-netns) : si evidence_log.jsonl existe
     (retour du lab), chaque entrée doit pointer une feuille
     KindTelemetry valide du scan ; sans journal, ils restent « en
     attente du lab » — affichés, jamais silencieusement absents ;
  5. les trous résiduels DÉCLARÉS sont listés (USB, prévention hotspot,
     accès physique) — « holes counted, never ignored ».

Exit 1 si un seul trou NON déclaré. Exit 0 sinon.

Usage : assert_logged.py --in OUTDIR [--require-lab-evidence]
"""

import argparse
import json
import sys

KIND_TELEMETRY = 2


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_scenario_leaves(scenario, leaves):
    """Recoupe les comptes déclarés d'un scénario exécuté au scan.
    Rend une liste de fautes (vide = corrélation exacte)."""
    faults = []
    first, last = scenario.get("leaf_first", -1), scenario.get("leaf_last", -1)
    declared = scenario.get("leaves") or {}
    sid = scenario["id"]
    if first < 0 or last < first:
        if declared:
            faults.append(f"{sid}: feuilles déclarées sans plage d'index")
        return faults
    if last >= len(leaves):
        faults.append(f"{sid}: plage [{first},{last}] au-delà du scan ({len(leaves)} feuilles)")
        return faults
    scanned = {}
    for i in range(first, last + 1):
        k = str(leaves[i]["kind"])
        scanned[k] = scanned.get(k, 0) + 1
    if scanned != declared:
        faults.append(f"{sid}: feuilles scannées {scanned} ≠ déclarées {declared}")
    return faults


def check_coverage(scenarios, leaves, evidence_idx=frozenset()):
    """Les plages des scénarios exécutés + les feuilles d'évidence lab
    couvrent [0, len) sans trou. Les plages exécutées restent contiguës
    entre elles (elles sont écrites séquentiellement par le runner) ;
    les feuilles d'évidence, inscrites par des invocations séparées,
    comblent le reste — chacune doit être DÉCLARÉE dans le journal."""
    covered = 0
    for s in sorted(
        (s for s in scenarios if s["status"] == "executed" and s.get("leaf_first", -1) >= 0),
        key=lambda s: s["leaf_first"],
    ):
        # Des feuilles d'évidence peuvent précéder la plage (leaf-evidence
        # invoqué entre deux runs) — elles doivent être exactement là.
        while covered < s["leaf_first"] and covered in evidence_idx:
            covered += 1
        if s["leaf_first"] != covered:
            return f"trou de séquence avant {s['id']} (attendu {covered}, première feuille {s['leaf_first']})"
        covered = s["leaf_last"] + 1
    while covered < len(leaves) and covered in evidence_idx:
        covered += 1
    if covered != len(leaves):
        return f"registre {len(leaves)} feuilles, couvertes {covered} — feuilles orphelines ou manquantes"
    return ""


def check_evidence(scenarios, leaves, evidence_entries, require_lab):
    """Recoupe le journal d'évidence des scénarios lab au scan."""
    faults, pending = [], []
    by_scenario = {}
    for e in evidence_entries:
        by_scenario.setdefault(e["scenario"], []).append(e)
    for s in scenarios:
        if s["status"] != "lab-netns":
            continue
        entries = by_scenario.get(s["id"], [])
        if not entries:
            (faults if require_lab else pending).append(
                f"{s['id']} ({s['name']}): aucune feuille d'évidence — exécution lab requise"
            )
            continue
        for e in entries:
            idx = e["leaf_index"]
            if idx >= len(leaves):
                faults.append(f"{s['id']}: évidence index {idx} hors scan ({len(leaves)} feuilles)")
            elif leaves[idx]["kind"] != KIND_TELEMETRY:
                faults.append(f"{s['id']}: feuille {idx} kind {leaves[idx]['kind']} ≠ KindTelemetry({KIND_TELEMETRY})")
    return faults, pending


def verify(report, leaves, evidence_entries, require_lab=False):
    """Verdict transversal pur. Rend (faults, pending, lines)."""
    faults, lines = [], []

    for s in report["scenarios"]:
        if s["status"] == "executed":
            if s.get("held") is not True:
                faults.append(f"{s['id']} ({s['name']}): mécanisme NON TENU — {s.get('detail', '')}")
            faults.extend(check_scenario_leaves(s, leaves))

    evidence_idx = {e["leaf_index"] for e in evidence_entries}
    cov = check_coverage(report["scenarios"], leaves, evidence_idx)
    if cov:
        faults.append(cov)

    f, pending = check_evidence(report["scenarios"], leaves, evidence_entries, require_lab)
    faults.extend(f)

    for s in report["scenarios"]:
        verdict = {True: "TENU", False: "NON TENU", None: "—"}[s.get("held")]
        lines.append(f"  {s['id']:<4} {s['name']:<22} {verdict:<9} {s['mechanism']}")
    return faults, pending, lines


def main(argv=None):
    ap = argparse.ArgumentParser(description="vérificateur transversal T28 — feuille présente, trous comptés")
    ap.add_argument("--in", dest="indir", required=True, help="répertoire de sortie du run")
    ap.add_argument("--require-lab-evidence", action="store_true",
                    help="exige les feuilles d'évidence des scénarios lab (à utiliser APRÈS les scripts netns)")
    args = ap.parse_args(argv)

    import os
    report = load_json(os.path.join(args.indir, "run_report.json"))
    leaves = load_json(os.path.join(args.indir, "leaves_export.json"))
    evidence_entries = []
    ev_path = os.path.join(args.indir, "evidence_log.jsonl")
    if os.path.exists(ev_path):
        with open(ev_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    evidence_entries.append(json.loads(line))

    faults, pending, lines = verify(report, leaves, evidence_entries, args.require_lab_evidence)

    print(f"assert_logged: run {report.get('run_id', '?')} — {len(leaves)} feuilles scannées (chaîne vérifiée côté runner)")
    for line in lines:
        print(line)
    holes = report.get("declared_holes") or []
    print(f"  trous résiduels déclarés : {len(holes)}")
    for h in holes:
        if not h.get("description"):
            faults.append(f"trou {h.get('id', '?')} sans description — déclaré sans motif = ignoré")
        print(f"    - {h['id']} : {h.get('description', '(sans description)')}")
    for p in pending:
        print(f"  EN ATTENTE LAB : {p}")
    if faults:
        print("assert_logged: TROUS NON DÉCLARÉS — campagne ROUGE", file=sys.stderr)
        for f_ in faults:
            print(f"  FAULT: {f_}", file=sys.stderr)
        return 1
    print("assert_logged: zéro action dangereuse non journalisée — campagne VERTE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
