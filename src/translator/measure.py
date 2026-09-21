#!/usr/bin/env python3
"""measure.py — T26 (issue #22) : replay de corpus + métriques par classe (§4.5).

Rejoué à CHAQUE mise à jour du traducteur, bloquant en CI : code de sortie 1
sur régression. Les cibles FNR < 0,1 % et FPR < 2 % sont des CIBLES DE
CONCEPTION à valider sur le premier corpus natif au pilote (§15) — affichées
comme telles, jamais comme des résultats établis.

Corpus (cf. corpus/README.md) :
    <corpus_dir>/<lang>/<classe>/pos/*.txt   — cas que le traducteur DOIT accepter
    <corpus_dir>/<lang>/<classe>/neg/*.txt   — cas qu'il DOIT refuser
Classes : F, I, W, OUT (hors-classe) — §5.3.

Scorer (couture — le modèle/scorer déployé, T24) : --scorer-cmd CMD reçoit
sur stdin une ligne JSON par cas {"id","lang","class","text"} et rend sur
stdout une ligne JSON par cas {"id","label"} avec label ∈ {"accept","refuse"}.
Le replay est un mode SHADOW : il n'alimente aucune décision de production.

Sortie : rapport JSON — agrégats par classe + hash de corpus, JAMAIS de
contenu. Inscrit au registre par tmetrics (feuille « TBTM1 », hash-only §6.2).

Codes de sortie : 0 conforme (avertissements possibles), 1 régression
FNR/FPR (CI rouge), 2 usage/environnement.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

REPORT_VERSION = 1
CLASSES = ("F", "I", "W", "OUT")
TARGETS_STATUS = (
    "cibles de conception à valider sur le premier corpus natif au pilote "
    "(§15) — pas des résultats établis"
)


def iter_cases(corpus_dir):
    """Énumère les cas du corpus : (id_stable, lang, classe, attendu, texte)."""
    for lang in sorted(os.listdir(corpus_dir)):
        lang_dir = os.path.join(corpus_dir, lang)
        if not os.path.isdir(lang_dir):
            continue
        for classe in sorted(os.listdir(lang_dir)):
            if classe not in CLASSES:
                continue
            for expected in ("pos", "neg"):
                case_dir = os.path.join(lang_dir, classe, expected)
                if not os.path.isdir(case_dir):
                    continue
                for name in sorted(os.listdir(case_dir)):
                    path = os.path.join(case_dir, name)
                    if not os.path.isfile(path):
                        continue
                    case_id = os.path.relpath(path, corpus_dir)
                    with open(path, "r", encoding="utf-8") as fh:
                        yield case_id, lang, classe, expected, fh.read()


def corpus_hash(corpus_dir):
    """Hash déterministe du corpus : sha256 sur les (relpath, sha256 fichier)
    triés — toute mutation de contenu ou d'arborescence change le hash."""
    entries = []
    for root, _dirs, files in os.walk(corpus_dir):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, corpus_dir)
            with open(path, "rb") as fh:
                entries.append((rel, hashlib.sha256(fh.read()).hexdigest()))
    h = hashlib.sha256()
    for rel, digest in sorted(entries):
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(digest.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def run_scorer(scorer_cmd, cases):
    """Rejoue les cas contre le scorer (batch JSONL). Fail-closed : toute
    ligne mal formée, id inconnu ou label hors contrat est une faute."""
    payload = "".join(
        json.dumps({"id": cid, "lang": lang, "class": classe, "text": text})
        + "\n"
        for cid, lang, classe, _expected, text in cases
    )
    proc = subprocess.run(
        scorer_cmd,
        input=payload,
        capture_output=True,
        text=True,
        shell=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"scorer en échec (code {proc.returncode}) : {proc.stderr.strip()[:400]}"
        )
    labels = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"sortie scorer non JSON : {line[:200]!r}") from exc
        if item.get("label") not in ("accept", "refuse"):
            raise RuntimeError(f"label hors contrat : {item!r}")
        labels[item.get("id")] = item["label"]
    missing = [cid for cid, *_ in cases if cid not in labels]
    if missing:
        raise RuntimeError(f"scorer muet sur {len(missing)} cas (ex. {missing[0]})")
    return labels


def evaluate(corpus_dir, scorer_cmd, fnr_target, fpr_target):
    """Replay + métriques agrégées par classe (toutes langues confondues),
    avec ventilation par langue en détail. Aucun contenu dans le rapport."""
    cases = list(iter_cases(corpus_dir))
    labels = run_scorer(scorer_cmd, cases) if cases else {}

    per_class = {c: {"positives": 0, "negatives": 0,
                     "false_negatives": 0, "false_positives": 0}
                 for c in CLASSES}
    per_lang = {}
    for cid, lang, classe, expected, _text in cases:
        predicted = labels[cid]
        agg = per_class[classe]
        key = (lang, classe)
        detail = per_lang.setdefault(
            key, {"positives": 0, "negatives": 0,
                  "false_negatives": 0, "false_positives": 0})
        for bucket in (agg, detail):
            if expected == "pos":
                bucket["positives"] += 1
                if predicted == "refuse":
                    bucket["false_negatives"] += 1
            else:
                bucket["negatives"] += 1
                if predicted == "accept":
                    bucket["false_positives"] += 1

    warnings = []
    regressions = []
    classes_out = []
    for classe in CLASSES:
        agg = per_class[classe]
        pos, neg = agg["positives"], agg["negatives"]
        fnr = agg["false_negatives"] / pos if pos else None
        fpr = agg["false_positives"] / neg if neg else None
        if pos == 0:
            warnings.append(f"classe {classe} : aucun cas positif — FNR non mesurable")
        if neg == 0:
            warnings.append(f"classe {classe} : aucun cas négatif — FPR non mesurable")
        if fnr is not None and fnr > fnr_target:
            regressions.append(
                f"classe {classe} : FNR {fnr:.4%} > cible {fnr_target:.2%}")
        if fpr is not None and fpr > fpr_target:
            regressions.append(
                f"classe {classe} : FPR {fpr:.4%} > cible {fpr_target:.2%}")
        classes_out.append({
            "class": classe,
            "positives": pos,
            "negatives": neg,
            "false_negatives": agg["false_negatives"],
            "false_positives": agg["false_positives"],
            "fnr": fnr,
            "fpr": fpr,
        })

    return {
        "version": REPORT_VERSION,
        "corpus_hash": corpus_hash(corpus_dir),
        "classes": classes_out,
        "per_language": [
            {"lang": lang, "class": classe, **detail}
            for (lang, classe), detail in sorted(per_lang.items())
        ],
        "targets": {
            "fnr_max": fnr_target,
            "fpr_max": fpr_target,
            "status": TARGETS_STATUS,
        },
        "cases_total": len(cases),
        "warnings": warnings,
        "regressions": regressions,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Replay de corpus + métriques par classe du traducteur (T26, §4.5)")
    parser.add_argument("--corpus-dir", required=True,
                        help="racine du corpus (cf. corpus/README.md)")
    parser.add_argument("--scorer-cmd", required=True,
                        help="commande scorer (contrat JSONL, voir docstring)")
    parser.add_argument("--out", required=True, help="chemin du rapport JSON")
    parser.add_argument("--fnr-target", type=float, default=0.001,
                        help="cible FNR (défaut 0.001 — à valider au pilote, §15)")
    parser.add_argument("--fpr-target", type=float, default=0.02,
                        help="cible FPR (défaut 0.02 — à valider au pilote, §15)")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.corpus_dir):
        print(f"measure: corpus introuvable : {args.corpus_dir}", file=sys.stderr)
        return 2
    try:
        report = evaluate(args.corpus_dir, args.scorer_cmd,
                          args.fnr_target, args.fpr_target)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"measure: {exc}", file=sys.stderr)
        return 2

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"measure: {report['cases_total']} cas, corpus {report['corpus_hash'][:16]}…")
    print(f"measure: cibles FNR<{args.fnr_target:.2%} / FPR<{args.fpr_target:.2%}"
          f" — {TARGETS_STATUS}")
    for warning in report["warnings"]:
        print(f"measure: AVERTISSEMENT {warning}", file=sys.stderr)
    if report["regressions"]:
        for regression in report["regressions"]:
            print(f"measure: RÉGRESSION {regression}", file=sys.stderr)
        return 1
    print("measure: aucune régression — rapport", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
