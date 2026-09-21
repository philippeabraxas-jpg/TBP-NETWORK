#!/usr/bin/env python3
"""sample_human.py — T26 (issue #22) : tirage stratifié par classe pour la
revue humaine (§4.5 — mesure continue : replay + échantillonnage humain).

Entrée : JSONL de décisions de production (export shadow de l'opérateur —
une ligne JSON par décision, champ "class" ∈ {F,I,W,OUT}, champ "jti").
Tirage : STRATIFIÉ par classe — n_k = max(1, ceil(taux × N_k)) pour toute
classe représentée — et REPRODUCTIBLE : la graine figure dans le manifeste
(même entrée + même graine ⇒ même échantillon, auditable après coup).

Sortie : échantillon JSONL + manifeste JSON (comptages par classe, taux,
graine, hash de l'entrée). Le manifeste permet à un tiers de revérifier le
tirage ; il ne contient que des agrégats et des hash, jamais de contenu.

Codes de sortie : 0 OK, 2 usage/environnement.
"""

import argparse
import hashlib
import json
import math
import random
import sys

CLASSES = ("F", "I", "W", "OUT")


def stratified_sample(records, rate, seed):
    """Tirage stratifié déterministe. records : liste de dicts avec "class".
    Retourne (échantillon, comptages par classe)."""
    by_class = {}
    for rec in records:
        by_class.setdefault(rec.get("class", "OUT"), []).append(rec)
    sample = []
    counts = {}
    for classe in sorted(by_class):
        bucket = by_class[classe]
        n = max(1, math.ceil(rate * len(bucket)))
        n = min(n, len(bucket))
        rng = random.Random(f"{seed}:{classe}")
        picked = rng.sample(bucket, n)
        sample.extend(picked)
        counts[classe] = {"population": len(bucket), "echantillon": n}
    return sample, counts


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Tirage stratifié par classe pour revue humaine (T26, §4.5)")
    parser.add_argument("--in", dest="input", required=True,
                        help="JSONL de décisions de production (export shadow)")
    parser.add_argument("--rate", type=float, default=0.01,
                        help="taux de tirage par classe (défaut 0.01)")
    parser.add_argument("--seed", required=True,
                        help="graine de tirage — consignée au manifeste (reproductibilité)")
    parser.add_argument("--out", required=True, help="échantillon JSONL")
    parser.add_argument("--manifest", required=True, help="manifeste JSON du tirage")
    args = parser.parse_args(argv)

    if not 0 < args.rate <= 1:
        print("sample_human: --rate hors ]0, 1]", file=sys.stderr)
        return 2
    try:
        with open(args.input, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        print(f"sample_human: entrée illisible : {exc}", file=sys.stderr)
        return 2

    records = []
    for lineno, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"sample_human: ligne {lineno} non JSON", file=sys.stderr)
            return 2
    if not records:
        print("sample_human: entrée vide — rien à échantillonner", file=sys.stderr)
        return 2

    sample, counts = stratified_sample(records, args.rate, args.seed)

    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in sample:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    manifest = {
        "version": 1,
        "rate": args.rate,
        "seed": args.seed,
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "decisions_total": len(records),
        "echantillon_total": len(sample),
        "par_classe": counts,
        "reproductibilite": "même entrée + même graine ⇒ même échantillon (auditable)",
    }
    with open(args.manifest, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"sample_human: {len(sample)}/{len(records)} décisions tirées"
          f" (taux {args.rate:.2%}, graine {args.seed!r})")
    for classe in sorted(counts):
        c = counts[classe]
        print(f"sample_human:   classe {classe} : {c['echantillon']}/{c['population']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
