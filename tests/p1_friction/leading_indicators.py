#!/usr/bin/env python3
"""leading_indicators.py — T27 (issue #29) : indicateurs avancés (§9) et
verdict de seuils (§9.1), calculés sur les feuilles RÉELLES du registre
(leaves_export.json, scannées et vérifiées par le ChainWatcher de
supervision) corrélées à la vérité de mesure du harnais (measurements.json).

Seuils bloquants (CI rouge, D91) :
  - tier1_added_p95_ms  ≥ 5 ms   (bras « décision » − baseline, §9.1)
  - tier2_verify_p95_ms > 50 ms  (borne haute §9 — la borne basse 10 ms est
    une enveloppe incluant l'attente humaine hors champ : sous-enveloppe =
    informationnel, jamais un échec de friction)
  - arbitration_rate      ≥ 10 % (refus VerifyStep / vérifications — alerte
    §9 ; ≥ 20 % = danger), toutes deux bloquantes
  - uninstrumented_holes  > 0    (feuilles KindDecision/KindContract sans
    échantillon de mesure, ou l'inverse — compté, jamais ignoré)

Alarmes non bloquantes (tracées dans le rapport, leafé via D90) :
  - validation_p99_ms     > 5 ms (bras décision, alerte si soutenu)
  - durability_p95_ms     > 3 × CheckpointInterval configuré (bras
    « durabilité » — registre réel en mode sync, borne pire cas ; #71
    arbitré par T38 : prod par défaut async borné, HORS budget §9.1)
  - ttl_drift             : p50 des TTL ÉMIS > 2 × TTL nominal (vérité de
    menthe du harnais — la distribution s'étire = pression de friction)

Usage : python3 leading_indicators.py [--in OUTDIR] [--out REPORT]
Code de sortie : 1 si un seuil bloquant est franchi, 0 sinon.
"""

import argparse
import json
import sys
import time
from pathlib import Path

KIND_DECISION = 1
KIND_CONTRACT = 10

TIER1_ADDED_P95_BUDGET_MS = 5.0     # §9.1 — bloquant
TIER2_VERIFY_P95_MAX_MS = 50.0      # §9 borne haute — bloquant
ARBITRATION_ALERT = 0.10            # §9/§9.1 — bloquant
ARBITRATION_DANGER = 0.20           # §9 — bloquant, sévérité danger
VALIDATION_P99_ALERT_MS = 5.0       # §9 — avertissement
DURABILITY_FACTOR = 3               # p95 > 3 × CheckpointInterval — avertissement
TTL_STRETCH_FACTOR = 2              # p50 TTL émis > 2 × nominal — avertissement

PRODUCTION_NOTICE = (
    "PRODUCTION : le chemin réellement déployé (pepd + registre tessera POSIX) "
    "mesure la latence du bras « durabilité » — registre réel en mode sync "
    "(feuille intégrée ET publiée avant verdict), borne pire cas. Plancher "
    "structurel mesuré ~150-250 ms (checkpoint POSIX ≥ 100 ms, borne dure du "
    "driver, + poll 50 ms de l'awaiter) — 30-50x le budget §9.1. #71 arbitré "
    "par T38 : la production tourne par défaut en async borné (verdict à "
    "l'acceptation, rattrapage de publication borné par la fenêtre "
    "d'opposabilité) et ne paie plus ce plancher ; TBP_DURABILITY=sync le "
    "restaure. Cette variable d'infrastructure registre (T4/T7) reste HORS "
    "budget §9.1 ; le seuil bloquant §9.1 s'applique au bras « décision » "
    "(coût PEP isolé, plancher déterministe du §9.1). Les deux bras sont "
    "toujours rapportés ensemble."
)


def percentile_nearest_rank(values, p):
    """Rang le plus proche — strictement la même méthode que le harnais Go
    (percentileNearestRank) : les deux implémentations ne divergent jamais."""
    if not values:
        return 0.0
    s = sorted(values)
    i = int(p * len(s))
    if i >= len(s):
        i = len(s) - 1
    return s[i]


def arm_stats(samples, tier, op=None):
    vals = [s["duration_ns"] / 1e6 for s in samples
            if s["tier"] == tier and (op is None or s["op"] == op)]
    return {
        "n": len(vals),
        "p50_ms": percentile_nearest_rank(vals, 0.50),
        "p95_ms": percentile_nearest_rank(vals, 0.95),
        "p99_ms": percentile_nearest_rank(vals, 0.99),
    }


def indicator(value, threshold, severity, blocking, detail):
    return {
        "value": value,
        "threshold": threshold,
        "severity": severity,  # ok | warning | alert | danger
        "blocking": blocking,  # franchissement bloquant pour la CI (D91)
        "detail": detail,
    }


def compute(measurements, leaves):
    """Calcule les indicateurs et rend le rapport (dict). Fonction pure —
    testée unitairement sur fixtures synthétiques."""
    samples = measurements["samples"]
    counters = measurements["counters"]
    cfg = measurements.get("config", {})

    arms = {
        "tier1_baseline": arm_stats(samples, "tier1_baseline", "noop"),
        "tier1_decision": arm_stats(samples, "tier1_decision", "evaluate"),
        "tier1_durability": arm_stats(samples, "tier1_durability", "evaluate"),
        "tier2_decision_submit": arm_stats(samples, "tier2_decision", "submit"),
        "tier2_decision_approve": arm_stats(samples, "tier2_decision", "approve"),
        "tier2_decision_verify": arm_stats(samples, "tier2_decision", "verify"),
        "tier2_durability_verify": arm_stats(samples, "tier2_durability", "verify"),
    }

    ind = {}

    # --- tier1 : latence AJOUTÉE = p95(décision) − p95(baseline) (D85).
    added = arms["tier1_decision"]["p95_ms"] - arms["tier1_baseline"]["p95_ms"]
    breach = added >= TIER1_ADDED_P95_BUDGET_MS
    ind["tier1_added_latency"] = indicator(
        round(added, 4), f"p95 < {TIER1_ADDED_P95_BUDGET_MS} ms (§9.1)",
        "alert" if breach else "ok", breach,
        f"p95 décision {arms['tier1_decision']['p95_ms']:.3f} ms − baseline "
        f"{arms['tier1_baseline']['p95_ms']:.3f} ms (n={arms['tier1_decision']['n']})")

    # --- tier2 : borne haute §9 sur la vérification d'étape (hors temps
    # humain). La borne basse (10 ms) est une enveloppe incluant l'attente
    # opérateur hors champ de mesure — sous-enveloppe = informationnel.
    t2 = arms["tier2_decision_verify"]["p95_ms"]
    breach = t2 > TIER2_VERIFY_P95_MAX_MS
    ind["tier2_verify_latency"] = indicator(
        round(t2, 4), f"p95 ≤ {TIER2_VERIFY_P95_MAX_MS} ms (§9, borne haute)",
        "alert" if breach else "ok", breach,
        f"p95 verify bras décision (n={arms['tier2_decision_verify']['n']}) — "
        "sous-enveloppe (< 10 ms) = informationnel, pas un échec")

    # --- arbitrage : refus VerifyStep = action renvoyée à l'arbitrage
    # humain (vérité comptée par le harnais, revue #29).
    ok = counters.get("tier2_decision_verify_ok", 0)
    denied = counters.get("tier2_decision_verify_denied", 0)
    total = ok + denied
    rate = denied / total if total else 0.0
    severity = "ok"
    if rate >= ARBITRATION_DANGER:
        severity = "danger"
    elif rate >= ARBITRATION_ALERT:
        severity = "alert"
    ind["arbitration_rate"] = indicator(
        round(rate, 4), f"< {ARBITRATION_ALERT:.0%} (danger ≥ {ARBITRATION_DANGER:.0%})",
        severity, rate >= ARBITRATION_ALERT,
        f"{denied}/{total} vérifications d'étape refusées")

    # --- trous non instrumentés (D88) : corrélation feuilles réelles ↔
    # échantillons. Compté, jamais ignoré.
    actual_decision = sum(1 for l in leaves if l["kind"] == KIND_DECISION)
    actual_contract = sum(1 for l in leaves if l["kind"] == KIND_CONTRACT)
    exp_decision = counters.get("leaves_expected_decision", 0)
    exp_contract = counters.get("leaves_expected_contract", 0)
    other_kinds = sorted({l["kind"] for l in leaves} - {KIND_DECISION, KIND_CONTRACT})
    holes = abs(actual_decision - exp_decision) + abs(actual_contract - exp_contract)
    ind["uninstrumented_holes"] = indicator(
        holes, "= 0 (chaque décision leafée a un échantillon, et inversement)",
        "alert" if holes > 0 else "ok", holes > 0,
        f"KindDecision réelles {actual_decision}/attendues {exp_decision} ; "
        f"KindContract réelles {actual_contract}/attendues {exp_contract}"
        + (f" ; kinds inattendus présents : {other_kinds}" if other_kinds else ""))

    # --- validation_p99 (bras décision) — avertissement si > 5 ms soutenu.
    p99 = arms["tier1_decision"]["p99_ms"]
    breach = p99 > VALIDATION_P99_ALERT_MS
    ind["validation_p99"] = indicator(
        round(p99, 4), f"≤ {VALIDATION_P99_ALERT_MS} ms (soutenu)",
        "warning" if breach else "ok", False,
        "p99 des validations tier1, bras décision")

    # --- bras durabilité : surveillance indexée sur le CheckpointInterval
    # configuré (revue #29) — mode sync = borne pire cas (T38/#71), HORS §9.1.
    dur = arms["tier1_durability"]["p95_ms"]
    cp_ms = counters.get("checkpoint_interval_ms", 100)
    watch = DURABILITY_FACTOR * cp_ms
    breach = dur > watch
    ind["durability_watch"] = indicator(
        round(dur, 2), f"p95 ≤ {DURABILITY_FACTOR}×{cp_ms} ms (3 × CheckpointInterval)",
        "warning" if breach else "ok", False,
        "coût de la preuve fail-closed en mode sync = borne pire cas (T38/#71 : "
        "prod par défaut async borné) — hors budget §9.1, jamais masqué "
        "(condition A de la revue)")

    # --- ttl_drift : distribution des TTL ÉMIS (vérité de menthe) — la
    # dérive vers le haut = pression de friction (on émet plus long pour
    # éviter l'arbitrage).
    ttls = [s["ttl_s"] for s in samples if s["tier"] == "tier1_decision" and "ttl_s" in s]
    ttl_base = cfg.get("ttl_base_s", 300)
    p50_ttl = percentile_nearest_rank(ttls, 0.50) if ttls else 0.0
    breach = p50_ttl > TTL_STRETCH_FACTOR * ttl_base
    ind["ttl_drift"] = indicator(
        round(p50_ttl, 1), f"p50 ≤ {TTL_STRETCH_FACTOR}×{ttl_base} s (TTL nominal)",
        "warning" if breach else "ok", False,
        f"p50 des TTL émis (n={len(ttls)}) — vérité de menthe du harnais")

    alarms = [name for name, v in ind.items() if v["severity"] != "ok"]
    blocking = any(v["blocking"] for v in ind.values())

    return {
        "tool": "leading_indicators.py (T27, issue #29)",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": measurements.get("run_id", "inconnu"),
        "production_notice": PRODUCTION_NOTICE,
        "arms": arms,
        "indicators": ind,
        "alarms": alarms,
        "blocking": blocking,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="indicateurs avancés §9 + verdict §9.1 (T27, #29)")
    ap.add_argument("--in", dest="indir", default="out", help="répertoire des artefacts du harnais")
    ap.add_argument("--out", dest="report", default=None, help="chemin du rapport (défaut: <in>/friction_report.json)")
    args = ap.parse_args(argv)

    indir = Path(args.indir)
    measurements = json.loads((indir / "measurements.json").read_text())
    leaves = json.loads((indir / "leaves_export.json").read_text())
    report = compute(measurements, leaves)

    report_path = Path(args.report) if args.report else indir / "friction_report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    print(f"friction: rapport {report_path}")
    print(f"  {report['production_notice'][:120]}…")
    for name, v in report["indicators"].items():
        mark = {"ok": "OK ", "warning": "WARN", "alert": "ALERTE", "danger": "DANGER"}[v["severity"]]
        gate = " [bloquant]" if v["blocking"] else ""
        print(f"  {mark:7s} {name:22s} = {v['value']}  (seuil {v['threshold']}){gate}")
    if report["blocking"]:
        print("friction: SEUIL BLOQUANT FRANCHI — CI rouge (§9.1, D91)")
        return 1
    print("friction: seuils bloquants tenus" + (f" (avertissements : {', '.join(report['alarms'])})" if report["alarms"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
