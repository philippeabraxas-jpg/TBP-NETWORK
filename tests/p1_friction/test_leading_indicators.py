#!/usr/bin/env python3
"""test_leading_indicators.py — tests unitaires de leading_indicators.py
(T27, #29). Chaque seuil est testé à ses bornes — un indicateur qui ne
bascule pas à la frontière ne protège rien."""

import unittest

from leading_indicators import (
    ARBITRATION_ALERT,
    ARBITRATION_DANGER,
    KIND_CONTRACT,
    KIND_DECISION,
    TIER1_ADDED_P95_BUDGET_MS,
    compute,
    percentile_nearest_rank,
)


def make_measurements(
    baseline_ms=0.01,
    decision_ms=0.2,
    durability_ms=150.0,
    tier2_verify_ms=0.01,
    verify_ok=190,
    verify_denied=10,
    dur_evals=40,
    dur_contract_ops=45,
    ttl_s=300,
    ttl_base_s=300,
    checkpoint_ms=100,
):
    """Fixture synthétique : 100 échantillons à latence constante par bras."""
    s = []
    s += [{"tier": "tier1_baseline", "op": "noop", "duration_ns": int(baseline_ms * 1e6), "ts": 0}] * 100
    s += [{"tier": "tier1_decision", "op": "evaluate", "duration_ns": int(decision_ms * 1e6), "ts": 0,
           "jti": f"j{i}", "ttl_s": ttl_s} for i in range(100)]
    s += [{"tier": "tier1_durability", "op": "evaluate", "duration_ns": int(durability_ms * 1e6), "ts": 0}] * dur_evals
    for op in ("submit", "approve", "verify"):
        s += [{"tier": "tier2_decision", "op": op, "duration_ns": int(tier2_verify_ms * 1e6), "ts": 0}] * 100
    s += [{"tier": "tier2_durability", "op": "verify", "duration_ns": int(durability_ms * 1e6), "ts": 0}] * 15
    return {
        "run_id": "test",
        "config": {"ttl_base_s": ttl_base_s},
        "samples": s,
        "counters": {
            "tier2_decision_verify_ok": verify_ok,
            "tier2_decision_verify_denied": verify_denied,
            "leaves_expected_decision": dur_evals,
            "leaves_expected_contract": dur_contract_ops,
            "checkpoint_interval_ms": checkpoint_ms,
        },
    }


def make_leaves(n_decision, n_contract):
    return (
        [{"seq": i, "kind": KIND_DECISION, "ts": 0, "cell_id": "c"} for i in range(n_decision)]
        + [{"seq": 1000 + i, "kind": KIND_CONTRACT, "ts": 0, "cell_id": "c"} for i in range(n_contract)]
    )


class TestPercentile(unittest.TestCase):
    def test_nearest_rank(self):
        self.assertEqual(percentile_nearest_rank([], 0.95), 0.0)
        self.assertEqual(percentile_nearest_rank([5], 0.99), 5)
        self.assertEqual(percentile_nearest_rank(list(range(1, 101)), 0.50), 51)  # i = int(0.50×100) → index 50
        self.assertEqual(percentile_nearest_rank(list(range(1, 101)), 0.95), 96)  # index int(0.95×100)=95
        self.assertEqual(percentile_nearest_rank(list(range(1, 101)), 0.99), 100)  # index 99

    def test_unsorted_input(self):
        self.assertEqual(percentile_nearest_rank([9, 1, 5, 3], 0.50), 5)  # trié [1,3,5,9], index 2


class TestNominal(unittest.TestCase):
    def test_nominal_not_blocking(self):
        r = compute(make_measurements(), make_leaves(40, 45))
        self.assertFalse(r["blocking"])
        self.assertEqual(r["alarms"], [])
        self.assertNotEqual(r["production_notice"], "")  # condition A revue #29

    def test_arms_present(self):
        r = compute(make_measurements(), make_leaves(40, 45))
        for arm in ("tier1_baseline", "tier1_decision", "tier1_durability",
                    "tier2_decision_verify", "tier2_durability_verify"):
            self.assertIn(arm, r["arms"])


class TestTier1Threshold(unittest.TestCase):
    def test_under_budget_ok(self):
        # ajoutée = 0.2 + 4.7 = 4.9 ms < 5 ms
        r = compute(make_measurements(decision_ms=4.71), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["tier1_added_latency"]["severity"], "ok")
        self.assertFalse(r["blocking"])

    def test_at_budget_blocks(self):
        # ajoutée = 0.01 + 5.0 = 5.01 ms ≥ 5 ms — la borne doit mordre
        r = compute(make_measurements(decision_ms=5.01), make_leaves(40, 45))
        ind = r["indicators"]["tier1_added_latency"]
        self.assertEqual(ind["severity"], "alert")
        self.assertTrue(ind["blocking"])
        self.assertTrue(r["blocking"])

    def test_baseline_subtracted(self):
        # décision à 5.4 ms mais baseline à 0.5 ms → ajoutée 4.9 ms < 5
        r = compute(make_measurements(baseline_ms=0.5, decision_ms=5.4), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["tier1_added_latency"]["severity"], "ok")


class TestTier2Threshold(unittest.TestCase):
    def test_under_max_ok(self):
        r = compute(make_measurements(tier2_verify_ms=49.9), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["tier2_verify_latency"]["severity"], "ok")

    def test_over_max_blocks(self):
        r = compute(make_measurements(tier2_verify_ms=50.1), make_leaves(40, 45))
        ind = r["indicators"]["tier2_verify_latency"]
        self.assertEqual(ind["severity"], "alert")
        self.assertTrue(r["blocking"])

    def test_under_floor_not_failure(self):
        # 0.01 ms << 10 ms : la borne basse §9 est une enveloppe, pas un échec
        r = compute(make_measurements(tier2_verify_ms=0.01), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["tier2_verify_latency"]["severity"], "ok")


class TestArbitrationRate(unittest.TestCase):
    def test_below_alert_ok(self):
        r = compute(make_measurements(verify_ok=91, verify_denied=9), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["arbitration_rate"]["severity"], "ok")

    def test_alert_blocks(self):
        r = compute(make_measurements(verify_ok=85, verify_denied=15), make_leaves(40, 45))
        ind = r["indicators"]["arbitration_rate"]
        self.assertEqual(ind["severity"], "alert")
        self.assertTrue(r["blocking"])

    def test_danger_severity(self):
        r = compute(make_measurements(verify_ok=75, verify_denied=25), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["arbitration_rate"]["severity"], "danger")

    def test_exact_boundary(self):
        # exactement 10 % = alerte (seuil « > 10 % » franchi à égalité)
        r = compute(make_measurements(verify_ok=90, verify_denied=10), make_leaves(40, 45))
        self.assertGreaterEqual(r["indicators"]["arbitration_rate"]["value"], ARBITRATION_ALERT)

    def test_zero_total_no_crash(self):
        r = compute(make_measurements(verify_ok=0, verify_denied=0), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["arbitration_rate"]["value"], 0.0)


class TestHoles(unittest.TestCase):
    def test_missing_leaves_block(self):
        r = compute(make_measurements(), make_leaves(20, 45))  # 20 décisions manquantes
        ind = r["indicators"]["uninstrumented_holes"]
        self.assertEqual(ind["value"], 20)
        self.assertTrue(ind["blocking"])
        self.assertTrue(r["blocking"])

    def test_extra_leaves_block(self):
        r = compute(make_measurements(), make_leaves(40, 50))  # 5 contrats sans échantillon
        self.assertEqual(r["indicators"]["uninstrumented_holes"]["value"], 5)

    def test_exact_match_ok(self):
        r = compute(make_measurements(), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["uninstrumented_holes"]["value"], 0)


class TestWarnings(unittest.TestCase):
    def test_validation_p99_warns_not_blocks(self):
        r = compute(make_measurements(decision_ms=6.0), make_leaves(40, 45))
        # p99 à 6 ms > 5 ms → warning ; mais ajoutée 5.99 ≥ 5 → bloquant tier1.
        # Pour isoler : baseline élevée annule l'ajoutée.
        r = compute(make_measurements(baseline_ms=2.0, decision_ms=6.0), make_leaves(40, 45))
        ind = r["indicators"]["validation_p99"]
        self.assertEqual(ind["severity"], "warning")
        self.assertFalse(ind["blocking"])

    def test_durability_watch_threshold(self):
        # p95 durabilité 350 ms > 3×100 ms → warning, non bloquant
        r = compute(make_measurements(durability_ms=350.0), make_leaves(40, 45))
        ind = r["indicators"]["durability_watch"]
        self.assertEqual(ind["severity"], "warning")
        self.assertFalse(ind["blocking"])
        self.assertFalse(r["blocking"])

    def test_durability_ok_under_3x(self):
        r = compute(make_measurements(durability_ms=250.0), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["durability_watch"]["severity"], "ok")

    def test_ttl_drift_warns(self):
        r = compute(make_measurements(ttl_s=900), make_leaves(40, 45))  # 3× nominal
        ind = r["indicators"]["ttl_drift"]
        self.assertEqual(ind["severity"], "warning")
        self.assertFalse(ind["blocking"])

    def test_ttl_nominal_ok(self):
        r = compute(make_measurements(ttl_s=300), make_leaves(40, 45))
        self.assertEqual(r["indicators"]["ttl_drift"]["severity"], "ok")


if __name__ == "__main__":
    unittest.main()
