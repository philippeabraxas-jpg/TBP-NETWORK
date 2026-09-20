#!/usr/bin/env python3
"""test_assert_logged.py — T28 (issue #28) : tests unitaires du
vérificateur transversal. Chaque garde-fou est testé à sa frontière —
un vérificateur qui ne bascule pas sur un trou ne protège rien."""

import unittest

from assert_logged import KIND_TELEMETRY, check_coverage, check_scenario_leaves, verify


def make_leaves(kinds):
    """Registre scanné synthétique : une suite de kinds."""
    return [{"seq": i, "kind": k, "ts": 0, "cell_id": "c"} for i, k in enumerate(kinds)]


def make_scenario(sid, kinds_by_range, held=True, status="executed"):
    """Scénario exécuté cohérent : plage [first,last] + comptes par kind."""
    first, last, kinds = kinds_by_range
    counts = {}
    for k in kinds:
        counts[str(k)] = counts.get(str(k), 0) + 1
    return {
        "id": sid, "name": sid.lower(), "mechanism": "§x", "status": status,
        "held": held, "leaf_first": first, "leaf_last": last, "leaves": counts,
    }


def make_report(scenarios, holes=None):
    return {
        "tool": "tbp-redteam-runner", "run_id": "test", "generated_at": "now",
        "scenarios": scenarios,
        "declared_holes": holes if holes is not None else [
            {"id": "S3-usb", "description": "compensation endpoint"},
            {"id": "S4-prevention", "description": "prévention incompressible"},
        ],
    }


class TestNominal(unittest.TestCase):
    def test_green_campaign(self):
        # 2 scénarios exécutés couvrant 5 feuilles, sans trou.
        leaves = make_leaves([1, 1, 10, 10, 12])
        scenarios = [
            make_scenario("S5", (0, 1, [1, 1])),
            make_scenario("S6", (2, 4, [10, 10, 12])),
        ]
        faults, pending, _ = verify(make_report(scenarios), leaves, [])
        self.assertEqual(faults, [])
        self.assertEqual(pending, [])

    def test_lab_scenarios_pending_not_blocking(self):
        leaves = make_leaves([6])
        scenarios = [
            {"id": "S1", "name": "laptop-inconnu", "mechanism": "§5.1",
             "status": "lab-netns", "held": None},
            make_scenario("S4", (0, 0, [6])),
        ]
        faults, pending, _ = verify(make_report(scenarios), leaves, [])
        self.assertEqual(faults, [])
        self.assertEqual(len(pending), 1)  # affiché, jamais silencieux


class TestHolesAreBlocking(unittest.TestCase):
    def test_held_false_blocks(self):
        leaves = make_leaves([1])
        scenarios = [make_scenario("S8", (0, 0, [1]), held=False)]
        faults, _, _ = verify(make_report(scenarios), leaves, [])
        self.assertTrue(any("NON TENU" in f for f in faults))

    def test_missing_leaf_blocks(self):
        # Le scénario déclare 2 feuilles, le scan n'en trouve qu'une.
        leaves = make_leaves([1])
        scenarios = [make_scenario("S8", (0, 0, [1]))]
        scenarios[0]["leaves"] = {"1": 2}
        faults, _, _ = verify(make_report(scenarios), leaves, [])
        self.assertTrue(any("≠" in f for f in faults))

    def test_wrong_kind_blocks(self):
        leaves = make_leaves([1])
        scenarios = [make_scenario("S9", (0, 0, [1]))]
        scenarios[0]["leaves"] = {"8": 1}  # déclaré KindQuorum, scanné KindDecision
        faults, _, _ = verify(make_report(scenarios), leaves, [])
        self.assertTrue(any("≠" in f for f in faults))

    def test_sequence_gap_blocks(self):
        # Feuille index 1 orpheline : ni S5 ni S6 ne la couvre.
        leaves = make_leaves([1, 1, 10])
        scenarios = [
            make_scenario("S5", (0, 0, [1])),
            make_scenario("S6", (2, 2, [10])),
        ]
        faults, _, _ = verify(make_report(scenarios), leaves, [])
        self.assertTrue(any("trou de séquence" in f or "orphelines" in f for f in faults))

    def test_orphan_tail_blocks(self):
        leaves = make_leaves([1, 1, 10])
        scenarios = [make_scenario("S5", (0, 1, [1, 1]))]  # index 2 non couvert
        faults, _, _ = verify(make_report(scenarios), leaves, [])
        self.assertTrue(any("orphelines" in f for f in faults))

    def test_declared_holes_never_blocking(self):
        # Les trous DÉCLARÉS sont listés, pas bloquants — la doctrine est
        # « comptés, jamais ignorés », pas « interdits ».
        leaves = make_leaves([1])
        scenarios = [make_scenario("S8", (0, 0, [1]))]
        holes = [{"id": "usb", "description": "hors réseau"}] * 5
        faults, _, _ = verify(make_report(scenarios, holes), leaves, [])
        self.assertEqual(faults, [])


class TestEvidence(unittest.TestCase):
    def lab_scenario(self, sid="S1"):
        return {"id": sid, "name": sid.lower(), "mechanism": "§5.1", "status": "lab-netns", "held": None}

    def test_valid_evidence_clears_pending(self):
        leaves = make_leaves([KIND_TELEMETRY])
        scenarios = [self.lab_scenario()]
        entry = [{"scenario": "S1", "leaf_index": 0, "evidence_sha256": "ab", "at": "now"}]
        faults, pending, _ = verify(make_report(scenarios), leaves, entry)
        self.assertEqual(faults, [])
        self.assertEqual(pending, [])

    def test_evidence_wrong_kind_blocks(self):
        leaves = make_leaves([1])  # KindDecision, pas KindTelemetry
        scenarios = [self.lab_scenario()]
        entry = [{"scenario": "S1", "leaf_index": 0, "evidence_sha256": "ab", "at": "now"}]
        faults, _, _ = verify(make_report(scenarios), leaves, entry)
        self.assertTrue(any("KindTelemetry" in f for f in faults))

    def test_evidence_out_of_range_blocks(self):
        leaves = make_leaves([KIND_TELEMETRY])
        scenarios = [self.lab_scenario()]
        entry = [{"scenario": "S1", "leaf_index": 7, "evidence_sha256": "ab", "at": "now"}]
        faults, _, _ = verify(make_report(scenarios), leaves, entry)
        self.assertTrue(any("hors scan" in f for f in faults))

    def test_require_lab_evidence_blocks_pending(self):
        leaves = make_leaves([KIND_TELEMETRY])
        scenarios = [self.lab_scenario(),
                     {"id": "S4", "name": "hotspot", "mechanism": "§5.2",
                      "status": "executed", "held": True,
                      "leaf_first": 0, "leaf_last": 0, "leaves": {str(KIND_TELEMETRY): 1}}]
        faults, pending, _ = verify(make_report(scenarios), leaves, [], require_lab=True)
        self.assertTrue(any("S1" in f for f in faults))
        self.assertEqual(pending, [])


class TestCoverageBoundaries(unittest.TestCase):
    def test_empty_registry_zero_scenarios(self):
        self.assertEqual(check_coverage([], []), "")

    def test_scenario_without_leaves_skipped(self):
        leaves = make_leaves([1])
        scenarios = [
            {"id": "S9", "name": "x", "mechanism": "§x", "status": "executed",
             "held": True, "leaf_first": -1, "leaf_last": -1, "leaves": {}},
            make_scenario("S5", (0, 0, [1])),
        ]
        # S9 sans feuille (plage −1) est sauté par la couverture ; la
        # corrélation par scénario, elle, vérifie leaves={} cohérent.
        self.assertEqual(check_coverage(scenarios, leaves), "")

    def test_declared_without_range_but_with_counts(self):
        faults = check_scenario_leaves(
            {"id": "S5", "leaf_first": -1, "leaf_last": -1, "leaves": {"1": 2}}, [])
        self.assertTrue(any("sans plage" in f for f in faults))


if __name__ == "__main__":
    unittest.main()
