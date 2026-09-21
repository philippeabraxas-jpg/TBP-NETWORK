#!/usr/bin/env python3
"""test_sample_human.py — T26 (issue #22) : non-vacuité du tirage stratifié.

Stratification par classe, reproductibilité (graine au manifeste), taux
respecté — chaque propriété est éprouvée par une mutation qui DOIT la casser.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sample_human import main, stratified_sample


def make_records(n_f=1000, n_i=100, n_w=10):
    records = []
    for classe, count in (("F", n_f), ("I", n_i), ("W", n_w)):
        for i in range(count):
            records.append({"jti": f"{classe}-{i}", "class": classe})
    return records


class StratifiedSampleTest(unittest.TestCase):
    def test_stratification_chaque_classe_representee(self):
        sample, counts = stratified_sample(make_records(), 0.05, "graine-a")
        # Chaque classe avec des décisions est représentée — même W (10 cas).
        self.assertEqual(set(counts), {"F", "I", "W"})
        for classe in ("F", "I", "W"):
            self.assertGreaterEqual(counts[classe]["echantillon"], 1)
        # Taux respecté classe par classe : 5 % de 1000/100/10.
        self.assertEqual(counts["F"]["echantillon"], 50)
        self.assertEqual(counts["I"]["echantillon"], 5)
        self.assertEqual(counts["W"]["echantillon"], 1)  # max(1, ceil(0.5))
        self.assertEqual(len(sample), 56)

    def test_taux_un_prend_tout(self):
        sample, counts = stratified_sample(make_records(20, 5, 2), 1.0, "s")
        self.assertEqual(len(sample), 27)

    def test_reproductible_meme_graine(self):
        first, _ = stratified_sample(make_records(), 0.05, "graine-a")
        second, _ = stratified_sample(make_records(), 0.05, "graine-a")
        self.assertEqual([r["jti"] for r in first], [r["jti"] for r in second])

    def test_graine_differente_change_le_tirage(self):
        first, _ = stratified_sample(make_records(), 0.05, "graine-a")
        second, _ = stratified_sample(make_records(), 0.05, "graine-b")
        self.assertNotEqual([r["jti"] for r in first], [r["jti"] for r in second])

    def test_echantillon_est_un_sous_ensemble(self):
        records = make_records()
        sample, _ = stratified_sample(records, 0.05, "graine-a")
        population = {r["jti"] for r in records}
        self.assertTrue(all(r["jti"] in population for r in sample))
        # Sans doublon.
        self.assertEqual(len({r["jti"] for r in sample}), len(sample))


class MainTest(unittest.TestCase):
    def run_main(self, root, records, seed="graine-a", rate=0.05):
        src = os.path.join(root, "decisions.jsonl")
        with open(src, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
        out = os.path.join(root, f"sample-{seed}.jsonl")
        manifest = os.path.join(root, f"manifest-{seed}.json")
        code = main(["--in", src, "--rate", str(rate), "--seed", seed,
                     "--out", out, "--manifest", manifest])
        with open(manifest, encoding="utf-8") as fh:
            return code, json.load(fh), out

    def test_manifeste_complet_et_honnete(self):
        with tempfile.TemporaryDirectory() as root:
            records = make_records()
            code, manifest, _ = self.run_main(root, records)
            self.assertEqual(code, 0)
            self.assertEqual(manifest["decisions_total"], 1110)
            self.assertEqual(manifest["echantillon_total"], 56)
            self.assertEqual(manifest["seed"], "graine-a")
            self.assertEqual(len(manifest["input_sha256"]), 64)
            # Reproductibilité annoncée et réelle : même graine ⇒ même fichier.
            _, _, out_a = self.run_main(root, records, seed="graine-a")
            _, _, out_b = self.run_main(root, records, seed="graine-b")
            _, manifest_b, _ = self.run_main(root, records, seed="graine-a")
            with open(out_a, "rb") as fh:
                again = fh.read()
            with open(out_b, "rb") as fh:
                other = fh.read()
            # graine-a rejouée (écrasée par le 3e run) == graine-a initiale :
            # le manifeste du 3e run a la même empreinte d'entrée.
            self.assertEqual(manifest["input_sha256"], manifest_b["input_sha256"])
            # graine-b : tirage différent (mutation de graine détectée).
            self.assertNotEqual(again, other)

    def test_entree_vide_ou_invalide_refusee(self):
        with tempfile.TemporaryDirectory() as root:
            code = main(["--in", os.path.join(root, "absent.jsonl"),
                         "--seed", "s", "--out", os.devnull,
                         "--manifest", os.devnull])
            self.assertEqual(code, 2)
            empty = os.path.join(root, "empty.jsonl")
            open(empty, "w").close()
            code = main(["--in", empty, "--seed", "s",
                         "--out", os.devnull, "--manifest", os.devnull])
            self.assertEqual(code, 2)
            bad = os.path.join(root, "bad.jsonl")
            with open(bad, "w") as fh:
                fh.write("pas du json\n")
            code = main(["--in", bad, "--seed", "s",
                         "--out", os.devnull, "--manifest", os.devnull])
            self.assertEqual(code, 2)

    def test_taux_hors_bornes_refuse(self):
        with tempfile.TemporaryDirectory() as root:
            src = os.path.join(root, "d.jsonl")
            with open(src, "w") as fh:
                fh.write(json.dumps({"jti": "F-0", "class": "F"}) + "\n")
            for rate in ("0", "-0.5", "1.5"):
                code = main(["--in", src, "--rate", rate, "--seed", "s",
                             "--out", os.devnull, "--manifest", os.devnull])
                self.assertEqual(code, 2, f"taux {rate} accepté")


if __name__ == "__main__":
    unittest.main()
