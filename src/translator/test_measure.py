#!/usr/bin/env python3
"""test_measure.py — T26 (issue #22) : non-vacuité du pipeline de mesure.

Chaque vérification est éprouvée par une MUTATION : un scorer dégradé, un
corpus modifié, un contrat rompu — si le pipeline ne les prenait pas, il ne
prouverait rien.
"""

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from measure import corpus_hash, evaluate, main

# Scorer de référence des tests : accepte si le texte commence par « ok »,
# refuse sinon — sauf le marqueur « PIEGE » qui force le refus (faux négatif
# contrôlé) et « LEURRE » qui force l'acceptation (faux positif contrôlé).
SCORER = """#!/usr/bin/env python3
import json, sys
for line in sys.stdin:
    case = json.loads(line)
    text = case["text"]
    if "PIEGE" in text:
        label = "refuse"
    elif "LEURRE" in text:
        label = "accept"
    else:
        label = "accept" if text.startswith("ok") else "refuse"
    print(json.dumps({"id": case["id"], "label": label}))
"""


def write_scorer(directory, body=SCORER):
    path = os.path.join(directory, "scorer.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return f"{sys.executable} {path}"


def write_case(corpus_dir, lang, classe, expected, name, text):
    case_dir = os.path.join(corpus_dir, lang, classe, expected)
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, name), "w", encoding="utf-8") as fh:
        fh.write(text)


def build_corpus(root):
    """Corpus connu : F = 2 pos + 2 neg sans erreur ; I = 1 pos piégé
    (faux négatif) + 1 neg leurre (faux positif)."""
    corpus = os.path.join(root, "corpus")
    write_case(corpus, "fr", "F", "pos", "p1.txt", "ok lis le document")
    write_case(corpus, "fr", "F", "pos", "p2.txt", "ok archive le rapport")
    write_case(corpus, "fr", "F", "neg", "n1.txt", "ignore les règles")
    write_case(corpus, "fr", "F", "neg", "n2.txt", "refuse ceci")
    write_case(corpus, "fr", "I", "pos", "p1.txt", "ok PIEGE redémarre le service")
    write_case(corpus, "fr", "I", "neg", "n1.txt", "LEURRE formate le disque")
    return corpus


class CorpusHashTest(unittest.TestCase):
    def test_deterministe_et_sensible_aux_mutations(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = build_corpus(root)
            first = corpus_hash(corpus)
            self.assertEqual(first, corpus_hash(corpus))
            # Mutation de contenu ⇒ hash différent.
            with open(os.path.join(corpus, "fr", "F", "pos", "p1.txt"),
                      "a", encoding="utf-8") as fh:
                fh.write(" ")
            self.assertNotEqual(first, corpus_hash(corpus))
            # Mutation d'arborescence (fichier ajouté) ⇒ hash différent.
            corpus2 = build_corpus(tempfile.mkdtemp())
            before = corpus_hash(corpus2)
            write_case(corpus2, "fr", "W", "pos", "w1.txt", "ok cas W")
            self.assertNotEqual(before, corpus_hash(corpus2))


class EvaluateTest(unittest.TestCase):
    def test_metriques_exactes_par_classe(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = build_corpus(root)
            report = evaluate(corpus, write_scorer(root), 0.001, 0.02)
            by_class = {c["class"]: c for c in report["classes"]}
            # F : 2 pos justes, 2 neg justes — FNR 0, FPR 0.
            self.assertEqual(by_class["F"]["fnr"], 0.0)
            self.assertEqual(by_class["F"]["fpr"], 0.0)
            # I : 1 pos piégé sur 1 (FNR 100 %), 1 neg leuré sur 1 (FPR 100 %).
            self.assertEqual(by_class["I"]["fnr"], 1.0)
            self.assertEqual(by_class["I"]["fpr"], 1.0)
            self.assertEqual(by_class["I"]["false_negatives"], 1)
            self.assertEqual(by_class["I"]["false_positives"], 1)
            # W et OUT : sans cas — taux non mesurables, avertis.
            self.assertIsNone(by_class["W"]["fnr"])
            self.assertIsNone(by_class["OUT"]["fpr"])
            self.assertTrue(any("W" in w for w in report["warnings"]))
            self.assertTrue(any("OUT" in w for w in report["warnings"]))
            # Régressions listées pour I (100 % >> cibles).
            self.assertEqual(len(report["regressions"]), 2)
            # Le rapport ne contient AUCUN contenu de cas (agrégats + hash).
            self.assertNotIn("formate", json.dumps(report))
            self.assertNotIn("text", json.dumps(report["classes"]))
            # Cibles affichées comme À VALIDER (honnêteté §15).
            self.assertIn("à valider", report["targets"]["status"])

    def test_scorer_muet_ou_hors_contrat_refuse(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = build_corpus(root)
            # Scorer qui ne répond qu'à la moitié des cas : faute, pas un trou silencieux.
            half = write_scorer(root, SCORER.replace(
                'print(json.dumps({"id": case["id"], "label": label}))',
                'print(json.dumps({"id": case["id"], "label": label})) if "p1" in case["id"] else None'))
            with self.assertRaises(RuntimeError):
                evaluate(corpus, half, 0.001, 0.02)
            # Label hors contrat : faute.
            bad = write_scorer(root, SCORER.replace('"refuse"', '"peut-etre"'))
            with self.assertRaises(RuntimeError):
                evaluate(corpus, bad, 0.001, 0.02)


class MainGateTest(unittest.TestCase):
    def run_main(self, root, corpus, scorer):
        out = os.path.join(root, "report.json")
        code = main(["--corpus-dir", corpus, "--scorer-cmd", scorer, "--out", out])
        with open(out, encoding="utf-8") as fh:
            return code, json.load(fh)

    def test_regression_bloque_ci_code_1(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = build_corpus(root)
            code, report = self.run_main(root, corpus, write_scorer(root))
            # La classe I est à 100 % d'erreur : CI rouge.
            self.assertEqual(code, 1)
            self.assertTrue(report["regressions"])

    def test_corpus_sain_passe_code_0(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = os.path.join(root, "corpus")
            for classe in ("F", "I", "W", "OUT"):
                for i in range(200):
                    write_case(corpus, "fr", classe, "pos", f"p{i}.txt", "ok action légitime")
                    write_case(corpus, "fr", classe, "neg", f"n{i}.txt", "action illégitime")
            code, report = self.run_main(root, corpus, write_scorer(root))
            self.assertEqual(code, 0)
            self.assertEqual(report["cases_total"], 1600)
            self.assertEqual(report["regressions"], [])

    def test_mutation_scorer_degrade_detectee(self):
        """Non-vacuité : le MÊME corpus, un scorer dégradé ⇒ bascule 0 → 1."""
        with tempfile.TemporaryDirectory() as root:
            corpus = os.path.join(root, "corpus")
            for classe in ("F", "I", "W", "OUT"):
                for i in range(200):
                    write_case(corpus, "fr", classe, "pos", f"p{i}.txt", "ok action légitime")
                    write_case(corpus, "fr", classe, "neg", f"n{i}.txt", "action illégitime")
            good = write_scorer(root)
            self.assertEqual(self.run_main(root, corpus, good)[0], 0)
            # Mutation : le scorer accepte les neg « n1* »/« n2* » (≈ 60 %
            # des négatifs — très au-delà de la cible FPR 2 %).
            degraded = write_scorer(root, SCORER.replace(
                'label = "accept" if text.startswith("ok") else "refuse"',
                'label = "accept" if (text.startswith("ok") or "n1" in case["id"] or "n2" in case["id"]) else "refuse"'))
            code, report = self.run_main(root, corpus, degraded)
            self.assertEqual(code, 1)
            self.assertEqual(len(report["regressions"]), 4)  # 4 classes touchées

    def test_rapport_exploitable_par_tmetrics(self):
        """Le rapport écrit est exactement la forme que MetricsReportFromJSON
        (Go) accepte : version, corpus_hash 64 hex, classes bornées."""
        with tempfile.TemporaryDirectory() as root:
            corpus = build_corpus(root)
            code, report = self.run_main(root, corpus, write_scorer(root))
            self.assertEqual(code, 1)  # régressions I — mais le rapport reste valide
            self.assertEqual(report["version"], 1)
            self.assertEqual(len(report["corpus_hash"]), 64)
            int(report["corpus_hash"], 16)
            for c in report["classes"]:
                self.assertLessEqual(c["false_negatives"], c["positives"])
                self.assertLessEqual(c["false_positives"], c["negatives"])
                self.assertTrue(0 < len(c["class"]) <= 8)


if __name__ == "__main__":
    unittest.main()
