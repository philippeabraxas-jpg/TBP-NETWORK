#!/usr/bin/env python3
"""Non-vacuité de check_pinned_actions.py : chaque faute précise DOIT être prise."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import check_pinned_actions as c  # noqa: E402

SHA = "11d5960a326750d5838078e36cf38b85af677262"


def perr(text: str) -> list[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
        fh.write(text)
    try:
        return c.check_permissions(fh.name)
    finally:
        os.unlink(fh.name)


def errs(text: str) -> list[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
        fh.write(text)
    try:
        return c.check_file(fh.name)
    finally:
        os.unlink(fh.name)


class PinnedActions(unittest.TestCase):
    def test_tag_is_refused(self):
        self.assertTrue(errs("steps:\n  - uses: actions/checkout@v4\n"))

    def test_branch_is_refused(self):
        self.assertTrue(errs("steps:\n  - uses: open-policy-agent/setup-opa@v2\n"))

    def test_short_sha_is_refused(self):
        self.assertTrue(errs("steps:\n  - uses: actions/checkout@11d5960\n"))

    def test_sha_is_accepted(self):
        self.assertEqual(errs(f"steps:\n  - uses: actions/checkout@{SHA}  # v4.4.0\n"), [])

    def test_uppercase_or_wrong_length_sha_is_refused(self):
        self.assertTrue(errs(f"steps:\n  - uses: actions/checkout@{SHA.upper()}\n"))
        self.assertTrue(errs(f"steps:\n  - uses: actions/checkout@{SHA}0\n"))

    def test_job_level_reusable_workflow_is_checked(self):
        self.assertTrue(errs("jobs:\n  x:\n    uses: o/r/.github/workflows/w.yml@v1\n"))

    def test_documented_exception_only(self):
        self.assertEqual(errs("    uses: slsa-framework/slsa-github-generator/.github/workflows/g.yml@v2.1.0\n"), [])
        self.assertTrue(errs("    uses: other/slsa-github-generator/x.yml@v1\n"))

    def test_comments_and_local_actions_are_ignored(self):
        self.assertEqual(errs("#     - uses: actions/checkout@v4\n  - uses: ./local\n"), [])

    def test_the_repo_workflows_are_pinned(self):
        self.assertEqual(c.main(["x"]), 0)


class Permissions(unittest.TestCase):
    def test_no_block_at_all_is_refused(self):
        self.assertTrue(perr("name: x\non: push\njobs:\n  a:\n    runs-on: u\n"))

    def test_top_level_block_is_accepted(self):
        self.assertEqual(perr("name: x\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: u\n"), [])

    def test_every_job_must_have_its_own_when_no_top_level(self):
        ok = "jobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: u\n  b:\n    permissions: {}\n    runs-on: u\n"
        self.assertEqual(perr(ok), [])
        one_missing = "jobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: u\n  b:\n    runs-on: u\n"
        r = perr(one_missing)
        self.assertEqual(len(r), 1)
        self.assertIn("« b »", r[0])

    def test_write_all_is_refused_even_with_a_block(self):
        self.assertTrue(perr("permissions: write-all\njobs:\n  a:\n    runs-on: u\n"))
        self.assertTrue(perr("permissions:\n  write-all\njobs:\n  a:\n    runs-on: u\n"))

    def test_a_commented_block_does_not_count(self):
        self.assertTrue(perr("# permissions:\n#   contents: read\njobs:\n  a:\n    runs-on: u\n"))

    def test_the_repo_workflows_declare_permissions(self):
        import glob
        for f in sorted(glob.glob(".github/workflows/*.yml")):
            self.assertEqual(c.check_permissions(f), [], f)


if __name__ == "__main__":
    unittest.main()
