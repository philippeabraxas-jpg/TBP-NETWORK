#!/usr/bin/env python3
"""Tests de check_doc_links.py : il doit pouvoir ÉCHOUER (le cas exact de la revue : figs/ au lieu de ../figs/)."""
import os
import tempfile
import unittest

import check_doc_links as c


def write(root, rel, text=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class DocLinks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        write(self.root, "figs/fig1.png")
        write(self.root, "docs/other.md")

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_figure_link_that_forgot_the_parent_directory_is_caught(self):
        spec = write(self.root, "docs/spec.md", "![Figure](figs/fig1.png)\n")
        self.assertEqual(c.check(spec), [(1, "figs/fig1.png")])

    def test_the_right_relative_path_passes(self):
        spec = write(self.root, "docs/spec.md", "![Figure](../figs/fig1.png) and [other](other.md#anchor)\n")
        self.assertEqual(c.check(spec), [])

    def test_what_is_not_a_repository_path_is_ignored(self):
        spec = write(self.root, "docs/spec.md", "[web](https://example.org/x) [mail](mailto:a@b.c) [here](#top) [abs](/etc/passwd)\n")
        self.assertEqual(c.check(spec), [])

    def test_code_is_not_a_link(self):
        spec = write(self.root, "docs/spec.md", "```\n[x](missing.md)\n```\nand `[y](missing.md)` inline\n")
        self.assertEqual(c.check(spec), [])

    def test_the_submodule_path_is_not_checked(self):
        spec = write(self.root, "README.md", "[core](tbp4.2.1/README.md)\n")
        self.assertEqual(c.check(spec), [])

    def test_a_missing_file_in_the_same_directory_is_caught(self):
        spec = write(self.root, "docs/spec.md", "[gone](gone.md)\n")
        self.assertEqual(c.check(spec), [(1, "gone.md")])


if __name__ == "__main__":
    unittest.main()
