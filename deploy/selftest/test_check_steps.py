#!/usr/bin/env python3
"""test_check_steps.py — T35 (issue #61) : non-vacuité du vérificateur.

Chaque test de rejet est une MUTATION du guide conforme : si le
vérificateur ne la prenait pas, il ne prouverait rien.
"""

import os
import tempfile
import unittest

from check_steps import check_file

VALID_GUIDE = """# Test guide

#### Step 1 — do the thing

**Verifiable prerequisite**: `go version` responds.

**Command**:

```bash
go build ./...  # config/ is to adapt, never copied as-is
```

**Observable success criterion**: the binary exists.

**On failure: STOP** — do not continue, fix the cause.

#### Step 2 — verify the thing

**Verifiable prerequisite**: step 1 succeeded.

**Command**:

```bash
./thing --verify
```

**Observable success criterion**: output « ok ».

**On failure: STOP** — registry inspected, cause fixed.
"""


class CheckStepsTest(unittest.TestCase):
    def _run(self, text: str) -> list[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as fh:
            fh.write(text)
            path = fh.name
        try:
            return check_file(path)
        finally:
            os.unlink(path)

    def test_guide_conforme_passe(self):
        self.assertEqual(self._run(VALID_GUIDE), [])

    def test_mutation_bloc_manquant(self):
        broken = VALID_GUIDE.replace("**On failure: STOP** — do not continue, fix the cause.\n", "", 1)
        errors = self._run(broken)
        self.assertTrue(any("On failure" in e for e in errors), errors)

    def test_mutation_bloc_hors_ordre(self):
        broken = VALID_GUIDE.replace(
            "**Verifiable prerequisite**: `go version` responds.\n\n**Command**:",
            "**Command**:\n\n**Verifiable prerequisite**: `go version` responds.",
            1,
        )
        errors = self._run(broken)
        self.assertTrue(any("hors ordre" in e for e in errors), errors)

    def test_mutation_config_sans_adapter(self):
        broken = VALID_GUIDE + "\ncopy `config/nftables/router-p1.nft` to /etc\n"
        errors = self._run(broken)
        self.assertTrue(any("D99" in e for e in errors), errors)

    def test_mutation_aucune_etape(self):
        errors = self._run("# Guide\n\nText without an executable step.\n")
        self.assertTrue(any("D96" in e for e in errors), errors)

    def test_config_avec_adapter_passe(self):
        ok = VALID_GUIDE + "\nadapt `config/sysctl/99-tbp-hardening.conf` to the local kernel\n"
        self.assertEqual(self._run(ok), [])

    def test_regression_commentaire_bash_dans_fence(self):
        # A bash comment « # … » at the start of a line INSIDE a fence is
        # not a Markdown heading: without this fix, the parser truncated
        # the step and accused the following blocks of being missing.
        guide = VALID_GUIDE.replace(
            "go build ./...  # config/ is to adapt, never copied as-is",
            "# bash comment at start of line\ngo build ./...  # config/ is to adapt",
            1,
        )
        self.assertEqual(self._run(guide), [])


if __name__ == "__main__":
    unittest.main()
