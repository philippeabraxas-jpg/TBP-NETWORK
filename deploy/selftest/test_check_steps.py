#!/usr/bin/env python3
"""test_check_steps.py — T35 (issue #61) : non-vacuité du vérificateur.

Chaque test de rejet est une MUTATION du guide conforme : si le
vérificateur ne la prenait pas, il ne prouverait rien.
"""

import os
import tempfile
import unittest

from check_steps import check_file

VALID_GUIDE = """# Guide de test

#### Étape 1 — faire la chose

**Prérequis vérifiable** : `go version` répond.

**Commande** :

```bash
go build ./...  # config/ est à adapter, jamais copié tel quel
```

**Critère de succès observable** : le binaire existe.

**En cas d'échec : STOP** — ne pas continuer, corriger la cause.

#### Étape 2 — vérifier la chose

**Prérequis vérifiable** : l'étape 1 a réussi.

**Commande** :

```bash
./chose --verify
```

**Critère de succès observable** : sortie « ok ».

**En cas d'échec : STOP** — registre inspecté, cause corrigée.
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
        broken = VALID_GUIDE.replace("**En cas d'échec : STOP** — ne pas continuer, corriger la cause.\n", "", 1)
        errors = self._run(broken)
        self.assertTrue(any("En cas d'échec" in e for e in errors), errors)

    def test_mutation_bloc_hors_ordre(self):
        broken = VALID_GUIDE.replace(
            "**Prérequis vérifiable** : `go version` répond.\n\n**Commande** :",
            "**Commande** :\n\n**Prérequis vérifiable** : `go version` répond.",
            1,
        )
        errors = self._run(broken)
        self.assertTrue(any("hors ordre" in e for e in errors), errors)

    def test_mutation_config_sans_adapter(self):
        broken = VALID_GUIDE + "\ncopier `config/nftables/router-p1.nft` vers /etc\n"
        errors = self._run(broken)
        self.assertTrue(any("D99" in e for e in errors), errors)

    def test_mutation_aucune_etape(self):
        errors = self._run("# Guide\n\nDu texte sans étape exécutable.\n")
        self.assertTrue(any("D96" in e for e in errors), errors)

    def test_config_avec_adapter_passe(self):
        ok = VALID_GUIDE + "\nadapter `config/sysctl/99-tbp-hardening.conf` au noyau local\n"
        self.assertEqual(self._run(ok), [])

    def test_regression_commentaire_bash_dans_fence(self):
        # Un commentaire « # … » en tête de ligne DANS une fence n'est pas
        # un titre Markdown : sans cette correction, le parseur tronquait
        # l'étape et accusait les blocs suivants d'être manquants.
        guide = VALID_GUIDE.replace(
            "go build ./...  # config/ est à adapter, jamais copié tel quel",
            "# commentaire bash en tête de ligne\ngo build ./...  # config/ est à adapter",
            1,
        )
        self.assertEqual(self._run(guide), [])


if __name__ == "__main__":
    unittest.main()
