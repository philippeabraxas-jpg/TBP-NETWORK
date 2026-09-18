# Fixture INVALIDE pour le self-test de validate_determinism.go (T2, #4).
# rand.intn produit une valeur différente à chaque processus d'évaluation —
# le test de stabilité (K évaluations identiques, §12) doit la rejeter.
# Vit dans son propre répertoire : validée isolément comme un bundle.

package tbp.testdata.nondet

import rego.v1

n := rand.intn("tbp-selftest", 1000000000)
