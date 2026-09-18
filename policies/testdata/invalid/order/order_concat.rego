# Fixture INVALIDE pour le self-test de validate_determinism.go (T2, #4).
# concat() sur une set comprehension : l'ordre d'itération d'un set n'est
# pas défini — le résultat dépend de l'ordre d'itération (§12).
# Vit dans son propre répertoire : validée isolément comme un bundle.

package tbp.testdata.order

import rego.v1

msg := concat(",", {x | some x in input.items})
