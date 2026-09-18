# Fixture INVALIDE pour le self-test de validate_determinism.go (T2, #4).
# Cycle de dépendances entre règles — doit être rejetée (§11.3).
# Vit dans son propre répertoire : validée isolément comme un bundle.

package tbp.testdata.cyclic

import rego.v1

a if {
	b
}

b if {
	a
}
