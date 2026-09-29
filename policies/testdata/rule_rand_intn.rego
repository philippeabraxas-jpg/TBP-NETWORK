# Règle NÉGATIVE : doit être REFUSÉE au chargement avec le capabilities.json
# restreint (policies/gen_capabilities.sh) — rand.intn est un aléa.
package tbp.testdata.rand_intn

import rego.v1

n := rand.intn("tbp", 10)
