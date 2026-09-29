# Fixture INVALIDE pour le self-test de validate_determinism.go :
# uuid.rfc4122 est un aléa. Le contrôle STATIQUE doit le refuser sans qu'aucune
# fixture de stabilité ne soit nécessaire (défense en profondeur, en plus de
# policies/gen_capabilities.sh).

package tbp.testdata.forbidden

import rego.v1

id := uuid.rfc4122("tbp-selftest")
