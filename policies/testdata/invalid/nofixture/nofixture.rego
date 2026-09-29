# Fixture INVALIDE pour le self-test de validate_determinism.go : un package
# parfaitement déterministe, mais sans fixture de stabilité. Il doit être refusé :
# sans fixture, le contrôle de stabilité ne voit rien.

package tbp.testdata.nofixture

import rego.v1

default allow := false

allow if input.ok == true
