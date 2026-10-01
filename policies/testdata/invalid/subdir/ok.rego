# Fixture INVALIDE pour le self-test de validate_determinism.go (#242) : ce fichier,
# à la racine du bundle, est irréprochable. La règle interdite est dans sub/late.rego,
# MÊME paquet : « opa eval -d » et « opa build » la chargent (parcours récursif), un
# validateur qui ne lit que la racine déclarerait ce bundle conforme.

package tbp.testdata.subdir

import rego.v1

default allow := false

allow if input.action == "read"
