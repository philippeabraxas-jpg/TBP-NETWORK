# Règle INTERDITE en sous-répertoire (#242) : time.now_ns est non déterministe (§11.3).
# Le même texte à la racine du bundle est refusé ; il doit l'être ici aussi.

package tbp.testdata.subdir

import rego.v1

allow if time.now_ns() > 0
