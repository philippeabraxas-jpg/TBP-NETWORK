# Règle de test T36 (issue #62, §4.4(1)) — la décision se prend AUSSI sur
# le diff d'état, pas seulement sur le scope déclaré.
#
# Utilisée par le test d'intégration réel (dryrun_test.go,
# TestDryRunRealOPA*) qui lance un vrai binaire OPA sur cette politique :
#
#   opa run --server --addr 127.0.0.1:<port> policies/testdata/rule_dryrun.rego
#
# endpoint évalué : /v1/data/tbp/test/dryrun
#
# Comportement : l'action "transfer" (classe F) n'est autorisée que si le
# dry-run est disponible ET qu'aucun champ interdit n'apparaît dans le
# diff. dry_run absent ou available=false ⇒ default-deny (une action
# marquée dry-run-requis ne passe pas sans diff — la politique tranche,
# résidu §10.5 sinon).

package tbp.test.dryrun

import rego.v1

default allow := false

forbidden_fields := {"balance", "root_password"}

allow if {
	input.action == "transfer"
	input.dry_run.available == true
	not touches_forbidden
}

touches_forbidden if {
	some e in input.dry_run.entries
	e.field in forbidden_fields
}
