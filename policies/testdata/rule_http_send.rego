# Règle de test NÉGATIVE pour gen_capabilities.sh (T1, issue #3).
#
# Elle appelle un built-in interdit par la doctrine (spec §12 : pas
# d'appel réseau sortant depuis une règle). Elle DOIT être refusée au
# chargement par :
#
#   opa check --capabilities policies/capabilities.json \
#       policies/testdata/rule_http_send.rego
#
# Si elle est acceptée, le filtrage de capabilities.json a échoué et le
# script gen_capabilities.sh doit sortir en erreur.
#
# import rego.v1 nécessaire pour 'contains'/'if' sans dépendre du défaut
# de version de l'OPA installé (rego v1 par défaut seulement depuis OPA
# 1.0) — sans cet import, un OPA pré-v1 refuse ce fichier pour une erreur
# de syntaxe, jamais atteint la vérification http.send visée : le test
# "passerait" en apparence sans jamais avoir vérifié ce qu'il prétend
# vérifier. Convention déjà suivie par policies/rego/action_example.rego.

package testdata.forbidden

import rego.v1

deny contains msg if {
	resp := http.send({"method": "GET", "url": "https://example.invalid"})
	resp.status_code == 200
	msg := "cette règle ne doit jamais compiler avec capabilities.json"
}
