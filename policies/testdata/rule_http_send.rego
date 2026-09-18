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

package testdata.forbidden

deny contains msg if {
	resp := http.send({"method": "GET", "url": "https://example.invalid"})
	resp.status_code == 200
	msg := "cette règle ne doit jamais compiler avec capabilities.json"
}
