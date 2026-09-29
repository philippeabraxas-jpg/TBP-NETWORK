# Paquet de règles « périmètre par agent » (tbp-compliance/143, LLM06 :
# limiter les outils et les permissions au strict minimum ; 162, API5).
#
# Le registre d'agents (#125) résout la CLASSE et le QUOTA d'un agent mais ne
# dit pas quelles actions ni quelles ressources il peut viser : c'est le rôle
# d'OPA. Ce paquet en fait une liste blanche PAR AGENT, dans le document de
# données du bundle signé (§12) — jamais une valeur fournie par l'agent :
#
#   data.tbp.agent_scope.agents = {
#     "agent-1": {"actions": ["read", "search"], "resources": ["doc-1", "doc-2"]},
#     "agent-2": {"actions": ["read"]}
#   }
#   data.tbp.agent_scope.require_agent_scope = true   (optionnel)
#
#   - « actions » et « resources » sont comparées à l'identique (littéral, jamais
#     un préfixe : « doc-1 » n'autorise pas « doc-10 ») ;
#   - une clé absente ne contraint pas sa dimension ; une liste VIDE n'autorise
#     rien (déclaré mais non provisionné pour agir, comme SkillRecord.Scope) ;
#   - « input.subject » est le sujet résolu par le broker (mTLS/registre), pas
#     une déclaration de l'agent.
#
# Par défaut, un agent SANS entrée n'est pas contraint (compatibilité : sans
# données, ce paquet ne dit rien). Avec require_agent_scope = true, un agent
# sans entrée est refusé (« agent-scope-missing ») : c'est le mode de production
# recommandé, default-deny par agent.
#
# Ce paquet borne CE QUE L'AGENT PEUT DEMANDER, il ne remplace ni le registre de
# skills (périmètre de chaque skill, hors-bande dans le broker) ni les règles
# d'autorisation : il s'ajoute comme garde (voir action_example.rego).

package tbp.pack.agent_scope

import rego.v1

require_scope if data.tbp.agent_scope.require_agent_scope == true

default require_scope := false

# L'entrée de l'agent, si le sujet figure dans les données (un sujet absent ou
# non chaîne ne désigne aucune clé : indéfini, donc « pas d'entrée »).
scope := s if {
	s := data.tbp.agent_scope.agents[input.subject]
}

default has_scope := false

has_scope if {
	_ := scope
}

# Gardes « preuve positive » : « not x in ensemble » ne se déclenche pas quand
# x est indéfini (voir pack_skill_tier.rego).
default action_allowed := false

action_allowed if input.action in scope.actions

default resource_allowed := false

resource_allowed if input.resource in scope.resources

violation contains "agent-scope-missing" if {
	require_scope
	not has_scope
}

violation contains "action-not-in-agent-scope" if {
	has_scope
	scope.actions
	not action_allowed
}

violation contains "resource-not-in-agent-scope" if {
	has_scope
	scope.resources
	not resource_allowed
}

default ok := false

ok if count(violation) == 0

reasons := sort(violation)
