# Paquet de règles « niveau de risque des skills » (tbp-compliance/142
# AST04.5 et AST09.2, voir policies/README.md, « Rule packs »).
#
# Le registre de skills du broker (TBP_SKILL_REGISTRY_FILE, hors-bande) porte
# pour chaque skill un « risk_tier » OBLIGATOIRE — low, medium, high, critical —
# validé au démarrage et recoupé avec la taille du périmètre déclaré. Le
# broker le transmet à OPA dans « input.skill » ({risk_tier, scope_size}) ;
# jamais l'agent : le champ vient du registre, pas de la demande.
#
# Ce paquet en tire la conséquence, que seule la politique peut porter :
#
#   low, medium : aucune contrainte supplémentaire ;
#   high        : le skill n'est invocable que par un agent de classe I ou W —
#                 donc sous plan approuvé (plan_binding obligatoire, #177) ;
#   critical    : le skill n'est invocable que par un agent de classe W —
#                 donc sous plan approuvé ET quorum (§7.5).
#
# La classe est celle du REGISTRE D'AGENTS (#125), jamais celle déclarée par
# l'agent : un agent de classe F ou hors F/I/W ne peut pas invoquer un skill
# high/critical, quelle que soit sa demande.
#
# Fail-closed : « input.skill » présent mais sans niveau connu est une
# violation ; une classe absente ou non entière est refusée pour high/critical.
#
# Sans registre de skills configuré, « input.skill » est absent : le paquet ne
# dit rien (comportement historique) — SAUF si le bundle déclare
#   data.tbp.hardening.require_skill_registry = true
# auquel cas l'absence est une violation (« skill-registry-required ») : un
# déploiement qui compte sur les niveaux ne peut pas les perdre en oubliant de
# configurer le registre.
#
# Ce que ce paquet ne fait PAS : il ne juge pas le niveau lui-même. Un niveau
# trop bas déclaré par l'opérateur est une faute de provisionnement, que seule
# la revue du fichier de registre (hors-bande) attrape — le recoupement avec la
# taille du périmètre n'en est qu'un garde-fou de cohérence, pas une preuve.

package tbp.pack.skill_tier

import rego.v1

tiers := {"low", "medium", "high", "critical"}

# Les classes qui ouvrent aux skills « high » (I, W) et « critical » (W seule),
# telles que numérotées par le PEP (0=F, 1=I, 2=W, 3=hors F/I/W).
classes_for_high := {1, 2}

classes_for_critical := {2}

require_registry if data.tbp.hardening.require_skill_registry == true

default require_registry := false

# « input.skill » présent, quelle que soit sa valeur (même false, null ou une
# chaîne : une forme inattendue est jugée, pas ignorée).
default has_skill := false

has_skill if {
	_ := input.skill
}

violation contains "skill-registry-required" if {
	require_registry
	not has_skill
}

# Gardes à valeur par défaut « false » : « not x in ensemble » NE se déclenche
# PAS quand x est indéfini (la référence est évaluée avant la négation) — un
# niveau ou une classe absents passeraient sans violation. Fail-closed : on
# demande la PREUVE positive (garde vraie), et son absence est la violation.
default tier_known := false

tier_known if input.skill.risk_tier in tiers

default class_opens_high := false

class_opens_high if input.class in classes_for_high

default class_opens_critical := false

class_opens_critical if input.class in classes_for_critical

# Niveau absent, non chaîne ou inconnu : jamais un niveau par défaut.
violation contains "skill-tier-invalid" if {
	has_skill
	not tier_known
}

violation contains "skill-high-requires-class-i-or-w" if {
	input.skill.risk_tier == "high"
	not class_opens_high
}

violation contains "skill-critical-requires-class-w" if {
	input.skill.risk_tier == "critical"
	not class_opens_critical
}

# ok : garde pour les politiques qui importent ce paquet.
default ok := false

ok if count(violation) == 0

reasons := sort(violation)
