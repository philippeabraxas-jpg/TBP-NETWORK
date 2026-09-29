# Exemple illustratif — PAS la politique de référence du pilote.
#
# Squelette minimal montrant la doctrine du §1 appliquée à une décision
# d'action (spec §4.1) : défaut-deny explicite, la classification
# inoffensive/à-arbitrer/hors-périmètre (§4.1), et la vérification d'un
# passeport à quota quand l'action ouvre un chemin lourd (§4.1-bis).
#
# input attendu (forme illustrative, à faire correspondre au schéma réel du
# token signé une fois le PEP implémenté — src/pep/) :
# {
#   "action": "read" | "write" | "open_tunnel" | ...,
#   "resource": "...",
#   "actor": {"cellule": "...", "policy_id": "..."},
#   "passeport": {"volume_used": 0, "volume_max": 1000, "ttl_remaining_s": 30} | null
# }

package tbp.example.action

import data.tbp.pack.agent_hardening as hardening
import data.tbp.pack.skill_tier as skill_tier
import rego.v1

# Défaut-deny explicite (doctrine §1 : "jamais par oui, toujours par
# défaut-deny") — sans cette ligne, une règle jamais atteinte se comporte
# différemment selon le mode d'évaluation OPA ; on ne veut jamais dépendre
# de ce comportement implicite.
default allow := false

# Le paquet de durcissement (policies/rego/pack_agent_hardening.rego) est une
# GARDE commune : fichiers de mémoire d'agent, magasins d'identifiants et
# sortie réseau. Le paquet de niveaux de skills (pack_skill_tier.rego) en est
# une seconde : un skill high/critical exige la classe I/W ou W. Aucune règle
# d'autorisation ci-dessous n'écarte ces gardes.

# Classe "inoffensive" (§4.1) : lecture seule, exécution directe.
allow if {
	input.action == "read"
	hardening.ok
	skill_tier.ok
}

# Ouverture de chemin lourd : n'autorise QUE si un passeport valide et non
# épuisé accompagne la requête (§4.1-bis) — jamais sur la seule classe de
# l'action.
allow if {
	input.action == "open_tunnel"
	hardening.ok
	skill_tier.ok
	input.passeport != null
	input.passeport.volume_used < input.passeport.volume_max
	input.passeport.ttl_remaining_s > 0
}

# Motif de refus explicite pour l'observabilité (même principe que le
# journal d'audit chaîné construit côté invarian-actuel/broker.py : un
# "deny" sans raison ne sert à rien pour l'investigation).
reason := concat(", ", sort(hardening.violation)) if {
	not hardening.ok
} else := concat(", ", sort(skill_tier.violation)) if {
	not skill_tier.ok
} else := "action inconnue ou hors classification" if {
	not allow
	not input.passeport
} else := "passeport absent, expiré ou quota épuisé" if {
	not allow
	input.action == "open_tunnel"
} else := "autorise"
