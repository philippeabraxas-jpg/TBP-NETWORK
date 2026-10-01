# Tests du paquet tbp.pack.agent_scope — hors bundle, chaque refus a son cas
# voisin autorisé.

package tbp.pack.agent_scope_test

import data.tbp.pack.agent_scope as s
import rego.v1

cfg := {"agents": {
	"agent-1": {"actions": ["read", "search"], "resources": ["doc-1", "doc-2"]},
	"agent-2": {"actions": ["read"]},
	"agent-3": {"actions": []},
	"agent-4": {"resources": ["doc-1"]},
}}

cfg_req := {
	"require_agent_scope": true,
	"agents": {"agent-1": {"actions": ["read"]}},
}

viol(inp) := v if {
	v := s.violation with input as inp
		with data.tbp.agent_scope as cfg
}

ok_(inp) if {
	s.ok with input as inp
		with data.tbp.agent_scope as cfg
}

# --- sans donnée : aucun avis ------------------------------------------------

test_no_data_no_opinion if {
	s.ok with input as {"subject": "agent-9", "action": "anything", "resource": "x"}
		with data.tbp.agent_scope as {}
}

# --- actions ------------------------------------------------------------------

test_action_in_scope_allowed if {
	ok_({"subject": "agent-1", "action": "read", "resource": "doc-1"})
	ok_({"subject": "agent-1", "action": "search", "resource": "doc-2"})
}

test_action_outside_scope_denied if {
	"action-not-in-agent-scope" in viol({"subject": "agent-1", "action": "write", "resource": "doc-1"})
	"action-not-in-agent-scope" in viol({"subject": "agent-2", "action": "delete", "resource": "doc-1"})
}

test_action_match_is_exact_never_prefix if {
	"action-not-in-agent-scope" in viol({"subject": "agent-1", "action": "read.all", "resource": "doc-1"})
	"action-not-in-agent-scope" in viol({"subject": "agent-1", "action": "Read", "resource": "doc-1"})
	"action-not-in-agent-scope" in viol({"subject": "agent-1", "action": "rea", "resource": "doc-1"})
}

test_empty_action_list_allows_nothing if {
	"action-not-in-agent-scope" in viol({"subject": "agent-3", "action": "read", "resource": "doc-1"})
}

test_missing_action_denied if {
	"action-not-in-agent-scope" in viol({"subject": "agent-1", "resource": "doc-1"})
}

# --- ressources -----------------------------------------------------------------

test_resource_outside_scope_denied if {
	"resource-not-in-agent-scope" in viol({"subject": "agent-1", "action": "read", "resource": "doc-3"})
	"resource-not-in-agent-scope" in viol({"subject": "agent-1", "action": "read", "resource": "doc-10"})
	"resource-not-in-agent-scope" in viol({"subject": "agent-1", "action": "read"})
}

test_no_resource_list_means_unconstrained_dimension if {
	ok_({"subject": "agent-2", "action": "read", "resource": "anything"})
}

test_resources_only_entry_leaves_actions_unconstrained if {
	ok_({"subject": "agent-4", "action": "anything", "resource": "doc-1"})
	"resource-not-in-agent-scope" in viol({"subject": "agent-4", "action": "anything", "resource": "doc-2"})
	not "action-not-in-agent-scope" in viol({"subject": "agent-4", "action": "anything", "resource": "doc-2"})
}

# --- sujet ---------------------------------------------------------------------

test_unknown_subject_unconstrained_by_default if {
	ok_({"subject": "agent-9", "action": "write", "resource": "x"})
}

test_require_scope_denies_unlisted_or_malformed_subject if {
	every inp in [
		{"subject": "agent-9", "action": "read"},
		{"action": "read"},
		{"subject": 1, "action": "read"},
		{"subject": null, "action": "read"},
		{"subject": ["agent-1"], "action": "read"},
	] {
		"agent-scope-missing" in s.violation with input as inp with data.tbp.agent_scope as cfg_req
	}
}

test_require_scope_allows_listed_subject if {
	s.ok with input as {"subject": "agent-1", "action": "read"}
		with data.tbp.agent_scope as cfg_req
	not s.ok with input as {"subject": "agent-1", "action": "write"}
		with data.tbp.agent_scope as cfg_req
}

test_require_scope_only_for_literal_true if {
	s.ok with input as {"subject": "agent-9", "action": "read"}
		with data.tbp.agent_scope as {"require_agent_scope": "true"}
}

test_reasons_sorted if {
	s.reasons == ["action-not-in-agent-scope", "resource-not-in-agent-scope"] with input as {"subject": "agent-1", "action": "write", "resource": "doc-9"}
		with data.tbp.agent_scope as cfg
}

# --- composition dans la politique d'exemple -------------------------------------

test_example_policy_gated_by_agent_scope if {
	data.tbp.example.action.allow with input as {"subject": "agent-1", "action": "read", "resource": "doc-1"}
		with data.tbp.agent_scope as cfg
	not data.tbp.example.action.allow with input as {"subject": "agent-1", "action": "read", "resource": "doc-3"}
		with data.tbp.agent_scope as cfg
	not data.tbp.example.action.allow with input as {"subject": "agent-2", "action": "read", "resource": "doc-1", "class": 3}
		with data.tbp.agent_scope as {"require_agent_scope": true, "agents": {}}
}

# --- #240 : une entrée vide ne contraint rien — refusée en mode strict -----------------------

cfg_strict_incomplete := {
	"require_agent_scope": true,
	"agents": {
		"empty": {},
		"null": null,
		"no-dims": {"note": "pas de périmètre"},
		"false-actions": {"actions": false},
		"string-actions": {"actions": "read"},
		"null-resources": {"actions": ["read"], "resources": null},
		"actions-only": {"actions": ["read"]},
		"resources-only": {"resources": ["doc-1"]},
		"both": {"actions": ["read"], "resources": ["doc-1"]},
		"nothing-allowed": {"actions": []},
	},
}

viol_strict(subject) := v if {
	v := s.violation with input as {"subject": subject, "action": "delete", "resource": "prod-db"}
		with data.tbp.agent_scope as cfg_strict_incomplete
}

# L'attaque de la revue : avec require_agent_scope, « {} » et « null » autorisaient « delete prod-db ».
test_strict_empty_or_null_entry_is_refused if {
	every subject in ["empty", "null", "no-dims"] {
		"agent-scope-incomplete" in viol_strict(subject)
	}
	not s.ok with input as {"subject": "empty", "action": "delete", "resource": "prod-db"}
		with data.tbp.agent_scope as cfg_strict_incomplete
	not s.ok with input as {"subject": "null", "action": "delete", "resource": "prod-db"}
		with data.tbp.agent_scope as cfg_strict_incomplete
}

# Une dimension déclarée qui n'est pas une liste ne contraint pas (« false ») ou contraint
# à tort (chaîne, null) : refusée, dans tous les modes.
test_declared_dimension_must_be_a_list if {
	every subject in ["false-actions", "string-actions", "null-resources"] {
		"agent-scope-incomplete" in viol_strict(subject)
	}
	not s.ok with input as {"subject": "x", "action": "delete", "resource": "prod-db"}
		with data.tbp.agent_scope as {"agents": {"x": {"actions": false}}}
	"agent-scope-incomplete" in s.violation with input as {"subject": "x", "action": "read", "resource": "r"}
		with data.tbp.agent_scope as {"agents": {"x": {"actions": "read"}}}
}

# Voisins autorisés : les entrées bien formées passent, y compris une dimension absente
# (documentée « non contrainte ») et une liste vide (qui n'autorise rien, mais n'est pas
# « incomplète »).
test_strict_wellformed_entries_are_not_incomplete if {
	every subject in ["actions-only", "resources-only", "both", "nothing-allowed"] {
		not "agent-scope-incomplete" in viol_strict(subject)
	}
	s.ok with input as {"subject": "both", "action": "read", "resource": "doc-1"}
		with data.tbp.agent_scope as cfg_strict_incomplete
	s.ok with input as {"subject": "actions-only", "action": "read", "resource": "n-importe-quoi"}
		with data.tbp.agent_scope as cfg_strict_incomplete
}

# Hors mode strict, une entrée vide reste « non contrainte » (compatibilité inchangée).
test_non_strict_empty_entry_unchanged if {
	s.ok with input as {"subject": "x", "action": "anything", "resource": "r"}
		with data.tbp.agent_scope as {"agents": {"x": {}}}
}
