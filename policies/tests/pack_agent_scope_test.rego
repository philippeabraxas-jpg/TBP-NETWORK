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
