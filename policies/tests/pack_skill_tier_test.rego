# Tests du paquet tbp.pack.skill_tier — mêmes règles que pour le paquet de
# durcissement : ce dossier reste hors du bundle, et chaque refus a son cas
# voisin autorisé (un paquet qui refuse tout ne prouverait rien).

package tbp.pack.skill_tier_test

import data.tbp.pack.skill_tier as t
import rego.v1

viol(inp) := v if {
	v := t.violation with input as inp
}

ok_(inp) if t.ok with input as inp

skill(tier) := {"risk_tier": tier, "scope_size": 1}

# --- sans registre configuré ------------------------------------------------

test_no_skill_no_opinion if {
	ok_({"action": "read", "resource": "x", "class": 3})
}

test_registry_required_when_declared if {
	"skill-registry-required" in t.violation with input as {"action": "read", "class": 1}
		with data.tbp.hardening as {"require_skill_registry": true}
}

test_registry_required_satisfied_by_skill if {
	t.ok with input as {"class": 3, "skill": skill("low")}
		with data.tbp.hardening as {"require_skill_registry": true}
}

test_registry_required_only_for_literal_true if {
	t.ok with input as {"class": 3}
		with data.tbp.hardening as {"require_skill_registry": "true"}
}

# --- niveaux bas ------------------------------------------------------------

test_low_and_medium_open_to_every_class if {
	every c in [0, 1, 2, 3] {
		ok_({"class": c, "skill": skill("low")})
		ok_({"class": c, "skill": skill("medium")})
	}
}

# --- high : classe I ou W ---------------------------------------------------

test_high_denied_for_class_f_and_out if {
	"skill-high-requires-class-i-or-w" in viol({"class": 0, "skill": skill("high")})
	"skill-high-requires-class-i-or-w" in viol({"class": 3, "skill": skill("high")})
}

test_high_allowed_for_class_i_and_w if {
	ok_({"class": 1, "skill": skill("high")})
	ok_({"class": 2, "skill": skill("high")})
}

# --- critical : classe W seule ----------------------------------------------

test_critical_denied_below_w if {
	every c in [0, 1, 3] {
		"skill-critical-requires-class-w" in viol({"class": c, "skill": skill("critical")})
	}
}

test_critical_allowed_for_class_w if {
	ok_({"class": 2, "skill": skill("critical")})
}

# --- fail-closed ------------------------------------------------------------

test_missing_or_unknown_tier_denied if {
	"skill-tier-invalid" in viol({"class": 2, "skill": {}})
	"skill-tier-invalid" in viol({"class": 2, "skill": {"scope_size": 1}})
	"skill-tier-invalid" in viol({"class": 2, "skill": {"risk_tier": ""}})
	"skill-tier-invalid" in viol({"class": 2, "skill": {"risk_tier": "Low"}})
	"skill-tier-invalid" in viol({"class": 2, "skill": {"risk_tier": 3}})
	"skill-tier-invalid" in viol({"class": 2, "skill": {"risk_tier": null}})
}

test_malformed_skill_object_denied if {
	"skill-tier-invalid" in viol({"class": 2, "skill": false})
	"skill-tier-invalid" in viol({"class": 2, "skill": null})
	"skill-tier-invalid" in viol({"class": 2, "skill": "high"})
	"skill-tier-invalid" in viol({"class": 2, "skill": []})
}

test_missing_class_denied_for_high_and_critical if {
	"skill-high-requires-class-i-or-w" in viol({"skill": skill("high")})
	"skill-critical-requires-class-w" in viol({"skill": skill("critical")})
	"skill-high-requires-class-i-or-w" in viol({"class": "2", "skill": skill("high")})
	"skill-critical-requires-class-w" in viol({"class": 2.5, "skill": skill("critical")})
}

test_reasons_sorted if {
	t.reasons == ["skill-critical-requires-class-w"] with input as {"class": 0, "skill": skill("critical")}
}

# --- composition dans la politique d'exemple --------------------------------

test_example_policy_gated_by_tier if {
	base := {"action": "read", "resource": "doc-1"}
	not data.tbp.example.action.allow with input as object.union(base, {"class": 0, "skill": skill("critical")})
	data.tbp.example.action.allow with input as object.union(base, {"class": 2, "skill": skill("critical")})
	data.tbp.example.action.allow with input as object.union(base, {"class": 3, "skill": skill("low")})
	data.tbp.example.action.allow with input as object.union(base, {"class": 3})
	not data.tbp.example.action.allow with input as object.union(base, {"class": 3, "skill": {}})
}
