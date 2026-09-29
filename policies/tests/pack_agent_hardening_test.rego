# Tests du paquet tbp.pack.agent_hardening.
#
# Ce dossier est VOLONTAIREMENT distinct de policies/rego/ : ce qui vit dans
# policies/rego/ part dans le bundle signé et passe par le validateur de
# déterminisme (§11.3) ; les tests n'ont rien à y faire.
#
#   opa test policies/rego policies/tests -v
#
# Chaque test d'un refus a son pendant « cas voisin autorisé » : un paquet qui
# refuse tout passerait les tests de refus sans rien prouver.

package tbp.pack.agent_hardening_test

import data.tbp.pack.agent_hardening as h
import rego.v1

viol(inp) := v if {
	v := h.violation with input as inp
}

viol_cfg(inp, cfg) := v if {
	v := h.violation with input as inp
		with data.tbp.hardening as cfg
}

ok_(inp) if h.ok with input as inp

# --- fichiers d'identité / de mémoire d'agent -------------------------------

test_protected_file_write_denied_below_w if {
	"protected-agent-file" in viol({"action": "write", "resource": "workspace/SOUL.md", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "workspace/SOUL.md", "class": 1})
	"protected-agent-file" in viol({"action": "delete", "resource": "MEMORY.md", "class": 3})
}

test_protected_file_write_allowed_for_class_w if {
	ok_({"action": "write", "resource": "workspace/SOUL.md", "class": 2})
	ok_({"action": "delete", "resource": "AGENTS.md", "class": 2})
}

test_protected_file_read_allowed if {
	ok_({"action": "read", "resource": "workspace/MEMORY.md", "class": 0})
}

test_protected_file_evasions_normalised if {
	"protected-agent-file" in viol({"action": "write", "resource": "notes/soul.MD", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "a/b/../MEMORY.md", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "%53OUL.md", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "C:\\agent\\AGENTS.md", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "SOUL.md.", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "SOUL.md ", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "soul.md:hidden", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "SOUL.md/", "class": 0})
	"protected-agent-file" in viol({"action": "write", "resource": "/api/files/SOUL.md?x=1#y", "class": 0})
}

test_protected_file_neighbours_not_flagged if {
	ok_({"action": "write", "resource": "docs/readme.md", "class": 0})
	ok_({"action": "write", "resource": "soul.md.bak", "class": 0})
	ok_({"action": "write", "resource": "soulmate.md", "class": 0})
	ok_({"action": "write", "resource": "SOUL.md/notes.txt", "class": 0})
}

# Fail-closed : une classe ou une action absente n'ouvre JAMAIS l'écriture.
test_protected_file_missing_class_or_action_is_violation if {
	"protected-agent-file" in viol({"action": "write", "resource": "SOUL.md"})
	"protected-agent-file" in viol({"resource": "SOUL.md", "class": 0})

	# la classe W (authoritative, résolue par le registre) lève CETTE violation
	# (une action absente reste, elle, une violation à part entière)
	not "protected-agent-file" in viol({"resource": "SOUL.md", "class": 2})
	"action-invalid" in viol({"resource": "SOUL.md", "class": 2})
}

# --- magasins d'identifiants -------------------------------------------------

test_credential_store_denied_even_for_read_and_class_w if {
	every r in [
		".env", ".env.production", "app/.env.local", "id_rsa", "home/u/.ssh/known_hosts", ".aws/credentials",
		"server.PEM", "tls/private.key", "wallet.dat", "/etc/shadow", "file:///etc/gshadow", ".netrc",
		"Chrome/Login Data", ".gnupg/pubring.kbx", "vault.kdbx", "x/.kube/config",
	] {
		"credential-store" in viol({"action": "read", "resource": r, "class": 2})
	}
}

test_credential_store_neighbours_not_flagged if {
	every r in [".environment", "environment.md", "src/keyboard.go", "monkey.txt", "docs/ssh-guide.md", "shadow-boxing.md", "etc/shadowed"] {
		ok_({"action": "read", "resource": r, "class": 0})
	}
}

test_credential_extra_lists_from_bundle_data if {
	cfg := {"extra_credential_files": ["Secrets.YAML"], "extra_credential_dirs": ["Vault"]}
	"credential-store" in viol_cfg({"action": "read", "resource": "cfg/secrets.yaml", "class": 0}, cfg)
	"credential-store" in viol_cfg({"action": "read", "resource": "vault/x.txt", "class": 0}, cfg)
	not "credential-store" in viol({"action": "read", "resource": "cfg/secrets.yaml", "class": 0})
}

test_extra_protected_files_from_bundle_data if {
	cfg := {"extra_protected_files": ["CLAUDE.md"]}
	"protected-agent-file" in viol_cfg({"action": "write", "resource": "CLAUDE.md", "class": 0}, cfg)
	not "protected-agent-file" in viol({"action": "write", "resource": "CLAUDE.md", "class": 0})
}

# --- egress -------------------------------------------------------------------

test_egress_default_deny if {
	"egress-not-allowlisted" in viol({"action": "read", "resource": "https://api.example.org/v1/x", "class": 0})
	"egress-not-allowlisted" in viol({"action": "write", "resource": "http://10.0.0.5:8080/", "class": 2})
	"egress-not-allowlisted" in viol({"action": "read", "resource": "//evil.example/x", "class": 0})
	"egress-not-allowlisted" in viol({"action": "read", "resource": "https:\\\\evil.example\\x", "class": 0})
	"egress-not-allowlisted" in viol({"action": "read", "resource": "ftp://files.example.org/a", "class": 0})
}

test_egress_allowlist_exact_and_wildcard if {
	cfg := {"allowed_domains": ["api.example.org", "*.cdn.example.net"]}
	ok_with := object.union({"class": 0, "action": "read"}, {})
	not "egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "https://api.example.org/v1/x"}), cfg)
	not "egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "HTTPS://API.EXAMPLE.ORG:8443/x?y=1"}), cfg)
	not "egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "https://api.example.org./x"}), cfg)
	not "egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "https://a.b.cdn.example.net/x"}), cfg)

	# le joker ne couvre pas le domaine nu, ni un domaine qui ne fait que finir pareil
	"egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "https://cdn.example.net/x"}), cfg)
	"egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "https://evilcdn.example.net/x"}), cfg)
	"egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "https://api.example.org.evil.example/x"}), cfg)
}

# Le piège classique : l'hôte réel est APRÈS le dernier « @ ».
test_egress_userinfo_trick if {
	cfg := {"allowed_domains": ["api.example.org"]}
	"egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": "https://api.example.org@evil.example/x"}, cfg)
	not "egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": "https://evil.example@api.example.org/x"}, cfg)
}

test_egress_malformed_and_opaque_uris if {
	cfg := {"allowed_domains": ["api.example.org"]}
	"malformed-authority" in viol_cfg({"action": "read", "class": 0, "resource": "https://api.example.org%2eevil.example/x"}, cfg)
	"malformed-authority" in viol_cfg({"action": "read", "class": 0, "resource": "https://api.example.org evil/x"}, cfg)
	"malformed-authority" in viol_cfg({"action": "read", "class": 0, "resource": "https:///x"}, cfg)
	"opaque-uri" in viol({"action": "read", "class": 0, "resource": "data:text/plain;base64,QQ=="})
	"opaque-uri" in viol({"action": "read", "class": 0, "resource": "javascript:alert(1)"})
}

test_non_urls_not_subject_to_egress_and_file_scheme_is_local if {
	ok_({"action": "read", "class": 0, "resource": "doc-1"})
	ok_({"action": "read", "class": 0, "resource": "/reports?action=list"})
	ok_({"action": "read", "class": 0, "resource": "file:///srv/data/report.txt"})
	ok_({"action": "read", "class": 0, "resource": "///srv/data/report.txt"})

	# un chemin local protégé reste protégé sous file://
	"protected-agent-file" in viol({"action": "write", "class": 0, "resource": "file:///home/u/SOUL.md"})
}

# --- fail-closed sur l'entrée --------------------------------------------------

test_invalid_input_is_violation if {
	"resource-invalid" in viol({"action": "read", "class": 0})
	"resource-invalid" in viol({"action": "read", "class": 0, "resource": 42})
	"resource-invalid" in viol({"action": "read", "class": 0, "resource": null})
	"resource-invalid" in viol({"action": "read", "class": 0, "resource": false})
	"resource-invalid" in viol({"action": "read", "class": 0, "resource": ["SOUL.md"]})
	"resource-invalid" in viol({"action": "read", "class": 0, "resource": {"path": "x"}})
	"resource-invalid" in viol({"action": "read", "class": 0, "resource": ""})
	"malformed-resource" in viol({"action": "read", "class": 0, "resource": "%zz"})

	# double encodage : « %2553 » se décode en « %53 », qui n'est pas canonique
	"malformed-resource" in viol({"action": "write", "class": 0, "resource": "%2553OUL.md"})
	not ok_({"action": "read", "class": 0})
	not ok_({"action": "read", "class": 0, "resource": "%zz"})
}

# --- exemptions -----------------------------------------------------------------

test_exemption_is_exact_and_from_bundle_data if {
	cfg := {"exempt_resources": ["Public/Server.pem"]}
	inp := {"action": "read", "class": 0, "resource": "public/server.pem"}
	not "credential-store" in viol_cfg(inp, cfg)
	"credential-store" in viol_cfg({"action": "read", "class": 0, "resource": "private/server.pem"}, cfg)
	"credential-store" in viol(inp)
}

# --- sortie triée, déterministe ---------------------------------------------------

test_reasons_are_sorted_and_stable if {
	r := h.reasons with input as {"action": "write", "class": 0, "resource": "https://evil.example/.env"}
	r == sort(r)
	count(r) >= 2
}

# --- commandes (AST03.3) -------------------------------------------------------

test_command_default_deny_without_allowlist if {
	"command-not-allowlisted" in viol({"action": "exec", "class": 0, "resource": "ls -la"})
	"command-not-allowlisted" in viol({"action": "EXEC", "class": 2, "resource": "ls"})
	"command-not-allowlisted" in viol({"action": "Run", "class": 0, "resource": "git status"})
	"command-not-allowlisted" in viol({"action": "spawn", "class": 0, "resource": "python -c 1"})
}

test_command_allowlist_is_exact_first_word if {
	cfg := {"allowed_commands": ["ls", "/usr/bin/git"]}
	not "command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "ls -la /srv"}, cfg)
	not "command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "  LS\t-la"}, cfg)
	not "command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "/usr/bin/git status"}, cfg)

	# « ls » n'autorise PAS un binaire déposé par l'agent, ni un autre chemin
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "/tmp/ls"}, cfg)
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "git status"}, cfg)
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "lsof"}, cfg)
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "rm -rf /"}, cfg)
}

test_command_shell_metacharacters_denied_even_if_command_allowed if {
	cfg := {"allowed_commands": ["ls"]}
	every c in [
		"ls; rm -rf /", "ls | sh", "ls & id", "ls $(id)", "ls `id`", "ls > /etc/x", "ls < /etc/x",
		"ls (a)", "ls {a,b}", "ls *.txt", "ls ?", "ls !x", "ls a\\b", "ls\nid", "ls\rid", "ls $HOME",
	] {
		"shell-metacharacter" in viol_cfg({"action": "exec", "class": 0, "resource": c}, cfg)
	}
	not "shell-metacharacter" in viol_cfg({"action": "exec", "class": 0, "resource": "ls -la /srv/data"}, cfg)
}

test_command_rules_only_for_command_actions if {
	# une ressource qui « ressemble » à une commande n'est pas une commande hors action d'exécution
	ok_({"action": "read", "class": 0, "resource": "notes about ls and git.txt"})
	not "command-not-allowlisted" in viol({"action": "read", "class": 0, "resource": "ls; rm"})
}

test_extra_command_actions_from_bundle_data if {
	cfg := {"extra_command_actions": ["Invoke"]}
	"command-not-allowlisted" in viol_cfg({"action": "invoke", "class": 0, "resource": "ls"}, cfg)
	not "command-not-allowlisted" in viol({"action": "invoke", "class": 0, "resource": "ls"})
}

# --- chemins explicites (AST03.4) ----------------------------------------------

test_glob_in_resource_denied if {
	"glob-in-resource" in viol({"action": "read", "class": 0, "resource": "reports/*.csv"})
	"glob-in-resource" in viol({"action": "write", "class": 2, "resource": "/srv/*"})
	"glob-in-resource" in viol({"action": "read", "class": 0, "resource": "%2A"})
	ok_({"action": "read", "class": 0, "resource": "reports/2026.csv"})

	# la query d'une URL locale n'est pas un chemin
	ok_({"action": "read", "class": 0, "resource": "/search?q=a*"})
}

# --- action invalide -------------------------------------------------------------

test_invalid_action_is_violation if {
	"action-invalid" in viol({"class": 0, "resource": "doc-1"})
	"action-invalid" in viol({"action": 7, "class": 0, "resource": "doc-1"})
	"action-invalid" in viol({"action": "", "class": 0, "resource": "doc-1"})
	not ok_({"class": 0, "resource": "doc-1"})
}
