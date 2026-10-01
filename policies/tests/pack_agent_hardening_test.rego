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
	not "egress-not-allowlisted" in viol_cfg(object.union(ok_with, {"resource": "HTTPS://API.EXAMPLE.ORG:443/x?y=1"}), cfg)
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

# #239 : un schéma réseau sans « // » n'est pas une URL de sortie reconnue ni une autorité
# mal formée « classique », mais les clients HTTP le normalisent vers « https://hote/x ».
# Chaque refus a son voisin autorisé (la forme canonique vers un hôte autorisé, et les
# ressources qui ne sont PAS des URL réseau).
test_network_scheme_without_double_slash_is_refused if {
	cfg := {"allowed_domains": ["api.example.org"]}
	every r in [
		"https:/evil.example/x", "https:evil.example/x", "HTTPS:/evil.example", "http:evil.example",
		"https:\\evil.example", "ftp:/files.example/a", "ssh:evil.example", "wss:/evil.example/s",
	] {
		"malformed-authority" in viol_cfg({"action": "read", "class": 0, "resource": r}, cfg)
	}

	# même hôte AUTORISÉ, forme canonique : accepté (le correctif ne refuse pas tout)
	ok_cfg := object.union({"action": "read", "class": 0}, {"resource": "https://api.example.org/x"})
	h.ok with input as ok_cfg with data.tbp.hardening as cfg
}

test_non_network_scheme_resources_are_not_malformed_authority if {
	every r in ["doc-1", "db:users", "c:/dir/file.txt", "c:\\dir\\file.txt", "file:/srv/data/report.txt", "git-notes/x", "https-log.txt", "/a/https:b"] {
		not "malformed-authority" in viol({"action": "read", "class": 0, "resource": r})
	}
}

# #239 (voisin) : les clients ignorent les contrôles C0 et espaces de TÊTE ; la liste d'hôtes aussi.
test_leading_blanks_do_not_hide_an_egress_url if {
	cfg := {"allowed_domains": ["api.example.org"]}
	every r in [" https://evil.example/x", "\thttps://evil.example/x", "\nhttps://evil.example/x", "\u0001https://evil.example/x", " https:/evil.example/x"] {
		viol_cfg({"action": "read", "class": 0, "resource": r}, cfg) != set()
	}
	"egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": " https://evil.example/x"}, cfg)
	not "egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": " https://api.example.org/x"}, cfg)
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

test_command_allowlist_is_exact_first_word_and_bare if {
	cfg := {"allowed_commands": ["ls", "/usr/bin/git"]}

	# commande NUE : passe ; en majuscules, avec blancs de tête : passe (même forme)
	not "command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "ls"}, cfg)
	not "command-args-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "  LS  "}, cfg)
	not "command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "/usr/bin/git"}, cfg)

	# « ls » n'autorise PAS un binaire déposé par l'agent, ni un autre chemin
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "/tmp/ls"}, cfg)
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "git status"}, cfg)
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "lsof"}, cfg)
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "rm -rf /"}, cfg)
}

# #267 : l'allow-list ne jugeait que le premier mot — « git » autorisé laissait passer
# n'importe quels arguments (« git -c core.sshCommand=… », « find -exec … »).
test_command_arguments_are_judged if {
	cfg := {"allowed_commands": ["ls", "find"], "allowed_command_lines": ["git status", "ls -la /srv"]}
	every r in [
		"ls -la", "ls /etc/shadow", "find . -exec rm -rf {} +", "find / -delete",
		"git -c core.sshCommand=evil status", "git status --porcelain", "git log", "git",
		"ls -la /srv/other",
	] {
		"command-args-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": r}, cfg)
	}

	# un mot inconnu reste « command-not-allowlisted », pas « arguments »
	"command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "rm -rf /"}, cfg)
	not "command-args-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": "rm -rf /"}, cfg)

	# voisins autorisés : la ligne EXACTE (blancs et casse normalisés) et la commande nue
	every r in ["git status", "  GIT   Status ", "ls -la /srv", "ls", "find"] {
		not "command-args-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": r}, cfg)
		not "command-not-allowlisted" in viol_cfg({"action": "exec", "class": 0, "resource": r}, cfg)
	}
	ok_with_cfg := object.union({"allowed_command_lines": ["git status"]}, {})
	h.ok with input as {"action": "exec", "class": 0, "resource": "git status"}
		with data.tbp.hardening as ok_with_cfg
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

# #268 : les règles de commande ne dépendaient que du NOM de l'action (exec/run/shell/execute/
# spawn). Une action qui n'est pas connue comme non-exécution est jugée comme une commande.
test_unknown_action_names_are_judged_as_commands if {
	every a in ["invoke", "tool_use", "terminal", "Call", "bash", "system", "popen", "cmd", "eval", "exec.shell"] {
		"command-not-allowlisted" in viol({"action": a, "class": 0, "resource": "rm -rf /"})
		"shell-metacharacter" in viol({"action": a, "class": 0, "resource": "ls; id"})
	}

	# voisins : les actions connues comme non-exécution ne sont pas jugées comme des commandes
	every a in ["read", "READ", "write", "delete", "list", "create", "update", "append", "get", "put", "post", "patch", "head", "options", "http.send", "open_tunnel"] {
		not "command-not-allowlisted" in viol({"action": a, "class": 0, "resource": "rm -rf /"})
	}

	# une action non chaîne n'est pas devinée : « action-invalid » seul
	"action-invalid" in viol({"action": 7, "class": 0, "resource": "ls"})
	not "command-not-allowlisted" in viol({"action": 7, "class": 0, "resource": "ls"})
}

test_extra_non_command_actions_from_bundle_data if {
	"command-not-allowlisted" in viol({"action": "read.list", "class": 0, "resource": "registry/docs/42"})
	cfg := {"extra_non_command_actions": ["Read.List"]}
	not "command-not-allowlisted" in viol_cfg({"action": "read.list", "class": 0, "resource": "registry/docs/42"}, cfg)
	ok_with_cfg := cfg
	h.ok with input as {"action": "read.list", "class": 0, "resource": "registry/docs/42"}
		with data.tbp.hardening as ok_with_cfg
}

test_command_rules_only_for_command_actions if {
	# une ressource qui « ressemble » à une commande n'est pas une commande hors action d'exécution
	ok_({"action": "read", "class": 0, "resource": "notes about ls and git.txt"})
	not "command-not-allowlisted" in viol({"action": "read", "class": 0, "resource": "ls; rm"})
}

test_extra_command_actions_force_command_judgement if {
	# « write » est connue comme non-exécution… sauf si le bundle la force à être jugée comme commande
	not "command-not-allowlisted" in viol({"action": "write", "class": 0, "resource": "ls"})
	cfg := {"extra_command_actions": ["Write"]}
	"command-not-allowlisted" in viol_cfg({"action": "write", "class": 0, "resource": "ls"}, cfg)
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

# #239 (re-revue de 8873638) : tabulation, saut de ligne et retour chariot sont retirés PARTOUT par les
# clients (spec WHATWG URL, urllib.parse de Python 3.13) : « ht<TAB>tps://hote/x » EST https vers hote.
test_control_characters_inside_the_url_do_not_hide_it if {
	cfg := {"allowed_domains": ["api.example.org"]}
	every r in [
		"ht\ttps://evil.example/x", "https\n://evil.example/x", "https:/\t/evil.example/x",
		"https:\r\n//evil.example/x", "h\tt\nt\rps://evil.example/x",
	] {
		"egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": r}, cfg)
	}

	# schéma sans « // » ET caractère de contrôle : toujours vu
	"malformed-authority" in viol_cfg({"action": "read", "class": 0, "resource": "h\tttps:evil.example/x"}, cfg)

	# voisins autorisés : même forme vers l'hôte AUTORISÉ ⇒ pas de sortie refusée ; et une ressource
	# qui n'est pas une URL réseau reste intacte malgré une tabulation
	not "egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": "ht\ttps://api.example.org/x"}, cfg)
	not "malformed-authority" in viol({"action": "read", "class": 0, "resource": "doc\t1"})
}

# #269 : un caractère de contrôle (NUL, saut de ligne, tabulation, DEL) dans la ressource — brute
# ou décodée — est refusé : un exécuteur en C tronque au NUL (« /etc/shadow%00.txt » ouvre
# « /etc/shadow »), et le paquet jugerait alors une autre ressource que celle exécutée.
test_control_characters_in_the_decoded_resource_are_refused if {
	every r in [
		"/etc/shadow%00.txt", "workspace/SOUL.md%00.png", "reports/2026.csv%00", "doc%0a1", "doc%0A1",
		"doc%09x", "doc%7f", "doc\u0000x", "doc\nx", "a%0d%0ab", "%00",
	] {
		"control-character" in viol({"action": "read", "class": 0, "resource": r})
		not ok_({"action": "read", "class": 0, "resource": r})
	}

	# l'exemption porte sur une ressource exacte : elle ne lève pas ce refus
	"control-character" in viol_cfg({"action": "read", "class": 0, "resource": "doc%001"}, {"exempt_resources": ["doc%001"]})

	# voisins : espace, « %20 », « %2F », unicode, caractère imprimable — pas de refus
	every r in ["reports/2026.csv", "my doc.txt", "my%20doc.txt", "reports%2F2026.csv", "dossier/é.txt", "a-b_c.d"] {
		not "control-character" in viol({"action": "read", "class": 0, "resource": r})
		ok_({"action": "read", "class": 0, "resource": r})
	}
}

# #270 : un hôte autorisé ne l'était que par son nom — sur TOUS les ports. Sans port déclaré, seul
# le port par défaut du schéma passe ; un autre port se déclare.
test_egress_port_is_judged if {
	cfg := {"allowed_domains": ["api.example.org", "*.cdn.example.net", "admin.example.org:8443", "*.svc.example.org:9000"]}
	every r in [
		"https://api.example.org:22/x", "https://api.example.org:8443/x", "http://api.example.org:443/x",
		"https://api.example.org:5432/", "https://a.cdn.example.net:8080/x", "https://admin.example.org/x",
		"https://admin.example.org:443/x", "https://admin.example.org:9000/x", "https://x.svc.example.org/x",
		"https://api.example.org:99999/x", "https://user:pw@api.example.org:2222/x", "//api.example.org/x",
	] {
		"egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": r}, cfg)
	}

	# voisins : port par défaut du schéma (implicite ou explicite, zéros de tête compris), port déclaré
	every r in [
		"https://api.example.org/x", "https://api.example.org:443/x", "https://api.example.org:0443/x",
		"http://api.example.org/x", "http://api.example.org:80/x", "HTTPS://API.EXAMPLE.ORG./x",
		"https://a.cdn.example.net/x", "https://admin.example.org:8443/x", "https://admin.example.org:08443/x",
		"https://x.svc.example.org:9000/x", "wss://api.example.org/x",
	] {
		not "egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": r}, cfg)
	}
}

# Un schéma sans port par défaut connu (« //hote », schéma inconnu de la liste) ne passe que
# par une entrée à port explicite.
test_egress_scheme_without_default_port_needs_explicit_entry if {
	"egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": "//api.example.org/x"}, {"allowed_domains": ["api.example.org"]})
	not "egress-not-allowlisted" in viol_cfg({"action": "read", "class": 0, "resource": "//api.example.org:443/x"}, {"allowed_domains": ["api.example.org:443"]})
}
