# Paquet de règles « durcissement d'agent » — premier paquet nommé du catalogue
# de règles (voir policies/README.md, « Rule packs »).
#
# Il ferme les points de conformité qu'une règle Rego peut fermer sans code
# supplémentaire (tbp-compliance/142 AST01.6, AST03.6/3.7/3.8 ; 143 LLM04 n°9) :
#
#   1. fichiers d'identité / de mémoire d'agent (SOUL.md, MEMORY.md,
#      AGENTS.md) : toute écriture exige la classe W (plan approuvé + quorum,
#      donc une revue humaine renforcée) ;
#   2. magasins d'identifiants (.env, clés SSH/GPG, .aws, portefeuilles,
#      données de navigateur, /etc/shadow…) : refus de TOUT accès, lecture
#      comprise ;
#   3. sortie réseau : une ressource qui est une URL doit viser un hôte
#      explicitement autorisé (default-deny de l'egress) ;
#   4. commandes (AST03.3) : une action d'exécution ne passe que si la commande
#      est explicitement autorisée ET sans métacaractère de shell — default-deny ;
#   5. chemins explicites (AST03.4) : un joker « * » dans une ressource est refusé.
#
# CE QUE CE PAQUET NE FAIT PAS (à lire avant de déployer) :
#   - il juge la ressource sous sa forme CANONIQUE (§4.5 : l'action exécutée est
#     l'action traduite). Il normalise la casse, l'encodage %, les
#     séparateurs « \ », les points/espaces finaux, les flux « :nom » et
#     « .. », mais ne résout pas les liens symboliques, les noms courts 8.3
#     ni les alias de système de fichiers : c'est le rôle du traducteur et de
#     l'exécuteur (voir #180) ;
#   - il ne décrit que les noms qu'il connaît : étendre la liste par le
#     document de données du bundle (ci-dessous), jamais en éditant ce fichier ;
#   - une ressource qui n'est pas une URL (chemin, identifiant) n'est pas
#     soumise à la liste d'hôtes ; une ressource sans schéma qui « ressemble »
#     à un hôte (« evil.example/x ») n'est pas reconnue comme URL.
#   - un schéma réseau connu (http, https, ftp, ftps, sftp, ws, wss, ssh, git, smb,
#     ldap, ldaps) non suivi de « // » (« https:/hote/x », « https:hote/x ») est
#     refusé comme autorité mal formée : les clients HTTP les normalisent vers
#     « https://hote/x ». Les blancs de tête sont ignorés avant l'analyse.
#
# Fail-closed : une entrée absente, non chaîne, ou dont l'encodage est invalide
# est une violation — jamais une règle silencieusement indéfinie.
#
# Configuration (document de données du BUNDLE signé, §12 — jamais une valeur
# fournie par l'agent) :
#   data.tbp.hardening.extra_protected_files   [nom de fichier, …]
#   data.tbp.hardening.extra_credential_files  [nom de fichier, …]
#   data.tbp.hardening.extra_credential_dirs   [nom de dossier, …]
#   data.tbp.hardening.allowed_domains         ["hote.exemple", "*.exemple.org"]
#   data.tbp.hardening.allowed_commands        ["ls", "/usr/bin/git"]  (1er mot, EXACT :
#                                              « ls » n'autorise pas « /tmp/ls »)
#   data.tbp.hardening.extra_command_actions   [nom d'action, …]
#   data.tbp.hardening.exempt_resources        [ressource exacte, …]  (faux positifs
#                                              documentés ; l'exemption est tracée
#                                              par le hash du bundle)

package tbp.pack.agent_hardening

import rego.v1

# ---------------------------------------------------------------------------
# Listes par défaut (étendues, jamais remplacées, par les données du bundle)
# ---------------------------------------------------------------------------

default_protected_files := {"soul.md", "memory.md", "agents.md"}

default_credential_files := {
	".netrc", ".npmrc", ".pypirc", ".git-credentials",
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
	"wallet.dat", "credentials.json",
	"login data", "cookies", "key3.db", "key4.db", "logins.json",
}

default_credential_dirs := {".ssh", ".aws", ".gnupg", ".kube", ".azure", ".docker", ".password-store"}

protected_files := default_protected_files | {lower(f) | some f in data.tbp.hardening.extra_protected_files}

credential_files := default_credential_files | {lower(f) | some f in data.tbp.hardening.extra_credential_files}

credential_dirs := default_credential_dirs | {lower(d) | some d in data.tbp.hardening.extra_credential_dirs}

allowed_domains := {lower(d) | some d in data.tbp.hardening.allowed_domains}

default_command_actions := {"exec", "run", "shell", "execute", "spawn"}

command_actions := default_command_actions | {lower(a) | some a in data.tbp.hardening.extra_command_actions}

allowed_commands := {lower(c) | some c in data.tbp.hardening.allowed_commands}

exempt_resources := {lower(r) | some r in data.tbp.hardening.exempt_resources}

# ---------------------------------------------------------------------------
# Normalisation de la ressource
# ---------------------------------------------------------------------------

# Décodé PUIS mis en minuscules (l'inverse laisserait « %53OUL.md » devenir
# « Soul.md »). Indéfini si l'encodage % est invalide : violation plus bas.
decoded := lower(urlquery.decode(input.resource))

# Chemin sans requête ni fragment, séparateurs unifiés.
path_no_query := split(split(replace(decoded, "\\", "/"), "?")[0], "#")[0]

# Segments non vides, normalisés : points/espaces finaux (alias NTFS) et flux
# « :nom » retirés.
segments := [s |
	some raw in split(path_no_query, "/")
	raw != ""
	raw != "."
	s := trim_right(split(raw, ":")[0], ". ")
	s != ""
]

basename := segments[count(segments) - 1] if count(segments) > 0

# ---------------------------------------------------------------------------
# Prédicats
# ---------------------------------------------------------------------------

is_read if input.action == "read"

is_w if input.class == 2

exempt if lower(input.resource) in exempt_resources

is_protected_file if basename in protected_files

is_credential_store if basename in credential_files

is_credential_store if regex.match(`^\.env(\..+)?$`, basename)

is_credential_store if regex.match(`\.(pem|key|p12|pfx|jks|keystore|kdbx)$`, basename)

is_credential_store if {
	some seg in segments
	seg in credential_dirs
}

is_credential_store if endswith(path_no_query, "/etc/shadow")

is_credential_store if endswith(path_no_query, "/etc/gshadow")

# --- URL et hôte ---------------------------------------------------------

# La ressource telle qu'un client HTTP la lit : les contrôles C0 et espaces de tête sont
# ignorés par les navigateurs et les bibliothèques courantes (« \thttps://hote/x »), et
# tabulation, saut de ligne et retour chariot sont retirés PARTOUT (« ht\ttps://hote/x »,
# « https\n://hote/x » : spec WHATWG URL, urllib.parse de Python) — #239, re-revue.
url_input := replace(replace(replace(trim_left(lower(input.resource), "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000a\u000b\u000c\u000d\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f "), "\t", ""), "\n", ""), "\r", "")

# [complet, schéma, autorité] ; le schéma est vide pour « //hote/… ». Le
# séparateur accepte « \ » (les navigateurs le traitent comme « / »).
url_match := regex.find_all_string_submatch_n(`^(?:([a-z][a-z0-9+.-]*):)?[/\\]{2}([^/\\?#]*)`, url_input, 1)

url_scheme := url_match[0][1]

url_authority := url_match[0][2]

# Hôte : sans identifiants (« user@ »), sans port, sans point final.
url_host := trim_right(regex.replace(split(url_authority, "@")[count(split(url_authority, "@")) - 1], `:[0-9]*$`, ""), ".")

# Une URL soumise à la liste d'hôtes : tout sauf « file:// » (chemin local, jugé
# par les règles de fichier) et sauf un « // » sans autorité (chemin absolu).
is_egress_url if {
	url_scheme != "file"
	url_authority != ""
}

# --- commandes et jokers ---------------------------------------------------

is_command_action if lower(input.action) in command_actions

# Métacaractères de shell : chaînage, redirection, substitution, sous-shell,
# jokers, échappement, saut de ligne. Une ressource qui en porte n'est plus UNE
# commande explicite (3.3 : « shell:false ou liste blanche »).
has_shell_metacharacter if regex.match("[;|&$`<>(){}*?!\\\\\n\r]", input.resource)

# Premier mot, EXACT (jamais le nom de base : « ls » ne doit pas autoriser un
# binaire « /tmp/ls » déposé par l'agent).
command_word := regex.split(`\s+`, trim_space(lower(input.resource)))[0]

has_glob if contains(path_no_query, "*")

opaque_uri if regex.match(`^(data|javascript|vbscript|mailto|tel|blob):`, lower(input.resource))

malformed_authority if {
	url_match[0]
	url_scheme != "file"
	regex.match(`[%\s]`, url_authority)
}

malformed_authority if {
	url_match[0]
	url_scheme != ""
	url_scheme != "file"
	url_authority == ""
}

# Schéma réseau SANS « // » (« https:/hote/x », « https:hote/x », « https:\\hote ») : ce
# n'est ni une URL de sortie reconnue ni une autorité mal formée au sens ci-dessus,
# mais beaucoup de clients HTTP normalisent ces formes vers « https://hote/x ».
# Refusé (#239) plutôt que laissé passer. Liste FERMÉE de schémas réseau : un schéma
# inconnu n'est pas deviné (un identifiant « a:b » reste une ressource ordinaire) ;
# « file: » reste local, jugé par les règles de fichier.
network_scheme_without_slashes if {
	regex.match(`^(?:https?|ftps?|sftp|wss?|ssh|git|smb|ldaps?):`, url_input)
	not url_match[0]
}

malformed_authority if network_scheme_without_slashes

host_allowed if url_host in allowed_domains

host_allowed if {
	some pattern in allowed_domains
	startswith(pattern, "*.")
	endswith(url_host, substring(pattern, 1, -1))
}

# ---------------------------------------------------------------------------
# Violations (codes stables, lisibles par l'audit)
# ---------------------------------------------------------------------------

violation contains "resource-invalid" if not is_string(input.resource)

# Trois formes distinctes : non chaîne (nombre, tableau, null…), absente, vide.
# `not is_string(x)` ne se déclenche PAS quand x est indéfini, d'où la seconde.
violation contains "resource-invalid" if not input.resource

violation contains "resource-invalid" if input.resource == ""

violation contains "malformed-resource" if {
	is_string(input.resource)
	not decoded
}

# Encore un « %xx » après UN décodage : double encodage, ce qui n'est pas une
# forme canonique (un exécuteur qui décode deux fois verrait une autre
# ressource que celle jugée). Refusé plutôt que deviné.
violation contains "malformed-resource" if {
	is_string(input.resource)
	regex.match(`%[0-9a-f]{2}`, decoded)
}

violation contains "protected-agent-file" if {
	not exempt
	is_protected_file
	not is_read
	not is_w
}

violation contains "credential-store" if {
	not exempt
	is_credential_store
}

violation contains "egress-not-allowlisted" if {
	not exempt
	is_egress_url
	not host_allowed
}

violation contains "opaque-uri" if {
	not exempt
	opaque_uri
}

violation contains "malformed-authority" if {
	not exempt
	malformed_authority
}

violation contains "action-invalid" if not is_string(input.action)

violation contains "action-invalid" if not input.action

violation contains "action-invalid" if input.action == ""

violation contains "shell-metacharacter" if {
	not exempt
	is_command_action
	has_shell_metacharacter
}

# Default-deny : sans « allowed_commands » dans les données du bundle, AUCUNE
# commande ne passe.
violation contains "command-not-allowlisted" if {
	not exempt
	is_command_action
	not command_word in allowed_commands
}

violation contains "glob-in-resource" if {
	not exempt
	is_string(input.resource)
	has_glob
}

# ok : aucune violation ne s'applique. Sert de garde aux politiques qui
# importent ce paquet (voir action_example.rego).
default ok := false

ok if count(violation) == 0

# Raisons triées : sortie déterministe (§11.3, §12).
reasons := sort(violation)
