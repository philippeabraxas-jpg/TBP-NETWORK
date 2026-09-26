package broker

// skill_registry.go — résolution d'identité et de périmètre des skills/
// outils qu'un agent peut invoquer. Né du catalogue de conformité
// (#142-#161) : le même trou structurel confirmé sept fois par des
// référentiels indépendants (OWASP AST01/02/10, OWASP LLM01.9-10/04,
// MAESTRO L3/L7, MITRE ATLAS Persistence, ISO 42001 A.10, NIST CSF
// Identify, ISO 27001 A.15) — TBP avait une notion d'agent (#125) et de
// plan (§4.2, T30), mais aucune notion de « skill » installable : un agent
// pouvait faire exister n'importe quelle action simplement en la nommant
// dans son intention structurée, sans que rien ne vérifie sa provenance ni
// ne borne les ressources qu'elle peut cibler.
//
// Doctrine IDENTIQUE à AgentRegistry (#125) : un registre provisionné
// HORS-BANDE, à la genèse — jamais résolu dynamiquement, jamais accepté
// depuis la demande elle-même, jamais muté à l'exécution. Il n'existe AUCUN
// chemin de rechargement à chaud dans ce fichier : la seule façon de faire
// apparaître, disparaître ou élargir un skill est qu'un opérateur de
// cellule modifie le fichier hors-bande et redémarre brokerd. Un agent
// (même compromis) n'a et n'aura jamais accès à ce chemin — il ne tourne
// jamais avec les droits qui permettent d'écrire ce fichier ni de
// redémarrer le démon, exactement comme pour TBP_AGENT_REGISTRY_FILE et
// TBP_OPERATOR_KEYS_FILE.
//
// Optionnel, comme Quorum/Contract/Envelope — jamais comme Registry/OPA/
// Issuer, qui restent fondationnels : une cellule qui ne configure pas ce
// registre garde son comportement actuel EXACTEMENT (aucune notion de
// skill, tr.Action est évalué par OPA sans restriction de périmètre
// supplémentaire) — pas de régression pour les déploiements existants.
// Dès qu'il est configuré, fail-closed (§1) : une action dont le nom ne
// correspond à AUCUN skill enregistré est refusée (skill-unknown), et une
// action ciblant une ressource hors du périmètre déclaré du skill est
// refusée (skill-scope-violation) — même absence de repli permissif
// qu'ailleurs dans ce paquet.
//
// « skill » est ici identifié par tr.Action lui-même (§4.5 : « the
// executed action is the translated action ») — pas un nouveau champ de
// fil, pas de changement de schéma de demande. Un skill EST une action
// nommée que le traducteur peut produire ; ce fichier ajoute une source de
// vérité indépendante sur QUI a le droit de faire exister cette action
// (Provenance, documentaire — jamais interprétée par le broker) et SUR
// QUOI elle peut agir (Scope, appliqué).
//
// Scope est une comparaison LITTÉRALE (jamais un préfixe, jamais un glob) :
// un préfixe autoriserait par exemple "compte-client" à couvrir
// "compte-client-admin" — la même classe de confusion que #107/#108 ont
// fermée pour la query string et le corps du proxy. No-DPI, comparaison
// exacte uniquement.

// SkillRecord est l'identité résolue d'un skill.
type SkillRecord struct {
	// Provenance identifie la source du skill (éditeur, dépôt, hash de
	// build...) — texte libre, jamais interprété par une décision
	// automatique : c'est une couture d'audit humain, pas un mécanisme de
	// contrôle d'accès. Un skill de provenance vide n'est pas provisionnable
	// (voir loadSkillRegistry, brokerd/main.go) — un skill sans provenance
	// connue n'est pas un skill à confiance minimale, c'est une identité
	// absente déguisée en identité présente.
	Provenance string
	// Scope borne les ressources exactes que ce skill peut cibler —
	// comparaison littérale uniquement (no-DPI). Vide ⇒ ce skill ne peut
	// cibler AUCUNE ressource : déclaré mais non provisionné pour agir,
	// jamais un accès total par omission (§1).
	Scope []string
}

// allows rend vrai si resource figure EXACTEMENT dans le scope déclaré.
func (r SkillRecord) allows(resource string) bool {
	for _, allowed := range r.Scope {
		if allowed == resource {
			return true
		}
	}
	return false
}

// SkillRegistry est la couture de résolution d'identité de skill. Resolve
// rend ok=false pour toute action absente du registre — un refus, jamais
// une valeur par défaut permissive (même contrat que AgentRegistry.Resolve).
type SkillRegistry interface {
	Resolve(action string) (SkillRecord, bool)
}

// StaticSkillRegistry est un SkillRegistry provisionné hors-bande (fichier
// JSON à la genèse, même doctrine que StaticAgentRegistry) : une table
// fixe, chargée une fois, jamais mutée à l'exécution — un agent compromis
// ne peut pas s'auto-enregistrer un nouveau skill ni élargir le périmètre
// d'un skill existant.
type StaticSkillRegistry map[string]SkillRecord

// Resolve rend l'enregistrement d'une action/skill, ou ok=false s'il est
// absent du registre.
func (r StaticSkillRegistry) Resolve(action string) (SkillRecord, bool) {
	rec, ok := r[action]
	return rec, ok
}
