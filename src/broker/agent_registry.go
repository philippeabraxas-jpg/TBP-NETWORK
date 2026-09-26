package broker

// agent_registry.go — résolution d'identité d'agent (revue de sécurité
// #125). Avant cette couture, un agent déclarait lui-même son identité
// (subject), sa classe d'action et son vecteur de quota dans la demande
// d'émission — rien côté broker ne vérifiait ces déclarations contre une
// source indépendante. Même famille de défaut que #94.A9 (action
// auto-déclarée, fermé par le traducteur : « the executed action is the
// translated action ») et #110 (quota auto-déclaré côté décompte), mais
// côté ÉMISSION cette fois : un agent compromis pouvait se déclarer avec
// une classe ou un quota plus favorable que ce qui lui est réellement dû.
//
// Doctrine (même que les clés de contrôleurs/opérateurs, §12/§3.2) : un
// registre d'agents provisionné HORS-BANDE, à la genèse — jamais résolu
// dynamiquement, jamais accepté depuis la demande elle-même. Un subject
// absent du registre n'est pas un agent à privilège minimal : c'est une
// identité inconnue, refusée AVANT même la traduction (§1 : le moindre
// défaut d'entrée est un refus, jamais une dégradation silencieuse).
//
// Suite donnée à la revue #125 par la revue #162/#163 : le lien
// cryptographique entre le subject déclaré et le canal de transport est
// maintenant résolu ICI pour le chemin réseau mTLS (revue #124) — voir
// AgentRecord.TransportIdentity ci-dessous. Le socket Unix garde sa
// frontière de confiance à gros grain (permissions 0660, §7.1) : tout
// process qui y a accès reste traité comme interne à la cellule, comme
// avant #163 — ce n'est pas un repli oublié, c'est la frontière déjà
// acceptée pour ce transport précis.

import (
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// AgentQuotaPolicy est le plafond de quota qu'un agent est autorisé à
// demander — jamais le volume qu'il déclare vouloir dans sa demande
// (Translation.Quota), qui reste une PROPOSITION bornée par ce plafond.
type AgentQuotaPolicy struct {
	// MaxVolume borne Translation.Quota.VolumeMax — une demande de
	// passeport au-delà est refusée (agent-quota-exceeded), jamais
	// silencieusement plafonnée (§1 : un plafond réécrit sans le dire est
	// une demi-vérité).
	MaxVolume uint64
	// MaxWindowS borne Translation.Quota.WindowS — même doctrine.
	MaxWindowS uint64
}

// AgentRecord est l'identité résolue d'un agent : sa classe d'action
// PLAFOND (jamais celle que l'agent déclare dans son intention) et sa
// politique de quota. Quota nil ⇒ cet agent ne peut demander AUCUN
// passeport (agent-quota-forbidden) — seules les actions simples lui sont
// ouvertes.
type AgentRecord struct {
	Class pep.Class
	Quota *AgentQuotaPolicy
	// TransportIdentity, si non vide, est le CN attendu du certificat
	// client mTLS (revue #124) pour cet agent. Une demande arrivant par
	// le plan de données RÉSEAU et déclarant ce subject doit présenter
	// EXACTEMENT ce CN, sinon refus (agent-transport-unbound, revue
	// #162/#163) — jamais un repli permissif (§1). Vide ⇒ cet agent n'est
	// provisionné que pour le socket Unix ; toute demande le déclarant
	// par le réseau mTLS est refusée, quel que soit le certificat
	// présenté — un agent non provisionné pour le réseau ne peut pas y
	// apparaître « par accident ».
	TransportIdentity string
}

// AgentRegistry est la couture de résolution d'identité (revue #125).
// « no direct client → server path » s'étend ici : aucune identité
// n'entre dans la chaîne de décision sans être résolue depuis une source
// que le broker contrôle. Resolve rend ok=false pour tout subject absent
// du registre — un refus, jamais une valeur par défaut permissive.
type AgentRegistry interface {
	Resolve(subject string) (AgentRecord, bool)
}

// StaticAgentRegistry est un AgentRegistry provisionné hors-bande
// (fichier JSON à la genèse, même doctrine que TBP_OPERATOR_KEYS_FILE et
// le manifest de contrôleurs, §12/§3.2) : une table fixe, chargée une
// fois, jamais mutée à l'exécution — un agent compromis ne peut pas
// s'auto-inscrire.
type StaticAgentRegistry map[string]AgentRecord

// Resolve rend l'enregistrement d'un subject, ou ok=false s'il est absent
// du registre.
func (r StaticAgentRegistry) Resolve(subject string) (AgentRecord, bool) {
	rec, ok := r[subject]
	return rec, ok
}
