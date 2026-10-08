package main

// plan_approvals.go — combien d'opérateurs approuvent un plan (issue #196).
//
// L'approbation d'un plan était UNE signature d'opérateur, quel que soit le quorum de la cellule,
// alors que l'action W isolée exige k-of-n (§7.5). La règle, décidée par le mainteneur le 2026-10-08 :
//
//   - classes F (financier) et W (survie) : k signatures DISTINCTES d'opérateurs ;
//   - classe I (infrastructure) : une signature ;
//   - le k est celui du quorum de la cellule (TBP_QUORUM_MIN). Il est ATTESTÉ par le témoin de
//     provisionnement (quorum-settings, #224) : l'abaisser par l'environnement fait refuser le démarrage,
//     donc le k que lit ce fichier à l'exécution est le k attesté. Échelle 1 : k = 1 ; échelle 2 : k = 2.
//
// La règle vit ICI, dans brokerd (ContractStore), et s'applique à tout chemin qui atteint
// plan/approve — socket d'administration local, bris de glace, future passerelle. Un seul code, un seul
// réglage : pas de variante plus faible selon le chemin.

import (
	"fmt"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// planApprovalsRequired rend la fonction que ContractStore appelle à la soumission d'un plan : le nombre
// de signatures distinctes d'opérateurs qui l'approuvent, d'après la classe de l'agent destinataire.
func planApprovalsRequired(reg broker.AgentRegistry, quorumMin int) func(subject string) int {
	return func(subject string) int {
		rec, ok := reg.Resolve(subject)
		if !ok {
			return 1 // sujet inconnu : le handler l'a déjà refusé (#235) ; jamais une exigence en dessous de 1
		}
		if rec.Class == pep.ClassF || rec.Class == pep.ClassW {
			return quorumMin
		}
		return 1
	}
}

// checkOperatorQuorum refuse de démarrer quand un plan F ou W ne pourrait JAMAIS être approuvé :
// un agent de classe F ou W est enregistré, k > 1, et le trousseau d'opérateurs compte moins de k clés
// distinctes. Même doctrine que « TBP_QUORUM_MIN > contrôleurs » : un quorum impossible est un refus
// de démarrage (fail-closed dès la configuration), pas un plan qui expire sans raison lisible.
func checkOperatorQuorum(reg broker.StaticAgentRegistry, quorumMin, distinctOperators int) error {
	if quorumMin <= 1 || distinctOperators >= quorumMin {
		return nil
	}
	for subject, rec := range reg {
		if rec.Class == pep.ClassF || rec.Class == pep.ClassW {
			return fmt.Errorf("l'agent %q est de classe F ou W : l'approbation de ses plans exige %d signatures distinctes d'opérateurs (TBP_QUORUM_MIN), mais le trousseau d'opérateurs n'a que %d clé(s) distincte(s) — ajouter des clés à TBP_OPERATOR_KEYS_FILE (issue #196)", subject, quorumMin, distinctOperators)
		}
	}
	return nil
}
