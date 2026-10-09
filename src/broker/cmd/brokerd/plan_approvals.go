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
	"errors"
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

// separateDuties dit si la cellule sépare les tâches : à partir de k = 2 (échelle 2), celui qui soumet un plan n'est pas celui
// qui l'approuve, donc la soumission est SIGNÉE (le broker sait qui l'a faite). À k = 1 (échelle 1), un seul opérateur fait les
// deux gestes : la règle n'a pas de sens, la soumission non signée reste ouverte. Le k est celui du quorum attesté
// (TBP_QUORUM_MIN) : un seul réglage, le même code partout.
func separateDuties(quorumMin int) bool { return quorumMin >= 2 }

// checkSeparatedDuties refuse de démarrer quand, la cellule séparant les tâches, aucun plan ne pourrait être approuvé : personne
// ne tient le rôle de soumission, ou, pour un agent enregistré, il n'existe aucun soumetteur dont les approbations exigées
// puissent venir d'AUTRES clés. Même doctrine que checkOperatorQuorum : un quorum impossible est un refus de démarrage, pas
// un plan qui expire sans raison lisible. Le soumetteur compte pour un approbateur de moins quand il tient aussi ce rôle.
func checkSeparatedDuties(reg broker.StaticAgentRegistry, quorumMin int, ring operatorKeyring) error {
	if !separateDuties(quorumMin) {
		return nil
	}
	if len(ring.Submitters) == 0 {
		return errors.New("la cellule sépare les tâches (TBP_QUORUM_MIN ≥ 2) : au moins une clé d'opérateur doit tenir le rôle « submit » — sans elle, aucun plan ne peut être soumis")
	}
	approver := make(map[[16]byte]bool, len(ring.Approvers))
	for _, k := range ring.Approvers {
		approver[pep.KeyIDFromPublicKey(k)] = true
	}
	// le plus d'approbateurs que laisse un soumetteur : tous, s'il n'approuve pas lui-même ; un de moins sinon
	best := 0
	for _, k := range ring.Submitters {
		n := len(approver)
		if approver[pep.KeyIDFromPublicKey(k)] {
			n--
		}
		if n > best {
			best = n
		}
	}
	need := planApprovalsRequired(reg, quorumMin)
	for subject, rec := range reg {
		if rec.Class == pep.ClassOut {
			continue // un agent de classe Out ne déroule pas de plan : s'il en soumet un, le refus est net à la soumission
		}
		if required := need(subject); required > best {
			return fmt.Errorf("l'agent %q exige %d approbation(s) distincte(s), mais aucun soumetteur ne laisse plus de %d approbateur(s) autre(s) que lui-même — donner le rôle « submit » à une clé qui n'approuve pas, ou ajouter des clés qui approuvent (soumetteur ≠ approbateur)", subject, required, best)
		}
	}
	return nil
}
