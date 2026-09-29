package ano

// classifier.go — la décision « ce champ doit-il être anonymisé ? » quand
// aucune règle ne tranche (#178). Le classifieur est une IA locale de type
// JEV : rapide (quelques millisecondes), oui/non par champ, exécutée dans la
// cellule sur des valeurs en clair.
//
// Doctrine :
//   - l'IA ne peut que RENFORCER : elle n'est jamais consultée pour un champ
//     que les règles masquent ou gardent explicitement, et elle ne peut pas
//     désactiver un motif ;
//   - tout ce qui n'est pas un « non » franc et à l'heure est un « oui » :
//     classifieur absent, en erreur, en retard ou saturé ⇒ le champ est masqué
//     (fail-closed — la direction qui ne fuit pas). Chaque faute déclenche
//     l'alarme OnTrip ;
//   - le classifieur voit la valeur en clair (elle ne quitte pas la cellule) :
//     il n'a AUCUN accès réseau par doctrine, comme le traducteur (§4.5).

import (
	"context"
	"time"
)

// Classifier décide si la valeur d'un champ doit être anonymisée.
type Classifier interface {
	// Decide rend true si la valeur doit être masquée. path est le chemin
	// pointé du champ (ex. « beneficiary.iban »), value sa forme texte
	// (tronquée à MaxClassifyBytes). Toute erreur est traitée comme « oui ».
	Decide(ctx context.Context, path, value string) (mask bool, err error)
}

const (
	// DefaultClassifierTimeout borne un appel au classifieur (« quelques
	// millisecondes »).
	DefaultClassifierTimeout = 5 * time.Millisecond
	minClassifierTimeout     = time.Millisecond
	maxClassifierTimeout     = 100 * time.Millisecond

	// DefaultClassifierInflight borne les appels simultanés : un classifieur
	// bloqué ne peut pas accumuler des goroutines sans limite.
	DefaultClassifierInflight = 16

	// MaxClassifyBytes borne la valeur transmise au classifieur.
	MaxClassifyBytes = 4096
)

// Raisons d'alarme OnTrip.
const (
	TripClassifierFault  = "ano-classifier-fault"
	TripVaultSaturated   = "ano-vault-saturated"
	TripEntriesSaturated = "ano-entries-saturated"
)

// classify rend (mask, fault). Sans classifieur : default-deny (mask=true,
// pas une faute — c'est la configuration).
func (a *Ano) classify(ctx context.Context, path, value string) (mask, fault bool) {
	if a.classifier == nil {
		return true, false
	}
	select {
	case a.inflight <- struct{}{}:
	default:
		a.trip(TripClassifierFault)
		return true, true
	}
	if len(value) > MaxClassifyBytes {
		value = value[:MaxClassifyBytes]
	}
	cctx, cancel := context.WithTimeout(ctx, a.classifierTimeout)
	defer cancel()
	type result struct {
		mask bool
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		// le jeton d'inflight est rendu quand le classifieur RENTRE, pas
		// quand on abandonne l'attente : c'est ce qui borne les goroutines.
		defer func() { <-a.inflight }()
		m, err := a.classifier.Decide(cctx, path, value)
		ch <- result{m, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			a.trip(TripClassifierFault)
			return true, true
		}
		return r.mask, false
	case <-cctx.Done():
		a.trip(TripClassifierFault)
		return true, true
	}
}
