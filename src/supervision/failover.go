// src/supervision/failover.go — T34b (issue #60)
//
// Détection de chute et déclenchement borné de bascule pré-autorisée
// (D80, plan et revue sur #60).
//
// Chute = les DEUX signaux de vie perdus EN MÊME TEMPS depuis FallDelay :
//
//   - aucune feuille nouvelle dans la chaîne de la cellule (taille
//     vérifiée par le ChainWatcher stable) ;
//   - aucun ancrage frais de la cellule dans la master chain.
//
// Le ET est porteur (revue Claude sur le plan, à ne pas simplifier en OU) :
// l'ancrage T6 est cadencé par le TEMPS, pas par l'activité (anchor.go) —
// une cellule vivante mais inactive n'écrit aucune feuille de décision et
// POURTANT continue d'ancrer. Seule une cellule réellement morte perd les
// deux signaux à la fois. Un OU transformerait toute cellule inactive en
// faux positif de bascule.
//
// Déclenchement : couture FailoverTrigger vers #30 (cluster.Tracker /
// PromotionController) — T34 DÉTECTE et DÉCLENCHE, il ne fence pas (D83 :
// fencing/quorum/promotion restent à #30). Budget pré-autorisé borné :
// max N déclenchements par fenêtre glissante d'une heure (défaut 2),
// compteur en mémoire borné. ATTENTION, deux budgets « N bascules/heure »
// cohabitent dans le dépôt (revue Claude — à ne pas confondre) :
//
//   - MaxFailoverTriggers (ici, défaut 2) borne combien de fois le
//     MONITEUR DÉCLENCHE une bascule ;
//   - MaxAutoFailoversPerHour=3 (src/cluster/epoch.go, T29) borne combien
//     de bascules mode=auto une CELLULE ACCEPTE.
//
// Deux couches différentes, pas de contradiction. Comme rien d'autre ne
// déclenche actuellement de bascule auto, le budget du moniteur (2 < 3)
// est de facto la borne effective — la plus stricte, donc dans le bon
// sens (moins d'intervention automatique, pas plus).
//
// Au-delà du budget, couture absente, ou couture en faute : escalade
// humaine (§5.3) — feuille KindSupervision event=AlertEventFailoverRefused
// verdict=Alarm + notification T14, et AUCUNE bascule automatique
// supplémentaire. Un déclenchement accepté est un constat (event=
// AlertEventFailoverTrigger, verdict=Notice), pas une alarme — mais il est
// feuillé comme toute alerte : le moniteur ne reste jamais silencieux.
//
// Épisodes : une chute confirmée n'est traitée qu'UNE fois (déclenchée ou
// refusée) — tant que la cellule reste morte, l'alarme continue est portée
// par anchor-stale (event 2) à chaque passage ; on ne re-déclenche ni ne
// re-refuse pas pour le même épisode. La reprise (feuille nouvelle OU
// ancrage frais) réarme le détecteur.
package supervision

import (
	"context"
	"encoding/binary"
	"time"
)

const (
	// DefaultMaxFailoverTriggers : budget pré-autorisé de bascules
	// DÉCLENCHÉES par le moniteur, par fenêtre glissante (voir l'en-tête
	// pour la distinction avec MaxAutoFailoversPerHour=3 côté cellule).
	DefaultMaxFailoverTriggers = 2
	// failoverWindow : fenêtre glissante du budget (une heure, D80).
	failoverWindow = time.Hour
	// DefaultFallDelay : durée sans AUCUN des deux signaux de vie avant de
	// conclure à la chute. Strictement supérieure à la borne d'ancrage :
	// l'alarme anchor-stale (T34a) précède toujours une bascule
	// automatique — l'humain est averti avant que la machine n'agisse.
	DefaultFallDelay = 2 * DefaultMaxAnchorLag
)

// FailoverEvidence est le constat de chute transmis à la couture #30 :
// tout ce qu'il faut pour que le déclenchement soit auditable sans
// re-vérifier les chaînes. Le détail hashé dans la feuille KindSupervision
// est l'encodage canonique ci-dessous (marshal).
type FailoverEvidence struct {
	// CellID : cellule déclarée en chute.
	CellID string
	// Size : dernière taille vérifiée de sa chaîne (figée depuis FallDelay).
	Size uint64
	// LastAnchor : dernier ancrage observé dans la master chain (zéro si
	// jamais observé).
	LastAnchor time.Time
	// FallenFor : durée écoulée depuis le dernier signe de vie de la
	// chaîne (progression de taille) au moment de la détection.
	FallenFor time.Duration
}

// marshal encode l'évidence de façon canonique (§11.3) — c'est ce tableau
// de 24 octets dont le sha256 est le DetailHash du record « TBPS1 » :
//
//	size(u64 BE) ‖ lastAnchorUnixNano(i64 BE, 0 si jamais observé) ‖
//	fallenForNanos(i64 BE)
func (e FailoverEvidence) marshal() []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint64(b[0:8], e.Size)
	var anchorNanos int64
	if !e.LastAnchor.IsZero() {
		anchorNanos = e.LastAnchor.UnixNano()
	}
	binary.BigEndian.PutUint64(b[8:16], uint64(anchorNanos))
	binary.BigEndian.PutUint64(b[16:24], uint64(e.FallenFor.Nanoseconds()))
	return b
}

// FailoverTrigger est la couture de déclenchement vers #30 (émission
// d'époque / promotion — cluster.Tracker, PromotionController.Promote).
// T34 détecte et déclenche ; le fencing, le quorum et la promotion sont
// du ressort de #30 (D83). Une erreur rendue = déclenchement refusé ou
// impossible : le moniteur escalade à l'humain (event 5), sans réessayer
// automatiquement pour cet épisode.
type FailoverTrigger interface {
	Trigger(ctx context.Context, ev FailoverEvidence) error
}

// FailoverTriggerFunc adapte une fonction en FailoverTrigger (tests,
// câblage #30).
type FailoverTriggerFunc func(ctx context.Context, ev FailoverEvidence) error

// Trigger implémente FailoverTrigger.
func (f FailoverTriggerFunc) Trigger(ctx context.Context, ev FailoverEvidence) error {
	return f(ctx, ev)
}

// fallState est l'état de détection de chute d'une cellule.
type fallState struct {
	// lastSize : dernière taille vérifiée vue par le moniteur.
	lastSize uint64
	// lastProgress : moment du dernier accroissement de taille observé
	// (ou construction du moniteur — conservateur : une chaîne figée
	// AVANT l'arrivée du moniteur n'est déclarée en chute qu'après
	// FallDelay de surveillance effective).
	lastProgress time.Time
	// episodeHandled : la chute courante a déjà été déclenchée ou
	// refusée — pas de second acte pour le même épisode (l'alarme
	// continue est portée par anchor-stale, event 2).
	episodeHandled bool
}

// checkFall détecte la chute d'une cellule (ET strict, voir l'en-tête) et,
// le cas échéant, déclenche ou refuse la bascule — dans les deux cas en
// feuillant (§5.3) via raise.
func (m *Monitor) checkFall(ctx context.Context, cellID string, raise func(string, byte, byte, string, []byte) error) error {
	st := m.falls[cellID]
	now := m.now()
	size := m.watchers[cellID].Size()

	// Signal 1 : progression de la chaîne.
	if size != st.lastSize {
		st.lastSize = size
		st.lastProgress = now
		st.episodeHandled = false
		return nil
	}
	// Signal 2 : ancrage frais. Le ET est ici — fraîcheur mesurée sur la
	// fenêtre de chute (FallDelay), pas sur la borne d'alarme §6.2 : une
	// cellule qui ancre encore, même en retard d'alarme, est vivante.
	if last, ok := m.lastAnchor[cellID]; ok && now.Sub(last) <= m.fallDelay {
		st.episodeHandled = false
		return nil
	}
	// Les deux signaux sont perdus — depuis assez longtemps ?
	if now.Sub(st.lastProgress) < m.fallDelay {
		return nil
	}
	if st.episodeHandled {
		return nil
	}
	// Chute confirmée — traitée une fois, quel que soit le dénouement.
	st.episodeHandled = true
	last, _ := m.lastAnchor[cellID]
	ev := FailoverEvidence{
		CellID:     cellID,
		Size:       size,
		LastAnchor: last,
		FallenFor:  now.Sub(st.lastProgress),
	}
	detail := ev.marshal()

	if m.trigger == nil {
		// Bascule automatique non configurée : le moniteur détecte et
		// escalade — il ne reste jamais silencieux (§5.3).
		return raise(cellID, AlertEventFailoverRefused, AlertVerdictAlarm, "failover-no-trigger", detail)
	}
	// Fenêtre glissante bornée : ne comptent que les déclenchements de la
	// dernière heure. Le compteur est borné par construction (les entrées
	// sorties de fenêtre sont oubliées).
	cutoff := now.Add(-failoverWindow)
	kept := m.triggerTimes[:0]
	for _, ts := range m.triggerTimes {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	m.triggerTimes = kept
	if len(m.triggerTimes) >= m.maxTriggers {
		// Budget épuisé : escalade humaine, AUCUNE bascule automatique
		// supplémentaire (D80, §5.3 classe W).
		return raise(cellID, AlertEventFailoverRefused, AlertVerdictAlarm, "failover-budget-exhausted", detail)
	}
	if err := m.trigger.Trigger(ctx, ev); err != nil {
		// La couture #30 a fauté : escalade humaine (le diagnostic suit le
		// préfixe canonique dans le détail hashé). Pas de consommation de
		// budget — la bascule n'a pas eu lieu.
		return raise(cellID, AlertEventFailoverRefused, AlertVerdictAlarm, "failover-trigger-fault",
			append(detail, []byte("\ntrigger: "+err.Error())...))
	}
	m.triggerTimes = append(m.triggerTimes, now)
	// Constat d'action pré-autorisée : Notice, pas Alarm — mais feuillé
	// comme toute alerte (§5.3 vaut pour les actes du moniteur aussi).
	return raise(cellID, AlertEventFailoverTrigger, AlertVerdictNotice, "failover-triggered", detail)
}
