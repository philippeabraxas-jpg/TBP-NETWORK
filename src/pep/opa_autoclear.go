package pep

// Reprise automatique BORNÉE du latch fail-closed après une faute OPA
// (issue #205, R-18).
//
// Le latch T14 (failclosed.go) ne se lève pas tout seul : un OPA qui
// redémarre, une pause GC, une reconnexion lente immobilisaient la cellule
// jusqu'à une cérémonie de quorum. La correction a deux moitiés :
//
//   - le client OPA ne bascule le latch qu'après TripAfter fautes
//     consécutives (opa_client.go) — le verdict de chaque requête fautée
//     reste un deny tracé ;
//   - ce fichier lève le latch quand — et seulement quand — OPA est
//     REVENU ET sert exactement le bundle épinglé, prouvé par une sonde
//     HORS du chemin de décision (même patron que OPARevisionWatcher et
//     ClockWatchdog : les sondes ne vivent jamais dans la boucle chaude).
//
// Garde-fous, inchangés ou ajoutés :
//   - jamais une condition classe W (FailClosed.AutoClear la refuse) : la
//     levée gouvernée par quorum n'est pas contournable par une sonde ;
//   - seules les conditions listées sont candidates — l'appelant NE liste
//     PAS opa-bad-response (contrat rompu : jamais transitoire) ni
//     opa-revision-mismatch (bundle substitué : classe W) ni les conditions
//     non-OPA (horloge, saturation, ancrage) ;
//   - il faut Probes sondes saines CONSÉCUTIVES, pas une seule ;
//   - anti-battement : si la condition rebascule peu après une levée
//     automatique, le nombre de sondes exigé double (plafonné) — un OPA
//     qui flappe ne produit ni une levée par réflexe ni une fatigue d'alarme ;
//   - chaque levée est une feuille « TBFF1 » de source « auto ».

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// DefaultOPAAutoClearInterval : période de sonde tant qu'une condition
	// candidate est basculée. Hors du chemin chaud.
	DefaultOPAAutoClearInterval = 2 * time.Second
	// DefaultOPAAutoClearProbes : sondes saines consécutives exigées.
	DefaultOPAAutoClearProbes = 3
	// autoClearFlapWindow : une rebascule dans cette fenêtre après une levée
	// automatique double le nombre de sondes exigé.
	autoClearFlapWindow = 60 * time.Second
	// autoClearMaxFactor plafonne le doublement (×8).
	autoClearMaxFactor = 8
)

// OPAAutoClearOptions paramètre la reprise.
type OPAAutoClearOptions struct {
	// FailClosed est le point unique. Requis.
	FailClosed *FailClosed
	// Probe prouve qu'OPA répond ET sert la révision épinglée
	// (typiquement OPARevisionWatcher.Verify). Requis.
	Probe func(ctx context.Context) error
	// Conditions sont les noms candidats à la levée automatique. Requis,
	// non vide.
	Conditions []string
	// Probes : sondes saines consécutives exigées. 0 ⇒ défaut ; négatif ⇒ erreur.
	Probes int
	// Interval : période de Run. 0 ⇒ défaut ; négatif ⇒ erreur.
	Interval time.Duration
	// Now : horloge (tests). Nil ⇒ time.Now.
	Now func() time.Time
}

// OPAAutoClearer lève les conditions OPA transitoires une fois OPA revenu.
type OPAAutoClearer struct {
	fc       *FailClosed
	probe    func(ctx context.Context) error
	cands    map[string]bool
	probes   int
	interval time.Duration
	now      func() time.Time

	mu        sync.Mutex
	streak    int
	required  int
	engaged   bool // un cycle de reprise est en cours
	factor    int
	lastClear time.Time
}

// NewOPAAutoClearer construit la reprise. Fail-closed dès la configuration.
func NewOPAAutoClearer(opts OPAAutoClearOptions) (*OPAAutoClearer, error) {
	if opts.FailClosed == nil {
		return nil, errors.New("pep: point fail-closed requis pour la reprise OPA")
	}
	if opts.Probe == nil {
		return nil, errors.New("pep: sonde requise pour la reprise OPA")
	}
	if len(opts.Conditions) == 0 {
		return nil, errors.New("pep: au moins une condition candidate à la reprise OPA")
	}
	if opts.Probes < 0 || opts.Interval < 0 {
		return nil, errors.New("pep: sondes/intervalle de reprise négatifs refusés")
	}
	probes, interval := opts.Probes, opts.Interval
	if probes == 0 {
		probes = DefaultOPAAutoClearProbes
	}
	if interval == 0 {
		interval = DefaultOPAAutoClearInterval
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	cands := make(map[string]bool, len(opts.Conditions))
	for _, c := range opts.Conditions {
		cands[c] = true
	}
	return &OPAAutoClearer{
		fc: opts.FailClosed, probe: opts.Probe, cands: cands,
		probes: probes, interval: interval, now: now, factor: 1,
	}, nil
}

// Interval rapporte la période de Run.
func (a *OPAAutoClearer) Interval() time.Duration { return a.interval }

// Tick effectue UNE passe — point d'entrée synchrone (tests, Run).
func (a *OPAAutoClearer) Tick(ctx context.Context) {
	var tripped []string
	for _, c := range a.fc.Tripped() {
		if a.cands[c.Name] && c.Class != ClassW {
			tripped = append(tripped, c.Name)
		}
	}

	a.mu.Lock()
	if len(tripped) == 0 {
		a.engaged, a.streak = false, 0
		a.mu.Unlock()
		return
	}
	if !a.engaged {
		// Nouveau cycle : anti-battement — une rebascule peu après une
		// levée automatique double l'exigence (plafonnée).
		a.engaged, a.streak = true, 0
		if !a.lastClear.IsZero() && a.now().Sub(a.lastClear) < autoClearFlapWindow {
			if a.factor < autoClearMaxFactor {
				a.factor *= 2
			}
		} else {
			a.factor = 1
		}
		a.required = a.probes * a.factor
	}
	a.mu.Unlock()

	healthy := a.probe(ctx) == nil

	a.mu.Lock()
	defer a.mu.Unlock()
	if !healthy {
		a.streak = 0
		return
	}
	a.streak++
	if a.streak < a.required {
		return
	}
	cleared := false
	for _, name := range tripped {
		if err := a.fc.AutoClear(name); err == nil {
			cleared = true
		}
	}
	if cleared {
		a.lastClear = a.now()
	}
	a.engaged, a.streak = false, 0
}

// Run boucle jusqu'à annulation du contexte.
func (a *OPAAutoClearer) Run(ctx context.Context) {
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.Tick(ctx)
		}
	}
}
