package main

// brokerEpochSource adapte GET /v1/supervision/epoch (brokerd, socket Unix
// co-localisé sur la même cellule — deploy/apercu.md : brokerd, pepd, la
// registre tessera et le tracker d'époque tournent tous sur le rôle
// « Cell ») en pep.EpochSource pour le scale 3 (fencing multi-cellules,
// §7.2-§7.3 — revue de sécurité #90, point 2).
//
// Lecture périodique en ARRIÈRE-PLAN (Run, même patron que
// ClockWatchdog.Run, T13, src/pep/clock.go) : CurrentEpoch() ne fait
// JAMAIS d'appel réseau sur le chemin chaud de /v1/evaluate (§9.1) — elle
// rend le dernier état observé, borné par une fenêtre de fraîcheur. Au-delà
// de cette fenêtre — brokerd injoignable, ou aucune époque encore vérifiée
// (epoch = −1, cf. cluster.TrackerStatus) — CurrentEpoch() refuse
// (fail-closed : le validateur T9 traduit en ReasonEpochUnavailable).
// Jamais un epoch figé qui masquerait une révocation en cours (§7.3).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const (
	// epochSourcePollInterval : même période que ClockWatchdog (T13).
	epochSourcePollInterval = time.Second
	// epochSourceHTTPTimeout borne l'appel Unix socket — brokerd est
	// co-localisé (même machine, même rôle « Cell ») : une latence bien
	// au-delà de ce budget est déjà une panne à traiter comme telle.
	epochSourceHTTPTimeout = 2 * time.Second
	// epochSourceMaxStaleness borne l'âge du dernier poll RÉUSSI accepté
	// par CurrentEpoch — au-delà, refus fail-closed plutôt qu'un epoch
	// obsolète silencieusement reconduit.
	epochSourceMaxStaleness = 5 * time.Second
)

type brokerEpochState struct {
	epoch    uint64
	valid    bool // false : aucune époque vérifiée observée (epoch=-1 côté brokerd)
	observed time.Time
}

// brokerEpochSource implémente pep.EpochSource.
type brokerEpochSource struct {
	hc    *http.Client
	url   string
	now   func() time.Time
	state atomic.Pointer[brokerEpochState]
}

// newBrokerEpochSource construit l'adaptateur — aucun appel réseau ici
// (voir Probe pour la vérification bloquante au démarrage).
func newBrokerEpochSource(socketPath string, now func() time.Time) *brokerEpochSource {
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: epochSourceHTTPTimeout}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: epochSourceHTTPTimeout,
	}
	if now == nil {
		now = time.Now
	}
	s := &brokerEpochSource{hc: hc, url: "http://brokerd/v1/supervision/epoch", now: now}
	s.state.Store(&brokerEpochState{})
	return s
}

// poll effectue une lecture LIVE de brokerd et met à jour l'état observé.
// Jamais appelé sur le chemin chaud — seulement par Probe (démarrage) et
// Run (arrière-plan).
func (s *brokerEpochSource) poll(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("statut %d", resp.StatusCode)
	}
	var view struct {
		Epoch int `json:"epoch"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(&view); err != nil {
		return err
	}
	st := &brokerEpochState{observed: s.now()}
	if view.Epoch >= 0 {
		st.epoch = uint64(view.Epoch)
		st.valid = true
	}
	s.state.Store(st)
	return nil
}

// Probe vérifie la source AU DÉMARRAGE (fail-closed §1 : pas de pepd dont
// la source d'époque configurée est morte à la naissance) — même doctrine
// que brokerSources.probe() de supervisord.
func (s *brokerEpochSource) Probe(ctx context.Context) error {
	return s.poll(ctx)
}

// Run interroge brokerd périodiquement jusqu'à annulation du contexte
// (même patron que ClockWatchdog.Run, T13) — l'échec d'un poll n'est PAS
// fatal : l'état se fane (staleness), CurrentEpoch refuse dès qu'il dépasse
// epochSourceMaxStaleness.
func (s *brokerEpochSource) Run(ctx context.Context) {
	t := time.NewTicker(epochSourcePollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.poll(ctx)
		}
	}
}

// CurrentEpoch implémente pep.EpochSource — lecture PURE, AUCUN appel
// réseau : le dernier état observé, s'il est frais et vérifié ; sinon,
// refus fail-closed.
func (s *brokerEpochSource) CurrentEpoch() (uint64, error) {
	st := s.state.Load()
	if st == nil || !st.valid {
		return 0, errors.New("pepd: aucune époque vérifiée observée de brokerd")
	}
	if s.now().Sub(st.observed) > epochSourceMaxStaleness {
		return 0, errors.New("pepd: dernière lecture d'époque de brokerd trop ancienne")
	}
	return st.epoch, nil
}
