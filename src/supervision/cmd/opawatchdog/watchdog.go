package main

// watchdog.go — la logique du chien de garde d'OPA (issue #275, suite de la file bornée devant OPA).
//
// Doctrine : le PEP SIGNALE (« opa-stalled », GET /v1/supervision/opa), il ne tue jamais OPA lui-même — séparation des
// privilèges (OPA tourne sous un autre utilisateur, SO_PEERCRED). Ce programme est le SUPERVISEUR qui redémarre.
//
// Ce qui déclenche un redémarrage : TOUTES les sources joignables disent « stalled » (pepd, brokerd — chacun a son propre
// client OPA), pendant `Confirm` relevés consécutifs. Une source muette ou illisible n'est jamais lue comme « bloqué » ;
// « overloaded » n'est jamais un blocage (OPA répond : le tuer jetterait le travail en cours et repartirait à froid).
//
// Ce qui borne un redémarrage : un délai de repos après chaque tentative (OPA a besoin de temps pour démarrer) et un
// budget par heure glissante. Les tentatives ÉCHOUÉES comptent : un redémarrage qui échoue ne doit pas boucler. Une
// source de statut compromise pourrait demander des redémarrages à volonté — le budget borne ce que cela coûte, et son
// épuisement est une escalade humaine explicite (jamais un silence).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/strictjson"
)

// statusPath : la route du plan d'administration de pepd et de brokerd (pep.OPAStatusHandler).
const statusPath = "/v1/supervision/opa"

// maxStatusBody borne le corps lu (un statut tient dans quelques centaines d'octets).
const maxStatusBody = 64 << 10

// Les états rendus par pep.OPAStatus.State.
const (
	stateHealthy    = "healthy"
	stateOverloaded = "overloaded"
	stateStalled    = "stalled"
)

// opaStatus reflète pep.OPAStatus champ pour champ. Le décodage est STRICT (strictjson) : un champ inconnu ou un doublon
// est refusé, donc une dérive de version entre pepd et ce programme se voit (statut illisible, loggé) au lieu de passer
// pour « sain ». Un test de contrat (watchdog_contract_test.go) lie les deux structures.
type opaStatus struct {
	State             string          `json:"state"`
	Stalled           bool            `json:"stalled"`
	SilentMS          int64           `json:"silent_ms"`
	Unanswered        int64           `json:"unanswered"`
	ConsecutiveFaults int64           `json:"consecutive_faults"`
	Admission         *admissionStats `json:"admission,omitempty"`
}

type admissionStats struct {
	Inflight         int   `json:"inflight"`
	Queued           int   `json:"queued"`
	Admitted         int64 `json:"admitted"`
	ShedQueueFull    int64 `json:"shed_queue_full"`
	ShedSubjectShare int64 `json:"shed_subject_share"`
	ShedExpired      int64 `json:"shed_expired"`
	SinceLastShedMS  int64 `json:"since_last_shed_ms"`
}

// Source : un plan d'administration à interroger (socket Unix).
type Source struct {
	Name   string
	Socket string
}

// Restarter redémarre l'unité OPA. Production : systemctl ; tests : un faux.
type Restarter interface {
	Restart(ctx context.Context, unit string) error
}

// StatusFetcher lit le statut d'une source.
type StatusFetcher func(ctx context.Context, s Source) (opaStatus, error)

// Settings : les bornes du chien de garde (validées par loadConfig).
type Settings struct {
	Sources    []Source
	Unit       string
	Confirm    int           // relevés « stalled » consécutifs avant de redémarrer
	Cooldown   time.Duration // repos après une tentative (démarrage d'OPA)
	MaxPerHour int           // tentatives par heure glissante
	DryRun     bool          // journalise sans redémarrer (calibrage)
}

// Outcome : ce qu'un relevé a décidé (rendu pour les tests ; journalisé par Tick).
type Outcome string

const (
	OutcomeHealthy   Outcome = "healthy"   // aucune raison d'agir
	OutcomeBlind     Outcome = "blind"     // aucune source lisible : pas d'action
	OutcomeSuspect   Outcome = "suspect"   // « stalled » vu, pas encore confirmé
	OutcomeCooldown  Outcome = "cooldown"  // confirmé, mais dans le repos qui suit une tentative
	OutcomeExhausted Outcome = "exhausted" // confirmé, mais budget horaire épuisé : escalade humaine
	OutcomeRestarted Outcome = "restarted"
	OutcomeRestartKO Outcome = "restart-failed"
	OutcomeDryRun    Outcome = "dry-run"
)

// Watchdog : un relevé par Tick. Non réentrant (une seule goroutine l'appelle).
type Watchdog struct {
	set     Settings
	fetch   StatusFetcher
	restart Restarter
	now     func() time.Time
	logf    func(format string, args ...any)

	mu           sync.Mutex
	stalledRuns  int         // relevés « stalled » consécutifs
	attempts     []time.Time // tentatives de redémarrage dans l'heure glissante
	cooldownTill time.Time
	last         Outcome // pour ne journaliser que les changements d'état
}

// NewWatchdog assemble le chien de garde. now et logf peuvent être nil (horloge réelle, log standard).
func NewWatchdog(set Settings, fetch StatusFetcher, restart Restarter, now func() time.Time, logf func(string, ...any)) (*Watchdog, error) {
	if len(set.Sources) == 0 || fetch == nil || restart == nil {
		return nil, errors.New("opawatchdog : sources, lecteur de statut et redémarreur requis")
	}
	if set.Confirm < 1 || set.MaxPerHour < 1 || set.Cooldown <= 0 {
		return nil, errors.New("opawatchdog : Confirm, MaxPerHour et Cooldown doivent être positifs")
	}
	if err := validUnit(set.Unit); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Watchdog{set: set, fetch: fetch, restart: restart, now: now, logf: logf}, nil
}

var unitRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,127}\.service$`)

// validUnit : un nom d'unité systemd, rien d'autre — il finit en argument de systemctl et dans une règle polkit.
func validUnit(u string) error {
	if !unitRE.MatchString(u) {
		return fmt.Errorf("opawatchdog : nom d'unité invalide %q (un nom .service systemd, sans espace ni tiret initial)", u)
	}
	return nil
}

// Tick fait un relevé de toutes les sources et agit si les conditions sont réunies.
func (w *Watchdog) Tick(ctx context.Context) Outcome {
	w.mu.Lock()
	defer w.mu.Unlock()

	readable, stalled := 0, 0
	for _, s := range w.set.Sources {
		st, err := w.fetch(ctx, s)
		if err != nil {
			w.logf("opawatchdog: source=%s illisible : %v", s.Name, err)
			continue
		}
		readable++
		if st.State == stateStalled {
			stalled++
		}
	}

	var out Outcome
	switch {
	case readable == 0:
		w.stalledRuns = 0
		out = OutcomeBlind
	case stalled < readable:
		// au moins une source lit OPA sain, lent à la file ou joignable : pas un blocage commun
		w.stalledRuns = 0
		out = OutcomeHealthy
	default:
		w.stalledRuns++
		out = w.decideLocked(ctx)
	}
	w.noteLocked(out, readable, stalled)
	return out
}

// decideLocked : toutes les sources lisibles disent « stalled ».
func (w *Watchdog) decideLocked(ctx context.Context) Outcome {
	if w.stalledRuns < w.set.Confirm {
		return OutcomeSuspect
	}
	now := w.now()
	if now.Before(w.cooldownTill) {
		return OutcomeCooldown
	}
	// budget : tentatives de l'heure glissante
	kept := w.attempts[:0]
	for _, t := range w.attempts {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	w.attempts = kept
	if len(w.attempts) >= w.set.MaxPerHour {
		return OutcomeExhausted
	}
	if w.set.DryRun {
		w.attempts = append(w.attempts, now)
		w.cooldownTill = now.Add(w.set.Cooldown)
		w.stalledRuns = 0
		return OutcomeDryRun
	}
	w.attempts = append(w.attempts, now) // une tentative qui échoue compte aussi
	w.cooldownTill = now.Add(w.set.Cooldown)
	w.stalledRuns = 0
	if err := w.restart.Restart(ctx, w.set.Unit); err != nil {
		w.logf("opawatchdog: event=restart-failed unit=%s : %v", w.set.Unit, err)
		return OutcomeRestartKO
	}
	return OutcomeRestarted
}

// noteLocked journalise les changements d'état (et chaque redémarrage), pas chaque relevé.
func (w *Watchdog) noteLocked(out Outcome, readable, stalled int) {
	always := out == OutcomeRestarted || out == OutcomeRestartKO || out == OutcomeDryRun
	if !always && out == w.last {
		return
	}
	w.last = out
	switch out {
	case OutcomeRestarted:
		w.logf("opawatchdog: event=restarted unit=%s sources_stalled=%d/%d restarts_last_hour=%d", w.set.Unit, stalled, readable, len(w.attempts))
	case OutcomeDryRun:
		w.logf("opawatchdog: event=dry-run unit=%s : redémarrage décidé, NON exécuté (TBP_OPAWD_DRY_RUN)", w.set.Unit)
	case OutcomeExhausted:
		w.logf("opawatchdog: event=ESCALADE unit=%s : OPA reste bloqué et le budget de %d redémarrage(s)/heure est épuisé — intervention humaine requise", w.set.Unit, w.set.MaxPerHour)
	case OutcomeCooldown:
		w.logf("opawatchdog: event=cooldown unit=%s : OPA bloqué, repos après le dernier redémarrage", w.set.Unit)
	case OutcomeSuspect:
		w.logf("opawatchdog: event=suspect : OPA vu bloqué (%d/%d relevé(s) consécutifs)", w.stalledRuns, w.set.Confirm)
	case OutcomeBlind:
		w.logf("opawatchdog: event=blind : aucune source de statut lisible — aucune action")
	case OutcomeHealthy:
		w.logf("opawatchdog: event=healthy")
	}
}

// Run boucle jusqu'à l'annulation du contexte.
func (w *Watchdog) Run(ctx context.Context, poll time.Duration) {
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------------------
// Lecture du statut (HTTP sur socket Unix) et redémarrage (systemctl)
// ---------------------------------------------------------------------------

const statusTimeout = 2 * time.Second

// SocketStatusFetcher lit GET /v1/supervision/opa sur le socket Unix de la source.
func SocketStatusFetcher() StatusFetcher {
	return func(ctx context.Context, s Source) (opaStatus, error) {
		var st opaStatus
		client := &http.Client{
			Timeout: statusTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", s.Socket)
				},
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		ctx, cancel := context.WithTimeout(ctx, statusTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+statusPath, nil)
		if err != nil {
			return st, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return st, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusBody+1))
		if err != nil {
			return st, err
		}
		if resp.StatusCode != http.StatusOK {
			return st, fmt.Errorf("statut HTTP %d", resp.StatusCode)
		}
		if len(body) > maxStatusBody {
			return st, errors.New("réponse trop grande")
		}
		if err := strictjson.Decode(body, &st); err != nil {
			return st, fmt.Errorf("statut illisible : %w", err)
		}
		switch st.State {
		case stateHealthy, stateOverloaded, stateStalled:
		default:
			return st, fmt.Errorf("état inconnu %q", st.State)
		}
		return st, nil
	}
}

// SystemctlRestarter exécute `<systemctl> --no-ask-password restart <unit>` — chemin absolu, aucun shell, environnement
// vide ; le nom d'unité est validé par validUnit. Le droit de le faire vient d'une règle polkit limitée à CETTE unité et
// à CE verbe (voir tbp-opa-watchdog.polkit.rules).
type SystemctlRestarter struct {
	Path    string
	Timeout time.Duration
}

func (r SystemctlRestarter) Restart(ctx context.Context, unit string) error {
	if err := validUnit(unit); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.Path, "--no-ask-password", "restart", unit)
	cmd.Env = []string{}            // aucun héritage
	cmd.WaitDelay = 2 * time.Second // un descendant qui garde le tube ouvert ne retient pas le chien de garde
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if len(msg) > 512 {
			msg = msg[:512]
		}
		return fmt.Errorf("systemctl restart %s : %w (%s)", unit, err, msg)
	}
	return nil
}
