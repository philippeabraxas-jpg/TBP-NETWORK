package pep

// Contrôle d'état horloge NTS + mode dégradé explicite (T13, §6.2 + §4.5).
//
// Le temps est une hypothèse fondatrice EXPLICITE (§6.2) : TTL, epochs,
// TSA et fraîcheur héritent tous d'une synchronisation d'horloge stricte.
// NTS (RFC 8915) borne la dérive en régime établi, mais ne dit rien de ce
// que le PEP fait PENDANT une resynchronisation (saut NTP) ou une perte
// de lock chrony. Ce watchdog poll l'état d'horloge noyau via
// ntp_adjtime(2) ; si STA_UNSYNC est levé : NI passage silencieux NI
// blocage silencieux — bascule en mode dégradé EXPLICITE :
//
//   - entrée en langage naturel rejetée (§4.5 : pas d'arbitrage humain
//     disponible en mode dégradé → default-deny sur le traducteur) ;
//   - seuls les jetons LOCAUX-SIGNÉS (iss == LocalIssuer) passent le
//     portillon ; tout jeton non local est barré AVANT validation ;
//   - alarme prioritaire tracée au registre de la cellule (feuille
//     KindTelemetry, hash-only §6.2) ;
//   - skew estimé au-delà de la borne déclarée ⇒ trip fail-closed T14
//     (fraîcheur refusée immédiatement) ;
//   - disparition du flag ⇒ retour à la normale automatique ET tracé
//     (feuille clock-resync).
//
// Cible : Linux (ntp_adjtime). La sonde est une couture (ClockOptions.
// Probe) — les tests injectent l'état noyau, la production utilise la
// sonde kernelClockProbe.
//
// Le validateur (T9) ne change pas : le portillon horloge se compose
// DEVANT lui — NaturalLanguageAllowed() barre le traducteur,
// IssuerAllowed(iss) barre les jetons non locaux.

import (
	"context"
	"errors"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	"golang.org/x/sys/unix"
)

// Paramètres déclarés (§6.2) : borne de skew fail-closed et période de
// polling de l'état noyau.
const (
	DefaultSkewBound     = 50 * time.Millisecond
	DefaultClockInterval = time.Second
)

// Raisons des feuilles d'alarme horloge. clock-skew est aussi la raison
// du trip T14 (fraîcheur refusée immédiatement).
const (
	ReasonClockUnsync     = "clock-unsync"
	ReasonClockSkew       = "clock-skew"
	ReasonClockResync     = "clock-resync"
	ReasonClockProbeError = "clock-probe-error"
)

// Priorités des feuilles d'alarme (§6.2 : l'alarme horloge est
// prioritaire — le temps est une hypothèse fondatrice).
const (
	ClockPriorityInfo byte = 0 // clock-resync (retour à la normale)
	ClockPriorityHigh byte = 1 // unsync / skew / sonde en échec
)

// ClockMode est l'état du portillon horloge.
type ClockMode int

const (
	ClockModeNormal   ClockMode = iota // tout suit son chemin normal
	ClockModeDegraded                  // local-signé uniquement, NL rejeté
)

func (m ClockMode) String() string {
	if m == ClockModeDegraded {
		return "degraded"
	}
	return "normal"
}

// ClockSample est l'état d'horloge noyau lu à un instant.
type ClockSample struct {
	Unsync   bool          // STA_UNSYNC levé (perte de lock chrony/NTS)
	EstError time.Duration // erreur estimée max (la borne de skew s'y compare)
}

// kernelClockProbe est la sonde de production : ntp_adjtime(2).
// Esterror est en microsecondes côté noyau.
func kernelClockProbe() (ClockSample, error) {
	var buf unix.Timex
	if _, err := unix.Adjtimex(&buf); err != nil {
		return ClockSample{}, err
	}
	return ClockSample{
		Unsync:   buf.Status&unix.STA_UNSYNC != 0,
		EstError: time.Duration(buf.Esterror) * time.Microsecond,
	}, nil
}

// ClockOptions paramètre le watchdog. Fail-closed dès la configuration.
type ClockOptions struct {
	// Probe lit l'état d'horloge noyau. Nil ⇒ kernelClockProbe
	// (ntp_adjtime). En échec ⇒ mode dégradé (fail-closed : impossible de
	// prouver l'heure, impossible de faire confiance à la fraîcheur).
	Probe func() (ClockSample, error)
	// Interval est la période de polling de Run. 0 ⇒ DefaultClockInterval
	// (1 s). Négatif ⇒ erreur.
	Interval time.Duration
	// SkewBound borne l'erreur estimée : au-delà (strictement), trip T14.
	// 0 ⇒ DefaultSkewBound (50 ms, §6.2). Négatif ⇒ erreur.
	SkewBound time.Duration
	// LocalIssuer est l'iss de la cellule : en mode dégradé, SEULS les
	// jetons qu'il a signés passent. Requis (sinon « local-signé » ne veut
	// rien dire).
	LocalIssuer string
	// CellID identifie la cellule dans les feuilles d'alarme. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : alarmes et resync y sont
	// tracés. Requis (une dégradation non tracée est une dégradation
	// silencieuse — exactement ce que ce livrable interdit).
	Leaves LeafSink
	// Journal reçoit le clair de chaque feuille AVANT son inscription (#275,
	// #271 : tbp-audit verify). Optionnel ici (nil = feuille nue, historique) ;
	// pepd et brokerd le renseignent toujours.
	Journal *registry.RecordStore
	// OnTrip est la couture d'alarme vers T14 (fail-closed unique) :
	// clock-skew y est signalé à chaque entrée en dégradé pour skew ;
	// l'échec d'écriture d'une feuille aussi. Nil ⇒ pas d'alarme.
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2) pour les feuilles.
	// Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// ClockWatchdog poll l'état d'horloge noyau et tient le portillon du mode
// dégradé. Sûr pour un usage concurrent.
type ClockWatchdog struct {
	probe       func() (ClockSample, error)
	interval    time.Duration
	skewBound   time.Duration
	localIssuer string
	cellID      string
	salt        []byte
	leaves      LeafSink
	journal     *registry.RecordStore
	onTrip      func(reason string)
	now         func() time.Time

	// transMu sérialise les transitions (Check) ; mu ne protège que mode/reason et n'est
	// jamais tenu pendant une écriture de feuille (R-17).
	transMu sync.Mutex
	mu      sync.Mutex
	mode    ClockMode
	reason  string
}

// NewClockWatchdog construit le watchdog. Fail-closed : émetteur local,
// cellID, sel ≥ 16 o et couture feuilles requis ; intervalle et borne
// négatifs rejetés.
func NewClockWatchdog(opts ClockOptions) (*ClockWatchdog, error) {
	if opts.LocalIssuer == "" {
		return nil, errors.New("pep: émetteur local requis (§4.5 : « local-signé » doit être défini)")
	}
	if opts.CellID == "" {
		return nil, errors.New("pep: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: couture feuilles requise (§6.2 : dégradation TOUJOURS tracée)")
	}
	if opts.Interval < 0 {
		return nil, errors.New("pep: intervalle de polling négatif refusé")
	}
	if opts.SkewBound < 0 {
		return nil, errors.New("pep: borne de skew négative refusée")
	}
	probe := opts.Probe
	if probe == nil {
		probe = kernelClockProbe
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultClockInterval
	}
	skewBound := opts.SkewBound
	if skewBound == 0 {
		skewBound = DefaultSkewBound
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &ClockWatchdog{
		probe:       probe,
		interval:    interval,
		skewBound:   skewBound,
		localIssuer: opts.LocalIssuer,
		cellID:      opts.CellID,
		salt:        salt,
		leaves:      opts.Leaves,
		journal:     opts.Journal,
		onTrip:      opts.OnTrip,
		now:         now,
	}, nil
}

// Interval rapporte la période de polling effective.
func (w *ClockWatchdog) Interval() time.Duration { return w.interval }

// SkewBound rapporte la borne de skew effective (paramètre déclaré §6.2).
func (w *ClockWatchdog) SkewBound() time.Duration { return w.skewBound }

// Check poll l'état noyau une fois et applique les transitions :
// unsync / sonde en échec ⇒ dégradé alarmé ; skew > borne ⇒ dégradé +
// trip T14 ; retour sain ⇒ normal tracé. Idempotent sans transition
// (jamais de feuille en double).
//
// L'écriture de la feuille (≈ 150–250 ms : checkpoint + sondage POSIX) se fait HORS du
// verrou de lecture w.mu — celui que prennent Mode / IssuerAllowed / NaturalLanguageAllowed
// sur le chemin chaud (budget ≈ 5 ms) : un battement chrony ne les fige plus (issue #210,
// R-17). transMu sérialise les transitions entre elles. L'ordre garde la doctrine fail-closed :
// ENTRER en dégradé (plus strict) est effectif AVANT la feuille ; REVENIR à la normale
// (plus permissif) n'est effectif qu'APRÈS sa feuille — le retour aussi est prouvé (§6.2).
func (w *ClockWatchdog) Check() ClockMode {
	sample, err := w.probe()

	w.transMu.Lock()
	defer w.transMu.Unlock()

	degraded, reason := true, ""
	switch {
	case err != nil:
		// Impossible de prouver l'heure ⇒ fail-closed (§6.2).
		reason = ReasonClockProbeError
	case sample.Unsync:
		reason = ReasonClockUnsync
	case sample.EstError > w.skewBound:
		reason = ReasonClockSkew
	default:
		degraded = false
	}

	w.mu.Lock()
	curMode, curReason := w.mode, w.reason
	w.mu.Unlock()

	if !degraded {
		if curMode == ClockModeNormal {
			return curMode
		}
		w.writeLeaf(ReasonClockResync, ClockPriorityInfo) // la feuille PRÈCÈDE le relâchement
		w.mu.Lock()
		w.mode, w.reason = ClockModeNormal, ""
		w.mu.Unlock()
		return ClockModeNormal
	}
	if curMode == ClockModeDegraded && curReason == reason {
		return curMode // déjà dans cet état précis : pas de doublon
	}
	// Fraîcheur refusée immédiatement : trip T14 à chaque ENTRÉE en dégradé pour skew
	// (T14 possède le latch global).
	if reason == ReasonClockSkew && !(curMode == ClockModeDegraded && curReason == ReasonClockSkew) && w.onTrip != nil {
		w.onTrip(ReasonClockSkew)
	}
	w.mu.Lock()
	w.mode, w.reason = ClockModeDegraded, reason
	w.mu.Unlock()
	w.writeLeaf(reason, ClockPriorityHigh)
	return ClockModeDegraded
}

// Run poll l'état noyau jusqu'à annulation du contexte — la boucle de
// production ; Check reste le point d'entrée synchrone (tests, wiring).
func (w *ClockWatchdog) Run(ctx context.Context) {
	w.Check()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Check()
		}
	}
}

// writeLeaf inscrit la feuille d'alarme (KindTelemetry : une alarme n'est pas une
// décision). Hash-only : le registre ne voit que l'engagement. Appelé sans w.mu.
func (w *ClockWatchdog) writeLeaf(reason string, priority byte) {
	if _, err := appendLeaf(context.Background(), w.leaves, w.journal, registry.KindTelemetry, w.cellID, w.salt, clockAlarmRecord(reason, priority), w.now().UnixNano()); err != nil && w.onTrip != nil {
		w.onTrip(ReasonLeafWriteFailed)
	}
}

// clockAlarmRecord sérialise le record d'alarme horloge :
// "TBPC1" ‖ u8 len(reason) ‖ reason ‖ priority(1).
func clockAlarmRecord(reason string, priority byte) []byte {
	record := make([]byte, 0, 5+1+len(reason)+1)
	record = append(record, "TBPC1"...)
	record = append(record, byte(len(reason)))
	record = append(record, reason...)
	record = append(record, priority)
	return record
}

// Mode rapporte l'état courant du portillon.
func (w *ClockWatchdog) Mode() ClockMode {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mode
}

// Reason rapporte la raison de la dégradation courante ("" en mode
// normal) — couture forensique pour l'observabilité.
func (w *ClockWatchdog) Reason() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reason
}

// Degraded rapporte si le portillon est en mode dégradé.
func (w *ClockWatchdog) Degraded() bool { return w.Mode() == ClockModeDegraded }

// NaturalLanguageAllowed barre le traducteur (§4.5) : en mode dégradé,
// toute entrée en langage naturel est rejetée — pas d'arbitrage humain
// disponible, default-deny.
func (w *ClockWatchdog) NaturalLanguageAllowed() bool { return w.Mode() == ClockModeNormal }

// IssuerAllowed est le portillon des jetons : en mode normal tout émetteur
// passe (le validateur T9 décide ensuite) ; en mode dégradé, SEUL
// l'émetteur local de la cellule passe.
func (w *ClockWatchdog) IssuerAllowed(iss string) bool {
	if w.Mode() == ClockModeNormal {
		return true
	}
	return iss == w.localIssuer
}
