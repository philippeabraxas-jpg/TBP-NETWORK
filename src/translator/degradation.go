// degradation.go — T25 (issue #26) : dégradation contrôlée du traducteur
// (§4.5), machine d'états des modes dégradés.
//
// La politique quand le traducteur tombe est « rejet du langage naturel,
// entrées structurées uniquement, AUCUN fallback cloud » (§4.5) — ici un
// comportement EXPLICITE et TESTÉ, jamais l'effet de bord d'une exception
// non gérée. Le traducteur est un paramètre de friction, pas de sécurité
// (§4.5) : la dégradation ne desserre aucune règle — les règles jugent
// sans exception, seul le chemin d'admission change.
//
// Modes par échelle de système (pseudo-code de l'issue, §4.5) :
//   - système CRITIQUE + cellule miroir disponible (§7.4) → failover :
//     règles pré-établies, chemin déterministe ;
//   - système STANDARD + arbitrage humain joignable → escalade ;
//   - ni l'un ni l'autre → default-deny immédiat.
//
// Un système critique SANS miroir n'escalade PAS vers l'humain : son
// chemin est déterministe ou rien (§4.5).
//
// Doctrine :
//   - le contrôleur démarre DÉGRADÉ : le mode normal se mérite par une
//     sonde verte (fail-closed §1 — jamais de confiance présumée) ;
//   - toute bascule et toute reprise est TRACÉE (feuille KindTelemetry,
//     hash-only §6.2) et toute dégradation est ALARMÉE — jamais silencieux ;
//   - la sonde tourne hors du chemin de décision (budget §9.1) : Accept ne
//     sonde pas, il lit l'état établi par CheckHealth ;
//   - aucun chemin de code ne résout un endpoint externe : l'absence de
//     fallback cloud est une assertion STRUCTURELLE (aucun import réseau),
//     vérifiée par test — pas une promesse de revue.
package translator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Mode est le mode d'admission rendu par la machine d'états (§4.5).
type Mode int

const (
	// ModeNormal : le traducteur est sain — le langage naturel passe par
	// lui, le structuré aussi.
	ModeNormal Mode = iota + 1
	// ModeMirrorFailover : failover vers la cellule miroir (§7.4) —
	// règles pré-établies, chemin déterministe, structuré seulement.
	ModeMirrorFailover
	// ModeHumanEscalation : escalade vers l'arbitrage humain — structuré
	// seulement, verdict différé à l'arbitre.
	ModeHumanEscalation
	// ModeDefaultDeny : ni miroir ni arbitrage — refus immédiat, y
	// compris pour le structuré.
	ModeDefaultDeny
)

// String rend le code machine stable du mode (feuilles, observabilité).
func (m Mode) String() string {
	switch m {
	case ModeNormal:
		return "normal"
	case ModeMirrorFailover:
		return "mirror-failover"
	case ModeHumanEscalation:
		return "human-escalation"
	case ModeDefaultDeny:
		return "default-deny"
	}
	return fmt.Sprintf("mode-inconnu(%d)", int(m))
}

// Erreurs d'admission en mode dégradé. ErrPendingArbitration n'est PAS un
// refus : la demande est acceptée en escalade — l'appelant DOIT la traiter
// distinctement (verdict différé à l'arbitre humain, §4.5).
var (
	// ErrDegradedMode : langage naturel rejeté — le traducteur est down,
	// structuré uniquement (§4.5).
	ErrDegradedMode = errors.New("translator: langage naturel rejeté en mode dégradé (§4.5)")
	// ErrDefaultDeny : ni miroir ni arbitrage — refus immédiat (§4.5).
	ErrDefaultDeny = errors.New("translator: default-deny — ni cellule miroir ni arbitrage joignable (§4.5)")
	// ErrPendingArbitration : demande escaladée — PAS un refus.
	ErrPendingArbitration = errors.New("translator: escaladé vers arbitrage humain — verdict différé (§4.5)")
)

// Raisons stables passées à la couture d'alarme (codes machine).
const (
	ReasonDown         = "translator-down"
	ReasonNLRejected   = "nl-rejected-degraded"
	ReasonDefaultDeny  = "translator-default-deny"
	ReasonLeafWriteErr = "translator-leaf-write-failed"
)

// SystemClass qualifie le système demandeur pour l'arbitrage de mode
// (§4.5 « modes dégradés par échelle »).
type SystemClass int

const (
	// SystemStandard : escalade vers l'arbitrage humain si joignable.
	SystemStandard SystemClass = iota
	// SystemCritical : failover vers la cellule miroir si disponible —
	// chemin déterministe ou rien, JAMAIS d'escalade humaine (§4.5).
	SystemCritical
)

// System est le système demandeur d'une admission.
type System struct {
	ID    string      // identifiant stable (feuilles, arbitrage)
	Class SystemClass // échelle §4.5
}

// Input est une demande d'admission au chemin de traduction.
type Input struct {
	JTI     [16]byte // identifiant de la demande (feuilles)
	Natural bool     // true = langage naturel ; false = entrée structurée
	Payload []byte   // intention OPAQUE relayée à l'arbitre en escalade — jamais interprétée ici (no-DPI)
}

// Probe est le healthcheck du service traducteur (T24). Toute erreur est
// une indisponibilité — « I can translate » ou « I cannot » (§4.5).
type Probe interface {
	Healthy(ctx context.Context) error
}

// MirrorCell est la couture de la cellule miroir (§7.4) : règles
// pré-établies, fenêtre saine ancrée. Available est un CONSTAT à l'instant
// (fenêtre saine ancrée), jamais une promesse.
type MirrorCell interface {
	Available(ctx context.Context) bool
}

// ArbitrationItem est une demande remise à l'arbitre humain (§4.5).
type ArbitrationItem struct {
	SystemID string
	JTI      [16]byte
	Payload  []byte // intention opaque (no-DPI)
	At       time.Time
}

// Arbitration est la couture de la file d'arbitrage humain (interface
// broker). Reachable est un constat à l'instant ; Enqueue remet la demande
// — son échec est fail-closed (default-deny, pas de file implicite).
type Arbitration interface {
	Reachable(ctx context.Context) bool
	Enqueue(ctx context.Context, item ArbitrationItem) error
}

// LeafSink est la couture vers le registre de la cellule (T7).
// *registry.CellLog l'implémente nativement.
type LeafSink interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// Options paramètre le contrôleur. Fail-closed dès la configuration :
// cellID, sel ≥ 16 octets, couture feuilles et sonde requis — une bascule
// non tracée ou une santé présumée sont interdites.
type Options struct {
	// CellID identifie la cellule dans les feuilles. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre : bascules, rejets et reprises y sont
	// tracés. Requis.
	Leaves LeafSink
	// Probe est le healthcheck du traducteur (T24). Requis.
	Probe Probe
	// Mirror est la cellule miroir (§7.4). Nil ⇒ pas de failover possible.
	Mirror MirrorCell
	// Arbitration est la file d'arbitrage humain. Nil ⇒ pas d'escalade.
	Arbitration Arbitration
	// OnAlarm est la couture d'alarme vers le monitor : appelée à chaque
	// dégradation (jamais silencieux — la déduplication est l'affaire du
	// monitor, pas du producteur). Nil ⇒ pas d'alarme externe (la feuille
	// reste obligatoire).
	OnAlarm func(reason string)
	// Now est l'horloge de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// Controller est la machine d'états des modes dégradés du traducteur
// (§4.5). Sûr pour un usage concurrent.
type Controller struct {
	cellID  string
	salt    []byte
	leaves  LeafSink
	probe   Probe
	mirror  MirrorCell
	arb     Arbitration
	onAlarm func(reason string)
	now     func() time.Time

	mu        sync.Mutex
	up        bool      // false tant qu'aucune sonde n'est verte (fail-closed)
	downSince time.Time // instant de la bascule down (épisode courant)
	episode   bool      // épisode down TRACÉ en cours (déduplication)
}

// NewController construit la machine d'états. Le contrôleur démarre
// DÉGRADÉ : le mode normal se mérite par une première sonde verte
// (fail-closed §1). Fail-closed dès la configuration.
func NewController(opts Options) (*Controller, error) {
	if opts.CellID == "" {
		return nil, errors.New("translator: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("translator: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("translator: couture feuilles requise (§4.5 : bascule TOUJOURS tracée)")
	}
	if opts.Probe == nil {
		return nil, errors.New("translator: sonde requise (§1 : santé vérifiée, jamais présumée)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &Controller{
		cellID:    opts.CellID,
		salt:      salt,
		leaves:    opts.Leaves,
		probe:     opts.Probe,
		mirror:    opts.Mirror,
		arb:       opts.Arbitration,
		onAlarm:   opts.OnAlarm,
		now:       now,
		downSince: now(),
	}, nil
}

// CheckHealth interroge la sonde et fait basculer l'état. Appelé par la
// boucle de supervision — JAMAIS par Accept (le chemin de décision reste
// dans le budget §9.1). Toute erreur de sonde est une indisponibilité :
// l'épisode down est TRACÉ et ALARMÉ une fois (re-sonde en échec pendant
// l'épisode : pas de doublon) — y compris l'épisode de BOOT : le
// contrôleur démarre dégradé, la première sonde en échec établit et trace
// cet épisode (une dégradation silencieuse est interdite). Sonde verte
// depuis l'état dégradé : reprise TRACÉE (feuille recovered) — le retour
// au mode normal est un événement de gouvernance, pas un détail
// d'exploitation.
func (c *Controller) CheckHealth(ctx context.Context) error {
	err := c.probe.Healthy(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if c.up || !c.episode {
			c.up = false
			c.downSince = c.now()
			c.episode = true
			c.writeLeafLocked(ctx, recordDown(err.Error()))
			c.alarmLocked(ReasonDown)
		}
		return fmt.Errorf("translator: sonde en échec : %w", err)
	}
	if !c.up {
		c.up = true
		c.episode = false
		c.writeLeafLocked(ctx, recordRecovered())
	}
	return nil
}

// ModeFor rend le mode d'admission courant pour un système. Déterministe,
// réévalué à chaque appel sur les coutures LIVE : un miroir qui devient
// sain en cours d'épisode ouvre le failover sans redémarrage (§7.4).
func (c *Controller) ModeFor(ctx context.Context, sys System) Mode {
	c.mu.Lock()
	up := c.up
	c.mu.Unlock()
	if up {
		return ModeNormal
	}
	// Pseudo-code de l'issue (§4.5) — critique d'abord : son chemin est
	// déterministe (miroir) ou rien ; l'escalade humaine est pour les
	// systèmes standard.
	if sys.Class == SystemCritical && c.mirror != nil && c.mirror.Available(ctx) {
		return ModeMirrorFailover
	}
	if sys.Class == SystemStandard && c.arb != nil && c.arb.Reachable(ctx) {
		return ModeHumanEscalation
	}
	return ModeDefaultDeny
}

// State rend un constat d'état pour l'observabilité (supervision).
func (c *Controller) State() (up bool, downSince time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up, c.downSince
}

// Accept décide l'admission d'une entrée selon le mode courant :
//   - ModeNormal → admise (nil) ;
//   - langage naturel en mode dégradé → rejet propre : feuille
//     « nl-rejected-degraded » + alarme, ErrDegradedMode (§4.5) ;
//   - ModeMirrorFailover, structuré → admis (chemin déterministe §7.4) ;
//   - ModeHumanEscalation, structuré → remis à l'arbitre humain,
//     ErrPendingArbitration (PAS un refus) ; échec de remise → default-deny
//     (fail-closed, pas de file implicite) ;
//   - ModeDefaultDeny → refus immédiat tracé, ErrDefaultDeny.
func (c *Controller) Accept(ctx context.Context, sys System, in Input) error {
	mode := c.ModeFor(ctx, sys)
	if mode == ModeNormal {
		return nil
	}
	if in.Natural {
		c.mu.Lock()
		c.writeLeafLocked(ctx, recordNLRejected(in.JTI, sys.ID))
		c.alarmLocked(ReasonNLRejected)
		c.mu.Unlock()
		return ErrDegradedMode
	}
	switch mode {
	case ModeMirrorFailover:
		// Règles pré-établies, chemin déterministe (§4.5, §7.4).
		return nil
	case ModeHumanEscalation:
		item := ArbitrationItem{
			SystemID: sys.ID,
			JTI:      in.JTI,
			Payload:  in.Payload,
			At:       c.now(),
		}
		if err := c.arb.Enqueue(ctx, item); err != nil {
			// Fail-closed : une escalade qui échoue est un refus, jamais
			// une admission silencieuse ni une file implicite.
			c.mu.Lock()
			c.writeLeafLocked(ctx, recordDefaultDeny(in.JTI, sys.ID))
			c.alarmLocked(ReasonDefaultDeny)
			c.mu.Unlock()
			return fmt.Errorf("%w (remise à l'arbitrage en échec : %v)", ErrDefaultDeny, err)
		}
		c.mu.Lock()
		c.writeLeafLocked(ctx, recordEscalated(in.JTI, sys.ID))
		c.mu.Unlock()
		return ErrPendingArbitration
	default: // ModeDefaultDeny — et tout mode inconnu (fail-closed).
		c.mu.Lock()
		c.writeLeafLocked(ctx, recordDefaultDeny(in.JTI, sys.ID))
		c.alarmLocked(ReasonDefaultDeny)
		c.mu.Unlock()
		return ErrDefaultDeny
	}
}

// alarmLocked appelle la couture d'alarme — jamais silencieux.
func (c *Controller) alarmLocked(reason string) {
	if c.onAlarm != nil {
		c.onAlarm(reason)
	}
}

// writeLeafLocked inscrit une feuille KindTelemetry (événement système,
// pas une décision — §4.1 : la feuille de la DÉCISION reste celle du
// PEP/broker appelant). Hash-only : le registre ne voit que l'engagement.
// L'échec d'écriture est alarmé (jamais silencieux) ; il ne DÉFAIT pas la
// décision — la direction d'échec reste le déni (§9.1).
func (c *Controller) writeLeafLocked(ctx context.Context, record []byte) {
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      c.cellID,
		PayloadHash: registry.HashPayload(c.salt, record),
		Timestamp:   c.now().UnixNano(),
	}
	if _, err := c.leaves.Append(ctx, leaf); err != nil {
		c.alarmLocked(ReasonLeafWriteErr)
	}
}

// --- Records versionnés « TBTD1 » (hash-only §6.2) ----------------------
//
// actions : 1=down, 2=recovered, 3=nl-rejected, 4=escalated, 5=default-deny.
// Formats :
//   down         : "TBTD1" ‖ 1 ‖ u16be len(detail) ‖ detail
//   recovered    : "TBTD1" ‖ 2
//   nl-rejected  : "TBTD1" ‖ 3 ‖ jti(16) ‖ u8 len(systemID) ‖ systemID
//   escalated    : "TBTD1" ‖ 4 ‖ jti(16) ‖ u8 len(systemID) ‖ systemID
//   default-deny : "TBTD1" ‖ 5 ‖ jti(16) ‖ u8 len(systemID) ‖ systemID

const (
	recordActionDown        byte = 1
	recordActionRecovered   byte = 2
	recordActionNLRejected  byte = 3
	recordActionEscalated   byte = 4
	recordActionDefaultDeny byte = 5

	// maxRecordDetailLen borne le diagnostic de sonde dans la feuille.
	maxRecordDetailLen = 512
	// maxRecordSystemLen borne l'identifiant système dans la feuille.
	maxRecordSystemLen = 255
)

func recordDown(detail string) []byte {
	if len(detail) > maxRecordDetailLen {
		detail = detail[:maxRecordDetailLen]
	}
	record := make([]byte, 0, 5+1+2+len(detail))
	record = append(record, "TBTD1"...)
	record = append(record, recordActionDown)
	record = append(record, byte(len(detail)>>8), byte(len(detail)))
	record = append(record, detail...)
	return record
}

func recordRecovered() []byte {
	return []byte{'T', 'B', 'T', 'D', '1', recordActionRecovered}
}

// recordRequest sérialise un record par demande (jti ‖ système).
func recordRequest(action byte, jti [16]byte, systemID string) []byte {
	if len(systemID) > maxRecordSystemLen {
		systemID = systemID[:maxRecordSystemLen]
	}
	record := make([]byte, 0, 5+1+16+1+len(systemID))
	record = append(record, "TBTD1"...)
	record = append(record, action)
	record = append(record, jti[:]...)
	record = append(record, byte(len(systemID)))
	record = append(record, systemID...)
	return record
}

func recordNLRejected(jti [16]byte, systemID string) []byte {
	return recordRequest(recordActionNLRejected, jti, systemID)
}

func recordEscalated(jti [16]byte, systemID string) []byte {
	return recordRequest(recordActionEscalated, jti, systemID)
}

func recordDefaultDeny(jti [16]byte, systemID string) []byte {
	return recordRequest(recordActionDefaultDeny, jti, systemID)
}
