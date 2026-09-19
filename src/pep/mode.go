package pep

// Bascule monitor / closed explicite, gouvernée et tracée (T15, §5.3).
//
// Doctrine de déploiement : mode MONITOR d'abord — on journalise chaque
// verdict, on ne bloque RIEN — jamais closed au premier rollout. La
// bascule en closed est un acte GOUVERNÉ : preuve de quorum exigée
// (couture QuorumVerifier, comme T14), feuille au registre de la cellule
// (hash-only §6.2) et alarme. Le retour à monitor est gouverné et tracé
// de la même façon : tout changement de posture d'application est un
// événement de gouvernance, pas un détail d'exploitation.
//
// Le contrôleur démarre TOUJOURS en monitor : un process qui revient de
// crash ne « se réveille » jamais en posture bloquante sans décision de
// gouvernance explicite.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// PEPMode est la posture d'application du PEP.
type PEPMode int

const (
	// ModeMonitor : verdicts journalisés (feuilles §4.1), RIEN bloqué —
	// le défaut doctrinal (§5.3), au premier déploiement comme au
	// redémarrage.
	ModeMonitor PEPMode = iota
	// ModeClosed : le verdict s'applique — deny ⇒ flux rejeté.
	ModeClosed
)

func (m PEPMode) String() string {
	if m == ModeClosed {
		return "closed"
	}
	return "monitor"
}

// ParsePEPMode décode une posture (« monitor » / « closed ») — entrée de
// l'API HTTP du listener.
func ParsePEPMode(s string) (PEPMode, error) {
	switch s {
	case "monitor":
		return ModeMonitor, nil
	case "closed":
		return ModeClosed, nil
	}
	return ModeMonitor, fmt.Errorf("pep: mode inconnu %q (monitor|closed)", s)
}

// ModeOptions paramètre le contrôleur. Fail-closed dès la configuration.
type ModeOptions struct {
	// CellID identifie la cellule dans les feuilles de bascule. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : chaque bascule y est tracée.
	// Requis (une bascule de posture non tracée est interdite).
	Leaves LeafSink
	// OnAlarm est la couture d'alarme : appelée « mode-<monitor|closed> »
	// à chaque bascule (jamais silencieuse). Nil ⇒ pas d'alarme externe.
	OnAlarm func(name string)
	// VerifyQuorum valide la preuve de gouvernance de chaque CHANGEMENT
	// de posture (§5.3). Nil ⇒ toute bascule est refusée (fail-closed) —
	// remplaçable via SetQuorumVerifier.
	VerifyQuorum QuorumVerifier
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// ModeController tient la posture monitor/closed du PEP. Sûr pour un
// usage concurrent.
type ModeController struct {
	cellID  string
	salt    []byte
	leaves  LeafSink
	onAlarm func(name string)
	now     func() time.Time

	mu       sync.Mutex
	mode     PEPMode
	verifier QuorumVerifier
}

// NewModeController construit le contrôleur — TOUJOURS en mode monitor
// (doctrine §5.3 : jamais closed au premier déploiement, ni au
// redémarrage). Fail-closed : cellID, sel ≥ 16 o et couture feuilles
// requis.
func NewModeController(opts ModeOptions) (*ModeController, error) {
	if opts.CellID == "" {
		return nil, errors.New("pep: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: couture feuilles requise (§5.3 : bascule TOUJOURS tracée)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &ModeController{
		cellID:   opts.CellID,
		salt:     salt,
		leaves:   opts.Leaves,
		onAlarm:  opts.OnAlarm,
		now:      now,
		mode:     ModeMonitor,
		verifier: opts.VerifyQuorum,
	}, nil
}

// SetQuorumVerifier (re)branche la couture de vérification de quorum.
func (c *ModeController) SetQuorumVerifier(v QuorumVerifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifier = v
}

// Mode rapporte la posture courante.
func (c *ModeController) Mode() PEPMode {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode
}

// SetMode change la posture — acte GOUVERNÉ : preuve de quorum exigée
// pour TOUT changement (aller comme retour), feuille tracée et alarme.
// Redemander la posture courante est un no-op (rien à gouverner, rien à
// tracer).
func (c *ModeController) SetMode(m PEPMode, proof QuorumProof) error {
	if m != ModeMonitor && m != ModeClosed {
		return fmt.Errorf("pep: mode invalide %d", m)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.mode == m {
		return nil
	}
	if c.verifier == nil {
		return fmt.Errorf("%w (bascule → %s)", ErrQuorumVerifierMissing, m)
	}
	if !c.verifier("mode-"+m.String(), proof) {
		return fmt.Errorf("%w (bascule → %s)", ErrQuorumRejected, m)
	}
	c.mode = m
	c.writeLeafLocked(m)
	if c.onAlarm != nil {
		c.onAlarm("mode-" + m.String())
	}
	return nil
}

// Allows applique la posture au verdict : en monitor, TOUT est forwardé
// (log seulement, doctrine §5.3) ; en closed, seul un allow passe.
func (c *ModeController) Allows(d Decision) bool {
	if c.Mode() == ModeMonitor {
		return true
	}
	return d.Allow
}

// writeLeafLocked inscrit la feuille de bascule (KindTelemetry : un
// événement de gouvernance, pas une décision). Hash-only : le registre ne
// voit que l'engagement. L'échec d'écriture est alarmé, jamais silencieux.
func (c *ModeController) writeLeafLocked(m PEPMode) {
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      c.cellID,
		PayloadHash: registry.HashPayload(c.salt, modeChangeRecord(m)),
		Timestamp:   c.now().UnixNano(),
	}
	if _, err := c.leaves.Append(context.Background(), leaf); err != nil && c.onAlarm != nil {
		c.onAlarm(ReasonLeafWriteFailed)
	}
}

// modeChangeRecord sérialise le record de bascule : "TBPM1" ‖ u8 mode.
func modeChangeRecord(m PEPMode) []byte {
	return []byte{'T', 'B', 'P', 'M', '1', byte(m)}
}
