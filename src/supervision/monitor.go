// src/supervision/monitor.go — T34a (issue #60)
//
// Monitor : le processus indépendant de §2 (« at least one independent
// monitor » dans la base de confiance) et §7.1 (« mêmes mécaniques, même
// doctrine, jamais une nouvelle boîte noire »). Il a sa propre clé et son
// propre log (un CellLog ordinaire, ouvert par l'appelant — réutilisation
// de T7 telle quelle), et il N'ÉCRIT JAMAIS dans les chaînes surveillées.
//
// Trois vérificateurs continus (D78, §6.2) :
//
//  1. continuité/intégrité de la chaîne de chaque cellule ET de la master
//     chain (ChainWatcher — preuve de consistance + re-hash des feuilles) ;
//  2. fraîcheur d'ancrage : lag depuis la dernière feuille KindAnchor de
//     la cellule dans la master chain (kind + timestamp EN CLAIR, §6.2 —
//     borne par défaut 120 s) — aucune lecture du sel T6 nécessaire ;
//  3. cohérence des manifestes : VerifyManifestChain (T31, §6.3) sur les
//     artefacts publiés de chaque cellule (leur intégrité est la
//     signature, D70 — ils ne sont pas un secret).
//
// T34b ajoute la détection de chute et le déclenchement borné de bascule
// (failover.go, D80) : chaîne figée ET ancrage échu ⇒ couture
// FailoverTrigger vers #30, budget glissant d'une heure, escalade humaine
// au-delà.
//
// T34c ajoute View() : instantané lecture seule pour la console (D82),
// pris sous le même verrou que CheckOnce — jamais un état à moitié
// reconstruit. Le moniteur reste SANS goroutine propre.
//
// Chaque divergence = feuille KindSupervision dans le log de supervision
// (record « TBPS1 » hashé-salé, alert.go) PUIS alarme vers la couture T14
// (AlarmSink). Jamais l'inverse, jamais sans la feuille : §5.3 — une
// alerte non feuillée est une alerte silencieuse. Une faute de feuillage
// du moniteur lui-même est rendue en erreur de CheckOnce (le moniteur ne
// peut pas se certifier — fail-closed, à surface obligatoire côté
// déploiement).
//
// Chemin FROID (§9.1, D84) : CheckOnce est hors chemin de décision — il
// lit des fichiers et vérifie des preuves, il n'est appelé par aucun
// composant du chemin chaud (aucun import de ce package dans broker/pep —
// testé).
package supervision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// DefaultMaxAnchorLag est la borne de fraîcheur d'ancrage de §6.2.
const DefaultMaxAnchorLag = 120 * time.Second

// supervisionSaltLen : sel des feuilles KindSupervision (≥ 16 octets,
// reste chez le moniteur — même doctrine que T6/T31).
const supervisionSaltLen = 16

// ErrAlarmSinkFault distingue un échec du sink T14 (notification refusée
// ou indisponible) d'une faute de feuillage du moniteur (raise ci-dessous) :
// dans le premier cas la preuve existe déjà — la feuille EST écrite avant
// que le sink soit appelé (§5.3) — dans le second non. CheckOnce ne doit
// interrompre le passage QUE dans le second cas (voir sa doc) : un simple
// accroc de notification sur UNE alerte ne doit ni faire perdre cette
// alerte déjà prouvée du retour de CheckOnce, ni empêcher la vérification
// des cellules suivantes du même passage (revue de #68).
var ErrAlarmSinkFault = errors.New("supervision: notification T14 en échec (feuille néanmoins écrite)")

// CellSpec décrit une cellule à surveiller. La configuration est
// fail-closed : tout champ requis manquant est une erreur de construction,
// pas une vérification silencieusement sautée.
type CellSpec struct {
	// CellID : identité de la cellule (= claim des feuilles, §6.2).
	CellID string
	// LogDir : répertoire POSIX du log de la cellule (lecture seule).
	LogDir string
	// Origin : origine note des checkpoints de la cellule (nom de clé).
	Origin string
	// Verifier : clé publique de checkpoint de la cellule — vérifie aussi
	// les manifestes (T31, D69 : la clé de cellule EST la clé du log).
	Verifier note.Verifier
	// ManifestDir : répertoire des artefacts SignedManifest publiés
	// (JSON, MarshalSignedManifest). La chaîne complète depuis la genèse
	// doit y être lisible — VerifyManifestChain part de seq 0.
	ManifestDir string
}

// MasterSpec décrit la master chain (source des feuilles KindAnchor).
type MasterSpec struct {
	// CellID : identité utilisée dans les alertes qui concernent la
	// master chain elle-même (ex. "master").
	CellID string
	// LogDir : répertoire POSIX de la master chain (lecture seule).
	LogDir string
	// Origin / Verifier : origine et clé publique de checkpoint.
	Origin   string
	Verifier note.Verifier
}

// MonitorOptions paramètre le Monitor. Fail-closed dès la construction.
type MonitorOptions struct {
	// MonitorCellID : identité du moniteur, portée par ses feuilles
	// KindSupervision (le moniteur est une cellule à périmètre élargi,
	// §7.1 — il s'identifie comme telle).
	MonitorCellID string
	// Log : log de supervision du moniteur (son propre CellLog, sa propre
	// clé de checkpoint — §2). Ouvert et détenu par l'appelant.
	Log *registry.CellLog
	// Cells : cellules surveillées (≥ 1).
	Cells []CellSpec
	// Master : master chain — requis : la fraîcheur d'ancrage (§6.2) est
	// un des trois vérificateurs, la surveiller « parfois » serait une
	// vérification optionnelle, ce que §5.3 interdit.
	Master MasterSpec
	// MaxAnchorLag : borne de fraîcheur d'ancrage. Zéro = défaut §6.2.
	MaxAnchorLag time.Duration
	// Sink : couture d'alarme vers T14. Nil toléré — la feuille, jamais.
	Sink AlarmSink
	// Now : horloge du moniteur. Nil ⇒ time.Now (dev).
	Now func() time.Time
	// Trigger : couture de déclenchement de bascule vers #30
	// (cluster.Tracker / PromotionController — T34 détecte et déclenche,
	// ne fence pas, D83). Nil = bascule automatique désactivée : chaque
	// chute confirmée est REFUSÉE (feuille event=5, escalade humaine) —
	// jamais silencieuse (failover.go).
	Trigger FailoverTrigger
	// FallDelay : durée sans progression de chaîne NI ancrage frais avant
	// de conclure à la chute (D80). Zéro = défaut (2 × borne d'ancrage).
	// Doit être STRICTEMENT supérieur à MaxAnchorLag — l'alarme
	// anchor-stale précède toujours une bascule automatique — sinon
	// erreur de construction.
	FallDelay time.Duration
	// MaxFailoverTriggers : budget de déclenchements par fenêtre glissante
	// d'une heure. Zéro = défaut 2 ; négatif = erreur. Pour interdire
	// toute bascule automatique : Trigger nil (le refus est feuillé,
	// l'humain escaladé) — pas un budget à zéro.
	// NB (revue Claude sur #60) : ce budget borne ce que le MONITEUR
	// DÉCLENCHE ; MaxAutoFailoversPerHour=3 (src/cluster/epoch.go, T29)
	// borne ce qu'une CELLULE ACCEPTE. Deux couches, pas de contradiction
	// — le budget moniteur (2 < 3) est de facto la borne effective, la
	// plus stricte (moins d'intervention automatique, pas plus).
	MaxFailoverTriggers int
}

// Monitor orchestre les vérificateurs. Pas de goroutine propre :
// CheckOnce est le cœur testable ; la cadence est un choix de déploiement
// (l'appelant boucle — la latence de détection est réglée là, pas ici).
type Monitor struct {
	cellID       string
	log          *registry.CellLog
	sink         AlarmSink
	now          func() time.Time
	maxLag       time.Duration
	master       *ChainWatcher
	cells        []CellSpec
	watchers     map[string]*ChainWatcher // par CellID
	lastAnchor   map[string]time.Time     // par CellID, max observé (monotone)
	trigger      FailoverTrigger
	fallDelay    time.Duration
	maxTriggers  int
	triggerTimes []time.Time           // déclenchements dans la fenêtre glissante (borné)
	falls        map[string]*fallState // par CellID

	// mu sérialise CheckOnce et View (console T34c) : le moniteur reste
	// SANS goroutine propre (le driver cadence CheckOnce), mais la console
	// lit depuis les goroutines HTTP — l'instantané est pris sous le même
	// verrou que le passage de vérification, jamais à moitié reconstruit.
	// Un sink d'alarme ne doit JAMAIS rappeler le moniteur (CheckOnce
	// tient le verrou pendant la notification — ce serait un interblocage).
	mu sync.Mutex
}

// NewMonitor construit les watchers (checkpoint initial de chaque chaîne
// vérifié à la construction — fail-closed).
func NewMonitor(ctx context.Context, opts MonitorOptions) (*Monitor, error) {
	if opts.MonitorCellID == "" || len(opts.MonitorCellID) > maxAlertCellIDLen {
		return nil, fmt.Errorf("supervision: MonitorCellID requis, ≤ %d octets", maxAlertCellIDLen)
	}
	if opts.Log == nil {
		return nil, errors.New("supervision: log de supervision requis (§7.1 : le moniteur feuille comme toute cellule)")
	}
	if len(opts.Cells) == 0 {
		return nil, errors.New("supervision: au moins une cellule à surveiller")
	}
	if opts.Master.LogDir == "" || opts.Master.Verifier == nil || opts.Master.Origin == "" || opts.Master.CellID == "" {
		return nil, errors.New("supervision: master chain complète requise (dir, origin, verifier, cellID) — l'ancrage (§6.2) n'est pas optionnel")
	}
	if opts.FallDelay < 0 {
		return nil, errors.New("supervision: FallDelay négatif")
	}
	if opts.MaxFailoverTriggers < 0 {
		return nil, errors.New("supervision: MaxFailoverTriggers négatif — pour interdire toute bascule automatique, laissez Trigger nil")
	}
	m := &Monitor{
		cellID:      opts.MonitorCellID,
		log:         opts.Log,
		sink:        opts.Sink,
		now:         opts.Now,
		maxLag:      opts.MaxAnchorLag,
		cells:       opts.Cells,
		watchers:    make(map[string]*ChainWatcher, len(opts.Cells)),
		lastAnchor:  make(map[string]time.Time, len(opts.Cells)),
		trigger:     opts.Trigger,
		fallDelay:   opts.FallDelay,
		maxTriggers: opts.MaxFailoverTriggers,
		falls:       make(map[string]*fallState, len(opts.Cells)),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.maxLag <= 0 {
		m.maxLag = DefaultMaxAnchorLag
	}
	if m.fallDelay == 0 {
		m.fallDelay = DefaultFallDelay
	}
	if m.fallDelay <= m.maxLag {
		return nil, fmt.Errorf("supervision: FallDelay (%s) doit être strictement supérieur à MaxAnchorLag (%s) — l'alarme anchor-stale précède toujours une bascule automatique", m.fallDelay, m.maxLag)
	}
	if m.maxTriggers == 0 {
		m.maxTriggers = DefaultMaxFailoverTriggers
	}
	// Master chain : bootstrap depuis 0 — l'état de fraîcheur d'ancrage
	// existe avant le premier tick (un ancrage échu ne doit pas attendre
	// une nouvelle feuille). O(n) une fois au démarrage, borne P1 assumée.
	masterLeaves, mw, err := NewChainWatcher(ctx, opts.Master.CellID, opts.Master.LogDir, opts.Master.Origin, opts.Master.Verifier, 0)
	if err != nil {
		return nil, err
	}
	m.master = mw
	m.observeAnchors(masterLeaves)
	for _, c := range opts.Cells {
		if c.CellID == "" || c.LogDir == "" || c.Origin == "" || c.Verifier == nil || c.ManifestDir == "" {
			return nil, fmt.Errorf("supervision: CellSpec incomplète (cellID=%q) — cellID, logDir, origin, verifier, manifestDir requis", c.CellID)
		}
		if _, dup := m.watchers[c.CellID]; dup {
			return nil, fmt.Errorf("supervision: cellule %q en double", c.CellID)
		}
		// Cellules aussi : bootstrap depuis 0 — audit complet à l'ouverture
		// (§3 : une corruption ancienne d'une feuille ne casse pas la
		// consistance Merkle FUTURE, seul un re-hash la voit). O(n) une
		// fois au démarrage, incrémental O(log n) ensuite. Borne P1.
		_, w, err := NewChainWatcher(ctx, c.CellID, c.LogDir, c.Origin, c.Verifier, 0)
		if err != nil {
			return nil, err
		}
		m.watchers[c.CellID] = w
		// Détection de chute (T34b) : point de départ conservateur — une
		// chaîne figée AVANT l'arrivée du moniteur n'est déclarée en chute
		// qu'après FallDelay de surveillance effective.
		m.falls[c.CellID] = &fallState{lastSize: w.Size(), lastProgress: m.now()}
	}
	return m, nil
}

// CheckOnce exécute un passage des vérificateurs (trois de T34a + la
// détection de chute/bascule bornée de T34b). Rend les alertes levées
// (chacune déjà feuillée puis notifiée). err non nil UNIQUEMENT si
// le moniteur lui-même a fauté (feuillage impossible) — les fautes des
// chaînes surveillées sont des ALERTES, pas des erreurs de CheckOnce.
func (m *Monitor) CheckOnce(ctx context.Context) ([]Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var alerts []Alert
	raise := func(cellID string, event byte, verdict byte, reason string, detail []byte) error {
		a, err := m.raise(ctx, cellID, event, verdict, reason, detail)
		// Une faute de SINK n'abandonne pas la feuille déjà écrite (a est
		// alors valide, LeafIndex compris) : elle reste dans les alertes
		// rendues et le passage continue. Seule une faute de feuillage
		// (a resté à zéro) interrompt CheckOnce — voir ErrAlarmSinkFault.
		if err != nil && !errors.Is(err, ErrAlarmSinkFault) {
			return err
		}
		alerts = append(alerts, a)
		return nil
	}

	// 1+2. Master chain : intégrité, puis récolte des ancrages.
	masterLeaves, err := m.master.Tick(ctx)
	if err != nil {
		if rerr := raise(m.master.cellID, AlertEventChainFault, AlertVerdictAlarm, "master-chain-fault", []byte(err.Error())); rerr != nil {
			return alerts, rerr
		}
	} else {
		m.observeAnchors(masterLeaves)
	}

	// Vérificateurs par cellule.
	for _, c := range m.cells {
		w := m.watchers[c.CellID]
		if _, err := w.Tick(ctx); err != nil {
			if rerr := raise(c.CellID, AlertEventChainFault, AlertVerdictAlarm, "cell-chain-fault", []byte(err.Error())); rerr != nil {
				return alerts, rerr
			}
			// Chaîne fautive : les deux autres vérificateurs restent
			// d'actualité (ancrage et manifestes sont hors chaîne locale).
		}
		if err := m.checkAnchorFreshness(c.CellID, raise); err != nil {
			return alerts, err
		}
		if err := m.checkManifests(c, raise); err != nil {
			return alerts, err
		}
		// T34b : chute (chaîne figée ET ancrage échu) ⇒ bascule bornée ou
		// escalade humaine (failover.go, D80).
		if err := m.checkFall(ctx, c.CellID, raise); err != nil {
			return alerts, err
		}
	}
	return alerts, nil
}

// observeAnchors intègre les feuilles KindAnchor vérifiées de la master
// chain : kind + timestamp EN CLAIR (le payload salé reste opaque — §6.2).
// Monotone : un ancrage plus ancien que le dernier observé ne fait jamais
// reculer la fraîcheur (rattrapage de backlog, même doctrine que T6).
func (m *Monitor) observeAnchors(leaves []registry.Leaf) {
	for _, leaf := range leaves {
		if leaf.Kind != registry.KindAnchor {
			continue
		}
		ts := time.Unix(0, leaf.Timestamp).UTC()
		if prev, ok := m.lastAnchor[leaf.CellID]; !ok || ts.After(prev) {
			m.lastAnchor[leaf.CellID] = ts
		}
	}
}

// checkAnchorFreshness alarme si la cellule n'a pas d'ancrage dans la
// borne §6.2. « Jamais observé » est une faute comme « trop vieux » : une
// cellule surveillée qui n'ancre pas est indistinguable d'une cellule
// morte (§6.2 : l'ancrage est cadencé par le TEMPS, pas par l'activité).
func (m *Monitor) checkAnchorFreshness(cellID string, raise func(string, byte, byte, string, []byte) error) error {
	last, ok := m.lastAnchor[cellID]
	now := m.now()
	if !ok {
		return raise(cellID, AlertEventAnchorStale, AlertVerdictAlarm, "anchor-missing",
			[]byte(fmt.Sprintf("cellule=%s aucun ancrage observé now=%s", cellID, now.UTC().Format(time.RFC3339Nano))))
	}
	lag := now.Sub(last)
	if lag > m.maxLag {
		return raise(cellID, AlertEventAnchorStale, AlertVerdictAlarm, "anchor-stale",
			[]byte(fmt.Sprintf("cellule=%s dernier=%s lag=%s borne=%s", cellID, last.UTC().Format(time.RFC3339Nano), lag, m.maxLag)))
	}
	return nil
}

// checkManifests recharge et revérifie TOUTE la chaîne publiée de la
// cellule à chaque passage : la vérification est O(n) sur des artefacts
// petits et rares (une transition par changement de composant, §6.3) —
// rejouer depuis la genèse est le niveau de preuve de §6.3, pas un luxe.
func (m *Monitor) checkManifests(c CellSpec, raise func(string, byte, byte, string, []byte) error) error {
	chain, err := loadManifestChain(c.ManifestDir)
	if err == nil {
		err = registry.VerifyManifestChain(chain, c.Verifier)
	}
	if err != nil {
		return raise(c.CellID, AlertEventManifestFault, AlertVerdictAlarm, "manifest-chain-fault", []byte(err.Error()))
	}
	return nil
}

// loadManifestChain lit le répertoire d'artefacts publiés (JSON
// MarshalSignedManifest) et rend la chaîne triée par seq — l'ordre des
// fichiers n'est PAS une donnée de confiance, le seq du record l'est
// (vérifié continu par VerifyManifestChain).
func loadManifestChain(dir string) ([]registry.SignedManifest, error) {
	var chain []registry.SignedManifest
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("supervision: artefact %s : %w", path, err)
		}
		sm, err := registry.ParseSignedManifest(raw)
		if err != nil {
			return fmt.Errorf("supervision: artefact %s : %w", path, err)
		}
		chain = append(chain, sm)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(chain, func(i, j int) bool {
		mi, _ := registry.ParseManifestRecord(chain[i].Record)
		mj, _ := registry.ParseManifestRecord(chain[j].Record)
		return mi.Seq < mj.Seq
	})
	return chain, nil
}

// raise construit le record « TBPS1 », le feuille (KindSupervision, hash
// salé — §6.2) PUIS notifie le sink. Ordre obligatoire (§5.3) : une alerte
// est d'abord une feuille. Feuille impossible ⇒ erreur (faute du moniteur)
// et PAS de notification d'une alerte qui n'existe pas encore comme
// preuve. Le verdict est un paramètre : Alarm pour les divergences (T34a),
// Notice pour un acte pré-autorisé du moniteur (déclenchement de bascule
// dans le budget — T34b).
func (m *Monitor) raise(ctx context.Context, cellID string, event byte, verdict byte, reason string, detail []byte) (Alert, error) {
	rec := AlertRecord{
		Event:      event,
		CellID:     cellID,
		DetailHash: sha256.Sum256(detail),
		Verdict:    verdict,
		Reason:     reason,
	}
	raw, err := MarshalAlertRecord(rec)
	if err != nil {
		return Alert{}, err
	}
	salt := make([]byte, supervisionSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return Alert{}, fmt.Errorf("supervision: sel de feuille : %w", err)
	}
	leafHash := registry.HashPayload(salt, raw)
	idx, err := m.log.Append(ctx, registry.Leaf{
		Kind:        registry.KindSupervision,
		CellID:      m.cellID,
		PayloadHash: leafHash,
		Timestamp:   m.now().UnixNano(),
	})
	if err != nil {
		return Alert{}, fmt.Errorf("supervision: feuille d'alerte impossible : %w", err)
	}
	a := Alert{Record: rec, Raw: raw, Salt: salt, Detail: detail, LeafIndex: idx, LeafHash: leafHash}
	if m.sink != nil {
		if err := m.sink.Raise(ctx, a); err != nil {
			// La feuille EST écrite : la preuve existe. Un sink en faute
			// est une erreur de notification, pas une perte d'alerte — on
			// rend l'alerte ET l'erreur au-dessus, marquée ErrAlarmSinkFault
			// pour que l'appelant (CheckOnce) la distingue d'une faute de
			// feuillage et ne perde ni n'interrompe rien pour autant.
			return a, fmt.Errorf("%w : %v", ErrAlarmSinkFault, err)
		}
	}
	return a, nil
}

// LastAnchor rend le dernier ancrage observé pour une cellule (tests et
// driver — la console consomme View(), sous verrou). ok=false : jamais
// observé.
func (m *Monitor) LastAnchor(cellID string) (time.Time, bool) {
	ts, ok := m.lastAnchor[cellID]
	return ts, ok
}

// Watcher rend le ChainWatcher d'une cellule (taille vérifiée — tests et
// détection de chute T34b ; la console consomme View(), sous verrou). nil
// si inconnue.
func (m *Monitor) Watcher(cellID string) *ChainWatcher { return m.watchers[cellID] }

// CellView est la lecture figée d'une cellule surveillée (console T34c,
// D82) : des FAITS bruts seulement — la logique de détection (fraîcheur
// §6.2, chute D80) n'est pas rejouée ici pour ne jamais dériver des
// vérificateurs. L'interprétation (stale, chute) est faite à l'affichage,
// clairement marquée comme dérivée.
type CellView struct {
	CellID         string
	ChainSize      uint64        // taille vérifiée de la chaîne lue
	LastAnchor     time.Time     // dernier ancrage observé — zéro si jamais
	AnchorLag      time.Duration // âge du dernier ancrage — −1 si jamais observé
	LastProgress   time.Time     // dernière progression de la chaîne lue
	EpisodeHandled bool          // épisode de chute traité (bascule déclenchée ou refusée) — la reprise le réarme
}

// MonitorView est l'instantané lecture seule du moniteur (console T34c) :
// pris sous le même verrou que CheckOnce — jamais un état à moitié
// reconstruit. Lecture rare (console d'opérateur) : bloquer un passage de
// vérification quelques millisecondes est le prix d'une copie cohérente.
type MonitorView struct {
	Now          time.Time
	MaxAnchorLag time.Duration // borne de fraîcheur d'ancrage (§6.2)
	FallDelay    time.Duration // seuil de chute (T34b, D80)
	MaxTriggers  int           // budget de bascules (fenêtre glissante 1 h)
	TriggersHour int           // bascules déclenchées dans la fenêtre courante
	Cells        []CellView    // dans l'ordre de configuration — déterministe
}

// View rend l'instantané. Pur : aucune feuille, aucune alarme, aucune
// mutation — la console ne peut pas changer ce qu'elle observe (D81).
func (m *Monitor) View() MonitorView {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	v := MonitorView{
		Now:          now,
		MaxAnchorLag: m.maxLag,
		FallDelay:    m.fallDelay,
		MaxTriggers:  m.maxTriggers,
		Cells:        make([]CellView, 0, len(m.cells)),
	}
	for _, ts := range m.triggerTimes {
		if ts.After(now.Add(-failoverWindow)) {
			v.TriggersHour++
		}
	}
	for _, c := range m.cells {
		fs := m.falls[c.CellID]
		cv := CellView{
			CellID:         c.CellID,
			ChainSize:      m.watchers[c.CellID].Size(),
			LastProgress:   fs.lastProgress,
			EpisodeHandled: fs.episodeHandled,
			AnchorLag:      -1,
		}
		if last, ok := m.lastAnchor[c.CellID]; ok {
			cv.LastAnchor = last
			cv.AnchorLag = now.Sub(last)
		}
		v.Cells = append(v.Cells, cv)
	}
	return v
}
