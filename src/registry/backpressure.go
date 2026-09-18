// src/registry/backpressure.go — T5 (issue #5)
//
// Backpressure disque du registre de cellule : quota fixe, arrêt propre à
// 80 %, arrêt tracé (dernière feuille KindBackpressure) et alarmé
// (traitement classe W, §5.3) — une condition fail-closed DÉCLENCHÉE PAR LE
// STOCKAGE, distincte du fencing par lag d'ancrage de §6.2.
//
// Pourquoi (src/registry/README.md) : pendant une partition prolongée, la
// cellule continue d'écrire des feuilles — chaque jeton refusé est lui-même
// une feuille — sans nulle part où les drainer. Un répertoire POSIX non
// borné peut remplir le disque hôte : une deuxième panne, auto-infligée,
// superposée à la partition réseau.
//
// Décision D6 (spike de l'issue #5) : Tessera n'expose PAS de hook dans le
// chemin d'écriture — mais T4 a déjà placé la couture BackpressureChecker
// dans Append (consultée avant chaque écriture, coût O(1)). Le présent
// Monitor est un sidecar : un ticker mesure l'usage hors du chemin chaud
// (aucune friction sur Append, §9.1), et Engaged() n'est qu'un booléen
// atomique lu dans le chemin d'écriture.
//
// Câblage (ordre imposé par la couture T4 : le moniteur existe AVANT le
// log pour être passé à Open, puis est lié au log pour tracer l'arrêt) :
//
//	mon, _ := NewMonitor(MonitorOptions{Dir: dir, CellID: id, QuotaBytes: q, ...})
//	log, _ := Open(ctx, Options{..., Backpressure: mon})  // la couture T4
//	mon.Bind(log)
//	go mon.Run(ctx)
package registry

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ErrMonitorClosed est retourné par les opérations sur un Monitor arrêté.
var ErrMonitorClosed = errors.New("registre : moniteur de backpressure arrêté")

// ErrMonitorNotBound est retourné par Run si le moniteur n'a pas été lié à
// un CellLog (Bind) — sans log, l'arrêt ne peut pas être tracé, et un
// moniteur muet serait une dégradation silencieuse (§5.3).
var ErrMonitorNotBound = errors.New("registre : moniteur non lié à un CellLog (Bind requis)")

const (
	// DefaultThreshold est la part du quota qui déclenche l'arrêt (80 %,
	// politique README).
	DefaultThreshold = 0.80
	// DefaultInterval est la période d'échantillonnage du sidecar.
	DefaultInterval = time.Second
	// DefaultSafetyMultiple couvre l'imprévu au-delà de l'horizon nominal
	// (rafales de refus pendant la partition : chaque refus est une feuille).
	DefaultSafetyMultiple = 3.0
	// leafStorageBytes est l'occupation disque par feuille, mesurée :
	// feuille sérialisée (layout fixe leaf.go, typiquement < 100 octets) +
	// hash de feuille RFC 6962 dans les tiles (32 octets × profondeur
	// moyenne) + overhead de bundle (2 octets). Arrondi haut : 512 octets.
	// À recalibrer sur les mesures de débit P1 (tests/p1_friction) dès
	// qu'elles existent — le critère d'acceptation de l'issue #5 exige un
	// quota dimensionné sur un taux mesuré, pas estimé.
	leafStorageBytes = 512
	// saltLen est la taille du sel de la feuille KindBackpressure (≥ 16
	// octets, doctrine leaf.go — le sel ne quitte jamais la cellule).
	saltLen = 16
)

// SizeQuotaBytes dimensionne le quota d'une cellule : taux de feuilles
// mesuré (P1) × horizon de partition × marge de sécurité × occupation par
// feuille. C'est un quota ALLOUÉ, pas « l'espace libre du moment » — le
// disque hôte peut être presque plein ou presque vide, la politique est
// identique.
//
// leafRatePerSec : feuilles/seconde mesurées sur le pilote P1 (décisions +
// télémétrie + refus — pendant une partition, les refus dominent).
// horizon : durée de partition à absorber (p.ex. le fencing §6.2 à 120 s
// borne l'autorisation, pas le stockage — le stockage doit tenir le
// multiple réaliste le plus défavorable).
// safetyMultiple : marge (0 ou négatif → DefaultSafetyMultiple).
func SizeQuotaBytes(leafRatePerSec float64, horizon time.Duration, safetyMultiple float64) uint64 {
	if leafRatePerSec <= 0 || horizon <= 0 {
		return 0
	}
	if safetyMultiple <= 0 {
		safetyMultiple = DefaultSafetyMultiple
	}
	return uint64(leafRatePerSec * horizon.Seconds() * safetyMultiple * leafStorageBytes)
}

// UsageSampler mesure l'occupation du répertoire du log (octets).
type UsageSampler interface {
	UsedBytes(dir string) (uint64, error)
}

// DirSampler additionne les fichiers réguliers du répertoire (récursif —
// le layout tlog-tiles est arborescent).
type DirSampler struct{}

// UsedBytes implémente UsageSampler. Un fichier qui disparaît PENDANT le
// parcours n'est pas une erreur : Tessera réécrit les bundles et tiles par
// renommage atomique, un instantané parfait n'existe pas — ignorer le
// fichier disparu (mesure légèrement pessimiste ou optimiste d'un fichier)
// est correct, alors qu'en faire une erreur déclencherait le fail-closed
// sur un non-événement.
func (DirSampler) UsedBytes(dir string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path != dir {
				return nil // fichier disparu pendant le parcours — skip
			}
			// La racine inexistante, elle, reste une erreur : mesure
			// impossible → fail-closed.
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			total += uint64(fi.Size())
		}
		return nil
	})
	return total, err
}

// FsStats rapporte l'espace LIBRE du système de fichiers hôte — garde
// secondaire : l'arrêt doit survenir avant que le disque hôte soit en
// risque, même si un autre locataire du même filesystem le remplit.
type FsStats interface {
	FreeBytes(dir string) (uint64, error)
}

// StatfsStats implémente FsStats via statfs(2).
type StatfsStats struct{}

// FreeBytes implémente FsStats (Bavail × Bsize — l'espace réellement
// disponible pour un processus non privilégié).
func (StatfsStats) FreeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// Alarm est l'événement émis à l'engagement — traitement classe W (§5.3) :
// signé, alarmé, enregistré. La signature et le transport vers le moniteur
// sont hors scope T5 (coutures OnTrip/OnAlarm) ; l'événement porte tout ce
// qu'il faut pour être signé en aval. Reason est stable et normalisée pour
// le filtrage moniteur.
type Alarm struct {
	Reason     string    // "registry-disk-80%" | "registry-host-disk-low" | "registry-sampler-error"
	CellID     string    // cellule concernée
	UsedBytes  uint64    // occupation mesurée du répertoire du log
	QuotaBytes uint64    // quota alloué
	Threshold  float64   // seuil configuré (0.80)
	HostFree   uint64    // espace libre hôte mesuré (0 si inconnu)
	At         time.Time // horodatage UTC
}

// MonitorOptions paramètre le moniteur de backpressure. Le CellLog n'en
// fait PAS partie : la couture T4 impose de construire le moniteur avant
// Open (c'est lui le BackpressureChecker) — il est lié ensuite par Bind.
type MonitorOptions struct {
	// Dir est le répertoire du log (mesuré par le Sampler).
	Dir string
	// CellID identifie la cellule dans la feuille d'arrêt et l'alarme.
	CellID string
	// QuotaBytes est le quota alloué (SizeQuotaBytes). Requis, > 0.
	QuotaBytes uint64
	// Threshold déclenche l'arrêt à Threshold × QuotaBytes (défaut 0.80).
	Threshold float64
	// HostFloorBytes, si > 0, engage aussi le backpressure quand l'espace
	// libre du filesystem hôte passe sous ce plancher — même sous quota.
	HostFloorBytes uint64
	// Interval est la période d'échantillonnage (défaut 1 s).
	Interval time.Duration
	// Sampler mesure l'occupation (défaut DirSampler — injectable en test).
	Sampler UsageSampler
	// Fs mesure l'espace libre hôte (défaut StatfsStats — injectable).
	Fs FsStats
	// OnTrip est appelé UNE fois à l'engagement — couture vers le module
	// fail-closed unique (T14) : c'est ici que le broker cessera d'émettre
	// dans le même chemin de décision que les autres conditions. Nil en
	// dev : Append refuse déjà via Engaged().
	OnTrip func(Alarm)
	// OnAlarm est appelé UNE fois à l'engagement — couture vers le
	// moniteur (classe W, §5.3). Nil en dev.
	OnAlarm func(Alarm)
}

// Monitor est le sidecar de backpressure disque. Il implémente
// BackpressureChecker : Engaged() est un booléen atomique lu par Append
// dans le chemin d'écriture (O(1), aucune friction — §9.1).
type Monitor struct {
	log       atomic.Pointer[CellLog] // lié par Bind — nil avant
	dir       string
	cellID    string
	quota     uint64
	threshold float64
	hostFloor uint64
	interval  time.Duration
	sampler   UsageSampler
	fs        FsStats
	onTrip    func(Alarm)
	onAlarm   func(Alarm)
	salt      []byte // sel des feuilles KindBackpressure — ne quitte pas la cellule

	engaged atomic.Bool
	closed  atomic.Bool
}

// NewMonitor valide les options et construit le moniteur (fail-closed :
// une configuration invalide est une erreur, pas un moniteur muet).
func NewMonitor(opts MonitorOptions) (*Monitor, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("MonitorOptions.Dir requis")
	}
	if opts.CellID == "" {
		return nil, fmt.Errorf("MonitorOptions.CellID requis (feuille d'arrêt et alarme)")
	}
	if opts.QuotaBytes == 0 {
		return nil, fmt.Errorf("MonitorOptions.QuotaBytes requis (quota alloué, pas l'espace libre)")
	}
	threshold := opts.Threshold
	if threshold == 0 {
		threshold = DefaultThreshold
	}
	if threshold <= 0 || threshold >= 1 {
		return nil, fmt.Errorf("Threshold %v hors ]0, 1[", threshold)
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	if interval < 0 {
		return nil, fmt.Errorf("Interval négatif")
	}
	sampler := opts.Sampler
	if sampler == nil {
		sampler = DirSampler{}
	}
	fsStats := opts.Fs
	if fsStats == nil {
		fsStats = StatfsStats{}
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("sel de la feuille d'arrêt: %w", err)
	}
	return &Monitor{
		dir: opts.Dir, cellID: opts.CellID,
		quota: opts.QuotaBytes, threshold: threshold, hostFloor: opts.HostFloorBytes,
		interval: interval, sampler: sampler, fs: fsStats,
		onTrip: opts.OnTrip, onAlarm: opts.OnAlarm, salt: salt,
	}, nil
}

// Bind lie le moniteur au CellLog dont il surveille le répertoire — requis
// avant Run : l'arrêt est tracé par une feuille KindBackpressure, dernière
// écrite avant l'engagement. Le moniteur doit DÉJÀ être le
// BackpressureChecker de ce log (passé à Open), sinon l'engagement ne
// refuserait rien — moniteur décoratif, exactement le genre de dérive que
// T14 interdit en centralisant « refuser maintenant ».
func (m *Monitor) Bind(log *CellLog) error {
	if log == nil {
		return fmt.Errorf("Bind: CellLog nil")
	}
	if !m.log.CompareAndSwap(nil, log) {
		return fmt.Errorf("Bind: moniteur déjà lié")
	}
	return nil
}

// Engaged implémente BackpressureChecker — lu par Append avant chaque
// écriture. O(1), jamais bloquant.
func (m *Monitor) Engaged() bool { return m.engaged.Load() }

// Run échantillonne périodiquement jusqu'à l'annulation du contexte. Le
// premier échantillon est pris immédiatement (un log déjà plein au
// démarrage engage sans attendre un intervalle).
func (m *Monitor) Run(ctx context.Context) error {
	if m.closed.Load() {
		return ErrMonitorClosed
	}
	if m.log.Load() == nil {
		return ErrMonitorNotBound
	}
	m.check(ctx)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			m.check(ctx)
		}
	}
}

// Close arrête le moniteur (Run le refuse ensuite). Sans effet sur le log.
func (m *Monitor) Close() { m.closed.Store(true) }

// Disengage lève le backpressure après remédiation opérateur (quota
// agrandi, répertoire drainé). Décision humaine, jamais automatique.
func (m *Monitor) Disengage() { m.engaged.Store(false) }

// check prend un échantillon et engage si nécessaire. Idempotent :
// l'engagement n'arrive qu'une fois (les callbacks ne tirent qu'une fois).
func (m *Monitor) check(ctx context.Context) {
	if m.engaged.Load() || m.closed.Load() {
		return
	}

	used, uerr := m.sampler.UsedBytes(m.dir)
	free, ferr := m.fs.FreeBytes(m.dir)

	alarm := Alarm{
		CellID: m.cellID, UsedBytes: used, QuotaBytes: m.quota,
		Threshold: m.threshold, HostFree: free, At: time.Now().UTC(),
	}
	switch {
	case uerr != nil || ferr != nil:
		// Fail-closed : une mesure impossible n'est pas un feu vert — un
		// moniteur aveugle sur un disque qui se remplit est exactement la
		// panne que ce livrable existe pour empêcher.
		alarm.Reason = "registry-sampler-error"
	case used >= uint64(m.threshold*float64(m.quota)):
		alarm.Reason = "registry-disk-80%"
	case m.hostFloor > 0 && free <= m.hostFloor:
		alarm.Reason = "registry-host-disk-low"
	default:
		return // sous le seuil : rien à faire
	}
	m.engage(ctx, alarm)
}

// engage verrouille D'ABORD, puis trace l'arrêt — ordre doctrinal : tout
// Append accepté avant le verrouillage est drainé (waitInflight), donc la
// feuille KindBackpressure est littéralement la DERNIÈRE feuille du
// registre (README). Si la feuille ne peut pas être écrite (disque déjà
// plein), le verrouillage tient quand même — fail-closed, jamais
// l'inverse.
func (m *Monitor) engage(ctx context.Context, alarm Alarm) {
	// Verrouillage : à partir d'ici, Append refuse tout (ErrBackpressure).
	// CAS plutôt que Store : si un échantillon concurrent a déjà engagé,
	// on ne re-déclenche ni feuille ni callbacks.
	if !m.engaged.CompareAndSwap(false, true) {
		return
	}
	if log := m.log.Load(); log != nil {
		// Drainage : les écritures acceptées avant le verrouillage
		// terminent ; plus aucune ne démarre (double contrôle d'Append).
		log.waitInflight()
		payload := fmt.Sprintf(`{"reason":%q,"cellID":%q,"usedBytes":%d,"quotaBytes":%d,"at":%q}`,
			alarm.Reason, alarm.CellID, alarm.UsedBytes, alarm.QuotaBytes,
			alarm.At.Format(time.RFC3339Nano))
		leaf := Leaf{
			Kind:        KindBackpressure,
			CellID:      m.cellID,
			PayloadHash: HashPayload(m.salt, []byte(payload)),
			Timestamp:   alarm.At.UnixNano(),
		}
		if _, err := log.appendInternal(ctx, leaf); err != nil {
			// La feuille d'arrêt n'a pas pu être écrite (p.ex. disque
			// plein) : on verrouille quand même — l'absence de feuille
			// est elle-même un symptôme classe W, remonté par l'alarme.
			alarm.Reason += "+leaf-write-failed"
		}
	} else {
		// Non lié : le verrouillage prime (fail-closed), le traçage est
		// signalé comme défaillant dans l'alarme.
		alarm.Reason += "+leaf-write-failed"
	}
	if m.onTrip != nil {
		m.onTrip(alarm) // couture T14 — même chemin de décision que le PEP
	}
	if m.onAlarm != nil {
		m.onAlarm(alarm) // couture moniteur classe W (§5.3)
	}
}
