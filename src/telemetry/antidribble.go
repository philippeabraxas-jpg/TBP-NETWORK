package telemetry

// src/telemetry/antidribble.go — T23 (issue #25)
//
// Détection anti-dribble sur métadonnées agrégées — le « detect » de
// « prevent what is cheap, detect what is expensive » (§4.1-bis) : une
// exfiltration en goutte-à-goutte passe sous chaque quota individuel de
// passeport (T12), mais agrège au-delà de tout usage légitime. Ce
// mécanisme la détecte sur les métadonnées SEULES — jamais de contenu,
// jamais de destination en clair conservée (§6.2).
//
// Décisions (plan et preuves sur l'issue #25) :
//
//   - D27 — couture : le détecteur implémente RecordSink (D19) et se
//     branche EN PARALLÈLE de l'agrégateur T22 via le tee FanOut —
//     zéro modification de l'exporteur et de l'agrégateur. Il voit tous
//     les records, pas seulement le top-k tronqué de l'agrégat : une
//     fuite vers une destination hors top-k n'est pas un angle mort.
//   - D28 — entité = destination hachée+salée (même schéma que T22) :
//     le record est haché à l'arrivée, seuls les compteurs par hash
//     vivent en mémoire. La concentration vers une destination fixe est
//     intrinsèque au modèle : l'entité EST la destination.
//   - D29 — fenêtres glissantes bornées (§4.3), pilotées par le fil :
//     anneau 1440 créneaux minute (24 h) + anneau 168 seaux heure (7 j),
//     avancée par le watermark (max FlowEnd vu) — aucune goroutine,
//     aucune horloge murale pour la fenêtrage. Jamais d'éviction
//     d'entité (ce serait un vecteur d'évasion) : map pleine ⇒ alarme
//     et comptage (§5.3).
//   - D30 — trois signaux binaires par entité (cumul 24 h/7 j au-delà
//     des seuils ; régularité = présence + faible variation, un automate
//     est trop régulier ; dérive EMA rapide/lente, réchauffée —
//     la naissance d'un profil n'est pas une dérive) composés en un score
//     per-mille par poids VERSIONNÉS — paramsHash dans chaque feuille :
//     un changement de seuils est visible dans le registre (§4.4(5),
//     même esprit). Arithmétique entière exclusivement (§11.3).
//   - D31 — l'alerte est une feuille KindTelemetryAlert hash-only
//     (manifeste « TBAD1 ») + un callback OnAlert — jamais de coupure
//     automatique (detect, pas prevent). Front montant uniquement,
//     réarmement par hystérésis. Une alerte qui ne peut pas laisser de
//     trace est une erreur propagée, pas un silence (§9.1).
//   - D32 — fail-closed partout (Window ≥ 1 ms — leçon de la revue
//     T22), horloge injectée pour les horodatages, stats atomiques.
//
// Simplification assumée et documentée : l'évaluation d'une entité a
// lieu au créneau scellé le plus récent. Les fronts montants sont
// déclenchés par l'arrivée d'octets — l'expiration de créneaux ne peut
// que faire baisser le cumul (les signaux de régularité/dérive exigent
// une activité récente) : aucune alerte n'est perdue par ce choix.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	defaultDetWindow   = time.Minute // aligné sur le défaut T22
	defaultMaxEntities = 4096

	ring24Slots = 1440 // créneaux minute sur 24 h
	ring7Slots  = 168  // seaux heure sur 7 j

	emaFastDen = 8  // EMA rapide : α = 1/8
	emaSlowDen = 64 // EMA lente : α = 1/64

	// Bits du bitmap de signaux (manifeste TBAD1, champ signals).
	sigBytes      uint8 = 1 // cumul 24 h ou 7 j au-delà du seuil
	sigRegularity uint8 = 2 // présence soutenue + faible variation
	sigDrift      uint8 = 4 // dérive EMA rapide au-dessus de la lente
)

// ReasonEntitiesFull est la raison d'alarme quand la map d'entités est
// pleine : une nouvelle destination n'est PAS suivie (comptée, alarmée —
// jamais silencieusement ignorée, §5.3).
const ReasonEntitiesFull = "antidribble-entities-full"

var (
	// ErrParamsInvalid : ScoreParams incohérents (version nulle, seuils
	// nuls, poids ou seuil d'alerte hors bornes, hystérésis > seuil).
	ErrParamsInvalid = errors.New("telemetry: paramètres de score invalides")
	// ErrMaxEntitiesInvalid : borne d'entités négative.
	ErrMaxEntitiesInvalid = errors.New("telemetry: borne d'entités invalide")
)

// ScoreParams est le composite de score VERSIONNÉ (§4.4(5)) : tout
// changement de seuils ou de poids change paramsHash, donc les feuilles
// d'alerte — le réglage est auditable dans le registre.
type ScoreParams struct {
	Version uint16 // ≥ 1 — à incrémenter à chaque réglage

	ByteThreshold24h uint64 // cumul 24 h déclenchant sigBytes
	ByteThreshold7d  uint64 // cumul 7 j déclenchant sigBytes

	MinActiveWindows  int // créneaux actifs sur 24 h requis pour sigRegularity/sigDrift
	JitterMaxPerMille int // variation (ÉAM/moyenne, per-mille) sous laquelle le rythme est « trop régulier »
	DriftPerMille     int // emaFast > emaSlow × (1000+DriftPerMille)/1000 ⇒ sigDrift

	WBytes      uint16 // poids per-mille du signal cumul
	WRegularity uint16 // poids per-mille du signal régularité
	WDrift      uint16 // poids per-mille du signal dérive

	AlertThreshold     uint16 // score per-mille déclenchant l'alerte
	HysteresisPerMille uint16 // réarmement sous AlertThreshold − hystérésis
}

// DefaultScoreParams est le réglage v1 — version 1. Les seuils par
// défaut visent un déploiement réel ; les tests passent leurs propres
// paramètres (plus petits, pour rester rapides).
func DefaultScoreParams() ScoreParams {
	return ScoreParams{
		Version:            1,
		ByteThreshold24h:   1 << 30, // 1 Gio/j agrégé vers une destination
		ByteThreshold7d:    4 << 30,
		MinActiveWindows:   240, // ≥ 4 h de présence dans les 24 h
		JitterMaxPerMille:  200,
		DriftPerMille:      250,
		WBytes:             500,
		WRegularity:        300,
		WDrift:             200,
		AlertThreshold:     500,
		HysteresisPerMille: 100,
	}
}

// validate applique le fail-closed sur les paramètres (D32).
func (p ScoreParams) validate() error {
	switch {
	case p.Version == 0:
		return ErrParamsInvalid // version explicite exigée — jamais implicite
	case p.ByteThreshold24h == 0 || p.ByteThreshold7d == 0:
		return ErrParamsInvalid // seuil nul = alerte sur tout octet : refusé
	case p.MinActiveWindows <= 0 || p.MinActiveWindows > ring24Slots:
		return ErrParamsInvalid
	case p.JitterMaxPerMille <= 0 || p.JitterMaxPerMille > 1000:
		return ErrParamsInvalid
	case p.DriftPerMille < 0:
		return ErrParamsInvalid
	case int(p.WBytes)+int(p.WRegularity)+int(p.WDrift) > 1000:
		return ErrParamsInvalid // le score doit rester dans [0, 1000]
	case p.AlertThreshold == 0 || p.AlertThreshold > 1000:
		return ErrParamsInvalid
	case p.HysteresisPerMille >= p.AlertThreshold:
		return ErrParamsInvalid // le réarmement doit rester sous le seuil
	}
	return nil
}

// paramsBytes sérialise les paramètres (layout « TBSP1 », déterministe) —
// la fenêtre du détecteur en fait partie : changer la fenêtre change le
// sens des seuils, donc doit changer le hash.
func paramsBytes(p ScoreParams, windowMs int64) []byte {
	buf := []byte("TBSP1")
	buf = binary.BigEndian.AppendUint16(buf, p.Version)
	buf = binary.BigEndian.AppendUint64(buf, uint64(windowMs))
	buf = binary.BigEndian.AppendUint64(buf, p.ByteThreshold24h)
	buf = binary.BigEndian.AppendUint64(buf, p.ByteThreshold7d)
	buf = binary.BigEndian.AppendUint32(buf, uint32(p.MinActiveWindows))
	buf = binary.BigEndian.AppendUint32(buf, uint32(p.JitterMaxPerMille))
	buf = binary.BigEndian.AppendUint32(buf, uint32(p.DriftPerMille))
	buf = binary.BigEndian.AppendUint16(buf, p.WBytes)
	buf = binary.BigEndian.AppendUint16(buf, p.WRegularity)
	buf = binary.BigEndian.AppendUint16(buf, p.WDrift)
	buf = binary.BigEndian.AppendUint16(buf, p.AlertThreshold)
	buf = binary.BigEndian.AppendUint16(buf, p.HysteresisPerMille)
	return buf
}

func paramsHash(p ScoreParams, windowMs int64) [32]byte {
	return sha256.Sum256(paramsBytes(p, windowMs))
}

// FanOut diffuse chaque record vers plusieurs RecordSink (D27) :
// l'agrégateur T22 et le détecteur T23 consomment le même fil en
// parallèle. Diffusion complète même en cas d'erreur — une cible en
// panne ne prive pas les autres de la preuve — puis la première erreur
// est propagée à l'appelant.
type FanOut []RecordSink

// Feed diffuse le record. Un FanOut vide est une erreur de configuration
// (fail-closed : les records ne doivent pas tomber dans un puits).
func (f FanOut) Feed(r Record) error {
	if len(f) == 0 {
		return ErrSinkRequired
	}
	var first error
	for _, s := range f {
		if err := s.Feed(r); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Alert décrit une alerte anti-dribble — passée au callback OnAlert
// (couture monitoring, §5.3). La destination n'y figure que hachée.
type Alert struct {
	DstHash  [32]byte // destination hachée+salée (jamais en clair)
	WindowID int64    // créneau minute scellé ayant déclenché l'alerte
	Score    uint16   // score composite per-mille
	Signals  uint8    // bitmap sigBytes|sigRegularity|sigDrift
	Sum24h   uint64   // cumul 24 h (octets)
	Sum7d    uint64   // cumul 7 j (octets)
}

// DetectorStats — compteurs atomiques (§5.3).
type DetectorStats struct {
	RecordsIn       uint64 // records reçus (delta > 0)
	LateRecords     uint64 // records hors fenêtre vivante (trop tardifs)
	Evaluations     uint64 // évaluations de score effectuées
	Alerts          uint64 // feuilles d'alerte écrites
	AlertFailures   uint64 // échecs d'écriture de feuille d'alerte
	EntitiesCreated uint64 // entités (destinations hachées) suivies
	EntitiesDropped uint64 // entités refusées — map pleine (alarmées)
}

// DetectorOptions — configuration fail-closed (D32).
type DetectorOptions struct {
	CellID string
	Salt   []byte       // ≥ 16 octets, reste chez le producteur (§6.2)
	Leaves pep.LeafSink // registre de la cellule (obligatoire)
	Params ScoreParams  // composite versionné — voir DefaultScoreParams

	Window      time.Duration // grille minute du détecteur (défaut 60 s)
	MaxEntities int           // borne de la map d'entités (défaut 4096)

	Now func() time.Time // horloge injectée — horodatage des feuilles uniquement

	// OnAlert est la couture monitoring : appelé à chaque alerte écrite
	// (nil ⇒ pas de callback). Le détecteur n'a AUCUNE API d'action sur
	// les flux : detect, pas prevent (§4.1-bis).
	OnAlert func(Alert)
	// OnTrip est la couture d'alarme (nil ⇒ pas d'alarme externe).
	OnTrip func(reason string)
}

// entityProfile est l'état borné par entité (D29) : deux anneaux à
// créneaux datés (la date du créneau invalide les valeurs périmées),
// EMAs en point fixe ×1000, hystérésis d'alerte.
type entityProfile struct {
	slotMin [ring24Slots]int64 // minute portée par chaque créneau (−1 = vide)
	ring24  [ring24Slots]uint64
	sum24   uint64 // somme courante (peut surestimer entre deux évals — resynchronisée au scan)

	slotHour [ring7Slots]int64 // heure portée par chaque seau (−1 = vide)
	ring7    [ring7Slots]uint64
	sum7     uint64

	curHour      int64 // heure en cours d'accumulation (−1 = aucune)
	curHourBytes uint64

	lastEval int64  // dernière minute intégrée aux EMAs (−1 = jamais)
	seen     uint64 // minutes intégrées depuis la (re)naissance du profil
	emaFast  uint64 // octets/minute ×1000 (α = 1/8)
	emaSlow  uint64 // octets/minute ×1000 (α = 1/64)

	alerted bool // hystérésis : feuille déjà écrite pour cet épisode
}

func newEntityProfile() *entityProfile {
	p := &entityProfile{curHour: -1, lastEval: -1}
	for i := range p.slotMin {
		p.slotMin[i] = -1
	}
	for i := range p.slotHour {
		p.slotHour[i] = -1
	}
	return p
}

// Detector profile chaque destination (hachée) sur fenêtres glissantes
// 24 h / 7 j et alerte quand le score composite versionné franchit le
// seuil. Pas de goroutine : le fil de records pilote tout (D29).
type Detector struct {
	cellID  string
	salt    []byte
	leaves  pep.LeafSink
	params  ScoreParams
	paramsH [32]byte
	window  time.Duration
	maxEnt  int
	now     func() time.Time
	onAlert func(Alert)
	onTrip  func(string)

	mu        sync.Mutex
	watermark int64                     // plus haute minute vue (−1 = aucune)
	entities  map[string]*entityProfile // clé = string(dstHash[:]) — triable, déterministe
	stats     DetectorStats
}

// NewDetector construit un détecteur — fail-closed (D32).
func NewDetector(opts DetectorOptions) (*Detector, error) {
	if opts.CellID == "" {
		return nil, ErrCellIDRequired
	}
	if len(opts.Salt) < 16 {
		return nil, ErrSaltTooShort
	}
	if opts.Leaves == nil {
		return nil, ErrLeavesRequired
	}
	if err := opts.Params.validate(); err != nil {
		return nil, err
	}
	w := opts.Window
	if w == 0 {
		w = defaultDetWindow
	}
	if w < time.Millisecond {
		// Positif mais sous-milliseconde : FlowEnd/windowMs serait une
		// division par zéro au premier record (revue T22 — rejeter à la
		// configuration, pas paniquer au runtime).
		return nil, ErrWindowInvalid
	}
	me := opts.MaxEntities
	if me == 0 {
		me = defaultMaxEntities
	}
	if me < 0 {
		return nil, ErrMaxEntitiesInvalid
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Detector{
		cellID:  opts.CellID,
		salt:    opts.Salt,
		leaves:  opts.Leaves,
		params:  opts.Params,
		paramsH: paramsHash(opts.Params, w.Milliseconds()),
		window:  w,
		maxEnt:  me,
		now:     now,
		onAlert: opts.OnAlert,
		onTrip:  opts.OnTrip,

		watermark: -1,
		entities:  make(map[string]*entityProfile),
	}, nil
}

// Stats retourne un instantané des compteurs (atomique).
func (d *Detector) Stats() DetectorStats {
	return DetectorStats{
		RecordsIn:       atomic.LoadUint64(&d.stats.RecordsIn),
		LateRecords:     atomic.LoadUint64(&d.stats.LateRecords),
		Evaluations:     atomic.LoadUint64(&d.stats.Evaluations),
		Alerts:          atomic.LoadUint64(&d.stats.Alerts),
		AlertFailures:   atomic.LoadUint64(&d.stats.AlertFailures),
		EntitiesCreated: atomic.LoadUint64(&d.stats.EntitiesCreated),
		EntitiesDropped: atomic.LoadUint64(&d.stats.EntitiesDropped),
	}
}

// Feed intègre un record de télémétrie (couture RecordSink, D27). La
// destination est hachée à l'arrivée — jamais conservée en clair (D28).
// Les octets alimentent le créneau minute du record ; le watermark
// scelle les créneaux clos et déclenche l'évaluation (D29/D30).
func (d *Detector) Feed(r Record) error {
	if r.OctetDelta == 0 {
		return nil // rien à apprendre d'un delta nul (cohérent avec T21, §4.3)
	}
	if r.FlowEnd <= 0 {
		atomic.AddUint64(&d.stats.LateRecords, 1)
		return nil
	}
	atomic.AddUint64(&d.stats.RecordsIn, 1)
	wms := d.window.Milliseconds()
	m := r.FlowEnd / wms
	h := hashDestination(d.salt, r.Resource)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.watermark < 0 {
		d.watermark = m
	}
	var firstErr error
	if m > d.watermark {
		// Les minutes ≤ m−1 sont closes : avancer les EMAs et évaluer au
		// créneau scellé le plus récent (simplification documentée).
		firstErr = d.sealLocked(m - 1)
		d.watermark = m
	}
	if m <= d.watermark-ring24Slots {
		// Créneau sorti de l'anneau : compter, ne jamais réécrire le
		// passé (un record tardif ne modifie pas une preuve scellée).
		atomic.AddUint64(&d.stats.LateRecords, 1)
		return firstErr
	}

	key := string(h[:])
	p, ok := d.entities[key]
	if !ok {
		if len(d.entities) >= d.maxEnt {
			// Jamais d'éviction (vecteur d'évasion) : on refuse de
			// suivre, on compte et on alarme (§5.3).
			atomic.AddUint64(&d.stats.EntitiesDropped, 1)
			if d.onTrip != nil {
				d.onTrip(ReasonEntitiesFull)
			}
			return firstErr
		}
		p = newEntityProfile()
		d.entities[key] = p
		atomic.AddUint64(&d.stats.EntitiesCreated, 1)
	}
	p.add(m, r.OctetDelta)
	return firstErr
}

// Flush force l'évaluation au watermark courant (arrêt, fin de test) :
// la dernière minute entamée est évaluée sans attendre un record futur.
func (d *Detector) Flush() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.watermark < 0 {
		return nil
	}
	return d.sealLocked(d.watermark)
}

// add écrit les octets dans les anneaux. Chaque créneau est DATÉ : une
// valeur portée par le même slot il y a 1440 minutes (ou 168 heures)
// est périmée — elle est défalquée de la somme courante avant réécriture.
func (p *entityProfile) add(minute int64, bytes uint64) {
	s := int(minute % ring24Slots)
	if p.slotMin[s] != minute {
		if p.slotMin[s] >= 0 {
			p.sum24 -= p.ring24[s]
		}
		p.ring24[s] = 0
		p.slotMin[s] = minute
	}
	p.ring24[s] += bytes
	p.sum24 += bytes

	// Les minutes s'accumulent dans l'heure courante ; au changement
	// d'heure, on verse le seau dans l'anneau 7 j (même discipline).
	h := minute / 60
	if p.curHour >= 0 && h != p.curHour {
		p.commitHour()
	}
	p.curHour = h
	p.curHourBytes += bytes
}

// commitHour verse l'heure courante dans l'anneau 7 j.
func (p *entityProfile) commitHour() {
	s := int(p.curHour % ring7Slots)
	if p.slotHour[s] != p.curHour {
		if p.slotHour[s] >= 0 {
			p.sum7 -= p.ring7[s]
		}
		p.ring7[s] = 0
		p.slotHour[s] = p.curHour
	}
	p.ring7[s] += p.curHourBytes
	p.sum7 += p.curHourBytes
	p.curHourBytes = 0
}

// sealLocked avance toutes les entités à la minute t et évalue celles
// encore actives. Itération par clés TRIÉES (§11.3 : l'ordre de parcours
// d'une map Go est aléatoire — l'ordre des feuilles d'alerte ne doit pas
// l'être).
func (d *Detector) sealLocked(t int64) error {
	keys := make([]string, 0, len(d.entities))
	for k := range d.entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var firstErr error
	for _, k := range keys {
		p := d.entities[k]
		if p.sum24 == 0 && p.emaFast == 0 {
			// Dormant : réinitialiser le réchauffement du signal de
			// dérive — une REPRISE après accalmie part d'EMAs nulles et
			// ressemblerait sinon à une dérive (ratio instable à ~0).
			// lastEval = t−1 : la minute t sera intégrée au prochain
			// scellement si l'entité reprend.
			p.seen = 0
			p.lastEval = t - 1
			continue
		}
		p.advanceEMA(t)
		atomic.AddUint64(&d.stats.Evaluations, 1)
		if err := d.evaluate(t, k, p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// advanceEMA intègre les minutes (lastEval, t] aux EMAs — x = octets du
// créneau (0 si vide). Au-delà de 1440 minutes de vide, les EMAs sont
// mathématiquement retombées à ~0 ((7/8)^1440 < 2^-200) : on les remet
// à zéro plutôt que de boucler (borné, D29).
func (p *entityProfile) advanceEMA(t int64) {
	if p.lastEval < 0 {
		p.lastEval = t
		return
	}
	gap := t - p.lastEval
	if gap <= 0 {
		return
	}
	if gap > ring24Slots {
		p.emaFast, p.emaSlow = 0, 0
		p.seen = 0         // renaissance : le signal de dérive se réchauffe à nouveau
		p.lastEval = t - 1 // la minute t est intégrée ci-dessous
		gap = 1
	}
	for j := t - gap + 1; j <= t; j++ {
		x := p.bytesAt(j) * 1000 // point fixe
		p.emaFast = (x + (emaFastDen-1)*p.emaFast) / emaFastDen
		p.emaSlow = (x + (emaSlowDen-1)*p.emaSlow) / emaSlowDen
		p.seen++
	}
	p.lastEval = t
}

// bytesAt lit les octets d'un créneau minute (0 si vide ou périmé).
func (p *entityProfile) bytesAt(minute int64) uint64 {
	s := int(minute % ring24Slots)
	if p.slotMin[s] == minute {
		return p.ring24[s]
	}
	return 0
}

// evaluate calcule les signaux au créneau t (scans bornés 1440+168, sommes
// fraîches — les créneaux périmés non réécrits sont exclus par leur date),
// compose le score versionné et applique l'hystérésis (D30/D31).
func (d *Detector) evaluate(t int64, key string, p *entityProfile) error {
	minMinute := t - ring24Slots + 1
	var sum24 uint64
	var active int
	for s := 0; s < ring24Slots; s++ {
		if mm := p.slotMin[s]; mm >= minMinute && mm <= t {
			sum24 += p.ring24[s]
			if p.ring24[s] > 0 {
				active++
			}
		}
	}
	p.sum24 = sum24 // resynchronisation de la somme courante
	if sum24 == 0 && p.emaFast == 0 {
		p.seen = 0 // dormance constatée sur sommes fraîches
	}

	hourNow := t / 60
	minHour := hourNow - ring7Slots + 1
	var sum7 uint64
	for s := 0; s < ring7Slots; s++ {
		if hh := p.slotHour[s]; hh >= minHour && hh <= hourNow {
			sum7 += p.ring7[s]
		}
	}
	if p.curHour >= minHour && p.curHour <= hourNow {
		sum7 += p.curHourBytes // l'heure en cours n'est pas encore versée
	}
	p.sum7 = sum7

	pm := d.params
	var sig uint8
	if sum24 > pm.ByteThreshold24h || sum7 > pm.ByteThreshold7d {
		sig |= sigBytes
	}
	if active >= pm.MinActiveWindows && sum24 > 0 {
		mean := sum24 / uint64(active)
		if mean > 0 {
			// Écart absolu moyen / moyenne (per-mille) — entier, pas de
			// math ni de carré (borné par la somme, jamais de débordement).
			var dev uint64
			for s := 0; s < ring24Slots; s++ {
				if mm := p.slotMin[s]; mm >= minMinute && mm <= t && p.ring24[s] > 0 {
					v := p.ring24[s]
					if v > mean {
						dev += v - mean
					} else {
						dev += mean - v
					}
				}
			}
			if mad := dev / uint64(active); mad*1000/mean < uint64(pm.JitterMaxPerMille) {
				sig |= sigRegularity
			}
		}
		// EMAs « établies » exigées (≥ 4× la constante de temps lente) :
		// sans ce réchauffement, la montée en régime initiale de TOUTE
		// entité nouvelle ressemblerait à une dérive (faux positif de
		// naissance — l'EMA rapide converge avant la lente).
		if p.seen >= 4*emaSlowDen && p.emaSlow > 0 &&
			p.emaFast*1000 > p.emaSlow*uint64(1000+pm.DriftPerMille) {
			sig |= sigDrift
		}
	}

	var score uint16
	if sig&sigBytes != 0 {
		score += pm.WBytes
	}
	if sig&sigRegularity != 0 {
		score += pm.WRegularity
	}
	if sig&sigDrift != 0 {
		score += pm.WDrift
	}

	if p.alerted && int(score) < int(pm.AlertThreshold)-int(pm.HysteresisPerMille) {
		p.alerted = false // réarmement par hystérésis (D31)
	}
	if !p.alerted && score >= pm.AlertThreshold {
		return d.fireAlert(t, key, p, score, sig, sum24, sum7)
	}
	return nil
}

// fireAlert écrit la feuille KindTelemetryAlert (manifeste « TBAD1 »
// hashé+salé — rien en clair) puis appelle OnAlert. L'échec d'écriture
// est une erreur propagée + alarme (§9.1) : jamais d'alerte sans trace.
func (d *Detector) fireAlert(t int64, key string, p *entityProfile, score uint16, sig uint8, sum24, sum7 uint64) error {
	var dstHash [32]byte
	copy(dstHash[:], key)

	a := Alert{
		DstHash:  dstHash,
		WindowID: t,
		Score:    score,
		Signals:  sig,
		Sum24h:   sum24,
		Sum7d:    sum7,
	}
	manifest := alertManifest(d.cellID, d.params.Version, a, p.emaFast, p.emaSlow, d.paramsH, d.now().UnixMilli())
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetryAlert,
		CellID:      d.cellID,
		PayloadHash: registry.HashPayload(d.salt, manifest),
		Timestamp:   d.now().UnixNano(),
	}
	if _, err := d.leaves.Append(context.Background(), leaf); err != nil {
		atomic.AddUint64(&d.stats.AlertFailures, 1)
		if d.onTrip != nil {
			d.onTrip(pep.ReasonLeafWriteFailed)
		}
		return err
	}
	p.alerted = true
	atomic.AddUint64(&d.stats.Alerts, 1)
	if d.onAlert != nil {
		d.onAlert(a)
	}
	return nil
}

// alertManifest sérialise le manifeste « TBAD1 » (déterministe, §11.3) :
// magic ‖ version ‖ cellule ‖ dstHash ‖ fenêtre ‖ score ‖ signaux ‖
// cumuls ‖ EMAs ‖ paramsHash ‖ horodatage. C'est le seul contenu engagé
// dans la feuille — le score ET le réglage qui l'a produit (paramsHash).
func alertManifest(cellID string, version uint16, a Alert, emaFast, emaSlow uint64, paramsH [32]byte, atMs int64) []byte {
	buf := []byte("TBAD1")
	buf = binary.BigEndian.AppendUint16(buf, version)
	buf = append(buf, byte(len(cellID)))
	buf = append(buf, cellID...)
	buf = append(buf, a.DstHash[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(a.WindowID))
	buf = binary.BigEndian.AppendUint16(buf, a.Score)
	buf = append(buf, a.Signals)
	buf = binary.BigEndian.AppendUint64(buf, a.Sum24h)
	buf = binary.BigEndian.AppendUint64(buf, a.Sum7d)
	buf = binary.BigEndian.AppendUint64(buf, emaFast)
	buf = binary.BigEndian.AppendUint64(buf, emaSlow)
	buf = append(buf, paramsH[:]...)
	buf = binary.BigEndian.AppendUint64(buf, uint64(atMs))
	return buf
}
