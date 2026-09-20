package telemetry

// Tests du détecteur anti-dribble (T23).
//
// Couverture du critère d'acceptation de l'issue #25 :
//   - une exfiltration drip-feed simulée (N sessions, chacune SOUS son
//     quota passeport) est détectée sur métadonnées seules — y compris
//     en bout en bout via l'exporteur T21 réel → FanOut → détecteur ;
//   - le taux de faux positifs sur un trafic légitime simulé est mesuré
//     (TestLegitTrafficFalsePositiveRate) et documenté ;
//   - chaque alerte est une feuille KindTelemetryAlert hash-only ;
//   - le composite de score est versionné : un changement de version des
//     paramètres change les feuilles (TestAlertLeafIsVersioned).

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// t23Params : seuils réduits pour des simulations rapides (le défaut
// DefaultScoreParams vise 1 Gio/j — inutilisable en test de quelques
// centaines de créneaux).
func t23Params() ScoreParams {
	p := DefaultScoreParams()
	p.ByteThreshold24h = 50_000
	p.ByteThreshold7d = 200_000
	p.MinActiveWindows = 30
	return p
}

func newTestDetector(t *testing.T, leaves *leafRecorder, trips *tripRecorder, alerts *[]Alert, params ScoreParams, maxEnt int) *Detector {
	t.Helper()
	opts := DetectorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves,
		Params: params, Window: time.Second, MaxEntities: maxEnt,
		Now: func() time.Time { return time.UnixMilli(1_700_000_000_000) },
	}
	if trips != nil {
		opts.OnTrip = trips.trip
	}
	if alerts != nil {
		opts.OnAlert = func(a Alert) { *alerts = append(*alerts, a) }
	}
	d, err := NewDetector(opts)
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	return d
}

// dripRecord construit un record de flux pour le créneau k (grille 1 s).
func dripRecord(b byte, dst string, octets uint64, k int64) Record {
	return Record{
		JTI: jtiOf(b), CellID: "cell-alpha-01", Resource: dst, Operation: "op",
		OctetDelta: octets, FlowStart: k * 1000, FlowEnd: (k + 1) * 1000,
	}
}

// feedDrip simule `sessions` sessions distinctes envoyant chacune
// `perSession` octets par créneau vers dst, des créneaux start à
// start+minutes−1 — chaque session reste sous n'importe quel quota
// individuel plausible ; c'est l'AGRÉGAT vers la destination qui dépasse.
func feedDrip(t *testing.T, d *Detector, dst string, sessions int, perSession uint64, start, minutes int64) {
	t.Helper()
	for k := start; k < start+minutes; k++ {
		for s := 0; s < sessions; s++ {
			if err := d.Feed(dripRecord(byte(s+1), dst, perSession, k)); err != nil {
				t.Fatalf("Feed créneau %d session %d: %v", k, s, err)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Configuration fail-closed (D32) — dont le cas « positif mais sous-
// milliseconde » de la revue T22.
// ---------------------------------------------------------------------------

func TestDetectorOptionsFailClosed(t *testing.T) {
	leaves := &leafRecorder{}
	base := DetectorOptions{
		CellID: "cell-alpha-01", Salt: t22Salt, Leaves: leaves,
		Params: t23Params(), Window: time.Second, MaxEntities: 8,
	}
	if _, err := NewDetector(base); err != nil {
		t.Fatalf("configuration de base refusée: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*DetectorOptions)
		want   error
	}{
		{"cellID manquant", func(o *DetectorOptions) { o.CellID = "" }, ErrCellIDRequired},
		{"sel trop court", func(o *DetectorOptions) { o.Salt = make([]byte, 8) }, ErrSaltTooShort},
		{"registre manquant", func(o *DetectorOptions) { o.Leaves = nil }, ErrLeavesRequired},
		{"version nulle", func(o *DetectorOptions) { o.Params.Version = 0 }, ErrParamsInvalid},
		{"seuil 24h nul", func(o *DetectorOptions) { o.Params.ByteThreshold24h = 0 }, ErrParamsInvalid},
		{"seuil 7j nul", func(o *DetectorOptions) { o.Params.ByteThreshold7d = 0 }, ErrParamsInvalid},
		{"présence minimale nulle", func(o *DetectorOptions) { o.Params.MinActiveWindows = 0 }, ErrParamsInvalid},
		{"présence > anneau", func(o *DetectorOptions) { o.Params.MinActiveWindows = ring24Slots + 1 }, ErrParamsInvalid},
		{"jitter nul", func(o *DetectorOptions) { o.Params.JitterMaxPerMille = 0 }, ErrParamsInvalid},
		{"jitter > 1000", func(o *DetectorOptions) { o.Params.JitterMaxPerMille = 1001 }, ErrParamsInvalid},
		{"poids > 1000", func(o *DetectorOptions) {
			o.Params.WBytes, o.Params.WRegularity, o.Params.WDrift = 600, 300, 200
		}, ErrParamsInvalid},
		{"seuil d'alerte nul", func(o *DetectorOptions) { o.Params.AlertThreshold = 0 }, ErrParamsInvalid},
		{"seuil d'alerte > 1000", func(o *DetectorOptions) { o.Params.AlertThreshold = 1001 }, ErrParamsInvalid},
		{"hystérésis ≥ seuil", func(o *DetectorOptions) { o.Params.HysteresisPerMille = o.Params.AlertThreshold }, ErrParamsInvalid},
		{"fenêtre sous-milliseconde", func(o *DetectorOptions) { o.Window = 500 * time.Microsecond }, ErrWindowInvalid},
		{"borne d'entités négative", func(o *DetectorOptions) { o.MaxEntities = -1 }, ErrMaxEntitiesInvalid},
	}
	for _, tc := range cases {
		opts := base
		tc.mutate(&opts)
		if _, err := NewDetector(opts); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, attendu %v", tc.name, err, tc.want)
		}
	}

	// un FanOut vide est une erreur de configuration (fail-closed) :
	// les records ne doivent pas tomber dans un puits silencieux.
	if err := (FanOut{}).Feed(dripRecord(1, "dst", 10, 0)); !errors.Is(err, ErrSinkRequired) {
		t.Errorf("FanOut vide: err = %v, attendu ErrSinkRequired", err)
	}
}

// ---------------------------------------------------------------------------
// Critère d'acceptation : drip-feed simulé détecté sur métadonnées seules.
// 8 sessions × 12 octets/créneau — chacune très sous tout quota ; l'agrégat
// vers la destination croise 50 000 octets au créneau 520.
// ---------------------------------------------------------------------------

func TestDripFeedDetected(t *testing.T) {
	leaves := &leafRecorder{}
	var alerts []Alert
	d := newTestDetector(t, leaves, &tripRecorder{}, &alerts, t23Params(), 0)

	feedDrip(t, d, "exfil.slow-leak.example", 8, 12, 0, 601)
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if len(alerts) != 1 {
		t.Fatalf("alertes = %d, attendu 1 (hystérésis : pas de spam)", len(alerts))
	}
	a := alerts[0]
	// l'entité est la destination HACHÉE — jamais en clair
	if a.DstHash != hashDestination(t22Salt, "exfil.slow-leak.example") {
		t.Errorf("dstHash ≠ sha256(sel ‖ destination)")
	}
	// cumul + régularité (96 octets/créneau constants : ÉAM = 0) ;
	// pas de dérive (rythme constant : EMA rapide == lente)
	if a.Signals != sigBytes|sigRegularity {
		t.Errorf("signaux = %08b, attendu cumul+régularité", a.Signals)
	}
	if a.Score != 800 {
		t.Errorf("score = %d, attendu 800 (500 cumul + 300 régularité)", a.Score)
	}
	if a.Sum24h <= t23Params().ByteThreshold24h {
		t.Errorf("sum24h = %d sous le seuil — alerte immotivée", a.Sum24h)
	}

	// l'alerte est une feuille KindTelemetryAlert hash-only, dont le
	// payload est EXACTEMENT l'engagement du manifeste TBAD1 recomputé
	if len(leaves.leaves) != 1 {
		t.Fatalf("feuilles = %d, attendu 1", len(leaves.leaves))
	}
	leaf := leaves.leaves[0]
	if leaf.Kind != registry.KindTelemetryAlert {
		t.Errorf("kind = %d, attendu KindTelemetryAlert", leaf.Kind)
	}
	p := d.entities[string(a.DstHash[:])]
	want := registry.HashPayload(t22Salt, alertManifest(
		"cell-alpha-01", t23Params().Version, a, p.emaFast, p.emaSlow,
		paramsHash(t23Params(), 1000), 1_700_000_000_000))
	if leaf.PayloadHash != want {
		t.Errorf("payload ≠ hash salé du manifeste recomputé")
	}
	if leaf.PayloadHash == [32]byte{} {
		t.Errorf("payload hash nul")
	}
}

// ---------------------------------------------------------------------------
// Bout en bout : exporteur T21 réel → FanOut[agrégateur T22, détecteur].
// ---------------------------------------------------------------------------

func TestDripFeedEndToEndExporterPipeline(t *testing.T) {
	src := &fakeSource{sessions: []Session{}}
	for s := 0; s < 8; s++ {
		src.sessions = append(src.sessions, Session{
			JTI: jtiOf(byte(s + 1)), Resource: "exfil.slow-leak.example",
			Operation: "egress", Consumed: 0,
		})
	}
	nowMs := &atomic.Int64{}
	nowMs.Store(1_700_000_000_000)
	leaves := &leafRecorder{}
	var alerts []Alert
	agg := newTestAgg(t, leaves, nil, nowMs, time.Second)
	d := newTestDetector(t, leaves, &tripRecorder{}, &alerts, t23Params(), 0)

	// le tee D27 : un seul fil, deux consommateurs
	e := newTestExporter(src, FanOut{agg, d}, nowMs)

	// 550 cycles d'une seconde ; chaque session consomme 12 octets/cycle
	for k := 0; k < 550; k++ {
		for i := range src.sessions {
			src.sessions[i].Consumed += 12
		}
		e.ExportOnce()
		nowMs.Add(1000)
		if err := agg.Tick(); err != nil {
			t.Fatalf("Tick: %v", err)
		}
	}

	if len(alerts) != 1 {
		t.Fatalf("alertes = %d, attendu 1 (dribble détecté via le pipeline réel)", len(alerts))
	}
	if alerts[0].DstHash != hashDestination(t22Salt, "exfil.slow-leak.example") {
		t.Errorf("mauvaise entité alertée")
	}
	// l'agrégateur a continué de feuilleter chaque fenêtre en parallèle
	if st := agg.Stats(); st.LeavesWritten < 549 {
		t.Errorf("fenêtres agrégées = %d — le tee prive l'agrégateur", st.LeavesWritten)
	}
	// et le registre contient les DEUX types de feuilles
	var kind2, kind6 int
	for _, l := range leaves.leaves {
		switch l.Kind {
		case registry.KindTelemetry:
			kind2++
		case registry.KindTelemetryAlert:
			kind6++
		}
	}
	if kind2 < 549 || kind6 != 1 {
		t.Errorf("feuilles : %d télémétrie / %d alerte", kind2, kind6)
	}
}

// ---------------------------------------------------------------------------
// Critère d'acceptation : taux de faux positifs MESURÉ sur trafic légitime
// simulé — 32 destinations, trafic « heures ouvrées » fortement variable
// (ÉAM/moyenne ≈ 35 %, très au-dessus du seuil de régularité de 20 %),
// cumul journalier sous le seuil. Résultat attendu et mesuré : 0/32.
// ---------------------------------------------------------------------------

func TestLegitTrafficFalsePositiveRate(t *testing.T) {
	leaves := &leafRecorder{}
	var alerts []Alert
	d := newTestDetector(t, leaves, &tripRecorder{}, &alerts, t23Params(), 0)

	const entities = 32
	const days = 2 // 2880 créneaux — l'anneau 24 h boucle complètement
	for k := int64(0); k < 1440*days; k++ {
		hourOfDay := (k / 60) % 24
		if hourOfDay < 8 || hourOfDay >= 18 {
			continue // nuits et soirées creuses
		}
		for i := 0; i < entities; i++ {
			// volume déterministe fortement variable (20..119 octets)
			x := uint64((k*2654435761 + int64(i)*97) % 1000)
			bytes := 20 + x%100
			dst := "service-" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".internal"
			if err := d.Feed(dripRecord(byte(i+1), dst, bytes, k)); err != nil {
				t.Fatalf("Feed: %v", err)
			}
		}
	}
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// mesure documentée : alertes / entités légitimes
	fp := len(alerts)
	t.Logf("taux de faux positifs mesuré : %d/%d (%.2f %%) — trafic légitime simulé, 2 jours, 32 destinations",
		fp, entities, 100*float64(fp)/entities)
	if fp != 0 {
		t.Errorf("faux positifs = %d, attendu 0 avec les paramètres par défaut", fp)
	}
	if st := d.Stats(); st.EntitiesCreated != entities {
		t.Errorf("entités suivies = %d, attendu %d", st.EntitiesCreated, entities)
	}
}

// ---------------------------------------------------------------------------
// Composite versionné : changer Version change les feuilles (critère
// d'acceptation) ; à version égale, les feuilles sont identiques (§11.3).
// ---------------------------------------------------------------------------

func TestAlertLeafIsVersioned(t *testing.T) {
	run := func(version uint16) [32]byte {
		leaves := &leafRecorder{}
		p := t23Params()
		p.Version = version
		d := newTestDetector(t, leaves, &tripRecorder{}, nil, p, 0)
		feedDrip(t, d, "exfil.slow-leak.example", 8, 12, 0, 601)
		if err := d.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		if len(leaves.leaves) != 1 {
			t.Fatalf("feuilles = %d, attendu 1", len(leaves.leaves))
		}
		return leaves.leaves[0].PayloadHash
	}
	v1, v1bis, v2 := run(1), run(1), run(2)
	if v1 != v1bis {
		t.Error("même trafic, même version ⇒ feuilles différentes (§11.3)")
	}
	if v1 == v2 {
		t.Error("changement de version invisible dans les feuilles — le réglage doit être auditable")
	}
}

// ---------------------------------------------------------------------------
// Déterminisme multi-entités (§11.3) : l'itération triée du scellement
// garantit le même ordre de feuilles quel que soit l'ordre interne des maps.
// ---------------------------------------------------------------------------

func TestDeterministicDetection(t *testing.T) {
	run := func() []registry.Leaf {
		leaves := &leafRecorder{}
		p := t23Params()
		p.ByteThreshold24h = 20_000 // plusieurs entités alertent
		d := newTestDetector(t, leaves, &tripRecorder{}, nil, p, 0)
		for k := int64(0); k < 400; k++ {
			// ordre d'arrivée fixe mais entrelacé entre 5 destinations
			for s := 0; s < 5; s++ {
				dst := "dst-" + string(rune('a'+(k+int64(s))%5)) + ".example"
				if err := d.Feed(dripRecord(byte(s+1), dst, 60, k)); err != nil {
					t.Fatalf("Feed: %v", err)
				}
			}
		}
		if err := d.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		return leaves.leaves
	}
	a, b := run(), run()
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("feuilles = %d / %d", len(a), len(b))
	}
	for i := range a {
		if a[i].PayloadHash != b[i].PayloadHash || a[i].Kind != b[i].Kind {
			t.Fatalf("feuille %d diverge entre deux runs", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Hystérésis : un épisode continu = une feuille ; le réarmement sous
// seuil−hystérésis permet l'alerte de l'épisode suivant.
// ---------------------------------------------------------------------------

func TestHysteresisRearm(t *testing.T) {
	leaves := &leafRecorder{}
	var alerts []Alert
	d := newTestDetector(t, leaves, &tripRecorder{}, &alerts, t23Params(), 0)

	feedDrip(t, d, "exfil.slow-leak.example", 8, 12, 0, 700)
	// épisode continu : le créneau 700 scelle sans nouvelle alerte
	if err := d.Feed(dripRecord(9, "heartbeat.internal", 1, 700)); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alertes après 1er épisode = %d, attendu 1", len(alerts))
	}

	// accalmie : le heartbeat seul fait avancer le watermark 1500 créneaux —
	// l'anneau 24 h se vide, le score retombe sous seuil−hystérésis
	for k := int64(701); k < 701+1500; k++ {
		if err := d.Feed(dripRecord(9, "heartbeat.internal", 1, k)); err != nil {
			t.Fatalf("Feed: %v", err)
		}
	}
	// re-dribble : l'alerte doit se réarmer et REFEUILLETER
	feedDrip(t, d, "exfil.slow-leak.example", 8, 12, 2201, 700)
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("alertes après 2e épisode = %d, attendu 2 (réarmement)", len(alerts))
	}
	// le heartbeat (1 octet/créneau, cumul 24 h = 1440) n'a JAMAIS alerté
	for _, a := range alerts {
		if a.DstHash == hashDestination(t22Salt, "heartbeat.internal") {
			t.Error("faux positif sur le heartbeat")
		}
	}
}

// ---------------------------------------------------------------------------
// Dérive seule : rampe 10 → 60 octets/créneau sous le seuil de cumul ;
// poids cumul/régularité à zéro — seul le signal de dérive compose le score.
// ---------------------------------------------------------------------------

func TestDriftSignalAlone(t *testing.T) {
	leaves := &leafRecorder{}
	var alerts []Alert
	p := t23Params()
	p.ByteThreshold24h = 1 << 40 // jamais atteint dans ce scénario
	p.ByteThreshold7d = 1 << 40
	p.WBytes, p.WRegularity = 0, 0
	p.WDrift = 600
	d := newTestDetector(t, leaves, &tripRecorder{}, &alerts, p, 0)

	for k := int64(0); k < 600; k++ {
		if err := d.Feed(dripRecord(1, "ramp.example", 10, k)); err != nil {
			t.Fatalf("Feed: %v", err)
		}
	}
	if len(alerts) != 0 {
		t.Fatalf("alerte prématurée avant la rampe")
	}
	for k := int64(600); k < 900; k++ {
		if err := d.Feed(dripRecord(1, "ramp.example", 60, k)); err != nil {
			t.Fatalf("Feed: %v", err)
		}
	}
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alertes = %d, attendu 1 (dérive détectée seule)", len(alerts))
	}
	if alerts[0].Signals&sigDrift == 0 || alerts[0].Signals&sigBytes != 0 {
		t.Errorf("signaux = %08b — dérive attendue, cumul exclu", alerts[0].Signals)
	}
	if alerts[0].Score != 600 {
		t.Errorf("score = %d, attendu 600 (seul le poids dérive compose)", alerts[0].Score)
	}
}

// ---------------------------------------------------------------------------
// Map pleine : jamais d'éviction silencieuse — refus compté et alarmé.
// ---------------------------------------------------------------------------

func TestEntityOverflowAlarmed(t *testing.T) {
	leaves := &leafRecorder{}
	trips := &tripRecorder{}
	d := newTestDetector(t, leaves, trips, nil, t23Params(), 2)

	for i, dst := range []string{"a.example", "b.example", "c.example"} {
		if err := d.Feed(dripRecord(byte(i+1), dst, 10, 0)); err != nil {
			t.Fatalf("Feed %s: %v", dst, err)
		}
	}
	st := d.Stats()
	if st.EntitiesCreated != 2 {
		t.Errorf("entités suivies = %d, attendu 2 (la borne)", st.EntitiesCreated)
	}
	if st.EntitiesDropped != 1 {
		t.Errorf("entités refusées = %d, attendu 1", st.EntitiesDropped)
	}
	if len(trips.reasons) != 1 || trips.reasons[0] != ReasonEntitiesFull {
		t.Errorf("alarmes = %v, attendu [%s]", trips.reasons, ReasonEntitiesFull)
	}
}

// ---------------------------------------------------------------------------
// Records tardifs : hors de l'anneau vivant ⇒ comptés, jamais réécrits
// dans une preuve scellée. Delta nul ⇒ ignoré (§4.3).
// ---------------------------------------------------------------------------

func TestLateAndZeroRecordsCounted(t *testing.T) {
	leaves := &leafRecorder{}
	d := newTestDetector(t, leaves, &tripRecorder{}, nil, t23Params(), 0)

	if err := d.Feed(dripRecord(1, "dst.example", 10, 5000)); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if err := d.Feed(dripRecord(1, "dst.example", 10, 1)); err != nil { // créneau 1 ≪ 5000−1440
		t.Fatalf("Feed tardif: %v", err)
	}
	if err := d.Feed(dripRecord(1, "dst.example", 0, 5001)); err != nil { // delta nul
		t.Fatalf("Feed delta nul: %v", err)
	}
	st := d.Stats()
	if st.LateRecords != 1 {
		t.Errorf("tardifs = %d, attendu 1", st.LateRecords)
	}
	if st.RecordsIn != 2 { // le delta nul n'entre pas dans les stats de fil
		t.Errorf("records = %d, attendu 2", st.RecordsIn)
	}
	if len(d.entities) != 1 {
		t.Errorf("entités = %d, attendu 1 (le tardif n'en crée pas)", len(d.entities))
	}
}

// ---------------------------------------------------------------------------
// Une alerte qui ne peut pas laisser de trace est une erreur (§9.1) :
// Feed propage l'erreur du registre, l'alarme part, rien n'est marqué
// « alerté » — la tentative sera refaite au prochain créneau.
// ---------------------------------------------------------------------------

func TestAlertWriteFailurePropagates(t *testing.T) {
	leaves := &leafRecorder{err: errors.New("registre en panne")}
	trips := &tripRecorder{}
	d := newTestDetector(t, leaves, trips, nil, t23Params(), 0)

	var feedErr error
	for k := int64(0); k < 601 && feedErr == nil; k++ {
		for s := 0; s < 8; s++ {
			if err := d.Feed(dripRecord(byte(s+1), "exfil.slow-leak.example", 12, k)); err != nil && feedErr == nil {
				feedErr = err
			}
		}
	}
	if feedErr == nil {
		t.Fatal("aucune erreur propagée alors que le registre refuse la feuille d'alerte")
	}
	st := d.Stats()
	if st.AlertFailures == 0 {
		t.Error("AlertFailures = 0")
	}
	if st.Alerts != 0 {
		t.Errorf("Alerts = %d — une alerte non tracée ne compte pas", st.Alerts)
	}
	if len(trips.reasons) == 0 || trips.reasons[0] != pep.ReasonLeafWriteFailed {
		t.Errorf("alarmes = %v, attendu %s", trips.reasons, pep.ReasonLeafWriteFailed)
	}
	// l'état hystérésis n'a pas été consommé : la panne ne masque pas l'épisode
	dh := hashDestination(t22Salt, "exfil.slow-leak.example")
	p := d.entities[string(dh[:])]
	if p.alerted {
		t.Error("alerted=true alors que la feuille n'a jamais été écrite")
	}
}

// ---------------------------------------------------------------------------
// Cellule silencieuse : aucun record ⇒ aucune alerte, aucune feuille,
// Flush sans effet. Le silence ne produit pas de bruit (§5.3 à l'envers :
// le détecteur ne s'invente pas de signal).
// ---------------------------------------------------------------------------

func TestSilentCellNoAlerts(t *testing.T) {
	leaves := &leafRecorder{}
	d := newTestDetector(t, leaves, &tripRecorder{}, nil, t23Params(), 0)
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(leaves.leaves) != 0 {
		t.Errorf("feuilles = %d sur cellule silencieuse", len(leaves.leaves))
	}
	if st := d.Stats(); st.Evaluations != 0 || st.Alerts != 0 {
		t.Errorf("stats = %+v sur cellule silencieuse", st)
	}
}

// ---------------------------------------------------------------------------
// La feuille d'alerte (kind 6) passe le marshalling du registre — le
// format T4 accepte le nouveau kind de façon additive.
// ---------------------------------------------------------------------------

func TestAlertLeafMarshalsThroughRegistry(t *testing.T) {
	leaves := &leafRecorder{}
	d := newTestDetector(t, leaves, &tripRecorder{}, nil, t23Params(), 0)
	feedDrip(t, d, "exfil.slow-leak.example", 8, 12, 0, 601)
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if len(leaves.leaves) != 1 {
		t.Fatalf("feuilles = %d", len(leaves.leaves))
	}
	raw, err := leaves.leaves[0].Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := registry.UnmarshalLeaf(raw)
	if err != nil {
		t.Fatalf("UnmarshalLeaf: %v", err)
	}
	if back.Kind != registry.KindTelemetryAlert || back.PayloadHash != leaves.leaves[0].PayloadHash {
		t.Errorf("round-trip feuille d'alerte incohérent")
	}
}
