// scenarios.go — T28 (issue #28) : campagne red-team P2 « Michel » (§13),
// scénarios exécutés in-process contre les composants RÉELS (D92).
//
// Doctrine : zéro action dangereuse non journalisée. Chaque scénario
// attaque un mécanisme §8, vérifie qu'il a tenu, et laisse ses feuilles
// dans le registre réel du run (comptées par scénario via countingSink,
// recoupées au scan ChainWatcher — D93/D94). Les mutations M-* (garde-
// fous) sont prouvées létales par runner_test.go : un scénario qui passe
// mécanisme cassé ne protège rien (D95).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	telemetry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/telemetry"
)

// Config paramètre la campagne. Fail-closed : Validate rejette toute
// configuration incomplète.
type Config struct {
	OutDir string
	CellID string

	FloodUp   int // S5 phase A — requêtes concurrentes, OPA sain
	FloodDown int // S5 phase B — requêtes après la chute d'OPA

	// Mutations M-* — garde-fous (D95), exercés par runner_test.go.
	MutDetectorDeaf       bool // M-S4 : seuil d'alerte muté au maximum légal (détecteur sourd)
	MutSilentFlood        bool // M-S5 : puits mutant — succès sans écriture (trou silencieux)
	MutAcceptDeviation    bool // M-S6 : gate mutant — avale les déviations de plan
	MutCanarySelfMeasured bool // M-S7 : fenêtre mesurée par le canari (interdit §7.4)
	MutReplayAccept       bool // M-S8 : cache anti-rejeu mutant — tout jti « nouveau »
	MutSkipQuorum         bool // M-S9 : gate mutant — accepte toute preuve de quorum
}

// DefaultConfig est le profil CI.
func DefaultConfig() Config {
	return Config{OutDir: "out", CellID: "tbp-cell-redteam", FloodUp: 120, FloodDown: 30}
}

// Validate rejette toute configuration incomplète (fail-closed).
func (c Config) Validate() error {
	if c.OutDir == "" {
		return fmt.Errorf("redteam: OutDir requis")
	}
	if c.CellID == "" {
		return fmt.Errorf("redteam: CellID requis (§6.2 : feuilles attribuées)")
	}
	if c.FloodUp < 8 || c.FloodDown < 2 {
		return fmt.Errorf("redteam: submersion trop faible pour prouver quoi que ce soit (up=%d down=%d)", c.FloodUp, c.FloodDown)
	}
	return nil
}

// ScenarioResult est la ligne du rapport pour un scénario.
type ScenarioResult struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Mechanism string            `json:"mechanism"`        // référence spec du mécanisme §8 attaqué
	Status    string            `json:"status"`           // executed | lab-netns | declared-hole
	Held      *bool             `json:"held,omitempty"`   // mécanisme tenu (nil = non exécuté ici)
	LeafFirst int64             `json:"leaf_first"`       // borne basse d'index (−1 = aucune)
	LeafLast  int64             `json:"leaf_last"`        // borne haute d'index (−1 = aucune)
	Leaves    map[string]uint64 `json:"leaves,omitempty"` // kind (décimal) → compte
	Detail    string            `json:"detail,omitempty"`
}

// DeclaredHole est un trou résiduel DÉCLARÉ — compté, jamais ignoré (§5.3).
type DeclaredHole struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// RunReport est la vérité de la campagne (out/run_report.json).
type RunReport struct {
	Tool          string           `json:"tool"`
	RunID         string           `json:"run_id"`
	GeneratedAt   string           `json:"generated_at"`
	Scenarios     []ScenarioResult `json:"scenarios"`
	DeclaredHoles []DeclaredHole   `json:"declared_holes"`
	// CorrelationFault porte un trou de couverture (correlate()) qu'AUCUN
	// scénario n'a pu s'attribuer (ex. feuille orpheline en toute fin de
	// registre, hors de la plage du dernier scénario exécuté) — voir Run().
	// Non vide = le rapport ment s'il affiche encore tous les scénarios
	// TENU : c'est le filet qui empêche ce cas de disparaître en silence.
	CorrelationFault string `json:"correlation_fault,omitempty"`
}

// seed32 dérive une graine Ed25519 déterministe de 32 octets à partir
// d'un label de test — reproductible, jamais un secret (clés de harnais).
func seed32(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

// scenarioFunc exécute une attaque contre un mécanisme réel. held=false
// est un résultat (mécanisme tombé) ; err est une faute de harnais.
type scenarioFunc func(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (held bool, detail string, err error)

// ---------------------------------------------------------------------------
// S4 — hotspot / 4G (§5.2) : la prévention est incompressible (canal hors
// mur) — le mécanisme est la DÉTECTION par télémétrie de métadonnées
// (T21–T23, anti-dribble). Jamais de DPI (§4.1-bis).
// ---------------------------------------------------------------------------

func scenarioHotspot(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (bool, string, error) {
	params := telemetry.ScoreParams{
		Version:            1,
		ByteThreshold24h:   500,
		ByteThreshold7d:    100000,
		MinActiveWindows:   3,
		JitterMaxPerMille:  50,
		DriftPerMille:      100,
		WBytes:             400,
		WRegularity:        400,
		WDrift:             200,
		AlertThreshold:     700,
		HysteresisPerMille: 100,
	}
	if cfg.MutDetectorDeaf {
		// M-S4 : seuil muté au maximum légal — le goutte-à-goutte (score
		// 800) passe sous un détecteur sourd. Le scénario doit le voir.
		params.AlertThreshold = 1000
	}
	var mu sync.Mutex
	var alerts []telemetry.Alert
	det, err := telemetry.NewDetector(telemetry.DetectorOptions{
		CellID: cfg.CellID, Salt: salt, Leaves: sink, Params: params,
		OnAlert: func(a telemetry.Alert) { mu.Lock(); alerts = append(alerts, a); mu.Unlock() },
	})
	if err != nil {
		return false, "", fmt.Errorf("détecteur: %w", err)
	}

	// Attaque : exfiltration goutte-à-goutte via hotspot 4G — 100 octets
	// chaque minute, 10 minutes, destination unique, rythme régulier
	// (cumul 1000 > seuil 500 → sigBytes ; jitter nul → sigRegularity).
	base := time.Now().UnixMilli()
	for m := int64(0); m < 10; m++ {
		if err := det.Feed(telemetry.Record{
			CellID: cfg.CellID, Resource: "hotspot-4g-ap",
			OctetDelta: 100,
			FlowStart:  base + m*60000,
			FlowEnd:    base + m*60000 + 59000,
		}); err != nil {
			return false, "", fmt.Errorf("feed attaque minute %d: %w", m, err)
		}
	}
	// Contrôle bénin : rafale unique d'une destination légitime (cumul au-
	// dessus du seuil d'octets mais aucune régularité — score 400 < 700).
	if err := det.Feed(telemetry.Record{
		CellID: cfg.CellID, Resource: "maj.ubuntu.example",
		OctetDelta: 5000,
		FlowStart:  base + 10*60000,
		FlowEnd:    base + 10*60000 + 59000,
	}); err != nil {
		return false, "", fmt.Errorf("feed bénin: %w", err)
	}
	if err := det.Flush(); err != nil {
		return false, "", fmt.Errorf("flush: %w", err)
	}

	mu.Lock()
	nAlerts := len(alerts)
	mu.Unlock()
	counts, _, _ := sink.snapshot()
	alertLeaves := counts[registry.KindTelemetryAlert]
	switch {
	case nAlerts == 0:
		return false, "goutte-à-goutte hotspot NON détecté — la détection §5.2 est aveugle", nil
	case nAlerts > 1:
		return false, fmt.Sprintf("%d alertes pour 1 entité attaquante — doublon ou faux positif bénin", nAlerts), nil
	case alertLeaves < 1:
		return false, "alerte sans feuille KindTelemetryAlert — détection non opposable", nil
	}
	return true, fmt.Sprintf("goutte-à-goutte détecté (score ≥ %d, 1 alerte leafée) ; rafale bénine non alertée", params.AlertThreshold), nil
}

// ---------------------------------------------------------------------------
// S5 — submersion du broker (§7, §8) : un DoS doit être alarmé, jamais un
// acte silencieusement autorisé. Phase A : submersion OPA sain — tout est
// servi ET leafé. Phase B : le sidecar OPA tombe sous la charge — fail-
// closed : zéro allow, chaque refus leafé, alarme OnTrip (T14/T11).
// ---------------------------------------------------------------------------

// silentDropper est la mutation M-S5 : déclare chaque feuille écrite sans
// rien écrire — le trou silencieux que la corrélation doit compter.
type silentDropper struct{}

func (silentDropper) Append(_ context.Context, leaf registry.Leaf) (uint64, error) { return 0, nil }

func scenarioBrokerFlood(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (bool, string, error) {
	// Sidecar OPA simulé : allow général (la politique n'est pas l'objet —
	// la tenue sous submersion l'est).
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	defer opaSrv.Close()

	var leafSink leafSinkIface = sink
	if cfg.MutSilentFlood {
		leafSink = silentDropper{} // M-S5 : feuilles « écrites » mais perdues
	}

	var muT sync.Mutex
	var trips []string
	opa, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint: opaSrv.URL, Timeout: 500 * time.Millisecond,
		CellID: cfg.CellID, Salt: salt, Leaves: leafSink,
		OnTrip: func(reason string) { muT.Lock(); trips = append(trips, reason); muT.Unlock() },
	})
	if err != nil {
		return false, "", fmt.Errorf("client OPA: %w", err)
	}
	signer, err := broker.NewDevSigner(seed32("t28/broker"))
	if err != nil {
		return false, "", fmt.Errorf("signer: %w", err)
	}
	policyID := registry.HashPayload([]byte("tbp-redteam-policy"), []byte("v1"))
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: cfg.CellID, Signer: signer, PolicyID: policyID})
	if err != nil {
		return false, "", fmt.Errorf("issuer: %w", err)
	}
	brk, err := broker.NewBroker(broker.BrokerOptions{
		CellID: cfg.CellID, Salt: salt, Leaves: leafSink,
		OPA: opa, Translator: broker.StructuredTranslator{},
		Issuer: issuer, Epochs: broker.StaticEpoch(1),
	})
	if err != nil {
		return false, "", fmt.Errorf("broker: %w", err)
	}

	intent := `{"action":"read.list","resource":"registry/docs/7","class":3}`
	type outcome struct {
		allow, leafOK, opaLeafOK bool
	}
	flood := func(n int) []outcome {
		res := make([]outcome, n)
		var wg sync.WaitGroup
		sem := make(chan int, 16)
		for i := 0; i < n; i++ {
			wg.Add(1)
			sem <- i
			go func(i int) {
				defer wg.Done()
				defer func() { <-sem }()
				r := brk.HandleAction(ctx, "michel", intent)
				o := outcome{allow: r.Allow, leafOK: r.LeafWritten && r.LeafErr == nil}
				if r.OPADecision != nil {
					o.opaLeafOK = r.OPADecision.LeafWritten
				}
				res[i] = o
			}(i)
		}
		wg.Wait()
		return res
	}

	// Phase A — submersion, OPA sain : tout est servi, chaque décision leafée.
	phaseA := flood(cfg.FloodUp)
	// L'attaquant emporte le sidecar : OPA tombe sous la charge.
	opaSrv.Close()
	// Phase B — submersion continue : fail-closed, zéro allow silencieux.
	phaseB := flood(cfg.FloodDown)

	var aDenied, aUnleafed, bAllowed, bUnleafed int
	for _, o := range phaseA {
		if !o.allow {
			aDenied++
		}
		if !o.leafOK || !o.opaLeafOK {
			aUnleafed++
		}
	}
	for _, o := range phaseB {
		if o.allow {
			bAllowed++
		}
		if !o.leafOK || !o.opaLeafOK {
			bUnleafed++
		}
	}
	muT.Lock()
	nTrips := len(trips)
	muT.Unlock()

	// Corrélation : phase A = 2 feuilles/requête (évaluation OPA « TBPD1 »
	// + décision broker) ; phase B = 1 feuille/requête (l'évaluation OPA
	// fail-closed porte le refus — broker.go étape 5 n'en double pas).
	// La mutation silencieuse crée un trou dans ce compte.
	total := sink.total()
	expected := uint64(2*cfg.FloodUp + cfg.FloodDown)

	switch {
	case aDenied > 0:
		return false, fmt.Sprintf("phase A : %d refus sous charge OPA sain — le service légitime est tombé", aDenied), nil
	case bAllowed > 0:
		return false, fmt.Sprintf("phase B : %d ALLOW après la chute d'OPA — acte silencieusement autorisé (§7)", bAllowed), nil
	case aUnleafed+bUnleafed > 0:
		return false, fmt.Sprintf("%d décisions sans feuille complète — trou d'instrumentation sous submersion", aUnleafed+bUnleafed), nil
	case nTrips == 0:
		return false, "chute d'OPA sous charge SANS alarme OnTrip (T14) — dégradation silencieuse", nil
	case total != expected:
		return false, fmt.Sprintf("feuilles scannées/comptées %d ≠ attendues %d — trou de submersion", total, expected), nil
	}
	return true, fmt.Sprintf("%d requêtes servies+leafées (OPA sain), %d refus fail-closed leafés (OPA tombé), %d alarme(s)",
		cfg.FloodUp, cfg.FloodDown, nTrips), nil
}

// ---------------------------------------------------------------------------
// S6 — plan menteur (§4.2) : le plan approuvé est un contrat (T30). L'écart
// entre le plan arbitré et l'exécution réelle doit être refusé et leafé.
// ---------------------------------------------------------------------------

// contractGate est la couture consommée par le scénario — le mutant M-S6
// l'implémente en avalant les déviations.
type contractGate interface {
	Submit(ctx context.Context, steps []pep.PlanStep) ([32]byte, error)
	Approve(ctx context.Context, planHash [32]byte, expiry time.Time, sig []byte) error
	VerifyStep(ctx context.Context, binding []byte, action, resource string) ([32]byte, error)
}

// mutantDevStore (M-S6) accepte toute déviation de plan — l'écart
// approuvé/exécuté n'est plus refusé. Le scénario doit le détecter.
type mutantDevStore struct{ inner contractGate }

func (m mutantDevStore) Submit(ctx context.Context, steps []pep.PlanStep) ([32]byte, error) {
	return m.inner.Submit(ctx, steps)
}
func (m mutantDevStore) Approve(ctx context.Context, h [32]byte, e time.Time, s []byte) error {
	return m.inner.Approve(ctx, h, e, s)
}
func (m mutantDevStore) VerifyStep(ctx context.Context, b []byte, a, r string) ([32]byte, error) {
	seal, err := m.inner.VerifyStep(ctx, b, a, r)
	if err != nil {
		return seal, nil // mutation : le refus de déviation est avalé
	}
	return seal, nil
}

func scenarioLyingPlan(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (bool, string, error) {
	operator := ed25519.NewKeyFromSeed(seed32("t28/operator"))
	policyID := registry.HashPayload([]byte("tbp-redteam-policy"), []byte("v1"))
	store, err := pep.NewContractStore(pep.ContractOptions{
		CellID: cfg.CellID, PolicyID: policyID,
		OperatorKeys: []ed25519.PublicKey{operator.Public().(ed25519.PublicKey)},
		Salt:         salt, Leaves: sink,
	})
	if err != nil {
		return false, "", fmt.Errorf("store: %w", err)
	}
	var gate contractGate = store
	if cfg.MutAcceptDeviation {
		gate = mutantDevStore{inner: store} // M-S6
	}

	// Le plan arbitré : lire registry/docs/42 avec des paramètres scellés.
	params := []byte(`{"format":"liste","max":50}`)
	steps := []pep.PlanStep{{Action: "read.list", Resource: "registry/docs/42", ParamsHash: pep.HashParams(params)}}
	planHash, err := gate.Submit(ctx, steps)
	if err != nil {
		return false, "", fmt.Errorf("submit: %w", err)
	}
	expiry := time.Now().Add(30 * time.Minute).UTC()
	sig := ed25519.Sign(operator, pep.ApprovalMessage(planHash, expiry))
	if err := gate.Approve(ctx, planHash, expiry, sig); err != nil {
		return false, "", fmt.Errorf("approve: %w", err)
	}

	// Exécution honnête (contrôle) : les paramètres scellés passent.
	bindingOK, err := pep.BuildBinding(planHash, params)
	if err != nil {
		return false, "", fmt.Errorf("binding honnête: %w", err)
	}
	if _, err := gate.VerifyStep(ctx, bindingOK, "read.list", "registry/docs/42"); err != nil {
		return false, "", fmt.Errorf("exécution honnête refusée (%v) — faux positif du contrat", err)
	}

	// Attaque : le plan approuvé lisait 50 lignes de docs/42 ; l'exécution
	// exfiltre docs/42 en entier (paramètres déviés). Refus exigé (§4.2).
	bindingEvil, err := pep.BuildBinding(planHash, []byte(`{"format":"brut","max":-1}`))
	if err != nil {
		return false, "", fmt.Errorf("binding dévié: %w", err)
	}
	_, errDev := gate.VerifyStep(ctx, bindingEvil, "read.list", "registry/docs/42")
	if errDev == nil {
		return false, "déviation de paramètres ACCEPTÉE — le plan menteur passe (§4.2 violé)", nil
	}
	if !errors.Is(errDev, pep.ErrPlanDeviation) {
		return false, "", fmt.Errorf("déviation refusée pour une autre cause (%v) — le scénario ne prouve rien", errDev)
	}

	counts, _, _ := sink.snapshot()
	if counts[registry.KindContract] != 4 {
		return false, fmt.Sprintf("%d feuilles KindContract ≠ 4 (submit+approve+verify ok+refus déviation)", counts[registry.KindContract]), nil
	}
	return true, "exécution conforme acceptée ; déviation de paramètres refusée (plan-deviation) et leafée", nil
}

// ---------------------------------------------------------------------------
// S7 — canari sous partition (§7.4) : la fenêtre saine est ancrée dans la
// master chain, JAMAIS mesurée par le canari isolé (T29). Sous partition,
// la promotion est refusée — même avec une réception parfaitement signée.
// ---------------------------------------------------------------------------

// stubAnchorSource simule la lecture du master (T6). partitioned=true :
// le master est injoignable — ancre absente. canaryWindow=true (M-S7) :
// sous partition, le canari « s'atteste » LUI-MÊME — bundle et fenêtre
// mesurés localement, sans master — exactement le modèle interdit par
// §7.4 (la fenêtre saine ne se mesure pas, elle se lit dans le master).
type stubAnchorSource struct {
	bundle       [32]byte
	start, end   time.Time
	partitioned  bool
	canaryWindow bool
}

func (s stubAnchorSource) BundleAnchor(epoch uint64) ([32]byte, bool) {
	if s.partitioned && !s.canaryWindow {
		return [32]byte{}, false
	}
	return s.bundle, true
}

func (s stubAnchorSource) HealthyWindow(epoch uint64) (time.Time, time.Time, bool) {
	if s.partitioned && !s.canaryWindow {
		return time.Time{}, time.Time{}, false
	}
	return s.start, s.end, true
}

func signedReceipt(cellID string, epoch uint64, bundle [32]byte, at time.Time, priv ed25519.PrivateKey) ([]byte, error) {
	r := cluster.Receipt{
		CellID: cellID, Epoch: epoch,
		BundleHash: hex.EncodeToString(bundle[:]),
		ReceivedAt: at.UTC().Format(time.RFC3339),
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sr := cluster.SignedReceipt{Receipt: r, Sig: hex.EncodeToString(ed25519.Sign(priv, canonical))}
	return json.Marshal(sr)
}

func scenarioCanaryPartition(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (bool, string, error) {
	candidate := ed25519.NewKeyFromSeed(seed32("t28/candidate"))
	bundle := registry.HashPayload([]byte("bundle-regles"), []byte("epoch-7"))
	now := time.Now()

	mk := func(src cluster.MasterAnchorSource) (*cluster.PromotionController, error) {
		return cluster.NewPromotionController(cluster.PromotionConfig{
			CellID: cfg.CellID, Salt: salt, Leaves: sink, Source: src,
			CellKeys: map[string]ed25519.PublicKey{"tbp-cell-canari": candidate.Public().(ed25519.PublicKey)},
		})
	}
	receipt, err := signedReceipt("tbp-cell-canari", 7, bundle, now, candidate)
	if err != nil {
		return false, "", fmt.Errorf("réception: %w", err)
	}

	// Contrôle sain : bundle ancré + fenêtre ancrée valide → promotion.
	sound := stubAnchorSource{bundle: bundle, start: now.Add(-time.Hour), end: now.Add(time.Hour)}
	ctl, err := mk(sound)
	if err != nil {
		return false, "", fmt.Errorf("contrôleur sain: %w", err)
	}
	if err := ctl.Promote(ctx, receipt); err != nil {
		return false, "", fmt.Errorf("promotion saine refusée (%v) — faux positif", err)
	}

	// Attaque : la partition isole le canari du master. La fenêtre saine ne
	// peut plus être lue dans la master chain — promotion refusée (§7.4),
	// réception signée ou non.
	partitioned := stubAnchorSource{bundle: bundle, start: now.Add(-time.Hour), end: now.Add(time.Hour),
		partitioned: true, canaryWindow: cfg.MutCanarySelfMeasured} // M-S7
	ctlP, err := mk(partitioned)
	if err != nil {
		return false, "", fmt.Errorf("contrôleur partition: %w", err)
	}
	errPart := ctlP.Promote(ctx, receipt)
	if errPart == nil {
		return false, "promotion ACCEPTÉE sous partition — la fenêtre a été mesurée par le canari isolé (§7.4 violé)", nil
	}
	if !errors.Is(errPart, cluster.ErrPromotionAnchorUnavailable) &&
		!errors.Is(errPart, cluster.ErrPromotionWindowUnavailable) {
		return false, "", fmt.Errorf("refus de partition pour une autre cause (%v) — le scénario ne prouve rien", errPart)
	}

	// Fenêtre ancrée mais EXPIRÉE : hors fenêtre, pas de promotion.
	expired := stubAnchorSource{bundle: bundle, start: now.Add(-2 * time.Hour), end: now.Add(-time.Hour)}
	ctlE, err := mk(expired)
	if err != nil {
		return false, "", fmt.Errorf("contrôleur expiré: %w", err)
	}
	if err := ctlE.Promote(ctx, receipt); !errors.Is(err, cluster.ErrPromotionWindowExpired) {
		return false, "", fmt.Errorf("fenêtre expirée : erreur %v ≠ ErrPromotionWindowExpired", err)
	}

	counts, _, _ := sink.snapshot()
	if counts[registry.KindPromotion] != 3 {
		return false, fmt.Sprintf("%d feuilles KindPromotion ≠ 3 (promotion + refus partition + refus expiré)", counts[registry.KindPromotion]), nil
	}
	return true, "promotion saine admise ; sous partition : refusée (ancre master injoignable) ; fenêtre expirée : refusée — toutes leafées", nil
}

// ---------------------------------------------------------------------------
// S8 — replay au-delà TTL (§4.3, T10) : un jti consommé est refusé, un
// jeton expiré est refusé — chaque refus leafé (T9).
// ---------------------------------------------------------------------------

// alwaysNewCache est la mutation M-S8 : tout jti passe pour « nouveau » —
// l'anti-rejeu ne consomme plus rien. Le scénario doit le détecter.
type alwaysNewCache struct{}

func (alwaysNewCache) CheckAndConsume(_ [16]byte, _ time.Time) bool { return true }

func scenarioTokenReplay(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (bool, string, error) {
	fc, err := pep.NewFailClosed(pep.FailClosedOptions{CellID: cfg.CellID, Salt: salt, Leaves: sink})
	if err != nil {
		return false, "", fmt.Errorf("fail-closed: %w", err)
	}
	mc, err := pep.NewModeController(pep.ModeOptions{
		CellID: cfg.CellID, Salt: salt, Leaves: sink,
		VerifyQuorum: func(_ string, proof pep.QuorumProof) bool { return len(proof.Signers) >= 1 },
	})
	if err != nil {
		return false, "", fmt.Errorf("mode: %w", err)
	}
	var ar pep.AntiReplayCache
	if cfg.MutReplayAccept {
		ar = alwaysNewCache{} // M-S8
	} else {
		arReal, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 1 << 16})
		if err != nil {
			return false, "", fmt.Errorf("anti-rejeu: %w", err)
		}
		ar = arReal
	}
	ledger, err := pep.NewQuotaLedger(pep.QuotaLedgerOptions{
		MaxPassports: 1 << 16, CellID: cfg.CellID, Salt: salt, Leaves: sink,
	})
	if err != nil {
		return false, "", fmt.Errorf("quota: %w", err)
	}
	issuer := ed25519.NewKeyFromSeed(seed32("t28/issuer"))
	kid := pep.KeyIDFromPublicKey(issuer.Public().(ed25519.PublicKey))
	policyID := registry.HashPayload([]byte("tbp-redteam-policy"), []byte("v1"))
	v, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:   cfg.CellID,
		Keyring:  map[[16]byte]ed25519.PublicKey{kid: issuer.Public().(ed25519.PublicKey)},
		PolicyID: policyID, Salt: salt, Leaves: sink,
		AntiReplay: ar, Quota: ledger, Gate: fc,
	})
	if err != nil {
		return false, "", fmt.Errorf("validateur: %w", err)
	}
	l, err := pep.NewListener(pep.ListenerOptions{Validator: v, Mode: mc, Ledger: ledger})
	if err != nil {
		return false, "", fmt.Errorf("listener: %w", err)
	}
	// S8 teste des REFUS : la posture doit être closed — en monitor (§5.3,
	// défaut au démarrage) tout est forwardé par doctrine. La bascule est
	// l'acte gouverné de T15 : preuve de quorum, feuille KindTelemetry.
	if err := mc.SetMode(pep.ModeClosed, pep.QuorumProof{Signers: [][]byte{[]byte("operateur-p1")}}); err != nil {
		return false, "", fmt.Errorf("bascule closed: %w", err)
	}
	handler := l.Handler()

	// Le listener répond TOUJOURS 200 : le verdict est dans le corps
	// (allow = verdict T9 ; forwarded = ce qui passe réellement, selon la
	// posture §5.3). Juger sur le statut HTTP serait un harnais faux.
	type verdict struct {
		Allow     bool `json:"allow"`
		Forwarded bool `json:"forwarded"`
	}
	evaluate := func(token []byte) (verdict, error) {
		body, err := json.Marshal(map[string]any{
			"token":    base64.StdEncoding.EncodeToString(token),
			"action":   "read.list",
			"resource": "registry/docs/42",
			"epoch":    0,
		})
		if err != nil {
			return verdict{}, err
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			return verdict{}, fmt.Errorf("statut %d — faute de harnais, pas de verdict", rec.Code)
		}
		var v verdict
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			return verdict{}, fmt.Errorf("verdict illisible: %w", err)
		}
		return v, nil
	}
	mint := func(jti [16]byte, exp time.Time) ([]byte, error) {
		return mintToken(issuer, mintClaims{
			iss: "tbp-cell-maitresse", sub: cfg.CellID,
			exp: exp.Unix(), iat: time.Now().Add(-time.Second).Unix(),
			jti: jti[:], policyID: policyID[:],
			action: "read.list", resource: "registry/docs/42",
			class: int(pep.ClassOut), epoch: 0, version: 1, kid: kid[:],
		})
	}

	// Premier passage — valide.
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return false, "", fmt.Errorf("jti: %w", err)
	}
	tok, err := mint(jti, time.Now().Add(45*time.Second))
	if err != nil {
		return false, "", fmt.Errorf("menthe: %w", err)
	}
	v1, err := evaluate(tok)
	if err != nil {
		return false, "", err
	}
	if !v1.Allow || !v1.Forwarded {
		return false, "", fmt.Errorf("premier passage refusé (allow=%v forwarded=%v) — le harnais est faux, pas le mécanisme", v1.Allow, v1.Forwarded)
	}

	// Attaque 1 : rejeu du MÊME jti dans la fenêtre TTL — refus exigé (T10),
	// ET le refus doit être APPLIQUÉ (posture closed : forwarded=false).
	v2, err := evaluate(tok)
	if err != nil {
		return false, "", err
	}
	if v2.Allow || v2.Forwarded {
		return false, fmt.Sprintf("rejeu du jti consommé laissé passer (allow=%v forwarded=%v) — anti-rejeu T10 contourné (§4.3 violé)", v2.Allow, v2.Forwarded), nil
	}

	// Attaque 2 : jeton au-delà du TTL (expiré) — refus exigé (§4.3).
	var jti2 [16]byte
	if _, err := rand.Read(jti2[:]); err != nil {
		return false, "", fmt.Errorf("jti2: %w", err)
	}
	tokExp, err := mint(jti2, time.Now().Add(-10*time.Second))
	if err != nil {
		return false, "", fmt.Errorf("menthe expirée: %w", err)
	}
	v3, err := evaluate(tokExp)
	if err != nil {
		return false, "", err
	}
	if v3.Allow || v3.Forwarded {
		return false, "jeton EXPIRÉ laissé passer — borne TTL §4.3 violée", nil
	}

	counts, _, _ := sink.snapshot()
	if counts[registry.KindDecision] != 3 {
		return false, fmt.Sprintf("%d feuilles KindDecision ≠ 3 (allow + refus rejeu + refus expiré)", counts[registry.KindDecision]), nil
	}
	return true, "premier passage admis ; rejeu du jti refusé (T10) ; jeton expiré refusé — chaque décision leafée", nil
}

// ---------------------------------------------------------------------------
// S9 — coupure de la télémétrie par un admin sous pression (§5.3) : c'est
// une ACTION de classe W (« the maximal irreversible ») — elle passe par
// le quorum k-of-n du broker (§7.5, T29), qui écrit la feuille KindQuorum.
// (Revue #28 : FailClosed.Clear ne produit que KindTelemetry et n'exerce
// pas QuorumGate — le scénario va au broker, là où vit le mécanisme.)
// ---------------------------------------------------------------------------

// mutantAcceptGate (M-S9) accepte toute preuve de quorum, y compris
// insuffisante — le maximal irréversible devient un acte unilatéral.
type mutantAcceptGate struct{}

func (mutantAcceptGate) VerifyClassW(_ context.Context, _ []byte, _, _ string, _ uint64) error {
	return nil
}

// mintQuorumProof frappe une preuve k-of-n liée à (action, resource,
// policyID, epoch) — motif de cluster/quorum_test.go.
func mintQuorumProof(privs map[int]ed25519.PrivateKey, action, resource string, policyID [32]byte, epoch uint64, expiry time.Time, signers ...int) ([]byte, error) {
	st := cluster.QuorumStatement{
		Action: action, Resource: resource,
		PolicyID: hex.EncodeToString(policyID[:]),
		Epoch:    epoch,
		Expiry:   expiry.UTC().Format(time.RFC3339),
	}
	canonical, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	proof := cluster.QuorumProof{Statement: st, Quorum: fmt.Sprintf("%d-of-%d", len(signers), len(privs))}
	for _, id := range signers {
		proof.Signatures = append(proof.Signatures, cluster.ControllerSignature{
			KeyID: id, Sig: hex.EncodeToString(ed25519.Sign(privs[id], canonical)),
		})
	}
	return json.Marshal(proof)
}

func scenarioTelemetryCut(ctx context.Context, cfg Config, sink *countingSink, salt []byte) (bool, string, error) {
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	defer opaSrv.Close()

	opa, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint: opaSrv.URL, Timeout: 500 * time.Millisecond,
		CellID: cfg.CellID, Salt: salt, Leaves: sink,
	})
	if err != nil {
		return false, "", fmt.Errorf("client OPA: %w", err)
	}
	signer, err := broker.NewDevSigner(seed32("t28/broker"))
	if err != nil {
		return false, "", fmt.Errorf("signer: %w", err)
	}
	policyID := registry.HashPayload([]byte("tbp-redteam-policy"), []byte("v1"))
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: cfg.CellID, Signer: signer, PolicyID: policyID})
	if err != nil {
		return false, "", fmt.Errorf("issuer: %w", err)
	}

	// Manifest de 3 contrôleurs, quorum 2-of-3 (§7.5).
	privs := map[int]ed25519.PrivateKey{}
	pubs := map[int]ed25519.PublicKey{}
	for i, label := range []string{"t28/controller-0", "t28/controller-1", "t28/controller-2"} {
		privs[i] = ed25519.NewKeyFromSeed(seed32(label))
		pubs[i] = privs[i].Public().(ed25519.PublicKey)
	}
	var gate broker.QuorumGate
	if cfg.MutSkipQuorum {
		gate = mutantAcceptGate{} // M-S9
	} else {
		g, err := cluster.NewQuorumGate(cluster.QuorumGateConfig{
			CellID: cfg.CellID, Salt: salt, Leaves: sink,
			Controllers: pubs, K: 2, PolicyID: policyID,
		})
		if err != nil {
			return false, "", fmt.Errorf("quorum gate: %w", err)
		}
		gate = g
	}
	brk, err := broker.NewBroker(broker.BrokerOptions{
		CellID: cfg.CellID, Salt: salt, Leaves: sink,
		OPA: opa, Translator: broker.StructuredTranslator{},
		Issuer: issuer, Epochs: broker.StaticEpoch(7),
		Quorum: gate,
	})
	if err != nil {
		return false, "", fmt.Errorf("broker: %w", err)
	}

	const action, resource = "telemetry.disable", "telemetry/exporter"
	intent := func(proof []byte) string {
		if len(proof) == 0 {
			return fmt.Sprintf(`{"action":%q,"resource":%q}`, action, resource) // classe absente ⇒ W (§5.3)
		}
		return fmt.Sprintf(`{"action":%q,"resource":%q,"quorum_proof":%q}`, action, resource, hex.EncodeToString(proof))
	}
	expiry := time.Now().Add(2 * time.Minute)

	// Attaque 1 : l'admin seul, sans preuve — refus quorum-required (le
	// broker refuse avant même le gate : pas de preuve, pas de débat).
	res := brk.HandleAction(ctx, "admin-sous-pression", intent(nil))
	if res.Allow || res.Reason != broker.ReasonQuorumRequired {
		return false, fmt.Sprintf("coupure sans preuve : allow=%v reason=%q ≠ quorum-required", res.Allow, res.Reason), nil
	}

	// Attaque 2 : preuve insuffisante (1 signataire pour k=2) — le gate
	// refuse ET trace KindQuorum (le refus de quorum est opposable).
	weak, err := mintQuorumProof(privs, action, resource, policyID, 7, expiry, 0)
	if err != nil {
		return false, "", fmt.Errorf("preuve faible: %w", err)
	}
	res = brk.HandleAction(ctx, "admin-sous-pression", intent(weak))
	if res.Allow || res.Reason != broker.ReasonQuorumInsufficient {
		return false, fmt.Sprintf("preuve 1-of-3 (k=2) : allow=%v reason=%q ≠ quorum-insufficient — la coupure unilatérale passe", res.Allow, res.Reason), nil
	}

	// Contrôle gouverné : quorum 2-of-3 valide — l'action est admise, et
	// elle est TOUT AUTANT leafée (une coupure autorisée n'est pas moins
	// opposable qu'une coupable).
	strong, err := mintQuorumProof(privs, action, resource, policyID, 7, expiry, 0, 1)
	if err != nil {
		return false, "", fmt.Errorf("preuve forte: %w", err)
	}
	res = brk.HandleAction(ctx, "admin-sous-pression", intent(strong))
	if !res.Allow {
		return false, "", fmt.Errorf("quorum 2-of-3 valide refusé (%s) — faux positif du gate", res.Reason)
	}

	counts, _, _ := sink.snapshot()
	if counts[registry.KindQuorum] != 2 {
		return false, fmt.Sprintf("%d feuilles KindQuorum ≠ 2 (refus insuffisant + admission gouvernée)", counts[registry.KindQuorum]), nil
	}
	if counts[registry.KindDecision] < 3 {
		return false, fmt.Sprintf("%d feuilles KindDecision < 3 — une coupure (tentée ou admise) n'a pas laissé sa décision", counts[registry.KindDecision]), nil
	}
	return true, "sans preuve : quorum-required ; 1-of-3 : quorum-insufficient leafé KindQuorum ; 2-of-3 : admis, leafé KindQuorum — rien de silencieux", nil
}

// ---------------------------------------------------------------------------
// Orchestration (D92/D93/D94) : un registre réel par run, un countingSink
// par scénario, scan ChainWatcher, corrélation feuilles ↔ scénarios.
// ---------------------------------------------------------------------------

// scenarioSpec couple un scénario à sa fiche d'identité.
type scenarioSpec struct {
	id, name, mechanism string
	fn                  scenarioFunc
}

// Run exécute la campagne et écrit run_report.json + leaves_export.json
// dans cfg.OutDir. Ne tranche pas le verdict final (assert_logged.py) :
// rend le rapport ; le MAIN fixe le code de sortie (mécanisme non tenu ⇒ 1).
func Run(ctx context.Context, cfg Config) (*RunReport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("out dir: %w", err)
	}
	cellLog, regDir, err := openCellRegistry(ctx, cfg.OutDir, cfg.CellID)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 32) // sel des feuilles — reste dans le process (§6.2)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("sel: %w", err)
	}

	specs := []scenarioSpec{
		{"S4", "hotspot-4g", "§5.2 — détection télémétrie (prévention incompressible)", scenarioHotspot},
		{"S5", "submersion-broker", "§7/§8 — DoS alarmé, jamais d'acte silencieusement autorisé", scenarioBrokerFlood},
		{"S6", "plan-menteur", "§4.2 — contrat de plan : déviation refusée (T30)", scenarioLyingPlan},
		{"S7", "canari-partition", "§7.4 — fenêtre saine ancrée master, jamais mesurée par le canari (T29)", scenarioCanaryPartition},
		{"S8", "replay-au-dela-ttl", "§4.3/T10 — jti consommé refusé, jeton expiré refusé (T9)", scenarioTokenReplay},
		{"S9", "coupure-telemetry", "§5.3/§7.5 — action classe W : quorum k-of-n signé, leafé (T29)", scenarioTelemetryCut},
	}

	report := &RunReport{
		Tool:        "tbp-redteam-runner",
		RunID:       fmt.Sprintf("redteam-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	// S1/S2 : scénarios réseau — exécutés par les scripts netns sur le lab
	// (le sandbox CI ne monte pas de namespaces ; leurs feuilles d'évidence
	// arrivent via `leaf-evidence`). S3 : constat endpoint, trou déclaré.
	report.Scenarios = append(report.Scenarios,
		ScenarioResult{ID: "S1", Name: "laptop-inconnu", Mechanism: "§5.1 — mur + aiguillage (VLAN captif)",
			Status: "lab-netns", LeafFirst: -1, LeafLast: -1, Detail: "exécuté par scenario_01_unknown_laptop.sh sur le lab ; feuille d'évidence via leaf-evidence"},
		ScenarioResult{ID: "S2", Name: "sftp-direct", Mechanism: "§5.2 — aucun chemin direct client→serveur",
			Status: "lab-netns", LeafFirst: -1, LeafLast: -1, Detail: "exécuté par scenario_02_direct_sftp.sh sur le lab ; feuille d'évidence via leaf-evidence"},
		ScenarioResult{ID: "S3", Name: "usb-exfil", Mechanism: "§5.2 — hors réseau : compensation endpoint (USBGuard/GPO/BIOS-IOMMU)",
			Status: "declared-hole", LeafFirst: -1, LeafLast: -1, Detail: "constat par scenario_03_usb_exfil.sh ; trou résiduel déclaré, compté — jamais un faux vert"},
	)

	var execSinks []*countingSink
	for _, spec := range specs {
		sink := newCountingSink(cellLog)
		held, detail, err := spec.fn(ctx, cfg, sink, salt)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %w", spec.id, spec.name, err)
		}
		counts, first, last := sink.snapshot()
		leaves := make(map[string]uint64, len(counts))
		for k, v := range counts {
			leaves[fmt.Sprintf("%d", k)] = v
		}
		h := held
		report.Scenarios = append(report.Scenarios, ScenarioResult{
			ID: spec.id, Name: spec.name, Mechanism: spec.mechanism,
			Status: "executed", Held: &h,
			LeafFirst: first, LeafLast: last, Leaves: leaves, Detail: detail,
		})
		execSinks = append(execSinks, sink)
	}

	// Fermeture propre AVANT le scan (publication drainée).
	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := cellLog.Close(closeCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("fermeture registre: %w", err)
	}
	cancel()

	leaves, err := exportLeaves(ctx, cfg.CellID, regDir)
	if err != nil {
		return nil, fmt.Errorf("export feuilles: %w", err)
	}

	// Auto-corrélation (D94, côté runner) : pour chaque scénario exécuté,
	// les comptes par kind du sink doivent égaler le scan sur [first,last] ;
	// l'union des plages doit couvrir le registre sans trou.
	applyCorrelation(report, leaves)

	report.DeclaredHoles = []DeclaredHole{
		{ID: "S3-usb", Description: "exfiltration USB — prévention hors réseau (compensation endpoint USBGuard/GPO/BIOS-IOMMU) ; constatée, non testable au niveau réseau"},
		{ID: "S4-prevention", Description: "hotspot/4G — canal hors mur : la PRÉVENTION est incompressible (§5.2) ; seule la détection télémétrie est testée (S4)"},
		{ID: "physical-access", Description: "accès physique — hors scope réseau, déclaré (§13 scénario Michel étendu)"},
		{ID: "S1-S2-lab", Description: "scénarios réseau S1/S2 — exécution netns sur le lab (le sandbox CI ne monte pas de namespaces) ; feuilles d'évidence exigées au retour"},
	}

	if err := writeJSONFile(filepath.Join(cfg.OutDir, "run_report.json"), report); err != nil {
		return nil, err
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "leaves_export.json"), leaves); err != nil {
		return nil, err
	}
	return report, nil
}

// correlationFails recoupe un scénario exécuté au scan : comptes par kind
// égaux sur [first,last], plage bien formée.
func correlationFails(s ScenarioResult, leaves []leafRecord) bool {
	if s.LeafFirst < 0 || s.LeafLast < s.LeafFirst {
		return len(s.Leaves) != 0 // pas de plage mais des feuilles comptées : trou
	}
	if int(s.LeafLast) >= len(leaves) {
		return true
	}
	scan := map[string]uint64{}
	for i := s.LeafFirst; i <= s.LeafLast; i++ {
		scan[fmt.Sprintf("%d", leaves[i].Kind)]++
	}
	if len(scan) != len(s.Leaves) {
		return true
	}
	for k, v := range s.Leaves {
		if scan[k] != v {
			return true
		}
	}
	return false
}

// correlate vérifie la couverture sans trou : l'union des plages des
// scénarios exécutés couvre exactement [0, len(leaves)).
func correlate(report *RunReport, leaves []leafRecord) string {
	var covered int64
	for _, s := range report.Scenarios {
		if s.Status != "executed" || s.LeafFirst < 0 {
			continue
		}
		if s.LeafFirst != covered {
			return fmt.Sprintf("trou de séquence avant %s (attendu index %d, première feuille %d)", s.ID, covered, s.LeafFirst)
		}
		covered = s.LeafLast + 1
	}
	if covered != int64(len(leaves)) {
		return fmt.Sprintf("registre %d feuilles, plages couvrent %d — feuilles orphelines ou manquantes", len(leaves), covered)
	}
	return ""
}

// applyCorrelation recoupe le rapport au scan : un trou fait basculer le
// scénario fautif en non tenu quand il est identifiable, mais un trou de
// COUVERTURE (ex. feuille orpheline après le dernier scénario exécuté) ne
// tombe dans la plage [first,last] d'AUCUN scénario — aucun ne bascule
// alors, et le trou serait perdu s'il n'était reporté QUE via le
// basculement individuel. report.CorrelationFault est le filet : porté
// inconditionnellement, jamais subordonné à une attribution qui peut
// échouer (revue #28 : un rapport qui dit « tout tenu » alors que
// correlate() a trouvé quelque chose ment).
func applyCorrelation(report *RunReport, leaves []leafRecord) {
	bad := correlate(report, leaves)
	if bad == "" {
		return
	}
	report.CorrelationFault = bad
	for i := range report.Scenarios {
		s := &report.Scenarios[i]
		if s.Status == "executed" && s.Held != nil && *s.Held && correlationFails(*s, leaves) {
			f := false
			s.Held = &f
			s.Detail += " | CORRÉLATION : " + bad
		}
	}
}

// writeJSONFile sérialise indenté (artefact de preuve, relu humainement).
func writeJSONFile(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
