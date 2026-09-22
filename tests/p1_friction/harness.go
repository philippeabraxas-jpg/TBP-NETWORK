// harness.go — T27 (issue #29) : harnais de latence et indicateurs de
// friction. Mesure la latence AJOUTÉE PAR LE PEP SEUL (D85) : pile réelle
// assemblée avec les mêmes constructeurs que pepd (T15), OPA nil (pas de
// réseau, pas de traducteur, pas de sidecar), handlers invoqués via
// httptest.NewRecorder — aucun socket.
//
// Deux bras de mesure (D88 amendé, arbitrage revue #29) :
//
//   - bras « décision » : puits de feuilles synchrone IN-MEMORY — isole le
//     coût de décision du PEP (Ed25519, CBOR, anti-rejeu, quota, gate T14),
//     le « plancher déterministe » que §9.1 budgète à 5 ms. La synchronicité
//     et la doctrine T9 sont intactes : même chemin de code, même
//     ReasonLeafWriteFailed, seule la vitesse du magasin change.
//   - bras « durabilité » : pile identique sur registre tessera RÉEL (POSIX)
//     — mesure le coût de la preuve fail-closed (feuille intégrée ET
//     publiée avant verdict) et produit les feuilles réelles pour
//     leaves_export.json et la corrélation uninstrumented_holes (D88).
//     Plancher structurel ~150 ms (checkpoint POSIX ≥ 100 ms + poll 50 ms)
//     — HORS budget §9.1 ; #71 arbitré (T38) : ce bras mesure le mode sync
//     = borne pire cas, la production par défaut est async borné.
//
// Le rapport et le README affichent les deux bras côte à côte, jamais l'un
// sans l'autre (condition A de la revue) — le bras « durabilité » reste la
// borne pire cas même si la prod ne le paie plus par défaut.
//
// Le verdict de seuil est rendu par leading_indicators.py (D89/D91) — ce
// fichier ne fait que mesurer, exporter et leaf le rapport (D90).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

// posixCheckpointFloor est la borne dure du driver POSIX tessera
// (minCheckpointInterval, refus à la construction en dessous) — la
// composante principale du plancher du bras « durabilité ».
const posixCheckpointFloor = 100 * time.Millisecond

// Config paramètre un run du harnais.
type Config struct {
	Tier1Samples int // échantillons tier1 du bras décision (et baseline)
	Tier2Plans   int // plans du bras décision (submit+approve+verify)
	Workers      int // concurrence d'invocation (comme la production sous charge)
	DurTier1     int // échantillons tier1 du bras durabilité (registre réel)
	DurTier2     int // plans du bras durabilité (feuilles KindContract réelles)

	// Mutations prouvées létales (défauts = run nominal) :
	InjectLatency  time.Duration // M-harness : latence injectée sur le chemin tier1
	InjectDenyRate float64       // M-arbitrage : fraction de VerifyStep déviant [0,1]
	TTLStretch     float64       // M-ttl : multiplicateur des TTL émis (1 = nominal)

	TTLBase time.Duration // TTL nominal émis à la menthe (référence ttl_drift)
	OutDir  string        // artefacts : measurements.json, leaves_export.json, registry/
	CellID  string
}

// DefaultConfig : profil CI (D91) — assez grand pour des percentiles
// stables, assez petit pour rester sous la minute (le bras durabilité paie
// le plancher checkpoint sur chaque opération tier2, sérialisées par le
// mutex du store).
func DefaultConfig() Config {
	return Config{
		Tier1Samples:   2000,
		Tier2Plans:     200,
		Workers:        16,
		DurTier1:       40,
		DurTier2:       15,
		TTLBase:        300 * time.Second,
		InjectDenyRate: 0.05,
		TTLStretch:     1.0,
		OutDir:         "out",
		CellID:         "tbp-cell-friction",
	}
}

// Validate borne la config (fail-closed comme partout dans le dépôt).
func (c Config) Validate() error {
	switch {
	case c.Tier1Samples < 10:
		return fmt.Errorf("Tier1Samples %d < 10 (percentiles non significatifs)", c.Tier1Samples)
	case c.Tier2Plans < 2:
		return fmt.Errorf("Tier2Plans %d < 2", c.Tier2Plans)
	case c.Workers < 1:
		return fmt.Errorf("Workers %d < 1", c.Workers)
	case c.DurTier1 < 2 || c.DurTier2 < 1:
		return fmt.Errorf("bras durabilité sous-échantillonné (DurTier1=%d, DurTier2=%d)", c.DurTier1, c.DurTier2)
	case c.InjectLatency < 0:
		return fmt.Errorf("InjectLatency négative")
	case c.InjectDenyRate < 0 || c.InjectDenyRate > 1:
		return fmt.Errorf("InjectDenyRate %v hors [0,1]", c.InjectDenyRate)
	case c.TTLStretch <= 0:
		return fmt.Errorf("TTLStretch %v ≤ 0", c.TTLStretch)
	case c.TTLBase < 60*time.Second:
		return fmt.Errorf("TTLBase %v < 60 s (bornes d'approbation T30)", c.TTLBase)
	case c.OutDir == "" || c.CellID == "":
		return fmt.Errorf("OutDir et CellID requis")
	}
	return nil
}

// Sample est une mesure individuelle — la vérité terrain du harnais (D88).
type Sample struct {
	Tier       string `json:"tier"` // tier1_decision | tier1_baseline | tier1_durability | tier2_decision | tier2_durability
	Op         string `json:"op"`   // evaluate | noop | submit | approve | verify
	DurationNS int64  `json:"duration_ns"`
	TS         int64  `json:"ts"` // horodatage de la mesure (ns epoch)
	// Vérité de menthe (tier1) — le jti/iat/TTL déclaré, connus du harnais
	// par construction, servent à ttl_drift sans jamais lire un payload.
	JTI    string `json:"jti,omitempty"`
	TTLS   int64  `json:"ttl_s,omitempty"`
	Denied bool   `json:"denied,omitempty"` // tier2 verify : refus (= arbitrage humain requis)
}

// Counters agrège le run — la corrélation feuilles ↔ échantillons (D88) et
// arbitration_rate (D89) s'appuient dessus.
type Counters struct {
	Tier1DecisionEvals   uint64 `json:"tier1_decision_evals"`
	Tier1DecisionDenied  uint64 `json:"tier1_decision_denied"`
	Tier1DurabilityEvals uint64 `json:"tier1_durability_evals"`
	Tier2DecVerifyOK     uint64 `json:"tier2_decision_verify_ok"`
	Tier2DecVerifyDenied uint64 `json:"tier2_decision_verify_denied"`
	Tier2DurSubmits      uint64 `json:"tier2_durability_submits"`
	Tier2DurApproves     uint64 `json:"tier2_durability_approves"`
	Tier2DurVerifyOK     uint64 `json:"tier2_durability_verify_ok"`
	Tier2DurVerifyDenied uint64 `json:"tier2_durability_verify_denied"`
	// Attendus de corrélation (D88) : chaque opération du bras durabilité
	// écrit exactement une feuille (T9 : décision ; T30/D64 : submit,
	// approve, consume, refus) — comptés ici, comparés au scan réel.
	LeavesExpectedDecision uint64 `json:"leaves_expected_decision"`
	LeavesExpectedContract uint64 `json:"leaves_expected_contract"`
	CheckpointIntervalMS   int64  `json:"checkpoint_interval_ms"` // référence du seuil durabilité (3×)
}

// Measurements est le fichier measurements.json (D88).
type Measurements struct {
	RunID     string     `json:"run_id"`
	StartedAt time.Time  `json:"started_at"`
	Config    ConfigView `json:"config"`
	Samples   []Sample   `json:"samples"`
	Counters  Counters   `json:"counters"`
}

// ConfigView est la config rendue en unités lisibles dans le JSON.
type ConfigView struct {
	Tier1Samples    int     `json:"tier1_samples"`
	Tier2Plans      int     `json:"tier2_plans"`
	Workers         int     `json:"workers"`
	DurTier1        int     `json:"durability_tier1"`
	DurTier2        int     `json:"durability_tier2"`
	InjectLatencyMS float64 `json:"inject_latency_ms"`
	InjectDenyRate  float64 `json:"inject_deny_rate"`
	TTLStretch      float64 `json:"ttl_stretch"`
	TTLBaseS        int64   `json:"ttl_base_s"`
	OutDir          string  `json:"out_dir"`
}

func configView(c Config) ConfigView {
	return ConfigView{
		Tier1Samples: c.Tier1Samples, Tier2Plans: c.Tier2Plans, Workers: c.Workers,
		DurTier1: c.DurTier1, DurTier2: c.DurTier2,
		InjectLatencyMS: float64(c.InjectLatency) / float64(time.Millisecond),
		InjectDenyRate:  c.InjectDenyRate, TTLStretch: c.TTLStretch,
		TTLBaseS: int64(c.TTLBase / time.Second), OutDir: c.OutDir,
	}
}

// leafRecord est une ligne de leaves_export.json (D88) — UNIQUEMENT ce que
// le registre porte en clair : kind, timestamp, cellID (hash-only, §6.2 :
// jamais de payload, jamais de sel).
type leafRecord struct {
	Seq    uint64 `json:"seq"`
	Kind   byte   `json:"kind"`
	TS     int64  `json:"ts"`
	CellID string `json:"cell_id"`
}

// ---------------------------------------------------------------------------
// Puits de feuilles in-memory du bras « décision » — synchrone (la doctrine
// T9 est intacte : Append est appelé et son erreur niée avant le verdict),
// simplement sans la cadence de publication tessera.
// ---------------------------------------------------------------------------

type memSink struct {
	mu sync.Mutex
	n  uint64
}

func (s *memSink) Append(_ context.Context, _ registry.Leaf) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	return s.n, nil
}

// ---------------------------------------------------------------------------
// Assemblage de la pile — mêmes constructeurs que pepd (T15), OPA nil.
// ---------------------------------------------------------------------------

type pepStack struct {
	listener  http.Handler // listener (avec injection éventuelle) pour /v1/evaluate
	contracts *pep.ContractStore
	issuer    ed25519.PrivateKey
	operator  ed25519.PrivateKey
	policyID  [32]byte
	close     func(context.Context) error // nil pour le bras in-memory
}

var frictionKID = [16]byte{0xF1, 0x27, 0x00, 0x29, 0xA5, 0x5C, 0x3D, 0x8E, 0x71, 0xB4, 0x62, 0x09, 0xDD, 0xE8, 0x43, 0x1A}

// newPEPStack assemble le PEP réel sur le puits de feuilles fourni.
// cellLog nil ⇒ bras « décision » (puits in-memory) ; non nil ⇒ bras
// « durabilité » (registre tessera réel — les feuilles y sont opposables).
func newPEPStack(cfg Config, plans int, leaves interface {
	Append(context.Context, registry.Leaf) (uint64, error)
}, cellLogClose func(context.Context) error) (*pepStack, error) {
	salt := make([]byte, 32) // sel des feuilles — reste dans le process, jamais écrit
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("sel: %w", err)
	}
	fc, err := pep.NewFailClosed(pep.FailClosedOptions{CellID: cfg.CellID, Salt: salt, Leaves: leaves})
	if err != nil {
		return nil, fmt.Errorf("fail-closed: %w", err)
	}
	mc, err := pep.NewModeController(pep.ModeOptions{
		CellID: cfg.CellID, Salt: salt, Leaves: leaves,
		// Quorum vérificateur par comptage, comme pepd en P1 (crypto de
		// quorum : phase ultérieure, couture déjà en place).
		VerifyQuorum: func(_ string, proof pep.QuorumProof) bool { return len(proof.Signatures) >= 1 },
	})
	if err != nil {
		return nil, fmt.Errorf("mode: %w", err)
	}
	ar, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 1 << 20})
	if err != nil {
		return nil, fmt.Errorf("anti-rejeu: %w", err)
	}
	ledger, err := pep.NewQuotaLedger(pep.QuotaLedgerOptions{
		MaxPassports: 1 << 20, CellID: cfg.CellID, Salt: salt, Leaves: leaves,
	})
	if err != nil {
		return nil, fmt.Errorf("quota: %w", err)
	}
	issuer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x27}, 32))
	operator := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, 32))
	policyID := registry.HashPayload([]byte("tbp-friction-policy"), []byte("v1"))
	v, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:     cfg.CellID,
		Keyring:    map[[16]byte]ed25519.PublicKey{frictionKID: issuer.Public().(ed25519.PublicKey)},
		PolicyID:   policyID,
		Salt:       salt,
		Leaves:     leaves,
		AntiReplay: ar,
		Quota:      ledger,
		Gate:       fc,
	})
	if err != nil {
		return nil, fmt.Errorf("validateur: %w", err)
	}
	// OPA nil — pas de réseau, pas de sidecar : le PEP seul (D85).
	l, err := pep.NewListener(pep.ListenerOptions{Validator: v, Mode: mc, Ledger: ledger})
	if err != nil {
		return nil, fmt.Errorf("listener: %w", err)
	}
	contracts, err := pep.NewContractStore(pep.ContractOptions{
		CellID:       cfg.CellID,
		PolicyID:     policyID,
		OperatorKeys: []ed25519.PublicKey{operator.Public().(ed25519.PublicKey)},
		Salt:         salt,
		Leaves:       leaves,
		// Bornes dimensionnées au nombre de plans du run (§4.3 : saturation
		// = refus + alarme, jamais d'éviction — le harnais ne doit pas la
		// déclencher hors test dédié).
		MaxPending:  2 * plans,
		MaxApproved: 2 * plans,
	})
	if err != nil {
		return nil, fmt.Errorf("contrats: %w", err)
	}
	handler := l.Handler()
	if cfg.InjectLatency > 0 {
		// M-harness : dégrade le chemin tier1 APRÈS coup — le harnais doit
		// le voir (mutation léthale du garde-fou de latence).
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(cfg.InjectLatency)
			inner.ServeHTTP(w, r)
		})
	}
	return &pepStack{
		listener: handler, contracts: contracts,
		issuer: issuer, operator: operator, policyID: policyID,
		close: cellLogClose,
	}, nil
}

// ---------------------------------------------------------------------------
// Bras « décision » et baseline — invocations directes, aucun socket (D85).
// ---------------------------------------------------------------------------

// evalRequestBody sérialise le corps /v1/evaluate (même forme que le
// listener T15 : token base64, action, resource, epoch).
func evalRequestBody(token []byte, action, resource string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"token":    base64.StdEncoding.EncodeToString(token),
		"action":   action,
		"resource": resource,
		"epoch":    0,
	})
}

// mintTier1Tokens pré-mente les jetons (hors section chronométrée — la
// menthe est un coût émetteur, pas PEP). Chaque jeton a un jti FRAIS
// (l'anti-rejeu T10 refuse les rejoueurs) et porte son TTL déclaré.
func mintTier1Tokens(st *pepStack, cfg Config, n int) (tokens [][]byte, jtis []string, err error) {
	tokens = make([][]byte, n)
	jtis = make([]string, n)
	now := time.Now()
	ttl := time.Duration(float64(cfg.TTLBase) * cfg.TTLStretch)
	for i := range tokens {
		var jti [16]byte
		if _, err := rand.Read(jti[:]); err != nil {
			return nil, nil, fmt.Errorf("jti: %w", err)
		}
		tok, err := mintToken(st.issuer, mintClaims{
			iss: "tbp-cell-maitresse", sub: cfg.CellID,
			exp: now.Add(ttl).Unix(), iat: now.Add(-time.Second).Unix(),
			jti: jti[:], policyID: st.policyID[:],
			action: "read.list", resource: "registry/docs/42",
			// ClassOut (hors F/I/W) : D87 définit tier1 comme « jeton
			// valide classe hors-FIW » — pas ClassF. Sans effet sur les
			// chiffres mesurés aujourd'hui (le seul branchement sur la
			// classe dans src/pep, failclosed.go, ne teste que ClassW),
			// mais la mesure doit rester fidèle à ce qu'elle prétend
			// exercer plutôt que de dépendre de cette invariance.
			class: int(pep.ClassOut), epoch: 0, version: 1, kid: frictionKID[:],
		})
		if err != nil {
			return nil, nil, fmt.Errorf("menthe %d: %w", i, err)
		}
		tokens[i] = tok
		jtis[i] = hex.EncodeToString(jti[:])
	}
	return tokens, jtis, nil
}

// runTier1 mesure le chemin /v1/evaluate (ou la baseline no-op) avec la
// concurrence configurée. La construction de la requête est DANS la section
// chronométrée pour les deux bras — un overhead identique qui s'annule
// dans la soustraction (D85).
func runTier1(handler http.Handler, tier, op string, tokens [][]byte, jtis []string, ttlS int64, workers int) ([]Sample, error) {
	n := len(tokens)
	bodies := make([][]byte, n)
	for i := range tokens {
		var err error
		bodies[i], err = evalRequestBody(tokens[i], "read.list", "registry/docs/42")
		if err != nil {
			return nil, fmt.Errorf("corps %d: %w", i, err)
		}
	}
	samples := make([]Sample, n)
	var wg sync.WaitGroup
	sem := make(chan int, workers)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- i
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			req := httptest.NewRequest(http.MethodPost, "/v1/evaluate", bytes.NewReader(bodies[i]))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			start := time.Now()
			handler.ServeHTTP(rec, req)
			el := time.Since(start)
			if rec.Code != http.StatusOK {
				// Un refus fail-closed est une faute de harnais, pas un
				// échantillon : le run doit être relu, pas moyenné.
				samples[i] = Sample{Tier: tier, Op: op, DurationNS: -1}
				return
			}
			samples[i] = Sample{
				Tier: tier, Op: op, DurationNS: el.Nanoseconds(), TS: start.UnixNano(),
				JTI: jtis[i], TTLS: ttlS,
			}
		}(i)
	}
	wg.Wait()
	for i := range samples {
		if samples[i].DurationNS < 0 {
			return nil, fmt.Errorf("%s : échantillon %d refusé (statut non 200) — run invalide, pas moyenné", tier, i)
		}
	}
	return samples, nil
}

// baselineHandler répond 200 sans rien faire — la soustraction D85 :
// latence ajoutée = pXX(PEP) − pXX(baseline).
func baselineHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
}

// ---------------------------------------------------------------------------
// Tier2 — contrat de plan (T30) piloté en appels Go directs (revue #29 :
// Submit/Approve/VerifyStep sur pep.ContractStore, jamais par le broker —
// la mesure isole le PEP, hors traducteur/quorum/enveloppe).
// ---------------------------------------------------------------------------

// runTier2 exécute les flux de plans complets (soumission → approbation
// signée Ed25519 de l'opérateur → vérification d'étape) et chronomètre
// chaque phase. InjectDenyRate force des déviations (M-arbitrage) : chaque
// refus de VerifyStep est une action renvoyée à l'arbitrage humain.
func runTier2(st *pepStack, cfg Config, tier string, plans int) (samples []Sample, verifyOK, verifyDenied uint64, err error) {
	samples = make([]Sample, 0, 3*plans)
	ctx := context.Background()
	params := []byte(`{"limit":10}`)
	// Injection de déviations exacte et déterministe à tout N (accumulateur
	// amorcé à 0,5 : round(N×rate) refus répartis, pas floor — sinon les
	// petits runs à faible taux n'en produiraient jamais).
	denyAcc := 0.5
	for i := 0; i < plans; i++ {
		step := pep.PlanStep{
			Action:     "storage.write",
			Resource:   fmt.Sprintf("registry/docs/%d", i),
			ParamsHash: pep.HashParams(params),
		}
		// Soumission (tracée KindContract, D64).
		start := time.Now()
		hash, err := st.contracts.Submit(ctx, []pep.PlanStep{step})
		if err != nil {
			return nil, 0, 0, fmt.Errorf("submit plan %d: %w", i, err)
		}
		samples = append(samples, Sample{Tier: tier, Op: "submit", DurationNS: time.Since(start).Nanoseconds(), TS: start.UnixNano()})
		// Approbation opérateur — signature Ed25519 sur le canal opérateur
		// (§4.2 : l'arbitrage est une signature, pas un clic console).
		expiry := time.Now().Add(30 * time.Minute)
		sig := ed25519.Sign(st.operator, pep.ApprovalMessage(hash, expiry))
		start = time.Now()
		if err := st.contracts.Approve(ctx, hash, expiry, sig); err != nil {
			return nil, 0, 0, fmt.Errorf("approve plan %d: %w", i, err)
		}
		samples = append(samples, Sample{Tier: tier, Op: "approve", DurationNS: time.Since(start).Nanoseconds(), TS: start.UnixNano()})
		// Vérification d'étape — déviation injectée selon InjectDenyRate.
		resource := step.Resource
		denyAcc += cfg.InjectDenyRate
		denied := denyAcc >= 1
		if denied {
			denyAcc -= 1
			resource = step.Resource + "/deviation"
		}
		binding, err := pep.BuildBinding(hash, params)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("binding plan %d: %w", i, err)
		}
		start = time.Now()
		_, verr := st.contracts.VerifyStep(ctx, binding, step.Action, resource)
		el := time.Since(start)
		if denied && verr == nil {
			return nil, 0, 0, fmt.Errorf("plan %d : déviation injectée acceptée — harnais invalide", i)
		}
		if !denied && verr != nil {
			return nil, 0, 0, fmt.Errorf("plan %d : étape nominale refusée : %w", i, verr)
		}
		samples = append(samples, Sample{Tier: tier, Op: "verify", DurationNS: el.Nanoseconds(), TS: start.UnixNano(), Denied: denied})
		if denied {
			verifyDenied++
		} else {
			verifyOK++
		}
	}
	return samples, verifyOK, verifyDenied, nil
}

// ---------------------------------------------------------------------------
// Scan des feuilles réelles (D88) — via le ChainWatcher de supervision
// (lecteur tessera vérifié et indépendant, revue #29 : pas de deuxième
// implémentation du format).
// ---------------------------------------------------------------------------

func exportLeaves(ctx context.Context, cfg Config, regDir, origin string) ([]leafRecord, error) {
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		return nil, fmt.Errorf("clé de vérification: %w", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		return nil, fmt.Errorf("verifier: %w", err)
	}
	boot, w, err := supervision.NewChainWatcher(ctx, cfg.CellID, regDir, origin, verifier, 0)
	if err != nil {
		return nil, fmt.Errorf("chain watcher: %w", err)
	}
	more, err := w.Tick(ctx)
	if err != nil {
		return nil, fmt.Errorf("tick: %w", err)
	}
	all := append(boot, more...)
	recs := make([]leafRecord, len(all))
	for i, l := range all {
		recs[i] = leafRecord{Seq: uint64(i), Kind: l.Kind, TS: l.Timestamp, CellID: l.CellID}
	}
	return recs, nil
}

// ---------------------------------------------------------------------------
// Run complet — orchestration des bras, exports (D88).
// ---------------------------------------------------------------------------

// registryOrigin est l'origine (nom de clé note) du log du harnais.
func registryOrigin(cfg Config) string { return "tbp/registry/" + cfg.CellID }

// openRealRegistry ouvre (ou crée) le registre tessera du bras durabilité
// dans OutDir/registry — conservé entre les phases run et leaf-report (D90).
// La paire de clés note suit le motif pepd : cell_log.key (privée) +
// cell_log.vkey (publique) — artefacts locaux, gitignorés avec out/.
func openRealRegistry(ctx context.Context, cfg Config) (*registry.CellLog, string, error) {
	regDir := filepath.Join(cfg.OutDir, "registry")
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		return nil, "", fmt.Errorf("registry dir: %w", err)
	}
	origin := registryOrigin(cfg)
	signer, err := registry.LoadSigner(regDir)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("signer: %w", err)
		}
		skey, vkey, gerr := registry.GenerateCellKey(origin)
		if gerr != nil {
			return nil, "", fmt.Errorf("clé de cellule: %w", gerr)
		}
		if serr := registry.SaveSignerKey(regDir, skey); serr != nil {
			return nil, "", fmt.Errorf("sauvegarde clé: %w", serr)
		}
		if werr := os.WriteFile(filepath.Join(regDir, "cell_log.vkey"), []byte(vkey), 0o644); werr != nil {
			return nil, "", fmt.Errorf("sauvegarde vkey: %w", werr)
		}
		if signer, err = registry.LoadSigner(regDir); err != nil {
			return nil, "", fmt.Errorf("signer: %w", err)
		}
	}
	vkeyB, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		return nil, "", fmt.Errorf("clé de vérification: %w", err)
	}
	verifier, err := registry.NewVerifier(string(vkeyB))
	if err != nil {
		return nil, "", fmt.Errorf("verifier: %w", err)
	}
	cellLog, err := registry.Open(ctx, registry.Options{Dir: regDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return nil, "", fmt.Errorf("cell log: %w", err)
	}
	return cellLog, regDir, nil
}

// Run exécute le harnais complet et écrit measurements.json +
// leaves_export.json dans cfg.OutDir. Le verdict de seuil appartient à
// leading_indicators.py (D89/D91) — Run ne tranche pas, il mesure.
func Run(ctx context.Context, cfg Config) (*Measurements, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("out dir: %w", err)
	}
	m := &Measurements{
		RunID:     fmt.Sprintf("friction-%d", time.Now().UnixNano()),
		StartedAt: time.Now().UTC(),
		Config:    configView(cfg),
	}
	var ctr Counters
	ctr.CheckpointIntervalMS = posixCheckpointFloor.Milliseconds()

	// --- Bras « décision » (in-memory) — seuil bloquant §9.1 (D88 amendé).
	stDec, err := newPEPStack(cfg, cfg.Tier2Plans, &memSink{}, nil)
	if err != nil {
		return nil, fmt.Errorf("pile décision: %w", err)
	}
	ttlS := int64(time.Duration(float64(cfg.TTLBase)*cfg.TTLStretch) / time.Second)
	tokens, jtis, err := mintTier1Tokens(stDec, cfg, cfg.Tier1Samples)
	if err != nil {
		return nil, err
	}
	// Passe de chauffe, échantillons jetés : §9.1 budgète le régime établi,
	// pas le démarrage à froid (init CBOR/COSE, croissance des tables) —
	// la production, elle, chauffe une fois puis sert des millions de
	// décisions. Jetons de chauffe dédiés (jti frais, anti-rejeu intact).
	warmN := cfg.Tier1Samples / 10
	if warmN > 64 {
		warmN = 64
	}
	warmTok, warmJti, err := mintTier1Tokens(stDec, cfg, warmN)
	if err != nil {
		return nil, err
	}
	if _, err := runTier1(stDec.listener, "tier1_warmup", "evaluate", warmTok, warmJti, ttlS, cfg.Workers); err != nil {
		return nil, fmt.Errorf("chauffe: %w", err)
	}
	t1, err := runTier1(stDec.listener, "tier1_decision", "evaluate", tokens, jtis, ttlS, cfg.Workers)
	if err != nil {
		return nil, err
	}
	m.Samples = append(m.Samples, t1...)
	ctr.Tier1DecisionEvals = uint64(len(t1))
	// Baseline no-op — même forme de requête, même concurrence.
	base, err := runTier1(baselineHandler(), "tier1_baseline", "noop", tokens, jtis, ttlS, cfg.Workers)
	if err != nil {
		return nil, err
	}
	m.Samples = append(m.Samples, base...)
	// Tier2 décision (in-memory).
	t2dec, decOK, decDenied, err := runTier2(stDec, cfg, "tier2_decision", cfg.Tier2Plans)
	if err != nil {
		return nil, err
	}
	m.Samples = append(m.Samples, t2dec...)
	ctr.Tier2DecVerifyOK = decOK
	ctr.Tier2DecVerifyDenied = decDenied

	// --- Bras « durabilité » (registre tessera réel) — feuilles opposables
	// pour la corrélation (D88) ; mesure le coût de la preuve fail-closed
	// en mode sync (#71 arbitré par T38 : borne pire cas, hors budget §9.1).
	cellLog, regDir, err := openRealRegistry(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pile durabilité: %w", err)
	}
	stDur, err := newPEPStack(cfg, cfg.DurTier2, cellLog, cellLog.Close)
	if err != nil {
		return nil, fmt.Errorf("pile durabilité: %w", err)
	}
	tokensDur, jtisDur, err := mintTier1Tokens(stDur, cfg, cfg.DurTier1)
	if err != nil {
		return nil, err
	}
	t1d, err := runTier1(stDur.listener, "tier1_durability", "evaluate", tokensDur, jtisDur, ttlS, cfg.Workers)
	if err != nil {
		return nil, err
	}
	m.Samples = append(m.Samples, t1d...)
	ctr.Tier1DurabilityEvals = uint64(len(t1d))
	t2dur, durOK, durDenied, err := runTier2(stDur, cfg, "tier2_durability", cfg.DurTier2)
	if err != nil {
		return nil, err
	}
	m.Samples = append(m.Samples, t2dur...)
	ctr.Tier2DurSubmits = uint64(cfg.DurTier2)
	ctr.Tier2DurApproves = uint64(cfg.DurTier2)
	ctr.Tier2DurVerifyOK = durOK
	ctr.Tier2DurVerifyDenied = durDenied
	// Attendus de corrélation : 1 feuille KindDecision par évaluation du
	// bras durabilité ; 1 KindContract par submit/approve/verify(ok+refus).
	ctr.LeavesExpectedDecision = ctr.Tier1DurabilityEvals
	ctr.LeavesExpectedContract = ctr.Tier2DurSubmits + ctr.Tier2DurApproves + ctr.Tier2DurVerifyOK + ctr.Tier2DurVerifyDenied

	// Fermeture propre du registre AVANT le scan (publication drainée).
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := cellLog.Close(closeCtx); err != nil {
		cancel()
		return nil, fmt.Errorf("fermeture registre: %w", err)
	}
	cancel()
	m.Counters = ctr

	// --- Export des feuilles réelles (D88) — scan vérifié (ChainWatcher).
	leaves, err := exportLeaves(ctx, cfg, regDir, registryOrigin(cfg))
	if err != nil {
		return nil, fmt.Errorf("export feuilles: %w", err)
	}

	if err := writeJSONFile(filepath.Join(cfg.OutDir, "measurements.json"), m); err != nil {
		return nil, err
	}
	if err := writeJSONFile(filepath.Join(cfg.OutDir, "leaves_export.json"), leaves); err != nil {
		return nil, err
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// D90 — alarme leafée : le rapport de friction est inscrit comme feuille
// KindTelemetry (hash salé ; le sel du harnais reste local, jamais commité).
// ---------------------------------------------------------------------------

// LeafReport inscrit friction_report.json comme feuille KindTelemetry du
// registre du run, puis VÉRIFIE par un scan vérifié que la feuille est
// lisible (non-vacuole : taille +1 et kind exact). Rend l'index de la
// feuille inscrite.
func LeafReport(ctx context.Context, cfg Config, reportPath string) (uint64, error) {
	report, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, fmt.Errorf("rapport: %w", err)
	}
	cellLog, regDir, err := openRealRegistry(ctx, cfg) // rouvre le log du run
	if err != nil {
		return 0, err
	}
	reportSalt := make([]byte, 32) // ≥ 16 octets — reste chez le producteur (§6.2)
	if _, err := rand.Read(reportSalt); err != nil {
		return 0, fmt.Errorf("sel rapport: %w", err)
	}
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      cfg.CellID,
		PayloadHash: registry.HashPayload(reportSalt, report),
		Timestamp:   time.Now().UTC().UnixNano(),
	}
	idx, err := cellLog.Append(ctx, leaf)
	if err != nil {
		return 0, fmt.Errorf("feuille rapport: %w", err)
	}
	// Le sel est conservé à côté du rapport (artefact local gitignoré) pour
	// la preuve d'audit ultérieure — jamais dans le registre ni le dépôt.
	if err := os.WriteFile(filepath.Join(cfg.OutDir, "report_salt.hex"), []byte(hex.EncodeToString(reportSalt)), 0o600); err != nil {
		return 0, fmt.Errorf("sel rapport: %w", err)
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := cellLog.Close(closeCtx); err != nil {
		return 0, fmt.Errorf("fermeture registre: %w", err)
	}
	// Vérification non vacuole : la feuille du rapport est relue et
	// contrôlée (kind, position) par le lecteur indépendant.
	leaves, err := exportLeaves(ctx, cfg, regDir, registryOrigin(cfg))
	if err != nil {
		return 0, err
	}
	if uint64(len(leaves)) != idx+1 {
		return 0, fmt.Errorf("feuille rapport : taille %d ≠ index+1 %d", len(leaves), idx+1)
	}
	if leaves[idx].Kind != registry.KindTelemetry {
		return 0, fmt.Errorf("feuille rapport : kind %d ≠ KindTelemetry", leaves[idx].Kind)
	}
	return idx, nil
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

func writeJSONFile(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// percentileNearestRank : même méthode que leading_indicators.py (rang le
// plus proche) — les deux implémentations ne doivent jamais diverger.
func percentileNearestRank(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// summarize trie et rend p50/p95/p99 pour le résumé de log (le verdict de
// seuil reste à leading_indicators.py).
func summarize(samples []Sample) (p50, p95, p99 time.Duration) {
	d := make([]int64, len(samples))
	for i, s := range samples {
		d[i] = s.DurationNS
	}
	sort.Slice(d, func(a, b int) bool { return d[a] < d[b] })
	return time.Duration(percentileNearestRank(d, 0.50)),
		time.Duration(percentileNearestRank(d, 0.95)),
		time.Duration(percentileNearestRank(d, 0.99))
}
