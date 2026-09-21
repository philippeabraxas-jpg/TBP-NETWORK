// supervisord est le démon de supervision (T37, issue #74) : il ASSEMBLE
// les bibliothèques existantes — watchers (T34a), moniteur (T34/T34b),
// console (T34c) — en un service installable, comme pepd assemble le PEP.
// Aucune logique métier ici : la vérification des chaînes vit dans
// src/supervision, le registre du moniteur dans src/registry.
//
// Doctrine §2/§7.1 : le moniteur est une cellule à périmètre élargi —
// sa PROPRE chaîne, sa PROPRE clé de checkpoint, et il n'écrit JAMAIS
// dans les chaînes surveillées (ChainWatcher est lecture seule par
// construction ; rien ici ne peut lui donner un accès en écriture).
//
// Rôle du démon dans le patron Monitor : le Monitor n'a volontairement
// PAS de goroutine propre (« la cadence est un choix de déploiement ») —
// supervisord EST le driver : une boucle ticker appelle CheckOnce.
//
// Bascule automatique (T34b) : Trigger NIL en v1 — chaque chute confirmée
// est un refus feuillé avec escalade humaine (failover.go), jamais une
// bascule silencieuse. La couture automatique reste #30
// (PromotionController), hors scope de cette issue.
//
// Console (T34c) : servie sur socket Unix avec le Monitor local comme
// source des vues cellules, et trois adaptateurs de lecture LIVE
// (ci-dessous) vers les endpoints GET-only du brokerd de la cellule
// (T37, D109) pour les sources qui vivent sur la machine cellule
// (époque, compteurs, file d'arbitrage). HONNÊTETE PAR CONTRAT (D110
// élargi après revue de plan) : chaque méthode d'adaptateur refetch à
// l'appel et PORTE son erreur — les handlers de la console la traduisent
// en 503 {"error":"source indisponible"} PAR ROUTE, jamais en
// zero-value. Pas de cache (une valeur figée serait une demi-vérité),
// pas de middleware global (il sur-refuserait les routes qui ne
// dépendent pas de la source en panne). L'exposition réseau
// inter-cellules est une autre issue (T35).
//
// Configuration par variables d'environnement (toutes requises sauf
// mention contraire) :
//
//	TBP_MONITOR_CELL_ID      identité du moniteur (ex. monitor-01)
//	TBP_SALT                 sel des feuilles, hex ≥ 32 caractères (§6.2)
//	TBP_REGISTRY_DIR         répertoire du CellLog du MONITEUR (sa chaîne)
//	TBP_CELLS_FILE           JSON des chaînes surveillées :
//	                         {"cells":[{"cell_id","log_dir","origin",
//	                           "vkey_file","manifest_dir"}…],
//	                          "master":{"cell_id","log_dir","origin",
//	                           "vkey_file"}}
//	                         — clés PUBLIQUES de checkpoint seulement
//	                         (custody D97 : le .vkey suffit au scan vérifié)
//	TBP_CELL_BROKER_SOCKET   socket Unix du brokerd de la cellule (sources
//	                         de console : /v1/supervision/* — T37, D109)
//	TBP_TICK_MS              cadence CheckOnce — défaut 5000, [1000, 60000]
//	TBP_CONSOLE_SOCKET       défaut /run/tbp/supervision.sock
//
// Doctrine §1 : le moindre défaut de configuration est FATAL au démarrage,
// et un brokerd de cellule injoignable AU DÉMARRAGE est fatal aussi
// (fail-closed : pas de console dont les sources sont mortes).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

// Défauts du démon.
const (
	defaultConsoleSocket = "/run/tbp/supervision.sock"
	defaultTickMs        = 5000
	minTickMs            = 1000
	maxTickMs            = 60000
	readHeaderTimeout    = 5 * time.Second
	sourceTimeout        = 10 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		log.Fatalf("supervisord: %v", err)
	}
}

// config est la configuration validée du démon (fail-closed §1).
type config struct {
	monitorCellID string
	salt          []byte
	registryDir   string
	cellsFile     string
	brokerSocket  string
	tick          time.Duration
	consoleSocket string
}

func loadConfig(getenv func(string) string) (*config, error) {
	monitorCellID, err := envRequired(getenv, "TBP_MONITOR_CELL_ID")
	if err != nil {
		return nil, err
	}
	salt, err := envHex(getenv, "TBP_SALT", 16)
	if err != nil {
		return nil, err
	}
	registryDir, err := envRequired(getenv, "TBP_REGISTRY_DIR")
	if err != nil {
		return nil, err
	}
	cellsFile, err := envRequired(getenv, "TBP_CELLS_FILE")
	if err != nil {
		return nil, err
	}
	brokerSocket, err := envRequired(getenv, "TBP_CELL_BROKER_SOCKET")
	if err != nil {
		return nil, err
	}
	tick := time.Duration(defaultTickMs) * time.Millisecond
	if s := getenv("TBP_TICK_MS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < minTickMs || n > maxTickMs {
			return nil, fmt.Errorf("TBP_TICK_MS hors bornes [%d, %d] : %q", minTickMs, maxTickMs, s)
		}
		tick = time.Duration(n) * time.Millisecond
	}
	consoleSocket := getenv("TBP_CONSOLE_SOCKET")
	if consoleSocket == "" {
		consoleSocket = defaultConsoleSocket
	}
	return &config{
		monitorCellID: monitorCellID,
		salt:          salt,
		registryDir:   registryDir,
		cellsFile:     cellsFile,
		brokerSocket:  brokerSocket,
		tick:          tick,
		consoleSocket: consoleSocket,
	}, nil
}

// cellsFileJSON est le fichier des chaînes surveillées.
type cellsFileJSON struct {
	Cells []struct {
		CellID      string `json:"cell_id"`
		LogDir      string `json:"log_dir"`
		Origin      string `json:"origin"`
		VkeyFile    string `json:"vkey_file"`
		ManifestDir string `json:"manifest_dir"`
	} `json:"cells"`
	Master struct {
		CellID   string `json:"cell_id"`
		LogDir   string `json:"log_dir"`
		Origin   string `json:"origin"`
		VkeyFile string `json:"vkey_file"`
	} `json:"master"`
}

// loadCells charge les spécifications de chaînes — chaque vkey est lue et
// validée ICI (fail-closed : une clé illisible est une erreur de
// démarrage, pas une chaîne « en attente »).
func loadCells(path string) ([]supervision.CellSpec, supervision.MasterSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, supervision.MasterSpec{}, fmt.Errorf("cells file: %w", err)
	}
	var cf cellsFileJSON
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, supervision.MasterSpec{}, fmt.Errorf("cells file JSON: %w", err)
	}
	if len(cf.Cells) == 0 {
		return nil, supervision.MasterSpec{}, errors.New("cells file : au moins une cellule à surveiller (§5.3)")
	}
	loadVkey := func(p string) (note.Verifier, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("vkey %s: %w", p, err)
		}
		v, err := registry.NewVerifier(string(b))
		if err != nil {
			return nil, fmt.Errorf("vkey %s: %w", p, err)
		}
		return v, nil
	}
	cells := make([]supervision.CellSpec, 0, len(cf.Cells))
	for _, c := range cf.Cells {
		v, err := loadVkey(c.VkeyFile)
		if err != nil {
			return nil, supervision.MasterSpec{}, err
		}
		cells = append(cells, supervision.CellSpec{
			CellID: c.CellID, LogDir: c.LogDir, Origin: c.Origin,
			Verifier: v, ManifestDir: c.ManifestDir,
		})
	}
	mv, err := loadVkey(cf.Master.VkeyFile)
	if err != nil {
		return nil, supervision.MasterSpec{}, err
	}
	master := supervision.MasterSpec{
		CellID: cf.Master.CellID, LogDir: cf.Master.LogDir,
		Origin: cf.Master.Origin, Verifier: mv,
	}
	return cells, master, nil
}

func run(ctx context.Context, getenv func(string) string) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	cells, master, err := loadCells(cfg.cellsFile)
	if err != nil {
		return err
	}

	// Chaîne PROPRE du moniteur (§7.1) : il feuille comme toute cellule.
	if err := os.MkdirAll(cfg.registryDir, 0o700); err != nil {
		return fmt.Errorf("registry dir: %w", err)
	}
	signer, vkey, err := loadOrGenerateCellKey(cfg.registryDir, cfg.monitorCellID)
	if err != nil {
		return err
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		return fmt.Errorf("note verifier: %w", err)
	}
	monLog, err := registry.Open(ctx, registry.Options{
		Dir: cfg.registryDir, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("monitor log: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := monLog.Close(closeCtx); err != nil {
			log.Printf("supervisord: fermeture du registre: %v", err)
		}
	}()

	monitor, err := supervision.NewMonitor(ctx, supervision.MonitorOptions{
		MonitorCellID: cfg.monitorCellID,
		Log:           monLog,
		Cells:         cells,
		Master:        master,
		// Trigger NIL (T34b, v1) : chute confirmée ⇒ refus feuillé +
		// escalade humaine — la bascule automatique est la couture #30,
		// hors scope de cette issue. Sink : notification seule — la
		// feuille KindSupervision est déjà écrite sans lui (§5.3).
		Trigger: nil,
		Sink: supervision.AlarmSinkFunc(func(_ context.Context, a supervision.Alert) error {
			log.Printf("supervisord: ALERTE event=%d cellule=%s raison=%s",
				a.Record.Event, a.Record.CellID, a.Record.Reason)
			return nil
		}),
	})
	if err != nil {
		return fmt.Errorf("monitor: %w", err)
	}

	// Sources de console : adaptateurs de lecture LIVE vers le brokerd
	// de la cellule (D109/D110 élargi après revue) — chaque méthode
	// refetch à l'appel et PORTE son erreur ; les handlers de la console
	// la traduisent en 503 par route. Pas de middleware global (il
	// sur-refuse : /v1/epoch ne dépend pas des compteurs broker), pas
	// de cache (une zero-value figée serait une demi-vérité). Sonde de
	// démarrage fail-closed : broker injoignable ⇒ refus de démarrer.
	sources := newBrokerSources(cfg.brokerSocket)
	if err := sources.probe(); err != nil {
		return fmt.Errorf("sources de console injoignables au démarrage (brokerd de la cellule sur %s): %w", cfg.brokerSocket, err)
	}
	console, err := supervision.NewConsole(supervision.ConsoleOptions{
		Monitor:   monitor,
		Contracts: sources.arbitration,
		Epochs:    sources.epoch,
		Stats:     sources.stats,
	})
	if err != nil {
		return err
	}

	// Driver de cadence (le Monitor n'a pas de goroutine propre — c'est
	// ICI que la latence de détection se règle).
	go func() {
		ticker := time.NewTicker(cfg.tick)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := monitor.CheckOnce(ctx); err != nil {
					log.Printf("supervisord: faute du moniteur lui-même: %v", err)
				}
			}
		}
	}()

	// Console servie directement : l'honnêteté est dans le CONTRAT des
	// sources (erreur ⇒ 503 par handler), pas dans un middleware.
	if err := os.MkdirAll(filepath.Dir(cfg.consoleSocket), 0o750); err != nil {
		return fmt.Errorf("socket dir: %w", err)
	}
	lis, err := broker.ListenUnix(cfg.consoleSocket)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: console.Handler(), ReadHeaderTimeout: readHeaderTimeout}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	log.Printf("supervisord: moniteur %s — %d cellule(s) + master surveillés (tick %s), console sur unix://%s",
		cfg.monitorCellID, len(cells), cfg.tick, cfg.consoleSocket)
	if err := httpSrv.Serve(lis); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// — Adaptateurs de lecture LIVE vers brokerd (D109/D110 élargi après
// revue de plan) —
//
// Chaque méthode refetch à CHAQUE appel et rend son erreur au handler :
// l'erreur est un FAIT de la source, le handler la traduit en 503 pour
// SA route — jamais une zero-value, jamais un cache qui fige une
// demi-vérité (§1). L'interface ne porte pas de contexte : l'appel HTTP
// est borné par le timeout du client (sourceTimeout).

// brokerSources regroupe les trois adaptateurs et leur client HTTP.
type brokerSources struct {
	epoch       *epochSource
	stats       *statsSource
	arbitration *arbitrationSource
}

func newBrokerSources(brokerSocket string) *brokerSources {
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: sourceTimeout}).DialContext(ctx, "unix", brokerSocket)
			},
		},
		Timeout: sourceTimeout,
	}
	base := "http://brokerd" // hôte ignoré — le dial est Unix
	return &brokerSources{
		epoch:       &epochSource{hc: hc, base: base},
		stats:       &statsSource{hc: hc, base: base},
		arbitration: &arbitrationSource{hc: hc, base: base},
	}
}

// probe vérifie les trois sources AU DÉMARRAGE (fail-closed §1 : pas de
// console dont les sources sont mortes à la naissance). En cours de
// route, l'honnêteté est portée par le contrat d'erreur des adaptateurs.
func (p *brokerSources) probe() error {
	if _, err := p.epoch.Status(); err != nil {
		return fmt.Errorf("source époque: %w", err)
	}
	if _, err := p.stats.Stats(); err != nil {
		return fmt.Errorf("source compteurs: %w", err)
	}
	if _, err := p.arbitration.Snapshot(); err != nil {
		return fmt.Errorf("source arbitrage: %w", err)
	}
	return nil
}

// getJSON lit une vue JSON du brokerd (corps borné — les vues D109 sont
// bornées par construction : file et état bornés §4.3).
func getJSON(ctx context.Context, hc *http.Client, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("statut %d", resp.StatusCode)
	}
	return json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 1<<20)).Decode(dst)
}

// epochSource adapte GET /v1/supervision/epoch à EpochStatusSource —
// lecture LIVE à chaque appel (pas de cache : l'état d'époque change).
type epochSource struct {
	hc   *http.Client
	base string
}

func (s *epochSource) Status() (cluster.TrackerStatus, error) {
	var view struct {
		Epoch             int       `json:"epoch"`
		Authority         string    `json:"authority"`
		NotBefore         time.Time `json:"not_before"`
		ExpiresAt         time.Time `json:"expires_at"`
		Quarantined       []string  `json:"quarantined"`
		AutoFailoversHour int       `json:"auto_failovers_hour"`
	}
	if err := getJSON(context.Background(), s.hc, s.base+"/v1/supervision/epoch", &view); err != nil {
		return cluster.TrackerStatus{}, err // jamais une zero-value (§1)
	}
	return cluster.TrackerStatus{
		Epoch: view.Epoch, Authority: view.Authority,
		NotBefore: view.NotBefore, ExpiresAt: view.ExpiresAt,
		Quarantined: view.Quarantined, AutoFailoversHour: view.AutoFailoversHour,
	}, nil
}

// statsSource adapte GET /v1/supervision/stats à BrokerStatsSource —
// lecture LIVE à chaque appel (les compteurs bougent).
type statsSource struct {
	hc   *http.Client
	base string
}

func (s *statsSource) Stats() (broker.BrokerStats, error) {
	var view struct {
		Requests            uint64 `json:"requests"`
		Allows              uint64 `json:"allows"`
		Denies              uint64 `json:"denies"`
		TranslationFailures uint64 `json:"translation_failures"`
		EnvelopeEvals       uint64 `json:"envelope_evals"`
		EnvelopeDenies      uint64 `json:"envelope_denies"`
		QuorumDenies        uint64 `json:"quorum_denies"`
		PlanDenies          uint64 `json:"plan_denies"`
		IssuanceFailures    uint64 `json:"issuance_failures"`
		LeafFailures        uint64 `json:"leaf_failures"`
	}
	if err := getJSON(context.Background(), s.hc, s.base+"/v1/supervision/stats", &view); err != nil {
		return broker.BrokerStats{}, err // jamais une zero-value (§1)
	}
	return broker.BrokerStats{
		Requests: view.Requests, Allows: view.Allows, Denies: view.Denies,
		TranslationFailures: view.TranslationFailures,
		EnvelopeEvals:       view.EnvelopeEvals, EnvelopeDenies: view.EnvelopeDenies,
		QuorumDenies: view.QuorumDenies, PlanDenies: view.PlanDenies,
		IssuanceFailures: view.IssuanceFailures, LeafFailures: view.LeafFailures,
	}, nil
}

// arbitrationSource adapte GET /v1/supervision/arbitration à
// ArbitrationSource (D110 élargi) — lecture LIVE à chaque appel.
// PolicyID rend la policy du DERNIER Snapshot réussi (contrat de
// l'interface : le handler appelle Snapshot en premier et ne lit
// PolicyID qu'après succès — les deux valeurs viennent du même
// instantané, jamais de deux lectures disjointes).
type arbitrationSource struct {
	hc   *http.Client
	base string

	mu       sync.Mutex
	policyID [32]byte
}

func (s *arbitrationSource) Snapshot() ([]pep.PendingPlan, error) {
	var view struct {
		PolicyID string `json:"policy_id"`
		Pending  []struct {
			Hash        string    `json:"hash"`
			SubmittedAt time.Time `json:"submitted_at"`
			ExpiresAt   time.Time `json:"expires_at"`
			Steps       int       `json:"steps"`
		} `json:"pending"`
	}
	if err := getJSON(context.Background(), s.hc, s.base+"/v1/supervision/arbitration", &view); err != nil {
		return nil, err // jamais une zero-value (§1)
	}
	policyBytes, err := hex.DecodeString(view.PolicyID)
	if err != nil || len(policyBytes) != 32 {
		return nil, fmt.Errorf("policy_id illisible (%d octets)", len(policyBytes))
	}
	pending := make([]pep.PendingPlan, 0, len(view.Pending))
	for _, p := range view.Pending {
		hashBytes, err := hex.DecodeString(p.Hash)
		if err != nil || len(hashBytes) != 32 {
			return nil, fmt.Errorf("hash de plan illisible (%d octets)", len(hashBytes))
		}
		var h [32]byte
		copy(h[:], hashBytes)
		pending = append(pending, pep.PendingPlan{
			Hash: h, SubmittedAt: p.SubmittedAt, ExpiresAt: p.ExpiresAt, Steps: p.Steps,
		})
	}
	var policy [32]byte
	copy(policy[:], policyBytes)
	s.mu.Lock()
	s.policyID = policy
	s.mu.Unlock()
	return pending, nil
}

func (s *arbitrationSource) PolicyID() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyID
}

// — Chargements fail-closed —

func envRequired(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s requis", name)
	}
	return v, nil
}

func envHex(getenv func(string) string, name string, minBytes int) ([]byte, error) {
	s, err := envRequired(getenv, name)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) < minBytes {
		return nil, fmt.Errorf("%s : hex ≥ %d octets requis", name, minBytes)
	}
	return b, nil
}

// loadOrGenerateCellKey — même motif que pepd (T15) et brokerd (T37) :
// clef signante 0600 créée au premier démarrage, rechargée ensuite ;
// toute incohérence est fatale (§1). Duplication d'assemblage assumée.
func loadOrGenerateCellKey(dir, cellID string) (note.Signer, string, error) {
	vkeyPath := filepath.Join(dir, "cell_log.vkey")
	signer, err := registry.LoadSigner(dir)
	if err == nil {
		vkeyB, rerr := os.ReadFile(vkeyPath)
		if rerr != nil {
			return nil, "", fmt.Errorf("clef de vérification illisible: %w", rerr)
		}
		return signer, string(vkeyB), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	skey, vkey, gerr := registry.GenerateCellKey(cellID)
	if gerr != nil {
		return nil, "", gerr
	}
	if serr := registry.SaveSignerKey(dir, skey); serr != nil {
		return nil, "", serr
	}
	if werr := os.WriteFile(vkeyPath, []byte(vkey), 0o644); werr != nil {
		return nil, "", werr
	}
	ns, nerr := note.NewSigner(skey)
	if nerr != nil {
		return nil, "", nerr
	}
	return ns, vkey, nil
}
