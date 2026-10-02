package main

// telemetry.go — la télémétrie anti-dribble de pepd (§4.1-bis, #275 suite).
//
// OPT-IN : TBP_TELEMETRY=1 fait tourner dans pepd le pipeline src/telemetry — exporteur de métadonnées de
// passeport (les compteurs monotones du QuotaLedger : jamais le contenu d'un flux) → agrégateur à fenêtres
// (une feuille « TBAG1 » par fenêtre scellée, y compris vide) + détecteur anti-dribble (feuille « TBAD1 »
// sur alerte) + rétention locale des bruts à TTL (feuille « TBRP1 » par purge). Chaque feuille laisse son
// clair dans le journal d'enregistrements AVANT d'être inscrite : sans clair, pas de feuille, et l'échec
// est une ALARME (log), jamais un silence. Detect, pas prevent : une alerte n'interrompt aucun flux.
//
//	TBP_TELEMETRY              « 1 » active ; absent ou « 0 » : rien ne tourne
//	TBP_TELEMETRY_INTERVAL_MS  cadence d'export, [1000, 3600000], défaut 10000
//	TBP_TELEMETRY_WINDOW_S     fenêtre d'agrégation, [1, 3600], défaut 60
//	TBP_TELEMETRY_COLLECTOR    optionnel — « hôte:port » UDP d'un collecteur IPFIX local ; absent : pas
//	                           d'envoi fil, les feuilles restent produites (la preuve ne dépend pas du fil)
//
// Un TBP_TELEMETRY_* sans TBP_TELEMETRY=1 est une incohérence de configuration : refus de démarrer.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	telemetry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/telemetry"
)

type telemetryConfig struct {
	enabled   bool
	interval  time.Duration
	window    time.Duration
	collector string
}

// telemetryFromEnv lit et valide TBP_TELEMETRY* — fail-closed.
func telemetryFromEnv(getenv func(string) string) (telemetryConfig, error) {
	cfg := telemetryConfig{interval: telemetry.DefaultPipelineInterval, window: time.Minute}
	knobs := []string{"TBP_TELEMETRY_INTERVAL_MS", "TBP_TELEMETRY_WINDOW_S", "TBP_TELEMETRY_COLLECTOR"}
	switch v := getenv("TBP_TELEMETRY"); v {
	case "", "0":
		for _, k := range knobs {
			if getenv(k) != "" {
				return cfg, fmt.Errorf("%s sans TBP_TELEMETRY=1 — configuration incohérente", k)
			}
		}
		return cfg, nil
	case "1":
		cfg.enabled = true
	default:
		return cfg, fmt.Errorf("TBP_TELEMETRY invalide %q (« 1 » pour activer, « 0 » ou absent sinon)", v)
	}
	intRange := func(name string, def, lo, hi int) (int, error) {
		s := getenv(name)
		if s == "" {
			return def, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < lo || n > hi {
			return 0, fmt.Errorf("%s : entier dans [%d, %d] requis, reçu %q", name, lo, hi, s)
		}
		return n, nil
	}
	ms, err := intRange("TBP_TELEMETRY_INTERVAL_MS", 10000, 1000, 3600000)
	if err != nil {
		return cfg, err
	}
	ws, err := intRange("TBP_TELEMETRY_WINDOW_S", 60, 1, 3600)
	if err != nil {
		return cfg, err
	}
	cfg.interval, cfg.window = time.Duration(ms)*time.Millisecond, time.Duration(ws)*time.Second
	if c := getenv("TBP_TELEMETRY_COLLECTOR"); c != "" {
		if _, _, err := net.SplitHostPort(c); err != nil {
			return cfg, fmt.Errorf("TBP_TELEMETRY_COLLECTOR %q : « hôte:port » requis (%v)", c, err)
		}
		cfg.collector = c
	}
	return cfg, nil
}

// setupTelemetry construit le pipeline (nil si la télémétrie n'est pas activée). Le journal est REQUIS :
// une télémétrie dont le clair ne serait pas vérifiable ne démarre pas. start lance Run ; stop attend la fin
// de Run puis scelle la fenêtre en cours — à appeler AVANT la fermeture du registre.
func setupTelemetry(cfg telemetryConfig, cellID string, salt []byte, leaves pep.LeafSink, journal *registry.RecordStore, ledger *pep.QuotaLedger) (start func(ctx context.Context), stop func(), err error) {
	if !cfg.enabled {
		return func(context.Context) {}, func() {}, nil
	}
	if journal == nil {
		return nil, nil, errors.New("TBP_TELEMETRY=1 exige le journal d'audit (#275) : le clair de chaque feuille de télémétrie doit rester vérifiable")
	}
	if ledger == nil {
		return nil, nil, errors.New("TBP_TELEMETRY=1 exige le registre de quotas (la source des compteurs de passeport)")
	}
	p, err := telemetry.NewPipeline(telemetry.PipelineOptions{
		CellID: cellID, Salt: salt, Leaves: leaves, Journal: journal,
		Source:   telemetry.LedgerSource(ledger),
		Interval: cfg.interval, Window: cfg.window, Collector: cfg.collector,
		OnTrip: func(reason string) { log.Printf("pepd: ALARME télémétrie: %s", reason) },
		OnAlert: func(a telemetry.Alert) {
			// destination HACHÉE seulement ; detect, pas prevent — aucun flux n'est coupé
			log.Printf("pepd: ALERTE anti-dribble — destination %x… score=%d signaux=%#x cumul24h=%d cumul7j=%d (feuille TBAD1 inscrite)",
				a.DstHash[:8], a.Score, a.Signals, a.Sum24h, a.Sum7d)
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("télémétrie: %w", err)
	}
	done := make(chan struct{})
	started := false
	var cancelRun context.CancelFunc
	start = func(ctx context.Context) {
		started = true
		var runCtx context.Context
		runCtx, cancelRun = context.WithCancel(ctx)
		go func() { defer close(done); p.Run(runCtx) }()
		log.Printf("pepd: télémétrie anti-dribble active (export %s, fenêtre %s) — métadonnées de passeport uniquement (§4.1-bis)", cfg.interval, cfg.window)
	}
	stop = func() {
		if started {
			cancelRun() // ne dépend pas de l'annulation du contexte du démon (retour sur erreur de run())
			<-done
		}
		if err := p.Close(); err != nil {
			log.Printf("pepd: télémétrie — scellement final: %v", err)
		}
	}
	return start, stop, nil
}
