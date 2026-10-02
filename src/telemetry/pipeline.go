package telemetry

// pipeline.go — l'assemblage que pepd fait tourner (#275, suite) : exporteur de métadonnées passeport
// (T21) → agrégateur à fenêtres (T22) + détecteur anti-dribble (T23) en parallèle (FanOut), rétention
// locale des bruts à TTL. Chaque feuille (agrégat « TBAG1 », purge « TBRP1 », alerte « TBAD1 ») laisse
// son clair dans le journal d'enregistrements AVANT d'être inscrite (registry.AppendLeaf) : sans clair,
// pas de feuille — l'erreur remonte par la couture d'alarme, jamais en silence (§5.3).
//
// Doctrine (§4.1-bis) : des MÉTADONNÉES uniquement (compteurs monotones du QuotaLedger), jamais le
// contenu d'un flux ; detect, pas prevent — une alerte est une feuille et un callback, jamais une coupure.

import (
	"context"
	"errors"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// DefaultPipelineInterval est la cadence d'export de Run.
const DefaultPipelineInterval = 10 * time.Second

// PipelineOptions paramètre le pipeline. Fail-closed dès la configuration.
type PipelineOptions struct {
	CellID string
	// Salt ≥ 16 octets, reste chez le producteur (§6.2). Requis.
	Salt []byte
	// Leaves reçoit les feuilles (le CellLog de la cellule). Requis.
	Leaves pep.LeafSink
	// Journal reçoit le clair de chaque feuille AVANT son inscription (#275, #271). Optionnel ici (nil =
	// feuille nue, historique) ; pepd le renseigne toujours.
	Journal *registry.RecordStore
	// Source : les sessions passeport vivantes (LedgerSource(*pep.QuotaLedger)). Requis.
	Source SessionSource
	// Interval : période d'export de Run (défaut DefaultPipelineInterval).
	Interval time.Duration
	// Window : fenêtre d'agrégation (défaut 60 s). Une feuille par fenêtre scellée, y compris vide.
	Window time.Duration
	// Collector : adresse UDP d'un collecteur IPFIX local ; vide ⇒ pas d'envoi fil, les feuilles restent.
	Collector string
	// RetentionTTL / MaxBatches : rétention locale des bruts (défauts : 24 h, 1440 lots).
	RetentionTTL time.Duration
	MaxBatches   int
	// Params : seuils du détecteur anti-dribble (zéro ⇒ DefaultScoreParams). Versionnés : le hash des
	// paramètres entre dans chaque feuille d'alerte.
	Params ScoreParams
	// OnTrip : alarme (échec d'envoi collecteur, d'écriture de feuille, store plein, entités pleines).
	OnTrip func(reason string)
	// OnAlert : alerte anti-dribble (destination hachée, jamais en clair). Nil ⇒ la feuille suffit.
	OnAlert func(Alert)
	// Now : horloge NTS de la cellule (§6.2). Nil ⇒ time.Now.
	Now func() time.Time
}

// Pipeline est l'assemblage exporteur + agrégateur + détecteur + rétention.
type Pipeline struct {
	Exporter   *Exporter
	Aggregator *Aggregator
	Detector   *Detector
	Store      *RetentionStore

	interval time.Duration
	onTrip   func(string)
}

// NewPipeline construit le pipeline.
func NewPipeline(opts PipelineOptions) (*Pipeline, error) {
	if opts.Source == nil {
		return nil, ErrSourceRequired
	}
	interval := opts.Interval
	if interval == 0 {
		interval = DefaultPipelineInterval
	}
	params := opts.Params
	if params == (ScoreParams{}) {
		params = DefaultScoreParams()
	}
	store, err := NewRetentionStore(RetentionOptions{
		CellID: opts.CellID, Salt: opts.Salt, Leaves: opts.Leaves, Journal: opts.Journal,
		TTL: opts.RetentionTTL, MaxBatches: opts.MaxBatches, Now: opts.Now, OnTrip: opts.OnTrip,
	})
	if err != nil {
		return nil, err
	}
	agg, err := NewAggregator(AggregatorOptions{
		CellID: opts.CellID, Salt: opts.Salt, Leaves: opts.Leaves, Journal: opts.Journal,
		Window: opts.Window, RetStore: store, Now: opts.Now, OnTrip: opts.OnTrip,
	})
	if err != nil {
		return nil, err
	}
	det, err := NewDetector(DetectorOptions{
		CellID: opts.CellID, Salt: opts.Salt, Leaves: opts.Leaves, Journal: opts.Journal,
		Params: params, Now: opts.Now, OnAlert: opts.OnAlert, OnTrip: opts.OnTrip,
	})
	if err != nil {
		return nil, err
	}
	exp, err := NewExporter(ExporterOptions{
		CellID: opts.CellID, Source: opts.Source, Sink: FanOut{agg, det},
		Collector: opts.Collector, Interval: interval, OnTrip: opts.OnTrip, Now: opts.Now,
	})
	if err != nil {
		return nil, err
	}
	return &Pipeline{Exporter: exp, Aggregator: agg, Detector: det, Store: store, interval: interval, onTrip: opts.OnTrip}, nil
}

// Step exécute UN cycle : export des deltas de sessions, scellement des fenêtres écoulées, purge des
// bruts expirés. Les erreurs de feuille (journal refusé compris) remontent par OnTrip, jamais en silence.
func (p *Pipeline) Step() {
	p.Exporter.ExportOnce()
	if err := p.Aggregator.Tick(); err != nil && p.onTrip != nil {
		p.onTrip(pep.ReasonLeafWriteFailed)
	}
	p.Store.PurgeExpired()
}

// Run boucle Step à l'intervalle configuré jusqu'à annulation du contexte.
func (p *Pipeline) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Step()
		}
	}
}

// Close scelle la fenêtre en cours et vide le détecteur (arrêt propre : les feuilles doivent partir AVANT
// la fermeture du registre). Rend la première erreur ; best effort pour le reste.
func (p *Pipeline) Close() error {
	return errors.Join(p.Aggregator.Seal(), p.Detector.Flush())
}
