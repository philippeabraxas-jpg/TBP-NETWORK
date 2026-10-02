package main

// translator_guard.go — la dégradation contrôlée du traducteur (T25, §4.5) devant le broker (#275 suite).
//
// OPT-IN : TBP_TRANSLATOR_GUARD=1 interpose le contrôleur de dégradation devant le traducteur. Le contrôleur
// démarre DÉGRADÉ ; le mode normal se mérite par une sonde verte (GET sur une URL de loopback, 200). Tant
// qu'elle n'est pas verte, toute demande est refusée (refus sain « translation-failed », sans détail vers
// l'agent). Chaque bascule et chaque refus laisse une feuille « TBTD1 » (clair journalisé AVANT la feuille) et
// une alarme. Pas de cellule miroir ni d'arbitrage humain câblés : dégradé ⇒ default-deny.
//
//	TBP_TRANSLATOR_GUARD               « 1 » active ; absent ou « 0 » : comportement historique
//	TBP_TRANSLATOR_PROBE_URL           requis avec la garde — http://<IP de loopback littérale>:port/chemin
//	TBP_TRANSLATOR_PROBE_INTERVAL_MS   cadence de la sonde, [500, 60000], défaut 5000
//	TBP_TRANSLATOR_PROBE_TIMEOUT_MS    délai d'une sonde, [100, 10000], défaut 2000
//
// Un TBP_TRANSLATOR_PROBE_* sans TBP_TRANSLATOR_GUARD=1 est une incohérence de configuration : refus.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	translator "github.com/philippeabraxas-jpg/TBP-NETWORK/src/translator"
)

// controllerGate adapte *translator.Controller à broker.AdmissionGate (le broker n'importe pas le paquet
// translator : voir broker.AdmissionGate). Le jti de la feuille est tiré au hasard — l'intention n'est jamais
// transmise ni hachée (no-DPI : un haché d'intention serait un oracle de dictionnaire dans une feuille).
type controllerGate struct {
	ctl *translator.Controller
	// critical dit si le sujet est un système CRITIQUE (§4.5) ; nil ⇒ tous STANDARD.
	critical func(subject string) bool
}

func (g controllerGate) Admit(ctx context.Context, subject string, natural bool) error {
	var in translator.Input
	if _, err := rand.Read(in.JTI[:]); err != nil { // inatteignable — fail-closed
		return fmt.Errorf("tirage jti de garde : %w", err)
	}
	in.Natural = natural
	// La classe vient du registre d'agents (AUTORITAIRE, hors-bande) : F, I, W ⇒ critique (failover miroir si
	// disponible, jamais d'escalade humaine) ; le reste ⇒ standard (arbitrage si joignable). Sans miroir ni
	// arbitrage câblés, la classe ne change pas l'issue (default-deny). Toute issue non nulle — y compris
	// ErrPendingArbitration, qu'aucune file câblée ici ne saurait honorer — est un refus.
	class := translator.SystemStandard
	if g.critical != nil && g.critical(subject) {
		class = translator.SystemCritical
	}
	return g.ctl.Accept(ctx, translator.System{ID: subject, Class: class}, in)
}

type translatorGuardConfig struct {
	enabled  bool
	probeURL string
	interval time.Duration
	timeout  time.Duration
}

// translatorGuardFromEnv lit et valide TBP_TRANSLATOR_GUARD* — fail-closed.
func translatorGuardFromEnv(getenv func(string) string) (translatorGuardConfig, error) {
	cfg := translatorGuardConfig{interval: 5 * time.Second, timeout: 2 * time.Second}
	knobs := []string{"TBP_TRANSLATOR_PROBE_URL", "TBP_TRANSLATOR_PROBE_INTERVAL_MS", "TBP_TRANSLATOR_PROBE_TIMEOUT_MS"}
	switch v := getenv("TBP_TRANSLATOR_GUARD"); v {
	case "", "0":
		for _, k := range knobs {
			if getenv(k) != "" {
				return cfg, fmt.Errorf("%s sans TBP_TRANSLATOR_GUARD=1 — configuration incohérente", k)
			}
		}
		return cfg, nil
	case "1":
		cfg.enabled = true
	default:
		return cfg, fmt.Errorf("TBP_TRANSLATOR_GUARD invalide %q (« 1 » pour activer, « 0 » ou absent sinon)", v)
	}
	cfg.probeURL = getenv("TBP_TRANSLATOR_PROBE_URL")
	if cfg.probeURL == "" {
		return cfg, errors.New("TBP_TRANSLATOR_PROBE_URL requis avec TBP_TRANSLATOR_GUARD=1 (la santé est vérifiée, jamais présumée)")
	}
	msRange := func(name string, def time.Duration, lo, hi int) (time.Duration, error) {
		s := getenv(name)
		if s == "" {
			return def, nil
		}
		ms, err := strconv.Atoi(s)
		if err != nil || ms < lo || ms > hi {
			return 0, fmt.Errorf("%s invalide %q (entier dans [%d, %d] attendu)", name, s, lo, hi)
		}
		return time.Duration(ms) * time.Millisecond, nil
	}
	var err error
	if cfg.interval, err = msRange("TBP_TRANSLATOR_PROBE_INTERVAL_MS", cfg.interval, 500, 60000); err != nil {
		return cfg, err
	}
	if cfg.timeout, err = msRange("TBP_TRANSLATOR_PROBE_TIMEOUT_MS", cfg.timeout, 100, 10000); err != nil {
		return cfg, err
	}
	// l'URL est validée ici déjà (loopback littéral…) : un démarrage refusé vaut mieux qu'une sonde inutile
	if _, err := broker.NewHTTPProbe(cfg.probeURL, cfg.timeout); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// setupTranslatorGuard rend le traducteur à passer au broker (inner tel quel si la garde est désactivée) et la
// fonction qui lance la boucle de sonde : une sonde SYNCHRONE d'abord (l'état est établi avant que le broker
// ne serve), puis périodique jusqu'à annulation de ctx. Le chemin de décision ne sonde jamais.
func setupTranslatorGuard(cfg translatorGuardConfig, inner broker.Translator, cellID string, salt []byte,
	leaves translator.LeafSink, journal *registry.RecordStore, onAlarm func(string),
	mirror translator.MirrorCell, critical func(subject string) bool) (broker.Translator, func(ctx context.Context), error) {
	if !cfg.enabled {
		return inner, func(context.Context) {}, nil
	}
	probe, err := broker.NewHTTPProbe(cfg.probeURL, cfg.timeout)
	if err != nil {
		return nil, nil, err
	}
	ctl, err := translator.NewController(translator.Options{
		CellID: cellID, Salt: salt, Leaves: leaves, Journal: journal, Probe: probe, Mirror: mirror, OnAlarm: onAlarm,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("contrôleur de dégradation : %w", err)
	}
	guarded, err := broker.NewGuardedTranslator(inner, controllerGate{ctl: ctl, critical: critical}, false)
	if err != nil {
		return nil, nil, err
	}
	start := func(ctx context.Context) {
		_ = ctl.CheckHealth(ctx) // l'erreur est déjà tracée et alarmée par le contrôleur
		go func() {
			t := time.NewTicker(cfg.interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					_ = ctl.CheckHealth(ctx)
				}
			}
		}()
	}
	return guarded, start, nil
}
