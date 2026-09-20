// src/supervision/failover_test.go — T34b (issue #60)
//
// Doctrine de test : chutes RÉELLES (chaîne de cellule figée, ancrages
// arrêtés — les deux signaux perdus), bascule déclenchée via la couture
// enregistreuse, budget borné prouvé par une troisième chute refusée,
// escalade humaine feuillée et relue (dogfooding §7.1). Délais par défaut
// du moniteur : borne d'ancrage 120 s, délai de chute 240 s, budget 2/h.
package supervision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// triggerRecorder : couture FailoverTrigger de test (enregistre les
// déclenchements, peut fauter sur demande).
type triggerRecorder struct {
	calls []FailoverEvidence
	err   error
}

func (r *triggerRecorder) Trigger(_ context.Context, ev FailoverEvidence) error {
	if r.err != nil {
		return r.err
	}
	r.calls = append(r.calls, ev)
	return nil
}

// alertsOf filtre les alertes d'un passage par event.
func alertsOf(alerts []Alert, event byte) []Alert {
	var out []Alert
	for _, a := range alerts {
		if a.Record.Event == event {
			out = append(out, a)
		}
	}
	return out
}

// advanceToFall avance l'horloge au-delà du délai de chute (240 s) sans
// aucun signe de vie, en vérifiant qu'aucune bascule n'est déclenchée
// AVANT le terme (l'alarme anchor-stale, elle, précède la bascule). Les
// pas sont ajustés aux comparaisons strictes : borne d'ancrage franchie à
// > 120 s, chute confirmée à > 240 s (à 240 s pile, l'ancrage est encore
// « frais » pour la fenêtre de chute — la borne exacte ne bascule pas).
func advanceToFall(t *testing.T, fx *monitorFixture) []Alert {
	t.Helper()
	nTrig := len(fx.trig.calls)
	// +121 s : ancrage échu (borne 120 s, comparaison stricte) mais chute
	// pas encore confirmée.
	fx.clk.advance(2*time.Minute + time.Second)
	alerts := fx.check(t)
	if len(alertsOf(alerts, AlertEventAnchorStale)) != 1 {
		t.Fatalf("à +121 s : attendu anchor-stale, %+v", alerts)
	}
	if len(fx.trig.calls) != nTrig || len(alertsOf(alerts, AlertEventFailoverTrigger)) != 0 {
		t.Fatalf("à +121 s : bascule déclenchée avant le délai de chute — l'alarme doit précéder l'acte")
	}
	// +240 s pile : l'ancrage est encore « frais » pour la fenêtre de chute
	// (≤ FallDelay) — pas de bascule à la borne exacte.
	fx.clk.advance(2*time.Minute - time.Second)
	alerts = fx.check(t)
	if len(fx.trig.calls) != nTrig || len(alertsOf(alerts, AlertEventFailoverTrigger)) != 0 {
		t.Fatalf("à +240 s (borne exacte) : bascule déclenchée trop tôt")
	}
	// +241 s : les deux signaux sont perdus AU-DELÀ du délai — chute.
	fx.clk.advance(time.Second)
	return fx.check(t)
}

// revive ramène la cellule à la vie (feuille nouvelle + ancrage frais) et
// vérifie que le passage est sain — l'épisode de chute est réarmé.
func revive(t *testing.T, fx *monitorFixture) {
	t.Helper()
	fx.cell.appendLeaf(t, registry.KindDecision, "reprise", fx.clk.t)
	waitCheckpoint(t, fx.cell.dir, fx.cell.verifier, fx.cell.n)
	fx.anchorAt(t, fx.clk.t)
	if alerts := fx.check(t); len(alerts) != 0 {
		t.Fatalf("reprise : passage non sain : %+v", alerts)
	}
}

// TestMonitorFrozenChainFreshAnchorNoFailover : le ET strict de D80. Une
// cellule INACTIVE (chaîne figée — aucune feuille nouvelle) mais VIVANTE
// (ancrage cadencé par le temps, anchor.go) n'est JAMAIS déclarée en
// chute : l'ancrage frais suffit à écarter la bascule, même bien au-delà
// du délai de chute. Simplifier le ET en OU déclencherait ici une bascule
// sur une cellule saine — ce test est la garde contre cette régression.
func TestMonitorFrozenChainFreshAnchorNoFailover(t *testing.T) {
	fx := newMonitorFixture(t)
	// 5 pas de 2 min : chaîne figée 10 minutes (≫ FallDelay 240 s).
	for i := 0; i < 5; i++ {
		fx.clk.advance(2 * time.Minute)
		fx.anchorAt(t, fx.clk.t) // vivante : elle ancre, sans décision à feuiller
		if alerts := fx.check(t); len(alerts) != 0 {
			t.Fatalf("pas %d : cellule inactive mais vivante alarmée : %+v", i, alerts)
		}
	}
	if len(fx.trig.calls) != 0 {
		t.Fatalf("bascule déclenchée sur une cellule vivante : %+v", fx.trig.calls)
	}
}

// TestMonitorFallTriggersFailover : critère d'acceptation #60 — cellule
// tuée ⇒ détection, bascule pré-autorisée déclenchée dans la borne.
func TestMonitorFallTriggersFailover(t *testing.T) {
	fx := newMonitorFixture(t)
	t0 := fx.clk.t
	fx.anchorAt(t, t0) // dernier signe de vie à t0
	if alerts := fx.check(t); len(alerts) != 0 {
		t.Fatalf("départ non sain : %+v", alerts)
	}

	// La cellule MEUR : plus de feuilles, plus d'ancrages.
	frozenSize := fx.monitor.Watcher(fx.cell.cellID).Size() // decision + genèse + transition
	alerts := advanceToFall(t, fx)

	// Le passage qui confirme la chute porte l'alarme anchor-stale (l'humain
	// est averti) ET le constat de déclenchement (event 4, verdict Notice).
	stale := alertsOf(alerts, AlertEventAnchorStale)
	trig := alertsOf(alerts, AlertEventFailoverTrigger)
	if len(stale) != 1 || len(trig) != 1 {
		t.Fatalf("chute : attendu anchor-stale + failover-triggered, %+v", alerts)
	}
	a := trig[0]
	if a.Record.Verdict != AlertVerdictNotice || a.Record.Reason != "failover-triggered" || a.Record.CellID != fx.cell.cellID {
		t.Fatalf("constat de déclenchement inattendu : %+v", a.Record)
	}
	// La couture #30 a reçu l'évidence complète de la chute.
	if len(fx.trig.calls) != 1 {
		t.Fatalf("couture : %d appels, attendu 1", len(fx.trig.calls))
	}
	ev := fx.trig.calls[0]
	if ev.CellID != fx.cell.cellID || ev.Size != frozenSize || !ev.LastAnchor.Equal(t0) || ev.FallenFor < DefaultFallDelay {
		t.Fatalf("évidence inattendue : %+v (taille figée %d)", ev, frozenSize)
	}
	// Le détail hashé est l'encodage canonique de l'évidence (24 octets).
	if len(a.Detail) != 24 || a.Record.DetailHash != sha256.Sum256(a.Detail) {
		t.Fatalf("détail non canonique ou hash incohérent : %d octets", len(a.Detail))
	}
	if rec, err := ParseAlertRecord(a.Raw); err != nil || rec != a.Record {
		t.Fatalf("record de déclenchement non reparseable : %v", err)
	}

	// Épisode clos : la cellule reste morte — l'alarme anchor-stale
	// CONTINUE (§5.3, jamais silencieuse) mais il n'y a PAS de second
	// déclenchement pour le même épisode.
	fx.clk.advance(5 * time.Minute)
	alerts = fx.check(t)
	if len(alertsOf(alerts, AlertEventAnchorStale)) != 1 || len(alertsOf(alerts, AlertEventFailoverTrigger)) != 0 || len(alertsOf(alerts, AlertEventFailoverRefused)) != 0 {
		t.Fatalf("épisode clos : %+v", alerts)
	}
	if len(fx.trig.calls) != 1 {
		t.Fatalf("re-déclenchement du même épisode : %d appels", len(fx.trig.calls))
	}

	// Dogfooding : la feuille du constat de déclenchement est relisible
	// dans le log de supervision par un ChainWatcher indépendant (§7.1).
	found := false
	for _, l := range fx.supervisionLeaves(t) {
		if l.Kind == registry.KindSupervision && l.PayloadHash == a.LeafHash {
			found = true
		}
	}
	if !found {
		t.Fatalf("feuille du constat de bascule absente du log de supervision")
	}
}

// TestMonitorFailoverBudgetExhausted : critère d'acceptation #60 — au-delà
// de la borne (N bascules/heure, défaut 2), escalade humaine et AUCUNE
// bascule automatique supplémentaire. Mutation M12 (budget ignoré) tue ce
// test : la troisième chute déclencherait.
func TestMonitorFailoverBudgetExhausted(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.anchorAt(t, fx.clk.t)
	if alerts := fx.check(t); len(alerts) != 0 {
		t.Fatalf("départ non sain : %+v", alerts)
	}

	// Épisodes 1 et 2 : dans le budget — déclenchés (fenêtre glissante
	// d'une heure : les trois épisodes tiennent en ~20 minutes).
	advanceToFall(t, fx)
	if len(fx.trig.calls) != 1 {
		t.Fatalf("épisode 1 : %d déclenchements", len(fx.trig.calls))
	}
	revive(t, fx)
	advanceToFall(t, fx)
	if len(fx.trig.calls) != 2 {
		t.Fatalf("épisode 2 : %d déclenchements", len(fx.trig.calls))
	}
	revive(t, fx)

	// Épisode 3 : budget épuisé ⇒ refus feuillé (event 5, verdict Alarm,
	// escalade humaine §5.3 classe W), couture #30 NON appelée.
	alerts := advanceToFall(t, fx)
	refused := alertsOf(alerts, AlertEventFailoverRefused)
	if len(refused) != 1 {
		t.Fatalf("épisode 3 : attendu un refus feuillé, %+v", alerts)
	}
	r := refused[0]
	if r.Record.Verdict != AlertVerdictAlarm || r.Record.Reason != "failover-budget-exhausted" || r.Record.CellID != fx.cell.cellID {
		t.Fatalf("refus inattendu : %+v", r.Record)
	}
	if len(fx.trig.calls) != 2 {
		t.Fatalf("budget ignoré : %d déclenchements, borne %d", len(fx.trig.calls), DefaultMaxFailoverTriggers)
	}
	// Le refus est une feuille comme toute alerte (jamais silencieux).
	found := false
	for _, l := range fx.supervisionLeaves(t) {
		if l.Kind == registry.KindSupervision && l.PayloadHash == r.LeafHash {
			found = true
		}
	}
	if !found {
		t.Fatalf("feuille de refus absente du log de supervision")
	}
}

// TestMonitorFailoverNoTriggerConfigured : couture #30 absente (Trigger
// nil = bascule automatique désactivée) — la chute est détectée et
// REFUSÉE avec escalade humaine, jamais silencieuse.
func TestMonitorFailoverNoTriggerConfigured(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.monitor.trigger = nil
	fx.anchorAt(t, fx.clk.t)
	if alerts := fx.check(t); len(alerts) != 0 {
		t.Fatalf("départ non sain : %+v", alerts)
	}
	alerts := advanceToFall(t, fx)
	refused := alertsOf(alerts, AlertEventFailoverRefused)
	if len(refused) != 1 || refused[0].Record.Reason != "failover-no-trigger" || refused[0].Record.Verdict != AlertVerdictAlarm {
		t.Fatalf("attendu failover-no-trigger en alarme, %+v", alerts)
	}
	// Le détail reste l'encodage canonique de l'évidence (24 octets).
	if len(refused[0].Detail) != 24 {
		t.Fatalf("détail non canonique : %d octets", len(refused[0].Detail))
	}
}

// TestMonitorFailoverTriggerFault : la couture #30 faute — escalade
// humaine feuillée (failover-trigger-fault), budget NON consommé (la
// bascule n'a pas eu lieu), et l'épisode est clos (pas de réessai
// automatique silencieux).
func TestMonitorFailoverTriggerFault(t *testing.T) {
	fx := newMonitorFixture(t)
	fx.trig.err = errors.New("tracker #30 indisponible")
	fx.anchorAt(t, fx.clk.t)
	if alerts := fx.check(t); len(alerts) != 0 {
		t.Fatalf("départ non sain : %+v", alerts)
	}
	alerts := advanceToFall(t, fx)
	refused := alertsOf(alerts, AlertEventFailoverRefused)
	if len(refused) != 1 || refused[0].Record.Reason != "failover-trigger-fault" {
		t.Fatalf("attendu failover-trigger-fault, %+v", alerts)
	}
	if !bytes.Contains(refused[0].Detail, []byte("tracker #30 indisponible")) {
		t.Fatalf("diagnostic de la couture absent du détail hashé")
	}
	if len(fx.trig.calls) != 0 {
		t.Fatalf("bascule comptée malgré la faute de la couture")
	}

	// Couture réparée, cellule revenue, nouvelle chute : le budget est
	// intact — le déclenchement aboutit.
	fx.trig.err = nil
	revive(t, fx)
	advanceToFall(t, fx)
	if len(fx.trig.calls) != 1 {
		t.Fatalf("budget consommé à tort par une faute de couture : %d déclenchements", len(fx.trig.calls))
	}
}

// TestNewMonitorFailClosedFailoverConfig : la configuration de la bascule
// est fail-closed comme le reste (D80) — un délai de chute qui ne laisse
// pas l'alarme anchor-stale précéder la bascule est refusé à la
// construction, pas silencieusement accepté.
func TestNewMonitorFailClosedFailoverConfig(t *testing.T) {
	fx := newMonitorFixture(t)
	base := MonitorOptions{
		MonitorCellID: "m", Log: fx.sup.log,
		Cells:  []CellSpec{{CellID: "c", LogDir: fx.cell.dir, Origin: fx.cell.origin, Verifier: fx.cell.verifier, ManifestDir: fx.manifDir}},
		Master: MasterSpec{CellID: "master", LogDir: fx.master.dir, Origin: fx.master.origin, Verifier: fx.master.verifier},
	}
	cases := map[string]func(o *MonitorOptions){
		"FallDelay négatif":           func(o *MonitorOptions) { o.FallDelay = -time.Second },
		"FallDelay sous MaxAnchorLag": func(o *MonitorOptions) { o.FallDelay = time.Minute },
		"FallDelay == MaxAnchorLag": func(o *MonitorOptions) {
			o.MaxAnchorLag = time.Minute
			o.FallDelay = time.Minute
		},
		"MaxFailoverTriggers négatif": func(o *MonitorOptions) { o.MaxFailoverTriggers = -1 },
	}
	for name, mutate := range cases {
		o := base
		mutate(&o)
		if _, err := NewMonitor(testCtx, o); err == nil {
			t.Fatalf("%s : construction acceptée, devait refuser", name)
		}
	}
	// Défauts appliqués : le fixture (zéro partout) tourne avec
	// FallDelay = 240 s et budget = 2.
	if fx.monitor.fallDelay != DefaultFallDelay || fx.monitor.maxTriggers != DefaultMaxFailoverTriggers {
		t.Fatalf("défauts non appliqués : fallDelay=%s maxTriggers=%d", fx.monitor.fallDelay, fx.monitor.maxTriggers)
	}
}
