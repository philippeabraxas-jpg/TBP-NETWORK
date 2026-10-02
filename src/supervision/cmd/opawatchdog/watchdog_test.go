package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fakeRestarter struct {
	calls []string
	err   error
	order *[]string
}

func (f *fakeRestarter) Restart(_ context.Context, unit string) error {
	if f.order != nil {
		*f.order = append(*f.order, "restart")
	}
	f.calls = append(f.calls, unit)
	return f.err
}

type recEntry struct {
	event, verdict byte
	reason         string
	detail         string
}

// fakeRecorder consigne les feuilles ; order enregistre l'entrelacement avec le redémarreur (la feuille d'abord).
type fakeRecorder struct {
	entries []recEntry
	err     error
	order   *[]string
}

func (f *fakeRecorder) Record(_ context.Context, event, verdict byte, reason string, detail []byte) error {
	if f.order != nil {
		*f.order = append(*f.order, "leaf:"+reason)
	}
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, recEntry{event, verdict, reason, string(detail)})
	return nil
}

// scripted : états rendus par nom de source (ou une erreur).
type scripted struct {
	states map[string]string
	errs   map[string]error
}

func (s *scripted) fetch(_ context.Context, src Source) (opaStatus, error) {
	if e := s.errs[src.Name]; e != nil {
		return opaStatus{}, e
	}
	return opaStatus{State: s.states[src.Name]}, nil
}

func (s *scripted) all(state string) {
	for k := range s.states {
		s.states[k] = state
	}
}

func fixture(t *testing.T, mut func(*Settings)) (*Watchdog, *scripted, *fakeRestarter, *fakeClock, *[]string) {
	w, sc, rs, clk, logs, _ := fixtureRec(t, mut)
	return w, sc, rs, clk, logs
}

func fixtureRec(t *testing.T, mut func(*Settings)) (*Watchdog, *scripted, *fakeRestarter, *fakeClock, *[]string, *fakeRecorder) {
	t.Helper()
	set := Settings{
		Sources:    []Source{{"pepd", "/run/p.sock"}, {"brokerd", "/run/b.sock"}},
		Unit:       "tbp-opa.service",
		Confirm:    3,
		Cooldown:   30 * time.Second,
		MaxPerHour: 3,
	}
	if mut != nil {
		mut(&set)
	}
	sc := &scripted{states: map[string]string{"pepd": stateHealthy, "brokerd": stateHealthy}, errs: map[string]error{}}
	var order []string
	rs := &fakeRestarter{order: &order}
	rec := &fakeRecorder{order: &order}
	clk := newClock()
	var logs []string
	w, err := NewWatchdog(set, sc.fetch, rs, rec, clk.now, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if err != nil {
		t.Fatal(err)
	}
	return w, sc, rs, clk, &logs, rec
}

func TestHealthyNeverRestarts(t *testing.T) {
	w, _, rs, _, _ := fixture(t, nil)
	for i := 0; i < 20; i++ {
		if o := w.Tick(context.Background()); o != OutcomeHealthy {
			t.Fatalf("outcome=%s", o)
		}
	}
	if len(rs.calls) != 0 {
		t.Fatal("OPA sain redémarré")
	}
}

func TestOverloadedIsNotAStall(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.all(stateOverloaded)
	for i := 0; i < 20; i++ {
		w.Tick(context.Background())
	}
	if len(rs.calls) != 0 {
		t.Fatal("« overloaded » (OPA répond) ne doit jamais redémarrer OPA")
	}
}

func TestRestartAfterConfirmConsecutiveStalls(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.all(stateStalled)
	if o := w.Tick(context.Background()); o != OutcomeSuspect {
		t.Fatalf("1er relevé : %s", o)
	}
	if o := w.Tick(context.Background()); o != OutcomeSuspect {
		t.Fatalf("2e relevé : %s", o)
	}
	if len(rs.calls) != 0 {
		t.Fatal("redémarrage avant confirmation")
	}
	if o := w.Tick(context.Background()); o != OutcomeRestarted {
		t.Fatalf("3e relevé : %s", o)
	}
	if len(rs.calls) != 1 || rs.calls[0] != "tbp-opa.service" {
		t.Fatalf("appels=%v", rs.calls)
	}
}

func TestAHealthyReadingResetsTheConfirmCount(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.all(stateStalled)
	w.Tick(context.Background())
	w.Tick(context.Background())
	sc.all(stateHealthy)
	w.Tick(context.Background())
	sc.all(stateStalled)
	w.Tick(context.Background())
	w.Tick(context.Background())
	if len(rs.calls) != 0 {
		t.Fatal("les relevés « stalled » doivent être CONSÉCUTIFS")
	}
}

func TestOneSourceNotStalledBlocksRestart(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.states["pepd"] = stateStalled // brokerd, lui, joint OPA : pas un blocage commun
	for i := 0; i < 10; i++ {
		w.Tick(context.Background())
	}
	if len(rs.calls) != 0 {
		t.Fatal("une seule source « stalled » ne suffit pas : OPA est partagé, un client isolé peut avoir un souci propre")
	}
}

func TestUnreadableSourceIsIgnoredNotBlamed(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.states["pepd"] = stateStalled
	sc.errs["brokerd"] = errors.New("connexion refusée")
	for i := 0; i < 3; i++ {
		w.Tick(context.Background())
	}
	if len(rs.calls) != 1 {
		t.Fatalf("la seule source lisible dit « stalled » : redémarrage attendu, appels=%v", rs.calls)
	}
}

func TestBlindWhenNoSourceReadable(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.errs["pepd"] = errors.New("x")
	sc.errs["brokerd"] = errors.New("y")
	for i := 0; i < 10; i++ {
		if o := w.Tick(context.Background()); o != OutcomeBlind {
			t.Fatalf("outcome=%s", o)
		}
	}
	if len(rs.calls) != 0 {
		t.Fatal("aveugle : aucune action")
	}
}

func TestBlindResetsTheConfirmCount(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, nil)
	sc.all(stateStalled)
	w.Tick(context.Background())
	w.Tick(context.Background())
	sc.errs["pepd"] = errors.New("x")
	sc.errs["brokerd"] = errors.New("y")
	w.Tick(context.Background())
	delete(sc.errs, "pepd")
	delete(sc.errs, "brokerd")
	w.Tick(context.Background())
	w.Tick(context.Background())
	if len(rs.calls) != 0 {
		t.Fatal("un trou de lecture doit remettre le compte à zéro")
	}
}

func TestCooldownAfterRestart(t *testing.T) {
	w, sc, rs, clk, _ := fixture(t, nil)
	sc.all(stateStalled)
	for i := 0; i < 3; i++ {
		w.Tick(context.Background())
	}
	// toujours bloqué : confirmation de nouveau, mais repos en cours
	var o Outcome
	for i := 0; i < 3; i++ {
		o = w.Tick(context.Background())
	}
	if o != OutcomeCooldown || len(rs.calls) != 1 {
		t.Fatalf("outcome=%s appels=%d : pas de second redémarrage pendant le repos", o, len(rs.calls))
	}
	clk.advance(31 * time.Second)
	if o := w.Tick(context.Background()); o != OutcomeRestarted || len(rs.calls) != 2 {
		t.Fatalf("après le repos : outcome=%s appels=%d", o, len(rs.calls))
	}
}

func TestHourlyBudgetExhaustedEscalates(t *testing.T) {
	w, sc, rs, clk, logs := fixture(t, func(s *Settings) { s.Confirm = 1; s.MaxPerHour = 2; s.Cooldown = time.Second })
	sc.all(stateStalled)
	for i := 0; i < 2; i++ {
		if o := w.Tick(context.Background()); o != OutcomeRestarted {
			t.Fatalf("tentative %d : %s", i, o)
		}
		clk.advance(2 * time.Second)
	}
	for i := 0; i < 5; i++ {
		if o := w.Tick(context.Background()); o != OutcomeExhausted {
			t.Fatalf("budget épuisé attendu, %s", o)
		}
		clk.advance(2 * time.Second)
	}
	if len(rs.calls) != 2 {
		t.Fatalf("appels=%d, 2 attendus", len(rs.calls))
	}
	n := 0
	for _, l := range *logs {
		if strings.Contains(l, "ESCALADE") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("l'escalade doit être journalisée UNE fois (changement d'état), pas à chaque relevé : %d", n)
	}
	// la fenêtre glisse : une heure plus tard, le budget revient
	clk.advance(time.Hour)
	if o := w.Tick(context.Background()); o != OutcomeRestarted {
		t.Fatalf("après une heure : %s", o)
	}
}

func TestFailedRestartCountsAgainstBudget(t *testing.T) {
	w, sc, rs, clk, _ := fixture(t, func(s *Settings) { s.Confirm = 1; s.MaxPerHour = 2; s.Cooldown = time.Second })
	rs.err = errors.New("polkit : accès refusé")
	sc.all(stateStalled)
	for i := 0; i < 2; i++ {
		if o := w.Tick(context.Background()); o != OutcomeRestartKO {
			t.Fatalf("%s", o)
		}
		clk.advance(2 * time.Second)
	}
	if o := w.Tick(context.Background()); o != OutcomeExhausted || len(rs.calls) != 2 {
		t.Fatalf("outcome=%s appels=%d : un redémarrage qui échoue ne doit pas boucler", o, len(rs.calls))
	}
}

func TestDryRunNeverRestarts(t *testing.T) {
	w, sc, rs, _, _ := fixture(t, func(s *Settings) { s.DryRun = true; s.Confirm = 1 })
	sc.all(stateStalled)
	if o := w.Tick(context.Background()); o != OutcomeDryRun || len(rs.calls) != 0 {
		t.Fatalf("outcome=%s appels=%d", o, len(rs.calls))
	}
}

func TestNewWatchdogRejectsBadSettings(t *testing.T) {
	ok := Settings{Sources: []Source{{"a", "/a"}}, Unit: "tbp-opa.service", Confirm: 1, Cooldown: time.Second, MaxPerHour: 1}
	f := func(context.Context, Source) (opaStatus, error) { return opaStatus{}, nil }
	for name, mut := range map[string]func(*Settings){
		"sans source":       func(s *Settings) { s.Sources = nil },
		"confirm 0":         func(s *Settings) { s.Confirm = 0 },
		"budget 0":          func(s *Settings) { s.MaxPerHour = 0 },
		"repos 0":           func(s *Settings) { s.Cooldown = 0 },
		"unité vide":        func(s *Settings) { s.Unit = "" },
		"unité avec tiret":  func(s *Settings) { s.Unit = "--now.service" },
		"unité avec espace": func(s *Settings) { s.Unit = "a b.service" },
		"unité non service": func(s *Settings) { s.Unit = "tbp-opa.socket" },
		"unité injection":   func(s *Settings) { s.Unit = "tbp-opa.service;reboot.service" },
	} {
		s := ok
		mut(&s)
		if _, err := NewWatchdog(s, f, &fakeRestarter{}, &fakeRecorder{}, nil, nil); err == nil {
			t.Errorf("%s : refus attendu", name)
		}
	}
	if _, err := NewWatchdog(ok, nil, &fakeRestarter{}, &fakeRecorder{}, nil, nil); err == nil {
		t.Error("lecteur nil : refus attendu")
	}
	if _, err := NewWatchdog(ok, f, &fakeRestarter{}, nil, nil, nil); err == nil {
		t.Error("enregistreur nil : refus attendu (pas de redémarrage sans trace)")
	}
}

// ---------------------------------------------------------------------------
// Lecture du statut sur socket Unix
// ---------------------------------------------------------------------------

func unixServer(t *testing.T, h http.Handler) Source {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return Source{Name: "t", Socket: sock}
}

func TestSocketFetcherReadsStatus(t *testing.T) {
	src := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != statusPath || r.Method != http.MethodGet {
			http.Error(w, "x", 404)
			return
		}
		_, _ = io.WriteString(w, `{"state":"stalled","stalled":true,"silent_ms":4000,"unanswered":9,"consecutive_faults":3}`)
	}))
	st, err := SocketStatusFetcher()(context.Background(), src)
	if err != nil || st.State != stateStalled || !st.Stalled || st.Unanswered != 9 {
		t.Fatalf("st=%+v err=%v", st, err)
	}
}

func TestSocketFetcherRefusesBadResponses(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"statut 500": func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
		"json cassé": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"state":`) },
		"champ inconnu": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"state":"healthy","extra":1}`)
		},
		"clé en double": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"state":"healthy","state":"stalled"}`)
		},
		"état inconnu": func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"state":"great"}`) },
		"état vide":    func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) },
		"trop gros": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, `{"state":"`+strings.Repeat("a", maxStatusBody)+`"}`)
		},
		"redirection": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ailleurs", 302) },
	} {
		src := unixServer(t, h)
		if _, err := SocketStatusFetcher()(context.Background(), src); err == nil {
			t.Errorf("%s : refus attendu", name)
		}
	}
	// socket absent
	if _, err := SocketStatusFetcher()(context.Background(), Source{Name: "x", Socket: "/nonexistent/s.sock"}); err == nil {
		t.Error("socket absent : erreur attendue")
	}
}

func TestSocketFetcherTimesOutOnAHangingSource(t *testing.T) {
	block := make(chan struct{})
	src := unixServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block) })
	start := time.Now()
	if _, err := SocketStatusFetcher()(context.Background(), src); err == nil {
		t.Fatal("source muette : erreur attendue")
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("lecture non bornée : %v", d)
	}
}

// ---------------------------------------------------------------------------
// systemctl
// ---------------------------------------------------------------------------

func fakeSystemctl(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSystemctlRestarterArgsAndEmptyEnv(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("SECRET_FROM_PARENT", "oui")
	sc := fakeSystemctl(t, `echo "$@" > `+out+`; env >> `+out)
	r := SystemctlRestarter{Path: sc, Timeout: 5 * time.Second}
	if err := r.Restart(context.Background(), "tbp-opa.service"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	if !strings.HasPrefix(s, "--no-ask-password restart tbp-opa.service\n") {
		t.Fatalf("arguments inattendus : %q", s)
	}
	if strings.Contains(s, "SECRET_FROM_PARENT") {
		t.Fatal("l'environnement du parent ne doit pas être hérité")
	}
}

func TestSystemctlRestarterFailureAndTimeoutAndBadUnit(t *testing.T) {
	r := SystemctlRestarter{Path: fakeSystemctl(t, `echo "Access denied" >&2; exit 1`), Timeout: 5 * time.Second}
	if err := r.Restart(context.Background(), "tbp-opa.service"); err == nil || !strings.Contains(err.Error(), "Access denied") {
		t.Fatalf("err=%v : l'échec et sa raison doivent remonter", err)
	}
	r = SystemctlRestarter{Path: fakeSystemctl(t, `sleep 5`), Timeout: 200 * time.Millisecond}
	start := time.Now()
	if err := r.Restart(context.Background(), "tbp-opa.service"); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("délai non respecté (%v) err=%v", time.Since(start), err)
	}
	if err := (SystemctlRestarter{Path: "/bin/true", Timeout: time.Second}).Restart(context.Background(), "--now"); err == nil {
		t.Fatal("nom d'unité invalide : refus attendu")
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// baseEnv : la configuration minimale valide.
func baseEnv(extra map[string]string) map[string]string {
	m := map[string]string{
		"TBP_OPAWD_SOURCES": "a=/a.sock", "TBP_OPAWD_CELL_ID": "cell-a", "TBP_OPAWD_LOG_ID": "opawd-cell-a",
		"TBP_OPAWD_REGISTRY_DIR": "/var/lib/tbp/opa-watchdog", "TBP_OPAWD_AUDIT_RECORDS": "/var/lib/tbp/opa-watchdog/audit.jnl",
		"TBP_OPAWD_AUDIT_RECORDS_KEY_FILE": "/etc/tbp/opawd-audit.key",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestLoadConfigDefaultsAndExplicit(t *testing.T) {
	cfg, err := loadConfig(envMap(baseEnv(map[string]string{"TBP_OPAWD_SOURCES": "pepd=/run/tbp/pepd-admin.sock,brokerd=/run/tbp/brokerd-admin.sock"})))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.set
	if len(s.Sources) != 2 || s.Unit != "tbp-opa.service" || s.Confirm != 3 || s.Cooldown != 30*time.Second || s.MaxPerHour != 3 || s.DryRun ||
		cfg.poll != time.Second || cfg.systemctl != "/usr/bin/systemctl" {
		t.Fatalf("défauts = %+v poll=%v", cfg, cfg.poll)
	}
	if cfg.cellID != "cell-a" || cfg.logID != "opawd-cell-a" || cfg.registryDir == "" || cfg.auditRecords == "" || cfg.auditKeyFile == "" {
		t.Fatalf("identités et chemins de la chaîne mal lus : %+v", cfg)
	}
	cfg, err = loadConfig(envMap(baseEnv(map[string]string{
		"TBP_OPAWD_SOURCES": "a=/a.sock", "TBP_OPAWD_UNIT": "opa@1.service", "TBP_OPAWD_POLL_MS": "500", "TBP_OPAWD_CONFIRM": "5",
		"TBP_OPAWD_COOLDOWN_S": "60", "TBP_OPAWD_MAX_PER_HOUR": "1", "TBP_OPAWD_SYSTEMCTL": "/bin/systemctl", "TBP_OPAWD_DRY_RUN": "1",
	})))
	if err != nil || cfg.set.Unit != "opa@1.service" || cfg.set.Confirm != 5 || !cfg.set.DryRun || cfg.poll != 500*time.Millisecond ||
		cfg.set.Cooldown != time.Minute || cfg.set.MaxPerHour != 1 || cfg.systemctl != "/bin/systemctl" {
		t.Fatalf("explicite = %+v err=%v", cfg, err)
	}
}

func TestLoadConfigRejectsBadValues(t *testing.T) {
	base := baseEnv(nil)
	for name, kv := range map[string]map[string]string{
		"sans cellule":         {"TBP_OPAWD_CELL_ID": ""},
		"sans identité de log": {"TBP_OPAWD_LOG_ID": ""},
		"sans registre":        {"TBP_OPAWD_REGISTRY_DIR": ""},
		"sans journal d'audit": {"TBP_OPAWD_AUDIT_RECORDS": ""},
		"sans clé du journal":  {"TBP_OPAWD_AUDIT_RECORDS_KEY_FILE": ""},
		"sans sources":         {"TBP_OPAWD_SOURCES": ""},
		"source sans =":        {"TBP_OPAWD_SOURCES": "/a.sock"},
		"socket relatif":       {"TBP_OPAWD_SOURCES": "a=run/a.sock"},
		"socket non propre":    {"TBP_OPAWD_SOURCES": "a=/run/../etc/a.sock"},
		"nom en double":        {"TBP_OPAWD_SOURCES": "a=/a.sock,a=/b.sock"},
		"unité invalide":       {"TBP_OPAWD_UNIT": "x y.service"},
		"poll bas":             {"TBP_OPAWD_POLL_MS": "10"},
		"confirm 0":            {"TBP_OPAWD_CONFIRM": "0"},
		"confirm texte":        {"TBP_OPAWD_CONFIRM": "trois"},
		"repos bas":            {"TBP_OPAWD_COOLDOWN_S": "1"},
		"budget 0":             {"TBP_OPAWD_MAX_PER_HOUR": "0"},
		"budget haut":          {"TBP_OPAWD_MAX_PER_HOUR": "61"},
		"systemctl relatif":    {"TBP_OPAWD_SYSTEMCTL": "systemctl"},
		"dry-run ambigu":       {"TBP_OPAWD_DRY_RUN": "oui"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		for k, v := range kv {
			env[k] = v
		}
		if _, err := loadConfig(envMap(env)); err == nil {
			t.Errorf("%s : refus attendu", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Traçabilité : chaque redémarrage décidé est feuillé AVANT d'être exécuté (§5.3)
// ---------------------------------------------------------------------------

func TestRestartIsLeafedBeforeItRuns(t *testing.T) {
	w, sc, rs, _, _, rec := fixtureRec(t, func(s *Settings) { s.Confirm = 1 })
	sc.all(stateStalled)
	if o := w.Tick(context.Background()); o != OutcomeRestarted {
		t.Fatalf("outcome=%s", o)
	}
	order := *rs.order
	if len(order) != 2 || order[0] != "leaf:opa-restart-requested" || order[1] != "restart" {
		t.Fatalf("ordre = %v : la feuille doit précéder le redémarrage", order)
	}
	if len(rec.entries) != 1 {
		t.Fatalf("feuilles = %+v", rec.entries)
	}
	e := rec.entries[0]
	if e.event != supervision.AlertEventOPARestart || e.verdict != supervision.AlertVerdictNotice {
		t.Fatalf("feuille = %+v", e)
	}
	for _, want := range []string{`"unit":"tbp-opa.service"`, `"pepd":"stalled"`, `"brokerd":"stalled"`, `"stalled_runs":1`} {
		if !strings.Contains(e.detail, want) {
			t.Errorf("détail %s : %s attendu", e.detail, want)
		}
	}
}

func TestNoLeafNoRestart(t *testing.T) {
	w, sc, rs, _, logs, rec := fixtureRec(t, func(s *Settings) { s.Confirm = 1 })
	rec.err = errors.New("registre saturé")
	sc.all(stateStalled)
	for i := 0; i < 3; i++ {
		if o := w.Tick(context.Background()); o != OutcomeUntraced {
			t.Fatalf("outcome=%s : sans feuille, pas de redémarrage", o)
		}
	}
	if len(rs.calls) != 0 {
		t.Fatal("redémarrage exécuté sans feuille : un acte privilégié sans trace")
	}
	// rien n'a eu lieu ⇒ aucune tentative dépensée : dès que le registre revient, le redémarrage part
	rec.err = nil
	if o := w.Tick(context.Background()); o != OutcomeRestarted || len(rs.calls) != 1 {
		t.Fatalf("registre revenu : outcome=%s appels=%d", o, len(rs.calls))
	}
	joined := strings.Join(*logs, "\n")
	if !strings.Contains(joined, "ESCALADE feuille impossible") {
		t.Fatalf("l'impossibilité de feuiller doit être journalisée : %s", joined)
	}
}

func TestFailedRestartIsLeafedAsAlarm(t *testing.T) {
	w, sc, rs, _, _, rec := fixtureRec(t, func(s *Settings) { s.Confirm = 1 })
	rs.err = errors.New("polkit : accès refusé")
	sc.all(stateStalled)
	if o := w.Tick(context.Background()); o != OutcomeRestartKO {
		t.Fatalf("outcome=%s", o)
	}
	if len(rec.entries) != 2 || rec.entries[0].reason != "opa-restart-requested" ||
		rec.entries[1].reason != "opa-restart-failed" || rec.entries[1].verdict != supervision.AlertVerdictAlarm || rec.entries[1].event != supervision.AlertEventOPARestart {
		t.Fatalf("feuilles = %+v", rec.entries)
	}
}

func TestExhaustedBudgetIsLeafedOncePerEpisode(t *testing.T) {
	w, sc, _, clk, _, rec := fixtureRec(t, func(s *Settings) { s.Confirm = 1; s.MaxPerHour = 1; s.Cooldown = time.Second })
	sc.all(stateStalled)
	w.Tick(context.Background()) // 1re tentative
	clk.advance(2 * time.Second)
	for i := 0; i < 5; i++ {
		if o := w.Tick(context.Background()); o != OutcomeExhausted {
			t.Fatalf("outcome=%s", o)
		}
		clk.advance(2 * time.Second)
	}
	n := 0
	for _, e := range rec.entries {
		if e.event == supervision.AlertEventOPARestartRefused && e.reason == "opa-restart-budget-exhausted" && e.verdict == supervision.AlertVerdictAlarm {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("feuilles d'escalade = %d, 1 attendue par épisode : %+v", n, rec.entries)
	}
	// OPA se rétablit puis se rebloque, budget toujours épuisé : NOUVEL épisode, nouvelle feuille
	sc.all(stateHealthy)
	w.Tick(context.Background())
	sc.all(stateStalled)
	w.Tick(context.Background())
	n = 0
	for _, e := range rec.entries {
		if e.event == supervision.AlertEventOPARestartRefused {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("un nouvel épisode d'épuisement doit être feuillé à nouveau : %d", n)
	}
}

func TestEscalationLeafIsRetriedUntilWritten(t *testing.T) {
	w, sc, _, clk, _, rec := fixtureRec(t, func(s *Settings) { s.Confirm = 1; s.MaxPerHour = 1; s.Cooldown = time.Second })
	sc.all(stateStalled)
	w.Tick(context.Background())
	clk.advance(2 * time.Second)
	rec.err = errors.New("registre saturé")
	w.Tick(context.Background())
	w.Tick(context.Background())
	rec.err = nil
	w.Tick(context.Background())
	n := 0
	for _, e := range rec.entries {
		if e.event == supervision.AlertEventOPARestartRefused {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("la feuille d'escalade doit être réessayée jusqu'à écriture, puis une seule fois : %d", n)
	}
}

func TestDryRunWritesNoLeaf(t *testing.T) {
	w, sc, _, _, _, rec := fixtureRec(t, func(s *Settings) { s.DryRun = true; s.Confirm = 1 })
	sc.all(stateStalled)
	w.Tick(context.Background())
	if len(rec.entries) != 0 {
		t.Fatalf("dry-run : aucune action, aucune feuille : %+v", rec.entries)
	}
}

// Le détail feuillé dit la vérité : une source devenue illisible n'y garde pas son ancien état.
func TestLeafDetailMarksUnreadableSources(t *testing.T) {
	w, sc, _, _, _, rec := fixtureRec(t, func(s *Settings) { s.Confirm = 2 })
	sc.all(stateStalled)
	w.Tick(context.Background()) // les deux sources ont dit « stalled »
	sc.errs["brokerd"] = errors.New("connexion refusée")
	w.Tick(context.Background())
	if len(rec.entries) != 1 || !strings.Contains(rec.entries[0].detail, `"brokerd":"unreadable"`) || !strings.Contains(rec.entries[0].detail, `"pepd":"stalled"`) {
		t.Fatalf("feuilles = %+v", rec.entries)
	}
}
