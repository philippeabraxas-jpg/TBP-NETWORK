// opa_latency — la latence RÉELLE d'OPA contre le disjoncteur de 5 ms (§9.1, pep.EvalTimeout).
//
// Le harnais de friction (tests/p1_friction) mesure le PEP SEUL, OPA nil : il ne dit rien de ce que coûte l'appel
// OPA lui-même, qui est précisément ce que borne EvalTimeout (5 ms, circuit-breaker §12 : au-delà, deny fail-closed
// et, après TripAfter fautes consécutives, verrou T14). Cet outil comble ce trou avec le VRAI OPA, la VRAIE
// politique (policies/rego/*.rego) et le VRAI client (pep.OPAClient, budget par défaut) :
//
//	COLD   N démarrages d'OPA ; pour chacun, la PREMIÈRE requête (connexion neuve, caches froids) puis la 2e
//	IDLE   OPA chaud, puis une requête après une inactivité (connexion fermée par le serveur, caches refroidis)
//	STEADY une charge à concurrence croissante : latence brute (p50/p90/p99/p99.9/max) ET verdicts du client réel
//	       (combien d'opa-timeout au budget de 5 ms)
//
// en TCP loopback et en socket Unix (le transport nominal, §92.A3). La mesure ne juge pas : elle rend des chiffres.
// Ils valent pour la machine où ils sont pris — voir le README, qui les date.
//
//	go run ./tests/opa_latency [-transport both] [-cold-trials 20] [-concurrency 1,2,4,8,16] [-out report.json]
//	taskset -c 2,3 go run ./tests/opa_latency -opa-cpus 0,1     (OPA et le client sur des cœurs DISTINCTS)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type nopLeaves struct{}

func (nopLeaves) Append(context.Context, registry.Leaf) (uint64, error) { return 0, nil }

// opaServer est un OPA lancé par l'outil.
type opaServer struct {
	cmd       *exec.Cmd
	transport string // "tcp" | "unix"
	addr      string // host:port ou chemin du socket
}

func (s *opaServer) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
	if s.transport == "unix" {
		_ = os.Remove(s.addr)
	}
}

// baseURL : l'hôte est fictif sur un socket Unix (le transport ignore l'adresse).
func (s *opaServer) baseURL() string {
	if s.transport == "unix" {
		return "http://opa"
	}
	return "http://" + s.addr
}

// httpClient rend un client NEUF (connexion neuve à la première requête) : keepAlive = connexions réutilisées.
func (s *opaServer) httpClient(keepAlive bool, maxConns int) *http.Client {
	var tr *http.Transport
	if s.transport == "unix" {
		// le transport NOMINAL de production (§92.A3) : socket Unix + contrôle SO_PEERCRED à chaque connexion
		var err error
		if tr, err = pep.NewOPAUnixTransport(s.addr, uint32(os.Getuid())); err != nil {
			panic(err)
		}
	} else {
		tr = &http.Transport{}
	}
	tr.DisableKeepAlives, tr.MaxIdleConnsPerHost = !keepAlive, maxConns
	return &http.Client{Transport: tr, Timeout: 3 * time.Second}
}

type config struct {
	opaBin, regoDir, path, opaCPUs string
	port                           int
}

func (c config) start(transport string, tmp string, n int) (*opaServer, error) {
	files, _ := filepath.Glob(filepath.Join(c.regoDir, "*.rego"))
	if len(files) == 0 {
		return nil, fmt.Errorf("aucun .rego dans %s", c.regoDir)
	}
	srv := &opaServer{transport: transport}
	var addr string
	if transport == "unix" {
		srv.addr = filepath.Join(tmp, fmt.Sprintf("opa-%d.sock", n))
		addr = "unix://" + srv.addr
	} else {
		srv.addr = fmt.Sprintf("127.0.0.1:%d", c.port)
		addr = srv.addr
	}
	args := []string{c.opaBin, "run", "--server", "--addr", addr, "--log-level", "error"}
	if c.opaCPUs != "" {
		args = append([]string{"taskset", "-c", c.opaCPUs}, args...)
	}
	cmd := exec.Command(args[0], append(args[1:], files...)...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	srv.cmd = cmd
	// prêt = /health répond (connexion jetable : ne réchauffe PAS le chemin de décision)
	hc := srv.httpClient(false, 1)
	for i := 0; i < 300; i++ {
		resp, err := hc.Get(srv.baseURL() + "/health")
		if err == nil {
			_ = resp.Body.Close()
			return srv, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	srv.stop()
	return nil, fmt.Errorf("OPA (%s) ne répond pas", transport)
}

// Corps réaliste : la forme exacte de pep.OPAInput (voir opa_client.go), classe W.
const evalBody = `{"input":{"jti":"00112233445566778899aabbccddeeff","subject":"agent-1","action":"read","resource":"doc-1","class":2,"epoch":0}}`

func rawPost(hc *http.Client, url string) time.Duration {
	t0 := time.Now()
	resp, err := hc.Post(url, "application/json", strings.NewReader(evalBody))
	if err != nil {
		return -1
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return time.Since(t0)
}

// realClient : le client de production (budget par défaut), sur le transport mesuré.
func (c config) realClient(s *opaServer, keepAlive bool, maxConns int) *pep.OPAClient {
	hc := s.httpClient(keepAlive, maxConns)
	cl, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint: s.baseURL() + c.path, HTTPClient: hc, CellID: "cell-latency", Salt: bytes.Repeat([]byte{1}, 16), Leaves: nopLeaves{},
	})
	if err != nil {
		panic(err)
	}
	return cl
}

func evalInput() pep.OPAInput {
	return pep.OPAInput{Subject: "agent-1", Action: "read", Resource: "doc-1", Class: pep.ClassW}
}

// --- statistiques -----------------------------------------------------------------------------------------------

type stats struct {
	N        int     `json:"n"`
	P50ms    float64 `json:"p50_ms"`
	P90ms    float64 `json:"p90_ms"`
	P99ms    float64 `json:"p99_ms"`
	P999ms   float64 `json:"p99_9_ms"`
	MaxMS    float64 `json:"max_ms"`
	Over     int     `json:"over_budget"`
	OverPct  float64 `json:"over_budget_pct"`
	Failures int     `json:"failures"`
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// summarize : d < 0 = requête en échec (transport), comptée à part ; « over » = strictement au-delà du budget.
func summarize(d []time.Duration, budget time.Duration) stats {
	st := stats{N: len(d)}
	var ok []time.Duration
	for _, x := range d {
		if x < 0 {
			st.Failures++
			continue
		}
		ok = append(ok, x)
		if x > budget {
			st.Over++
		}
	}
	if len(ok) == 0 {
		return st
	}
	sort.Slice(ok, func(i, j int) bool { return ok[i] < ok[j] })
	at := func(p float64) float64 { return ms(ok[int(float64(len(ok)-1)*p)]) }
	st.P50ms, st.P90ms, st.P99ms, st.P999ms, st.MaxMS = at(.5), at(.9), at(.99), at(.999), ms(ok[len(ok)-1])
	st.OverPct = 100 * float64(st.Over+st.Failures) / float64(st.N)
	return st
}

type verdicts map[string]int

func (v verdicts) pct(reason string) float64 {
	total := 0
	for _, n := range v {
		total += n
	}
	if total == 0 {
		return 0
	}
	return 100 * float64(v[reason]) / float64(total)
}

// --- mesures ----------------------------------------------------------------------------------------------------

type coldResult struct {
	Trials   int      `json:"trials"`
	First    stats    `json:"first_request"`
	Second   stats    `json:"second_request"`
	Verdicts verdicts `json:"first_request_verdicts"`
}

// cold : N démarrages d'OPA ; pour chacun, la première requête du client RÉEL (connexion neuve) puis la deuxième.
func cold(c config, transport, tmp string, trials int, budget time.Duration) (coldResult, error) {
	var firsts, seconds []time.Duration
	v := verdicts{}
	for i := 0; i < trials; i++ {
		srv, err := c.start(transport, tmp, i)
		if err != nil {
			return coldResult{}, err
		}
		cl := c.realClient(srv, true, 4)
		d1 := cl.Eval(context.Background(), evalInput())
		d2 := cl.Eval(context.Background(), evalInput())
		firsts, seconds = append(firsts, d1.Elapsed), append(seconds, d2.Elapsed)
		v[d1.Reason]++
		srv.stop()
		time.Sleep(150 * time.Millisecond)
	}
	return coldResult{Trials: trials, First: summarize(firsts, budget), Second: summarize(seconds, budget), Verdicts: v}, nil
}

type idleResult struct {
	GapS     float64  `json:"idle_gap_s"`
	Stats    stats    `json:"after_idle"`
	Verdicts verdicts `json:"verdicts"`
}

// idle : OPA chaud, puis une requête du client réel après une inactivité (la connexion keep-alive peut avoir été
// fermée par le serveur, les caches CPU refroidis).
func idle(c config, transport, tmp string, gap time.Duration, trials int, budget time.Duration) (idleResult, error) {
	srv, err := c.start(transport, tmp, 1000)
	if err != nil {
		return idleResult{}, err
	}
	defer srv.stop()
	cl := c.realClient(srv, true, 4)
	for i := 0; i < 300; i++ {
		cl.Eval(context.Background(), evalInput())
	}
	var ds []time.Duration
	v := verdicts{}
	for i := 0; i < trials; i++ {
		time.Sleep(gap)
		d := cl.Eval(context.Background(), evalInput())
		ds = append(ds, d.Elapsed)
		v[d.Reason]++
	}
	return idleResult{GapS: gap.Seconds(), Stats: summarize(ds, budget), Verdicts: v}, nil
}

type steadyResult struct {
	Concurrency int      `json:"concurrency"`
	Raw         stats    `json:"raw_latency"`        // latence TRUE (sans budget : le client n'abandonne pas à 5 ms)
	Verdicts    verdicts `json:"client_verdicts"`    // ce que le client réel (budget 5 ms) a rendu sous la même charge
	TimeoutPct  float64  `json:"client_timeout_pct"` // part d'opa-timeout
}

// steady : charge à concurrence fixe sur un OPA chaud. Deux passes de même taille : brute (latence vraie), puis
// client réel (verdicts au budget).
func steady(c config, srv *opaServer, conc, total int, budget time.Duration) steadyResult {
	run := func(do func() time.Duration) []time.Duration {
		var mu sync.Mutex
		var all []time.Duration
		var wg sync.WaitGroup
		per := total / conc
		for g := 0; g < conc; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				loc := make([]time.Duration, 0, per)
				for i := 0; i < per; i++ {
					loc = append(loc, do())
				}
				mu.Lock()
				all = append(all, loc...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		return all
	}
	hc := srv.httpClient(true, conc)
	url := srv.baseURL() + c.path
	for i := 0; i < 300; i++ {
		rawPost(hc, url)
	}
	raw := run(func() time.Duration { return rawPost(hc, url) })

	cl := c.realClient(srv, true, conc)
	for i := 0; i < 300; i++ {
		cl.Eval(context.Background(), evalInput())
	}
	v := verdicts{}
	var vmu sync.Mutex
	run(func() time.Duration {
		d := cl.Eval(context.Background(), evalInput())
		vmu.Lock()
		v[d.Reason]++
		vmu.Unlock()
		return d.Elapsed
	})
	return steadyResult{Concurrency: conc, Raw: summarize(raw, budget), Verdicts: v, TimeoutPct: v.pct(pep.ReasonOPATimeout)}
}

type transportReport struct {
	Cold   coldResult     `json:"cold"`
	Idle   idleResult     `json:"idle"`
	Steady []steadyResult `json:"steady"`
}

type report struct {
	At        string                     `json:"at"`
	GoOS      string                     `json:"goos"`
	GoArch    string                     `json:"goarch"`
	NumCPU    int                        `json:"num_cpu"`
	OPAVer    string                     `json:"opa_version"`
	OPACPUs   string                     `json:"opa_cpus,omitempty"`
	BudgetMS  float64                    `json:"budget_ms"`
	Transport map[string]transportReport `json:"transports"`
}

func opaVersion(bin string) string {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return "inconnue"
	}
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "Version:") {
			return strings.TrimSpace(strings.TrimPrefix(l, "Version:"))
		}
	}
	return "inconnue"
}

func main() {
	var c config
	flag.StringVar(&c.opaBin, "opa", "opa", "binaire OPA")
	flag.StringVar(&c.regoDir, "rego", "policies/rego", "répertoire des politiques (*.rego)")
	flag.StringVar(&c.path, "path", "/v1/data/tbp/example/action", "chemin de décision OPA")
	flag.StringVar(&c.opaCPUs, "opa-cpus", "", "épingler OPA à ces cœurs (taskset -c) ; lancer l'outil lui-même sous taskset sur les AUTRES")
	flag.IntVar(&c.port, "port", 18991, "port TCP d'OPA")
	transports := flag.String("transport", "both", "tcp | unix | both")
	coldTrials := flag.Int("cold-trials", 20, "démarrages d'OPA pour la mesure à froid")
	idleGap := flag.Duration("idle-gap", 5*time.Second, "inactivité avant la requête « après inactivité »")
	idleTrials := flag.Int("idle-trials", 6, "répétitions de la mesure après inactivité")
	concList := flag.String("concurrency", "1,2,4,8,16", "niveaux de concurrence (liste)")
	total := flag.Int("requests", 4000, "requêtes par niveau de concurrence et par passe")
	budget := flag.Duration("budget", pep.EvalTimeout, "budget de référence (défaut : pep.EvalTimeout)")
	out := flag.String("out", "", "rapport JSON à écrire")
	flag.Parse()

	if _, err := exec.LookPath(c.opaBin); err != nil {
		fatal("binaire OPA introuvable : %v", err)
	}
	var concs []int
	for _, f := range strings.Split(*concList, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			fatal("-concurrency invalide : %q", f)
		}
		concs = append(concs, n)
	}
	var ts []string
	switch *transports {
	case "tcp", "unix":
		ts = []string{*transports}
	case "both":
		ts = []string{"tcp", "unix"}
	default:
		fatal("-transport : tcp | unix | both")
	}
	tmp, err := os.MkdirTemp("", "opa-latency-")
	if err != nil {
		fatal("%v", err)
	}
	defer os.RemoveAll(tmp)

	rep := report{
		At: time.Now().UTC().Format(time.RFC3339), GoOS: runtime.GOOS, GoArch: runtime.GOARCH, NumCPU: runtime.NumCPU(),
		OPAVer: opaVersion(c.opaBin), OPACPUs: c.opaCPUs, BudgetMS: ms(*budget), Transport: map[string]transportReport{},
	}
	for _, tr := range ts {
		fmt.Fprintf(os.Stderr, "[%s] démarrage à froid (%d essais)…\n", tr, *coldTrials)
		var t transportReport
		if t.Cold, err = cold(c, tr, tmp, *coldTrials, *budget); err != nil {
			fatal("%v", err)
		}
		fmt.Fprintf(os.Stderr, "[%s] après inactivité (%d × %s)…\n", tr, *idleTrials, *idleGap)
		if t.Idle, err = idle(c, tr, tmp, *idleGap, *idleTrials, *budget); err != nil {
			fatal("%v", err)
		}
		srv, err := c.start(tr, tmp, 2000)
		if err != nil {
			fatal("%v", err)
		}
		for _, n := range concs {
			fmt.Fprintf(os.Stderr, "[%s] charge, concurrence %d…\n", tr, n)
			t.Steady = append(t.Steady, steady(c, srv, n, *total, *budget))
		}
		srv.stop()
		rep.Transport[tr] = t
	}
	printReport(rep)
	if *out != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
			fatal("%v", err)
		}
	}
}

func printReport(r report) {
	fmt.Printf("OPA %s — %s/%s, %d CPU", r.OPAVer, r.GoOS, r.GoArch, r.NumCPU)
	if r.OPACPUs != "" {
		fmt.Printf(" (OPA épinglé aux cœurs %s)", r.OPACPUs)
	}
	fmt.Printf(" — budget de référence %.1f ms (pep.EvalTimeout)\n", r.BudgetMS)
	names := make([]string, 0, len(r.Transport))
	for k := range r.Transport {
		names = append(names, k)
	}
	sort.Strings(names)
	row := func(label string, s stats) {
		fmt.Printf("  %-22s n=%-5d p50=%6.2f p90=%6.2f p99=%6.2f p99.9=%6.2f max=%7.2f ms   >budget: %d (%.1f %%)\n",
			label, s.N, s.P50ms, s.P90ms, s.P99ms, s.P999ms, s.MaxMS, s.Over+s.Failures, s.OverPct)
	}
	for _, name := range names {
		t := r.Transport[name]
		fmt.Printf("\n== %s ==\n", strings.ToUpper(name))
		row("À FROID, 1re requête", t.Cold.First)
		row("À FROID, 2e requête", t.Cold.Second)
		fmt.Printf("  verdicts de la 1re requête à froid : %v\n", t.Cold.Verdicts)
		row(fmt.Sprintf("après %.0f s d'inactivité", t.Idle.GapS), t.Idle.Stats)
		for _, st := range t.Steady {
			row(fmt.Sprintf("charge, concurrence %d", st.Concurrency), st.Raw)
			fmt.Printf("  %-22s client réel au budget : %v  → opa-timeout %.1f %%\n", "", st.Verdicts, st.TimeoutPct)
		}
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "opa_latency: "+f+"\n", a...)
	os.Exit(1)
}
