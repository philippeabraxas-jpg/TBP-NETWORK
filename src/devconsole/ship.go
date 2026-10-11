package devconsole

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ShipConfig : ce que fait l'expéditeur sur M1 ou M2 — suivre les fichiers de trace de la machine, rapporter l'état de
// ses composants, et tout envoyer à la console. Il ne reçoit rien et n'agit sur rien : il lit des fichiers et des
// sockets d'administration en lecture (GET).
type ShipConfig struct {
	ConsoleURL string
	Key        string
	Machine    string // M1 | M2
	TraceFiles []string
	LogFile    string // M1 : journal de brokerd, seul à connaître les poignées de main TLS refusées
	RunDir     string // les fichiers .pid des processus
	AdminSock  string // M1 : socket d'administration de brokerd ; M2 : celui de pepd
	OPASock    string
	AppURL     string // M2
	Interval   time.Duration
}

const maxQueue = 5000

type sender struct {
	url, key string
	mu       sync.Mutex
	q        [][]byte
	dropped  int
	client   *http.Client
	lastWarn time.Time
}

func (s *sender) push(line []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.q) >= maxQueue {
		s.q = s.q[1:]
		s.dropped++
	}
	s.q = append(s.q, append([]byte(nil), line...))
}

func (s *sender) flush(ctx context.Context) {
	for {
		s.mu.Lock()
		n := len(s.q)
		if n == 0 {
			s.mu.Unlock()
			return
		}
		if n > 200 {
			n = 200
		}
		batch := s.q[:n]
		s.mu.Unlock()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url+"/ingest", bytes.NewReader(bytes.Join(batch, []byte("\n"))))
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+s.key)
		resp, err := s.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				s.mu.Lock()
				s.q = s.q[n:]
				s.mu.Unlock()
				continue
			}
			err = fmt.Errorf("console answered %s", resp.Status)
		}
		if time.Since(s.lastWarn) > 10*time.Second {
			log.Printf("devconsole ship: cannot deliver to %s: %v (kept for retry)", s.url, err)
			s.lastWarn = time.Now()
		}
		return
	}
}

// follower suit un fichier ajouté en fin : il rend les lignes complètes écrites depuis son dernier passage.
type follower struct {
	path    string
	offset  int64
	partial []byte
}

func (f *follower) poll() [][]byte {
	fh, err := os.Open(f.path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil
	}
	if st.Size() < f.offset { // tronqué ou remplacé
		f.offset, f.partial = 0, nil
	}
	if st.Size() == f.offset {
		return nil
	}
	if _, err := fh.Seek(f.offset, io.SeekStart); err != nil {
		return nil
	}
	buf, err := io.ReadAll(io.LimitReader(fh, 4<<20))
	if err != nil {
		return nil
	}
	f.offset += int64(len(buf))
	data := append(f.partial, buf...)
	var out [][]byte
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		if line := bytes.TrimSpace(data[:i]); len(line) > 0 {
			out = append(out, append([]byte(nil), line...))
		}
		data = data[i+1:]
	}
	f.partial = append([]byte(nil), data...)
	if len(f.partial) > maxLineBytes {
		f.partial = nil
	}
	return out
}

var tlsLine = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) http: TLS handshake error from (\S+): (.*)$`)

// TLSEventFromLog lit une ligne du journal de brokerd. Le journal est en heure LOCALE de la machine (log.Printf), pas
// en UTC : on la convertit avec le fuseau de cette machine.
func TLSEventFromLog(line string, loc *time.Location) ([]byte, bool) {
	m := tlsLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return nil, false
	}
	t, err := time.ParseInLocation("2006/01/02 15:04:05", m[1], loc)
	if err != nil {
		return nil, false
	}
	b, _ := json.Marshal(map[string]string{
		"ts": t.UTC().Format(time.RFC3339Nano), "component": "transport", "stage": "handshake", "outcome": "deny",
		"reason": "tls-handshake-error", "detail": "TLS handshake failed: " + m[3], "peer": m[2],
	})
	return b, true
}

func unixClient(sock string) *http.Client {
	return &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", sock)
		}}}
}

func getJSON(c *http.Client, url string, dst any) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst)
}

func pidAlive(runDir, name string) bool {
	b, err := os.ReadFile(filepath.Join(runDir, name+".pid"))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false
	}
	err = syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

func status(ok bool) string {
	if ok {
		return "up"
	}
	return "down"
}

// CollectState rapporte l'état des composants de la machine. Un composant dont la sonde échoue est « down » : on ne
// déduit jamais « up » de l'absence d'erreur.
func CollectState(cfg ShipConfig) State {
	st := State{Type: "state", Machine: cfg.Machine, Facts: map[string]string{}}
	add := func(name, status, detail string) {
		st.Components = append(st.Components, ComponentState{Name: name, Status: status, Detail: detail})
	}
	opaOK := false
	if cfg.OPASock != "" {
		resp, err := unixClient(cfg.OPASock).Get("http://opa/health")
		if err == nil {
			resp.Body.Close()
			opaOK = resp.StatusCode == http.StatusOK
		}
	}
	add("opa (rules engine)", status(pidAlive(cfg.RunDir, "opa") && opaOK), "")
	switch cfg.Machine {
	case "M1":
		c := unixClient(cfg.AdminSock)
		var stats struct {
			Requests, Allows, Denies, QuorumDenies, PlanDenies, EnvelopeDenies uint64
			IssuanceFailures, LeafFailures, TranslationFailures                uint64
		}
		var raw map[string]json.Number
		err := getJSON(c, "http://broker/v1/supervision/stats", &raw)
		get := func(k string) uint64 { n, _ := raw[k].Int64(); return uint64(n) }
		if err == nil {
			stats.Requests, stats.Allows, stats.Denies = get("requests"), get("allows"), get("denies")
			stats.QuorumDenies, stats.PlanDenies, stats.EnvelopeDenies = get("quorum_denies"), get("plan_denies"), get("envelope_denies")
			stats.IssuanceFailures, stats.LeafFailures, stats.TranslationFailures = get("issuance_failures"), get("leaf_failures"), get("translation_failures")
		}
		up := pidAlive(cfg.RunDir, "brokerd") && err == nil
		faults := stats.IssuanceFailures + stats.LeafFailures + stats.TranslationFailures
		switch {
		case !up:
			add("brokerd (the cell)", "down", "")
		case faults > 0:
			add("brokerd (the cell)", "degraded", fmt.Sprintf("%d fault(s) of the cell itself", faults))
		default:
			add("brokerd (the cell)", "up", "")
		}
		if up {
			st.Facts["decisions"] = fmt.Sprintf("%d (%d allowed, %d denied)", stats.Requests, stats.Allows, stats.Denies)
			st.Facts["denied by"] = fmt.Sprintf("quorum %d · plan %d · envelope %d", stats.QuorumDenies, stats.PlanDenies, stats.EnvelopeDenies)
			st.Facts["cell faults"] = strconv.FormatUint(faults, 10)
			var arb struct {
				PolicyID string `json:"policy_id"`
				Pending  []any  `json:"pending"`
			}
			if getJSON(c, "http://broker/v1/supervision/arbitration", &arb) == nil {
				st.Facts["rules in force"] = arb.PolicyID[:min(16, len(arb.PolicyID))] + "…"
				st.Facts["plans waiting"] = strconv.Itoa(len(arb.Pending))
			}
			var opa struct {
				State   string `json:"state"`
				Stalled bool   `json:"stalled"`
			}
			if getJSON(c, "http://broker/v1/supervision/opa", &opa) == nil {
				st.Facts["OPA seen by the cell"] = opa.State
				if opa.Stalled {
					add("opa (rules engine)", "degraded", "stalled")
					st.Components = st.Components[1:]
				}
			}
		}
	case "M2":
		var h struct {
			Mode  string `json:"mode"`
			Stats struct {
				Evaluations, Forwarded, Denied, WouldDeny uint64
				MaxElapsedUs, TotalElapsedUs              int64
			} `json:"stats"`
		}
		var raw struct {
			Mode  string `json:"mode"`
			Stats map[string]json.Number
		}
		err := getJSON(unixClient(cfg.AdminSock), "http://pepd/healthz", &raw)
		if err == nil {
			h.Mode = raw.Mode
			g := func(k string) int64 { n, _ := raw.Stats[k].Int64(); return n }
			h.Stats.Evaluations, h.Stats.Forwarded = uint64(g("evaluations")), uint64(g("forwarded"))
			h.Stats.Denied, h.Stats.WouldDeny = uint64(g("denied")), uint64(g("would_deny"))
			h.Stats.MaxElapsedUs, h.Stats.TotalElapsedUs = g("max_elapsed_us"), g("total_elapsed_us")
		}
		up := pidAlive(cfg.RunDir, "pepd") && err == nil
		if up {
			add("pepd (enforcement point)", "up", "posture "+h.Mode)
			st.Facts["posture"] = h.Mode
			st.Facts["verdicts"] = fmt.Sprintf("%d (%d forwarded, %d blocked, %d would-deny not blocked)", h.Stats.Evaluations, h.Stats.Forwarded, h.Stats.Denied, h.Stats.WouldDeny)
			if h.Stats.Evaluations > 0 {
				st.Facts["verdict time"] = fmt.Sprintf("mean %.2f ms · max %.2f ms (since pepd started)", float64(h.Stats.TotalElapsedUs)/float64(h.Stats.Evaluations)/1000, float64(h.Stats.MaxElapsedUs)/1000)
			}
		} else {
			add("pepd (enforcement point)", "down", "")
		}
		appOK := false
		if cfg.AppURL != "" {
			if resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(strings.TrimRight(cfg.AppURL, "/") + "/healthz"); err == nil {
				resp.Body.Close()
				appOK = resp.StatusCode == http.StatusOK
			}
		}
		add("application", status(pidAlive(cfg.RunDir, "app") && appOK), "")
	}
	return st
}

// Ship tourne jusqu'à l'annulation du contexte.
func Ship(ctx context.Context, cfg ShipConfig) error {
	if cfg.ConsoleURL == "" || cfg.Key == "" || (cfg.Machine != "M1" && cfg.Machine != "M2") {
		return fmt.Errorf("ship: console URL, key and machine (M1 or M2) are required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	s := &sender{url: strings.TrimRight(cfg.ConsoleURL, "/"), key: cfg.Key, client: &http.Client{Timeout: 3 * time.Second}}
	var follows []*follower
	for _, p := range cfg.TraceFiles {
		follows = append(follows, &follower{path: p})
	}
	var logFollow *follower
	if cfg.LogFile != "" {
		logFollow = &follower{path: cfg.LogFile}
	}
	nextState := time.Now()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		for _, f := range follows {
			for _, l := range f.poll() {
				s.push(l)
			}
		}
		if logFollow != nil {
			for _, l := range logFollow.poll() {
				if ev, ok := TLSEventFromLog(string(l), time.Local); ok {
					s.push(ev)
				}
			}
		}
		if !time.Now().Before(nextState) {
			st := CollectState(cfg)
			b, _ := json.Marshal(struct {
				State
				At int64 `json:"at"`
			}{st, time.Now().UnixNano()})
			s.push(b)
			nextState = time.Now().Add(cfg.Interval)
		}
		s.flush(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
