package devconsole

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	viewKey   = "view-key-0123456789abcdef"
	ingestKey = "ingest-key-0123456789abcd"
)

func newTestServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	st := NewStore(nil)
	s, err := NewServer(Config{ViewKey: viewKey, IngestKey: ingestKey, Label: "unit"}, st)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func do(t *testing.T, method, url string, hdr map[string]string, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestNewServerRefusesWeakOrSharedKeys(t *testing.T) {
	for _, c := range []Config{{ViewKey: "short", IngestKey: ingestKey}, {ViewKey: viewKey, IngestKey: "short"}, {ViewKey: viewKey, IngestKey: viewKey}} {
		if _, err := NewServer(c, NewStore(nil)); err == nil {
			t.Errorf("clés refusées attendues: %+v", c)
		}
	}
}

func TestReadingNeedsTheViewKeyAndIngestNeedsTheIngestKey(t *testing.T) {
	ts, _ := newTestServer(t)
	view := map[string]string{"Authorization": "Bearer " + viewKey}
	ingest := map[string]string{"Authorization": "Bearer " + ingestKey}
	for _, p := range []string{"/", "/app.js", "/app.css", "/api/snapshot", "/api/stream", "/api/request/x"} {
		if r, _ := do(t, "GET", ts.URL+p, nil, ""); r.StatusCode != 401 {
			t.Errorf("GET %s sans clé: %d", p, r.StatusCode)
		}
		if r, _ := do(t, "GET", ts.URL+p, ingest, ""); r.StatusCode != 401 {
			t.Errorf("GET %s avec la clé d'ingestion: %d — qui peut envoyer ne doit pas pouvoir lire", p, r.StatusCode)
		}
	}
	if r, _ := do(t, "GET", ts.URL+"/api/snapshot", view, ""); r.StatusCode != 200 {
		t.Errorf("snapshot avec la clé de lecture: %d", r.StatusCode)
	}
	for _, h := range []map[string]string{nil, view, {"Authorization": "Bearer wrong-wrong-wrong-wrong"}} {
		if r, _ := do(t, "POST", ts.URL+"/ingest", h, `{}`); r.StatusCode != 401 {
			t.Errorf("POST /ingest avec %v: %d — qui peut lire ne doit pas pouvoir écrire", h, r.StatusCode)
		}
	}
	if r, _ := do(t, "POST", ts.URL+"/ingest", ingest, ""); r.StatusCode != 200 {
		t.Errorf("ingest valide: %d", r.StatusCode)
	}
	if r, b := do(t, "GET", ts.URL+"/healthz", nil, ""); r.StatusCode != 200 || strings.TrimSpace(b) != "ok" {
		t.Errorf("healthz: %d %q", r.StatusCode, b)
	}
}

func TestKeyInTheAddressBecomesACookieAndLeavesTheAddress(t *testing.T) {
	ts, _ := newTestServer(t)
	r, _ := do(t, "GET", ts.URL+"/?key="+viewKey, nil, "")
	if r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/" {
		t.Fatalf("redirection attendue vers / sans la clé: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	var ck *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == cookieName {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Value != viewKey {
		t.Fatalf("cookie: %+v", ck)
	}
	if r2, _ := do(t, "GET", ts.URL+"/?key=not-the-key-not-the-key", nil, ""); r2.StatusCode != 401 {
		t.Fatalf("mauvaise clé: %d", r2.StatusCode)
	}
	r3, body := do(t, "GET", ts.URL+"/", map[string]string{"Cookie": cookieName + "=" + viewKey}, "")
	if r3.StatusCode != 200 || !strings.Contains(body, "TBP dev-test console") {
		t.Fatalf("page avec le cookie: %d", r3.StatusCode)
	}
	csp := r3.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP sans %q: %s", want, csp)
		}
	}
	if r3.Header.Get("X-Content-Type-Options") != "nosniff" || r3.Header.Get("Cache-Control") != "no-store" || r3.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("en-têtes: %v", r3.Header)
	}
}

func TestIngestIsBounded(t *testing.T) {
	ts, st := newTestServer(t)
	h := map[string]string{"Authorization": "Bearer " + ingestKey}
	big := strings.Repeat("x", maxIngestBytes+10)
	if r, _ := do(t, "POST", ts.URL+"/ingest", h, big); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("corps trop gros: %d", r.StatusCode)
	}
	var lines strings.Builder
	for i := 0; i < maxIngestLines+20; i++ {
		lines.WriteString(`{"component":"app","stage":"request","outcome":"received","intent":"n` + strings.Repeat("a", 1) + string(rune('a'+i%26)) + `","ts":"` + strings.Repeat("0", i%7) + `","peer":"` + string(rune('a'+i/26)) + `"}` + "\n")
	}
	_, out := do(t, "POST", ts.URL+"/ingest", h, lines.String())
	if !strings.Contains(out, `"rejected"`) {
		t.Errorf("réponse: %s", out)
	}
	if n := len(st.Snapshot(maxRequests).Loose); n > maxIngestLines {
		t.Errorf("%d lignes acceptées d'un coup, plafond %d", n, maxIngestLines)
	}
	long := `{"component":"app","stage":"request","outcome":"received","intent":"` + strings.Repeat("y", maxLineBytes) + `"}`
	_, out = do(t, "POST", ts.URL+"/ingest", h, long)
	if !strings.Contains(out, `"accepted":0`) {
		t.Errorf("ligne trop longue: %s", out)
	}
}

func TestLiveStreamPushesWhatIsIngested(t *testing.T) {
	ts, _ := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/stream", nil)
	req.Header.Set("Authorization", "Bearer "+viewKey)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("type %q", ct)
	}
	rd := bufio.NewReader(resp.Body)
	if l, _ := rd.ReadString('\n'); !strings.HasPrefix(l, ": connected") {
		t.Fatalf("première ligne %q", l)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		do(t, "POST", ts.URL+"/ingest", map[string]string{"Authorization": "Bearer " + ingestKey},
			`{"ts":"x","trace_id":"t-live","component":"agent","stage":"request","outcome":"emitted","detail":"agent-i asks: read doc-1"}`)
	}()
	var got string
	for i := 0; i < 8 && got == ""; i++ {
		l, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(l, "event: request") {
			data, _ := rd.ReadString('\n')
			got = data
		}
	}
	if !strings.Contains(got, `"id":"t-live"`) || !strings.Contains(got, "agent-i asks") {
		t.Fatalf("mise à jour attendue en temps réel, reçu %q", got)
	}
}

func TestSlowSubscriberIsCutNotWaitedFor(t *testing.T) {
	st := NewStore(nil)
	ch := st.Subscribe()
	for i := 0; i < subscriberBuf+10; i++ {
		st.AddLine([]byte(`{"type":"state","machine":"M1","components":[{"name":"opa","status":"up"}]}`))
	}
	n := 0
	for range ch {
		n++
	}
	if n > subscriberBuf {
		t.Fatalf("%d messages mis en file", n)
	}
}

// — l'expéditeur —

func TestFollowerReadsWholeLinesAndSurvivesTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "t.jsonl")
	f := &follower{path: p}
	if len(f.poll()) != 0 {
		t.Fatal("fichier absent: rien")
	}
	if err := os.WriteFile(p, []byte("{\"a\":1}\n{\"b\":"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.poll(); len(got) != 1 || string(got[0]) != `{"a":1}` {
		t.Fatalf("une ligne complète seulement: %q", got)
	}
	fh, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString("2}\n")
	fh.Close()
	if got := f.poll(); len(got) != 1 || string(got[0]) != `{"b":2}` {
		t.Fatalf("la ligne coupée doit être recollée: %q", got)
	}
	if err := os.WriteFile(p, []byte("{\"c\":3}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.poll(); len(got) != 1 || string(got[0]) != `{"c":3}` {
		t.Fatalf("fichier tronqué: relire depuis le début: %q", got)
	}
}

func TestTLSEventFromLogUsesTheMachinesOwnTimeZone(t *testing.T) {
	loc := time.FixedZone("CEST", 2*3600)
	b, ok := TLSEventFromLog("2026/10/11 14:00:05 http: TLS handshake error from 10.0.0.9:51000: tls: client didn't provide a certificate", loc)
	if !ok {
		t.Fatal("ligne reconnue attendue")
	}
	ev, _, _ := ParseLine(b)
	if ev == nil || ev.Component != "transport" || ev.Peer != "10.0.0.9:51000" || !strings.HasPrefix(ev.TS, "2026-10-11T12:00:05") {
		t.Fatalf("%+v", ev)
	}
	if _, ok := TLSEventFromLog("2026/10/11 14:00:05 something else", loc); ok {
		t.Fatal("autre ligne: ignorée")
	}
}

func fakeUnixServer(t *testing.T, h http.Handler) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "dc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func writePID(t *testing.T, dir, name string, pid int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".pid"), []byte(strings.TrimSpace(itoaPID(pid))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
func itoaPID(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestCollectStateM1ReportsDownWhenASourceDoesNotAnswer(t *testing.T) {
	run := t.TempDir()
	opa := fakeUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) }))
	broker := fakeUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/supervision/stats":
			w.Write([]byte(`{"requests":12,"allows":4,"denies":8,"quorum_denies":0,"plan_denies":5,"envelope_denies":0,"issuance_failures":0,"leaf_failures":1,"translation_failures":0}`))
		case "/v1/supervision/arbitration":
			w.Write([]byte(`{"policy_id":"601b4836a09855f492d006cd10006053","pending":[{"hash":"x"}]}`))
		case "/v1/supervision/opa":
			w.Write([]byte(`{"state":"healthy","stalled":false}`))
		}
	}))
	pid := os.Getpid()
	writePID(t, run, "opa", pid)
	writePID(t, run, "brokerd", pid)
	st := CollectState(ShipConfig{Machine: "M1", RunDir: run, AdminSock: broker, OPASock: opa})
	by := map[string]ComponentState{}
	for _, c := range st.Components {
		by[c.Name] = c
	}
	if by["opa (rules engine)"].Status != "up" || by["brokerd (the cell)"].Status != "degraded" {
		t.Fatalf("une faute de feuille de la cellule doit la rendre « degraded »: %+v", st.Components)
	}
	if st.Facts["decisions"] != "12 (4 allowed, 8 denied)" || st.Facts["plans waiting"] != "1" || !strings.HasPrefix(st.Facts["rules in force"], "601b4836a09855f4") {
		t.Fatalf("faits: %+v", st.Facts)
	}
	// processus mort ou socket muet: down, jamais up
	os.Remove(filepath.Join(run, "brokerd.pid"))
	st = CollectState(ShipConfig{Machine: "M1", RunDir: run, AdminSock: broker, OPASock: opa})
	for _, c := range st.Components {
		if c.Name == "brokerd (the cell)" && c.Status != "down" {
			t.Fatalf("sans fichier pid: %+v", c)
		}
	}
	st = CollectState(ShipConfig{Machine: "M1", RunDir: run, AdminSock: filepath.Join(run, "nobody.sock"), OPASock: opa})
	for _, c := range st.Components {
		if c.Name == "brokerd (the cell)" && c.Status != "down" {
			t.Fatalf("sans socket: %+v", c)
		}
	}
}

func TestCollectStateM2(t *testing.T) {
	run := t.TempDir()
	pepd := fakeUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok","mode":"closed","stats":{"evaluations":10,"forwarded":7,"denied":3,"would_deny":0,"max_elapsed_us":2000,"total_elapsed_us":10000}}`))
	}))
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) }))
	defer app.Close()
	opa := fakeUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) }))
	for _, n := range []string{"opa", "pepd", "app"} {
		writePID(t, run, n, os.Getpid())
	}
	st := CollectState(ShipConfig{Machine: "M2", RunDir: run, AdminSock: pepd, OPASock: opa, AppURL: app.URL})
	for _, c := range st.Components {
		if c.Status != "up" {
			t.Errorf("%+v", c)
		}
	}
	if st.Facts["posture"] != "closed" || !strings.Contains(st.Facts["verdict time"], "mean 1.00 ms") {
		t.Fatalf("faits: %+v", st.Facts)
	}
}

func TestShipDeliversTraceFilesAndStateToTheConsole(t *testing.T) {
	ts, store := newTestServer(t)
	dir := t.TempDir()
	trace := filepath.Join(dir, "app.jsonl")
	if err := os.WriteFile(trace, line(t, Event{TS: "x", TraceID: "t-ship", Component: "agent", Stage: "request", Outcome: "emitted", Detail: "agent-i asks: read doc-1"}), 0o600); err != nil {
		t.Fatal(err)
	}
	fh, _ := os.OpenFile(trace, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString("\n")
	fh.Close()
	cfg := ShipConfig{ConsoleURL: ts.URL, Key: ingestKey, Machine: "M2", TraceFiles: []string{trace}, RunDir: dir, Interval: 200 * time.Millisecond}
	run := func() (cancel func()) {
		ctx, c := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { Ship(ctx, cfg); close(done) }()
		return func() { c(); <-done }
	}
	stop := run()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := store.Snapshot(10)
		if len(snap.Requests) == 1 && snap.Machines[1].AgeMs >= 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	snap := store.Snapshot(10)
	if len(snap.Requests) != 1 || snap.Requests[0].ID != "t-ship" {
		t.Fatalf("la trace n'est pas arrivée: %+v", snap.Requests)
	}
	if snap.Machines[1].AgeMs < 0 || snap.Machines[1].Status != "down" {
		t.Fatalf("M2 a rapporté un état (ses composants sont arrêtés ici): %+v", snap.Machines[1])
	}
	// un expéditeur qui redémarre renvoie tout: la console ne double rien
	run()()
	if n := len(store.Snapshot(10).Requests[0].Events); n != 1 {
		t.Fatalf("%d événements après redémarrage de l'expéditeur, voulu 1", n)
	}
	if err := Ship(context.Background(), ShipConfig{}); err == nil {
		t.Fatal("configuration incomplète refusée")
	}
}
