package devconsole

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func line(t *testing.T, e Event) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func feed(t *testing.T, s *Store, evs ...Event) {
	t.Helper()
	for _, e := range evs {
		if !s.AddLine(line(t, e)) {
			t.Fatalf("événement refusé: %+v", e)
		}
	}
}

// — les scénarios du test fonctionnel, tels que les machines les rapportent —

func emit(id, detail string) Event {
	return Event{TS: "2026-10-11T12:00:00.000000Z", TraceID: id, Component: "agent", Stage: "request", Outcome: "emitted", Detail: detail, PeerCN: "agent-i"}
}
func cellDecision(id, outcome, reason string, us int64) Event {
	return Event{TS: "x", TraceID: id, Component: "brokerd", Stage: "decision", Outcome: outcome, Reason: reason, Subject: "agent-i",
		Intent: `{"action":"read","resource":"doc-1"}`, PeerCN: "agent-i", Transport: "mtls", Peer: "10.0.0.9:5555", ElapsedUs: us}
}
func cellAnswer(id, outcome, reason string, connect, tls, wait, total int64) Event {
	return Event{TS: "x", TraceID: id, Component: "agent", Stage: "answer", Hop: "cell", Outcome: outcome, Reason: reason,
		Detail: "answer received from the cell", ConnectUs: connect, TLSUs: tls, WaitUs: wait, TotalUs: total}
}
func presenting(id string) Event {
	return Event{TS: "x", TraceID: id, Component: "agent", Stage: "request", Outcome: "presenting", Detail: "token presented to the application: read doc-1"}
}
func appReq(id string) Event {
	return Event{TS: "x", TraceID: id, Component: "app", Stage: "request", Outcome: "received", Intent: "read doc-1", Detail: "with a token", Peer: "10.0.0.9"}
}
func pepdVerdict(id, outcome, reason string, fwd bool, us int64) Event {
	return Event{TS: "x", TraceID: id, Component: "pepd", Stage: "verdict", Outcome: outcome, Reason: reason, Mode: "monitor", Forwarded: boolp(fwd), ElapsedUs: us}
}
func appOutcome(id, outcome, reason string, appUs int64) Event {
	return Event{TS: "x", TraceID: id, Component: "app", Stage: "outcome", Outcome: outcome, Reason: reason, AppUs: appUs, Detail: "200"}
}
func appAnswer(id string, connect, wait, total int64) Event {
	return Event{TS: "x", TraceID: id, Component: "agent", Stage: "answer", Hop: "app", Outcome: "executed",
		Detail: "the application answered [200]", ConnectUs: connect, WaitUs: wait, TotalUs: total}
}

func build(t *testing.T, id string, now time.Time, evs ...Event) RequestView {
	t.Helper()
	c := &clock{now: t0}
	s := NewStore(c.Now)
	feed(t, s, evs...)
	c.now = now
	v, ok := s.Request(id)
	if !ok {
		t.Fatal("requête inconnue")
	}
	return v
}

func executedFlow(id string) []Event {
	return []Event{emit(id, "agent-i asks: read doc-1"), cellDecision(id, "allow", "ok", 700), cellAnswer(id, "allow", "ok", 300, 4000, 9000, 14000),
		presenting(id), appReq(id), pepdVerdict(id, "allow", "ok", true, 250), appOutcome(id, "executed", "", 1200), appAnswer(id, 250, 2500, 3000)}
}

func TestEndings(t *testing.T) {
	later := t0.Add(time.Minute)
	cases := []struct {
		name string
		evs  []Event
		now  time.Time
		kind string
		text string
		by   string
	}{
		{"executed", executedFlow("a"), later, "executed", "EXECUTED", ""},
		{"monitor: pepd said no, it ran anyway", []Event{emit("a", "x"), cellDecision("a", "allow", "ok", 1), appReq("a"), pepdVerdict("a", "deny", "replay", true, 1), appOutcome("a", "executed", "", 1)}, later,
			"executed-monitor", "EXECUTED — although pepd's verdict was replay: in the monitor posture pepd records and blocks nothing", ""},
		{"rejected by pepd when closed", []Event{emit("a", "x"), appReq("a"), pepdVerdict("a", "deny", "replay", false, 1), appOutcome("a", "refused", "not-forwarded", 1)}, later,
			"rejected", "REJECTED by pepd (M2) — replay — pepd: token check: this token was already used once", "M2 pepd"},
		{"rejected by the cell", []Event{emit("a", "x"), cellDecision("a", "deny", "plan-binding-required", 1)}, later,
			"rejected", "REJECTED by the cell (M1) — plan-binding-required — the cell: plan contract: an action of class I or W needs a plan approved by operators, and none was given", "M1 brokerd"},
		{"rejected by the application for want of a token", []Event{{TS: "x", TraceID: "a", Component: "app", Stage: "request", Outcome: "received", Intent: "read doc-1"}, {TS: "x", TraceID: "a", Component: "app", Stage: "outcome", Outcome: "refused", Reason: "no-token"}}, later,
			"rejected", "REJECTED by the application (M2) — no-token — the application: the request carried no token", "M2 app"},
		{"token issued, never presented", []Event{emit("a", "x"), cellDecision("a", "allow", "ok", 1)}, later, "issued",
			"TOKEN ISSUED by the cell, not presented to the application (as far as these files show)", ""},
		{"in progress right after", []Event{emit("a", "x"), cellDecision("a", "allow", "ok", 1)}, t0.Add(2 * time.Second), "running", "in progress…", ""},
		{"incomplete", []Event{emit("a", "x")}, later, "incomplete", "INCOMPLETE — no end seen: the machines that took part may not all be reporting to this console", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := build(t, "a", c.now, c.evs...)
			if v.Ending.Kind != c.kind || v.Ending.Text != c.text || v.Ending.By != c.by {
				t.Fatalf("fin: %+v, voulu %s / %s / %s", v.Ending, c.kind, c.text, c.by)
			}
		})
	}
}

func TestOrderFollowsTheStepsNotTheArrival(t *testing.T) {
	flow := executedFlow("a")
	rev := make([]Event, len(flow))
	for i, e := range flow {
		rev[len(flow)-1-i] = e
	}
	a := build(t, "a", t0.Add(time.Minute), flow...)
	b := build(t, "a", t0.Add(time.Minute), rev...)
	if len(a.Events) != len(b.Events) {
		t.Fatal("même nombre d'événements attendu")
	}
	for i := range a.Events {
		if a.Events[i].Component != b.Events[i].Component || a.Events[i].Text != b.Events[i].Text {
			t.Fatalf("ligne %d: %q / %q — l'ordre dépend de l'arrivée", i, a.Events[i].Text, b.Events[i].Text)
		}
	}
	want := []string{"agent", "brokerd", "agent", "agent", "app", "pepd", "app", "agent"}
	for i, w := range want {
		if a.Events[i].Component != w {
			t.Fatalf("étape %d: %s, voulu %s", i, a.Events[i].Component, w)
		}
	}
}

func TestSegmentsAreMeasuredOnOneClockEach(t *testing.T) {
	v := build(t, "a", t0.Add(time.Minute), executedFlow("a")...)
	want := map[string]int64{
		"cell_total": 14000, "cell_connect": 300, "cell_tls": 4000, "cell_decision": 700, "cell_network": 8300, // 9000 attendu − 700 de décision
		"app_total": 3000, "app_connect": 250, "app_handling": 1200, "pepd_verdict": 250, "app_network": 1300, // 2500 − 1200
	}
	for k, w := range want {
		if v.Segments[k] != w {
			t.Errorf("%s = %d, voulu %d", k, v.Segments[k], w)
		}
	}
	if v.TotalUs != 17000 {
		t.Errorf("total = %d, voulu 17000", v.TotalUs)
	}
}

func TestPathNamesTheComponentThatStoppedTheRequest(t *testing.T) {
	status := func(v RequestView, name string) string {
		for _, h := range v.Path {
			if h.Name == name {
				return h.Status
			}
		}
		return "absent"
	}
	ok := build(t, "a", t0.Add(time.Minute), executedFlow("a")...)
	for _, h := range ok.Path {
		if h.Status != "ok" {
			t.Errorf("exécutée: %s = %s", h.Name, h.Status)
		}
	}
	cell := build(t, "a", t0.Add(time.Minute), emit("a", "x"), cellDecision("a", "deny", "opa-deny", 1))
	if status(cell, "cell decision") != "stopped" || status(cell, "application") != "skipped" || status(cell, "executed") != "skipped" {
		t.Errorf("refus de la cellule: %+v", cell.Path)
	}
	mon := build(t, "a", t0.Add(time.Minute), emit("a", "x"), cellDecision("a", "allow", "ok", 1), appReq("a"), pepdVerdict("a", "deny", "replay", true, 1), appOutcome("a", "executed", "", 1))
	if status(mon, "pepd verdict") != "warn" || status(mon, "executed") != "ok" {
		t.Errorf("monitor: %+v", mon.Path)
	}
	closed := build(t, "a", t0.Add(time.Minute), emit("a", "x"), cellDecision("a", "allow", "ok", 1), appReq("a"), pepdVerdict("a", "deny", "replay", false, 1), appOutcome("a", "refused", "not-forwarded", 1))
	if status(closed, "pepd verdict") != "stopped" || status(closed, "executed") != "stopped" {
		t.Errorf("fermé: %+v", closed.Path)
	}
	mism := build(t, "a", t0.Add(time.Minute), emit("a", "x"), cellDecision("a", "deny", "agent-transport-unbound", 1))
	if status(mism, "TLS / identity") != "stopped" || status(mism, "cell decision") != "skipped" {
		t.Errorf("identité: %+v", mism.Path)
	}
}

func TestTLSRefusalIsAttachedToTheRequestWithoutCertificateInBothOrders(t *testing.T) {
	noCert := Event{TS: "x", TraceID: "n", Component: "agent", Stage: "request", Outcome: "emitted", Detail: "agent-i asks: read doc-1 (no client certificate)", PeerCN: "none"}
	tls := Event{TS: "2026-10-11T12:00:00Z", Component: "transport", Stage: "handshake", Outcome: "deny", Reason: "tls-handshake-error", Detail: "TLS handshake failed: tls: client didn't provide a certificate"}
	for _, order := range []string{"request first", "handshake first"} {
		c := &clock{now: t0}
		s := NewStore(c.Now)
		if order == "request first" {
			feed(t, s, noCert)
			c.advance(400 * time.Millisecond)
			feed(t, s, tls)
		} else {
			feed(t, s, tls)
			c.advance(400 * time.Millisecond)
			feed(t, s, noCert)
		}
		c.advance(time.Minute)
		v, _ := s.Request("n")
		if v.Ending.Kind != "rejected" || !strings.HasPrefix(v.Ending.Text, "REJECTED at the TLS handshake (M1)") {
			t.Errorf("%s: fin %+v", order, v.Ending)
		}
		if snap := s.Snapshot(10); len(snap.Loose) != 0 {
			t.Errorf("%s: la poignée de main devrait être rattachée, pas laissée seule: %+v", order, snap.Loose)
		}
	}
	// trop loin dans le temps : elle reste seule
	c := &clock{now: t0}
	s := NewStore(c.Now)
	feed(t, s, noCert)
	c.advance(10 * time.Second)
	feed(t, s, tls)
	if len(s.Snapshot(10).Loose) != 1 {
		t.Error("une poignée de main sans requête proche doit rester dans « sans identifiant »")
	}
}

func TestLinesWithoutATraceIDAreListedApart(t *testing.T) {
	c := &clock{now: t0}
	s := NewStore(c.Now)
	feed(t, s, Event{TS: "x", Component: "app", Stage: "request", Outcome: "received", Intent: "read doc-9", Detail: "without a token", Peer: "10.0.0.66"},
		Event{TS: "x", Component: "app", Stage: "outcome", Outcome: "refused", Reason: "no-token", Detail: "401"})
	snap := s.Snapshot(10)
	if len(snap.Requests) != 0 || len(snap.Loose) != 2 {
		t.Fatalf("requêtes %d, sans identifiant %d", len(snap.Requests), len(snap.Loose))
	}
	if !strings.Contains(snap.Loose[0].Text, "no-token") || snap.Loose[0].Why == nil {
		t.Errorf("le refus doit être expliqué: %+v", snap.Loose[0])
	}
}

func TestDuplicatesAreDroppedButStateReportsAreNot(t *testing.T) {
	c := &clock{now: t0}
	s := NewStore(c.Now)
	e := line(t, emit("a", "x"))
	if !s.AddLine(e) || s.AddLine(e) {
		t.Fatal("la 2e ligne identique (un expéditeur qui redémarre) doit être ignorée")
	}
	st := []byte(`{"type":"state","machine":"M1","components":[{"name":"brokerd","status":"up"}]}`)
	if !s.AddLine(st) || !s.AddLine(st) {
		t.Fatal("deux rapports d'état identiques prouvent que la machine est là: les deux comptent")
	}
}

func TestSanitisingAndBounds(t *testing.T) {
	c := &clock{now: t0}
	s := NewStore(c.Now)
	for _, bad := range []string{`not json`, `{"component":"nobody","stage":"s","outcome":"o"}`, `{"component":"app","outcome":"o"}`,
		`{"type":"state","machine":"M9","components":[]}`} {
		if s.AddLine([]byte(bad)) {
			t.Errorf("refusé attendu: %s", bad)
		}
	}
	feed(t, s, Event{TS: "x", TraceID: "bad id!", Component: "app", Stage: "request", Outcome: "received", Intent: "a\nb\x1b[31m" + strings.Repeat("z", 1000), ElapsedUs: -5, TotalUs: 1 << 60})
	snap := s.Snapshot(10)
	if len(snap.Requests) != 0 || len(snap.Loose) != 1 {
		t.Fatalf("un identifiant mal formé ne doit pas devenir une requête: %+v", snap)
	}
	text := snap.Loose[0].Text
	if strings.ContainsAny(text, "\n\x1b") || len(text) > 400 {
		t.Errorf("texte non nettoyé ou non borné: %q", text)
	}
}

func TestMachinesAreNeverGreenWhenSilent(t *testing.T) {
	c := &clock{now: t0}
	s := NewStore(c.Now)
	status := func(m string) string {
		for _, v := range s.Snapshot(1).Machines {
			if v.Machine == m {
				return v.Status
			}
		}
		return ""
	}
	if status("M1") != "unknown" || status("M3") != "unknown" {
		t.Fatalf("rien reçu: M1=%s M3=%s", status("M1"), status("M3"))
	}
	s.AddLine([]byte(`{"type":"state","machine":"M1","components":[{"name":"opa","status":"up"},{"name":"brokerd","status":"up"}]}`))
	if status("M1") != "up" {
		t.Fatalf("M1 vient de rapporter: %s", status("M1"))
	}
	c.advance(9 * time.Second)
	if status("M1") != "unknown" {
		t.Fatalf("M1 muette depuis 9 s ne doit pas rester « up »: %s", status("M1"))
	}
	s.AddLine([]byte(`{"type":"state","machine":"M2","components":[{"name":"pepd","status":"up"},{"name":"application","status":"down"}]}`))
	if status("M2") != "down" {
		t.Fatalf("un composant down fait la machine down: %s", status("M2"))
	}
	s.AddLine([]byte(`{"type":"state","machine":"M2","components":[{"name":"brokerd","status":"degraded"}]}`))
	if status("M2") != "degraded" {
		t.Fatalf("degraded: %s", status("M2"))
	}
	feed(t, s, emit("a", "x"))
	if status("M3") != "idle" {
		t.Fatalf("M3 n'a pas de démon: idle, jamais down: %s", status("M3"))
	}
}

func TestPercentiles(t *testing.T) {
	var reqs []RequestView
	for i := 1; i <= 100; i++ {
		reqs = append(reqs, RequestView{Segments: map[string]int64{"cell_decision": int64(i) * 1000}, TotalUs: int64(i) * 2000})
	}
	st := ComputeStats(reqs)["cell_decision"]
	if st.N != 100 || st.P50 != 50000 || st.P95 != 95000 || st.P99 != 99000 || st.Max != 100000 {
		t.Fatalf("%+v", st)
	}
	if ComputeStats(reqs)["total"].P50 != 100000 {
		t.Fatalf("total: %+v", ComputeStats(reqs)["total"])
	}
	if len(ComputeStats(nil)) != 0 {
		t.Fatal("aucune requête: aucune statistique")
	}
}

func TestStoreIsBounded(t *testing.T) {
	c := &clock{now: t0}
	s := NewStore(c.Now)
	for i := 0; i < maxRequests+50; i++ {
		feed(t, s, emit("t-"+strconv.Itoa(i), "x"))
	}
	if n := len(s.Snapshot(maxRequests).Requests); n != maxRequests {
		t.Fatalf("%d requêtes gardées, voulu %d", n, maxRequests)
	}
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Replace(time.Duration(i).String(), "ns", "", 1))
}

// La copie embarquée du catalogue des raisons est celle que lit le CLI : les deux affichages expliquent pareil.
func TestReasonCatalogueIsTheSameAsTheCLIs(t *testing.T) {
	cli, err := os.ReadFile("../../scripts/devtest/reasons.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if string(cli) != reasonsTSV {
		t.Fatal("src/devconsole/reasons.tsv diffère de scripts/devtest/reasons.tsv : copiez l'un sur l'autre")
	}
	if _, ok := Explain("opa-deny"); !ok {
		t.Fatal("catalogue vide")
	}
}

func TestThePageNeverBuildsHTMLFromData(t *testing.T) {
	js, err := os.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "javascript:"} {
		if strings.Contains(string(js), bad) {
			t.Errorf("app.js contient %q : les données du test (intentions, noms, adresses) viennent d'un attaquant", bad)
		}
	}
	html, _ := os.ReadFile("web/index.html")
	for _, bad := range []string{"onclick=", "onerror=", "onload=", "<script>", "http://", "https://"} {
		if strings.Contains(string(html), bad) {
			t.Errorf("index.html contient %q", bad)
		}
	}
}

func TestSummaryOfAReplayedTokenComesFromWhatTheAgentPresented(t *testing.T) {
	v := build(t, "a", t0.Add(time.Minute), presenting("a"), appReq("a"), pepdVerdict("a", "deny", "replay", true, 1), appOutcome("a", "executed", "", 1))
	if !strings.Contains(v.Summary, "token presented") {
		t.Fatalf("résumé %q", v.Summary)
	}
}

func TestAReplayedTokenSkipsTheStepsItDidNotGoThrough(t *testing.T) {
	v := build(t, "a", t0.Add(time.Minute), presenting("a"), appReq("a"), pepdVerdict("a", "deny", "replay", true, 1), appOutcome("a", "executed", "", 1))
	want := map[string]string{"agent": "ok", "TLS / identity": "skipped", "cell decision": "skipped", "application": "ok", "pepd verdict": "warn", "executed": "ok"}
	for _, h := range v.Path {
		if want[h.Name] != h.Status {
			t.Errorf("%s = %s, voulu %s", h.Name, h.Status, want[h.Name])
		}
	}
}
