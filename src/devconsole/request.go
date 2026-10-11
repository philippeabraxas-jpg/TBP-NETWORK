package devconsole

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Ending dit comment une requête s'est terminée.
type Ending struct {
	Kind string `json:"kind"` // executed | executed-monitor | rejected | issued | incomplete | running
	Text string `json:"text"`
	By   string `json:"by,omitempty"` // le composant qui a arrêté la requête, s'il y en a un
}

// Hop est une étape du trajet d'une requête.
type Hop struct {
	Name    string `json:"name"`
	Machine string `json:"machine"`
	Status  string `json:"status"` // ok | warn | stopped | skipped | pending
	Detail  string `json:"detail,omitempty"`
	Us      int64  `json:"us,omitempty"`
}

// EventView est un événement prêt à être affiché.
type EventView struct {
	Seq       uint64 `json:"seq"`
	Machine   string `json:"machine"`
	Component string `json:"component"`
	Text      string `json:"text"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason,omitempty"`
	Why       *Why   `json:"why,omitempty"`
	RecvMs    int64  `json:"recv_ms"`
	TS        string `json:"ts"`
}

// RequestView est une requête, de son émission à sa fin.
type RequestView struct {
	ID       string           `json:"id"`
	Summary  string           `json:"summary"`
	Ending   Ending           `json:"ending"`
	Path     []Hop            `json:"path"`
	Events   []EventView      `json:"events"`
	Segments map[string]int64 `json:"segments"`
	TotalUs  int64            `json:"total_us"`
	StartMs  int64            `json:"start_ms"`
	LastMs   int64            `json:"last_ms"`
}

// rank ordonne les événements d'une requête par ENCHAÎNEMENT des étapes, pas par horloge : les horloges de trois
// machines ne sont pas comparables, l'ordre causal l'est.
func rank(e Event) int {
	switch {
	case e.Component == "agent" && e.Stage == "request" && e.Outcome == "emitted":
		return 10
	case e.Component == "transport":
		return 15
	case e.Component == "brokerd":
		return 20
	case e.Component == "agent" && e.Stage == "answer" && e.Hop != "app" && !strings.Contains(e.Detail, "the application answered"):
		return 30
	case e.Component == "agent" && e.Stage == "request":
		return 40
	case e.Component == "app" && e.Stage == "request":
		return 50
	case e.Component == "pepd":
		return 60
	case e.Component == "app":
		return 70
	case e.Component == "agent":
		return 80
	}
	return 90
}

func sortEvents(evs []Event) []Event {
	out := append([]Event(nil), evs...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i]), rank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

func last(evs []Event, f func(Event) bool) *Event {
	for i := len(evs) - 1; i >= 0; i-- {
		if f(evs[i]) {
			e := evs[i]
			return &e
		}
	}
	return nil
}

func actionOf(e Event) string {
	if e.Intent == "" {
		return ""
	}
	var in struct {
		Action   string `json:"action"`
		Resource string `json:"resource"`
	}
	if json.Unmarshal([]byte(e.Intent), &in) == nil && in.Action != "" {
		return in.Action + " " + in.Resource
	}
	return e.Intent
}

// BuildEnding applique les mêmes règles que scripts/devtest/trace.jq (un test de la suite les compare).
func BuildEnding(sorted []Event, now time.Time, lastMs int64) Ending {
	app := last(sorted, func(e Event) bool { return e.Component == "app" && e.Stage == "outcome" })
	pepd := last(sorted, func(e Event) bool { return e.Component == "pepd" })
	cell := last(sorted, func(e Event) bool { return e.Component == "brokerd" })
	got := last(sorted, func(e Event) bool { return e.Component == "agent" && e.Stage == "answer" })
	tls := last(sorted, func(e Event) bool { return e.Component == "transport" })
	switch {
	case tls != nil:
		return Ending{"rejected", "REJECTED at the TLS handshake (M1) — " + whyText("tls-handshake-refused"), "M1 transport"}
	case app != nil && app.Outcome == "executed" && pepd != nil && pepd.Outcome == "deny":
		return Ending{"executed-monitor", "EXECUTED — although pepd's verdict was " + pepd.Reason + ": in the monitor posture pepd records and blocks nothing", ""}
	case app != nil && app.Outcome == "executed":
		return Ending{"executed", "EXECUTED", ""}
	case app != nil && pepd != nil && pepd.Forwarded != nil && !*pepd.Forwarded:
		r := pepd.Reason
		if r == "" {
			r = app.Reason
		}
		return Ending{"rejected", "REJECTED by pepd (M2) — " + whyText(r), "M2 pepd"}
	case app != nil:
		return Ending{"rejected", "REJECTED by the application (M2) — " + whyText(app.Reason), "M2 app"}
	case cell != nil && cell.Outcome == "deny":
		return Ending{"rejected", "REJECTED by the cell (M1) — " + whyText(cell.Reason), "M1 brokerd"}
	case got != nil && got.Outcome == "deny" && got.Reason != "":
		return Ending{"rejected", "REJECTED — " + whyText(got.Reason), ""}
	case cell != nil && cell.Outcome == "allow" && now.UnixMilli()-lastMs > 10_000:
		return Ending{"issued", "TOKEN ISSUED by the cell, not presented to the application (as far as these files show)", ""}
	}
	if now.UnixMilli()-lastMs <= 10_000 {
		return Ending{"running", "in progress…", ""}
	}
	return Ending{"incomplete", "INCOMPLETE — no end seen: the machines that took part may not all be reporting to this console", ""}
}

func describe(e Event) string {
	ms := func(us int64) string { return fmt.Sprintf("%.1f ms", float64(us)/1000) }
	switch {
	case e.Component == "agent" && e.Stage == "request":
		s := e.Detail
		if e.PeerCN != "" {
			s += "   [certificate: " + e.PeerCN + "]"
		}
		return s
	case e.Component == "agent":
		s := "got: " + e.Outcome
		if e.Reason != "" {
			s += " " + e.Reason
		}
		if e.Detail != "" && e.Detail != "answer received from the cell" {
			s += " (" + e.Detail + ")"
		}
		if e.TotalUs > 0 {
			s += "   [" + ms(e.TotalUs) + " round trip]"
		}
		return s
	case e.Component == "brokerd" && e.Stage == "decision":
		s := upper(e.Outcome) + " " + e.Reason + "   [" + orDash(e.Subject) + " · " + actionOf(e) + " · certificate " + orNone(e.PeerCN) + " · " + orDash(e.Transport)
		if e.Peer != "" {
			s += " from " + e.Peer
		}
		if e.ElapsedUs > 0 {
			s += " · " + ms(e.ElapsedUs)
		}
		if e.JTI != "" {
			s += " · jti " + e.JTI[:min(8, len(e.JTI))] + "…"
		}
		return s + "]"
	case e.Component == "brokerd":
		s := "REFUSED " + e.Reason
		if e.Detail != "" {
			s += " (" + e.Detail + ")"
		}
		return s + "   [certificate " + orNone(e.PeerCN) + " · " + orDash(e.Transport) + "]"
	case e.Component == "transport":
		return e.Detail
	case e.Component == "pepd":
		f := "?"
		if e.Forwarded != nil {
			f = fmt.Sprint(*e.Forwarded)
		}
		s := "verdict " + e.Outcome + " " + e.Reason + "   [posture " + orDash(e.Mode) + " · forwarded " + f
		if e.ElapsedUs > 0 {
			s += " · " + ms(e.ElapsedUs)
		}
		return s + "]"
	case e.Component == "app" && e.Stage == "request":
		s := "request received: " + e.Intent + " " + e.Detail
		if e.Peer != "" {
			s += "   [from " + e.Peer + "]"
		}
		return s
	case e.Component == "app":
		s := upper(e.Outcome)
		if e.Reason != "" {
			s += " " + e.Reason
		}
		if e.Detail != "" {
			s += "   [HTTP " + e.Detail + "]"
		}
		return s
	}
	return e.Stage
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func segments(sorted []Event) (map[string]int64, int64) {
	seg := map[string]int64{}
	cellAns := last(sorted, func(e Event) bool { return e.Component == "agent" && e.Stage == "answer" && e.Hop == "cell" })
	appAns := last(sorted, func(e Event) bool { return e.Component == "agent" && e.Stage == "answer" && e.Hop == "app" })
	cell := last(sorted, func(e Event) bool { return e.Component == "brokerd" && e.Stage == "decision" })
	app := last(sorted, func(e Event) bool { return e.Component == "app" && e.Stage == "outcome" })
	pepd := last(sorted, func(e Event) bool { return e.Component == "pepd" })
	if cellAns != nil && cellAns.TotalUs > 0 {
		seg["cell_total"] = cellAns.TotalUs
		seg["cell_connect"] = cellAns.ConnectUs
		seg["cell_tls"] = cellAns.TLSUs
		if cell != nil && cell.ElapsedUs > 0 && cellAns.WaitUs > 0 {
			seg["cell_network"] = max(0, cellAns.WaitUs-cell.ElapsedUs)
		}
	}
	if cell != nil && cell.ElapsedUs > 0 {
		seg["cell_decision"] = cell.ElapsedUs
	}
	if appAns != nil && appAns.TotalUs > 0 {
		seg["app_total"] = appAns.TotalUs
		seg["app_connect"] = appAns.ConnectUs
		if app != nil && app.AppUs > 0 && appAns.WaitUs > 0 {
			seg["app_network"] = max(0, appAns.WaitUs-app.AppUs)
		}
	}
	if app != nil && app.AppUs > 0 {
		seg["app_handling"] = app.AppUs
	}
	if pepd != nil && pepd.ElapsedUs > 0 {
		seg["pepd_verdict"] = pepd.ElapsedUs
	}
	var total int64
	if v, ok := seg["cell_total"]; ok {
		total += v
	}
	if v, ok := seg["app_total"]; ok {
		total += v
	}
	return seg, total
}

func hops(sorted []Event, end Ending) []Hop {
	has := func(f func(Event) bool) *Event { return last(sorted, f) }
	emit := has(func(e Event) bool { return e.Component == "agent" && e.Stage == "request" && e.Outcome == "emitted" })
	tls := has(func(e Event) bool { return e.Component == "transport" })
	cell := has(func(e Event) bool { return e.Component == "brokerd" })
	cellAns := has(func(e Event) bool { return e.Component == "agent" && e.Stage == "answer" && e.Hop == "cell" })
	appReq := has(func(e Event) bool { return e.Component == "app" && e.Stage == "request" })
	pepd := has(func(e Event) bool { return e.Component == "pepd" })
	app := has(func(e Event) bool { return e.Component == "app" && e.Stage == "outcome" })

	// Un jeton déjà obtenu et présenté de nouveau (rejeu, autre ressource, jeton falsifié) ne passe ni par la poignée
	// de main ni par la cellule : ces deux étapes ne font pas partie de cette requête.
	reuse := emit == nil && cell == nil && tls == nil && appReq != nil
	out := []Hop{{Name: "agent", Machine: "M3", Status: "pending"}}
	if emit != nil {
		out[0].Status, out[0].Detail = "ok", strings.TrimSpace(emit.Detail)
	} else if first := has(func(e Event) bool { return e.Component == "agent" && e.Stage == "request" }); first != nil {
		out[0].Status, out[0].Detail = "ok", strings.TrimSpace(first.Detail)
	}
	h := Hop{Name: "TLS / identity", Machine: "M1", Status: "pending"}
	switch {
	case reuse:
		h.Status, h.Detail = "skipped", "token already issued"
	case tls != nil:
		h.Status, h.Detail = "stopped", "handshake refused: "+strings.TrimSpace(tls.Detail)
	case cell != nil:
		h.Status = "ok"
		if cell.PeerCN != "" {
			h.Detail = "certificate " + cell.PeerCN
		}
		if cell.Reason == "agent-transport-unbound" || cell.Reason == "agent-network-only" {
			h.Status, h.Detail = "stopped", cell.Reason
		}
		if cellAns != nil {
			h.Us = cellAns.ConnectUs + cellAns.TLSUs
		}
	}
	out = append(out, h)
	c := Hop{Name: "cell decision", Machine: "M1", Status: "pending"}
	switch {
	case reuse:
		c.Status, c.Detail = "skipped", "no new decision"
	case tls != nil:
		c.Status = "skipped"
	case cell != nil && cell.Outcome == "allow":
		c.Status, c.Detail, c.Us = "ok", "allow "+cell.Reason, cell.ElapsedUs
	case cell != nil:
		c.Status, c.Detail, c.Us = "stopped", cell.Reason, cell.ElapsedUs
		if out[1].Status == "stopped" {
			c.Status = "skipped"
		}
	}
	out = append(out, c)
	a := Hop{Name: "application", Machine: "M2", Status: "pending"}
	p := Hop{Name: "pepd verdict", Machine: "M2", Status: "pending"}
	x := Hop{Name: "executed", Machine: "M2", Status: "pending"}
	reachedApp := appReq != nil
	if !reachedApp {
		if end.Kind != "running" && end.Kind != "issued" && end.Kind != "incomplete" {
			a.Status, p.Status, x.Status = "skipped", "skipped", "skipped"
		}
	} else {
		a.Status = "ok"
		if app != nil && app.Reason == "no-token" {
			a.Status, a.Detail, p.Status, x.Status = "stopped", "no token", "skipped", "skipped"
		}
		if pepd != nil {
			f := pepd.Forwarded != nil && *pepd.Forwarded
			p.Detail, p.Us = pepd.Outcome+" "+pepd.Reason+" · posture "+pepd.Mode, pepd.ElapsedUs
			switch {
			case pepd.Outcome == "allow" && f:
				p.Status = "ok"
			case pepd.Outcome == "deny" && f:
				p.Status = "warn"
			default:
				p.Status = "stopped"
			}
		}
		if app != nil && a.Status != "stopped" {
			if app.Outcome == "executed" {
				x.Status = "ok"
			} else {
				x.Status = "stopped"
				if p.Status == "pending" {
					p.Status = "skipped"
				}
			}
		}
	}
	return append(out, a, p, x)
}

// BuildRequest assemble la vue d'une requête à partir de ses événements.
func BuildRequest(id string, evs []Event, now time.Time) RequestView {
	sorted := sortEvents(evs)
	var startMs, lastMs int64
	for i, e := range sorted {
		if i == 0 || e.RecvMs < startMs {
			startMs = e.RecvMs
		}
		if e.RecvMs > lastMs {
			lastMs = e.RecvMs
		}
	}
	end := BuildEnding(sorted, now, lastMs)
	seg, total := segments(sorted)
	v := RequestView{ID: id, Ending: end, Path: hops(sorted, end), Segments: seg, TotalUs: total, StartMs: startMs, LastMs: lastMs}
	if first := last(sorted, func(e Event) bool { return e.Component == "agent" && e.Stage == "request" && e.Outcome == "emitted" }); first != nil {
		v.Summary = first.Detail
	} else if first := last(sorted, func(e Event) bool { return e.Component == "agent" && e.Stage == "request" }); first != nil {
		v.Summary = first.Detail // « token presented again: … » : une requête rejouée n'a pas d'émission
	} else if c := last(sorted, func(e Event) bool { return e.Component == "brokerd" && e.Stage == "decision" }); c != nil {
		v.Summary = actionOf(*c)
	}
	for _, e := range sorted {
		ev := EventView{Seq: e.Seq, Machine: e.Machine(), Component: e.Component, Text: describe(e), Outcome: e.Outcome, Reason: e.Reason, RecvMs: e.RecvMs, TS: e.TS}
		if w, ok := Explain(e.Reason); ok {
			w := w
			ev.Why = &w
		}
		v.Events = append(v.Events, ev)
	}
	return v
}
