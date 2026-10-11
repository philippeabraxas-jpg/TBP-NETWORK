// Package devconsole : la console temps réel du DEV-TEST (issue #329).
//
// Un testeur déploie trois machines, ouvre UNE adresse dans un navigateur et voit, pendant qu'il agit : le trajet de
// chaque requête (agent → TLS/identité → cellule → application → pepd → exécution ou rejet), l'état de chaque
// composant, et les latences mesurées à chaque étape.
//
// Ce n'est PAS un composant de TBP. C'est un banc d'essai : il reçoit ce que les machines lui envoient (événements de
// trace, état des composants), n'a aucun pouvoir sur elles (aucune route qui agisse, aucune clé de gouvernance) et sert
// une page en lecture seule derrière une clé. Il peut tourner sur M1 ou sur une autre machine.
//
// Deux principes tenus partout :
//   - une source muette n'est jamais verte : un composant qui ne rapporte plus passe en UNKNOWN, jamais « up » ;
//   - les durées ne sont comparées qu'au sein d'une même horloge (curl sur M3, décision sur M1, traitement sur M2) :
//     l'ordre d'une requête vient de l'enchaînement des étapes, pas de la comparaison d'horloges de machines différentes.
package devconsole

import (
	"encoding/json"
	"regexp"
	"strings"
)

const maxField = 256

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Event est une ligne de trace : le sous-ensemble commun de devtrace.Event (écrit par brokerd), de ce que l'application
// de M2 consigne et de ce que M3 consigne. Les champs inconnus sont ignorés à la lecture.
type Event struct {
	TS        string `json:"ts"`
	TraceID   string `json:"trace_id,omitempty"`
	Component string `json:"component"`
	Stage     string `json:"stage"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Hop       string `json:"hop,omitempty"` // « cell » ou « app » : à qui l'agent parlait (réponses de l'agent)
	Subject   string `json:"subject,omitempty"`
	Intent    string `json:"intent,omitempty"`
	PeerCN    string `json:"peer_cn,omitempty"`
	Transport string `json:"transport,omitempty"`
	Peer      string `json:"peer,omitempty"`
	JTI       string `json:"jti,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Forwarded *bool  `json:"forwarded,omitempty"`

	// Durées en microsecondes, chacune mesurée par UNE machine, avec UNE horloge.
	ElapsedUs int64 `json:"elapsed_us,omitempty"` // brokerd : décision ; pepd : verdict
	ConnectUs int64 `json:"connect_us,omitempty"` // agent : connexion TCP (curl)
	TLSUs     int64 `json:"tls_us,omitempty"`     // agent : poignée de main TLS (curl)
	WaitUs    int64 `json:"wait_us,omitempty"`    // agent : de l'envoi de la requête au premier octet (curl)
	TotalUs   int64 `json:"total_us,omitempty"`   // agent : durée totale de l'échange (curl)
	RttUs     int64 `json:"rtt_us,omitempty"`     // application : aller-retour vers pepd
	AppUs     int64 `json:"app_us,omitempty"`     // application : de la réception à la réponse

	// Posés par la console à la réception.
	Seq    uint64 `json:"seq"`
	RecvMs int64  `json:"recv_ms"`
}

// Machine rend la machine d'un composant : l'agent est sur M3, la cellule (et la couche TLS devant elle) sur M1,
// pepd et l'application sur M2.
func (e Event) Machine() string {
	switch e.Component {
	case "agent":
		return "M3"
	case "brokerd", "transport":
		return "M1"
	case "pepd", "app":
		return "M2"
	}
	return ""
}

// ComponentState est l'état d'un composant tel que sa machine le rapporte.
type ComponentState struct {
	Name   string `json:"name"`
	Status string `json:"status"` // up | down | degraded
	Detail string `json:"detail,omitempty"`
}

// State est le rapport périodique d'une machine.
type State struct {
	Type       string            `json:"type"`
	Machine    string            `json:"machine"`
	Components []ComponentState  `json:"components"`
	Facts      map[string]string `json:"facts,omitempty"`
	ReceivedMs int64             `json:"received_ms"`
}

var knownComponents = map[string]bool{"agent": true, "brokerd": true, "transport": true, "pepd": true, "app": true}
var knownMachines = map[string]bool{"M1": true, "M2": true}
var knownStatus = map[string]bool{"up": true, "down": true, "degraded": true}

func clean(s string) string {
	if len(s) > maxField {
		s = s[:maxField]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c == 0x7f {
			b[i] = '?'
		}
	}
	return string(b)
}

func clampUs(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > 1_000_000_000_000 {
		return 1_000_000_000_000
	}
	return v
}

// sanitize borne et nettoie un événement reçu : tout ce qui vient d'un client est une donnée, jamais une consigne.
func (e *Event) sanitize() bool {
	if !knownComponents[e.Component] {
		return false
	}
	e.Stage, e.Outcome = clean(e.Stage), clean(e.Outcome)
	if e.Stage == "" || e.Outcome == "" {
		return false
	}
	if !idPattern.MatchString(e.TraceID) {
		e.TraceID = ""
	}
	e.TS, e.Reason, e.Detail, e.Hop = clean(e.TS), clean(e.Reason), clean(e.Detail), clean(e.Hop)
	e.Subject, e.Intent, e.PeerCN = clean(e.Subject), clean(e.Intent), clean(e.PeerCN)
	e.Transport, e.Peer, e.JTI, e.Mode = clean(e.Transport), clean(e.Peer), clean(e.JTI), clean(e.Mode)
	e.ElapsedUs, e.ConnectUs, e.TLSUs = clampUs(e.ElapsedUs), clampUs(e.ConnectUs), clampUs(e.TLSUs)
	e.WaitUs, e.TotalUs, e.RttUs, e.AppUs = clampUs(e.WaitUs), clampUs(e.TotalUs), clampUs(e.RttUs), clampUs(e.AppUs)
	e.Seq, e.RecvMs = 0, 0
	return true
}

// ParseLine lit une ligne d'ingestion : un événement, ou un état (« type »: « state »).
func ParseLine(line []byte) (ev *Event, st *State, ok bool) {
	var probe struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(line, &probe) != nil {
		return nil, nil, false
	}
	if probe.Type == "state" {
		var s State
		if json.Unmarshal(line, &s) != nil || !knownMachines[s.Machine] {
			return nil, nil, false
		}
		s.Type = "state"
		comps := s.Components
		s.Components = nil
		for _, c := range comps {
			if len(s.Components) >= 12 {
				break
			}
			c.Name, c.Detail = clean(c.Name), clean(c.Detail)
			if c.Name == "" || !knownStatus[c.Status] {
				continue
			}
			s.Components = append(s.Components, c)
		}
		facts := map[string]string{}
		for k, v := range s.Facts {
			if len(facts) >= 24 {
				break
			}
			facts[clean(k)] = clean(v)
		}
		s.Facts, s.ReceivedMs = facts, 0
		return nil, &s, true
	}
	var e Event
	if json.Unmarshal(line, &e) != nil || !e.sanitize() {
		return nil, nil, false
	}
	return &e, nil, true
}

func upper(s string) string { return strings.ToUpper(s) }
