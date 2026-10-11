package devconsole

import (
	"crypto/sha256"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxRequests   = 2000
	maxLoose      = 2000
	maxSeen       = 50000
	attachWindow  = 3000 // ms : une poignée de main TLS refusée et la requête sans certificat qui l'explique
	statsWindow   = 500
	subscriberBuf = 256
)

// Update est ce que la console pousse aux navigateurs ouverts.
type Update struct {
	Kind    string       `json:"kind"` // request | loose | state
	Request *RequestView `json:"request,omitempty"`
	Loose   *EventView   `json:"loose,omitempty"`
	State   *State       `json:"state,omitempty"`
}

// Store garde, en mémoire et bornés, les événements reçus, regroupés par requête.
type Store struct {
	mu      sync.Mutex
	now     func() time.Time
	seq     uint64
	reqs    map[string][]Event
	order   []string // identifiants, du plus ancien au plus récent
	loose   []Event
	states  map[string]State
	seen    map[[32]byte]struct{}
	seenQ   [][32]byte
	subs    map[chan Update]struct{}
	lastEvt map[string]int64 // machine → dernier événement reçu (ms)
}

// NewStore crée un Store. now est injectable pour les tests.
func NewStore(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{now: now, reqs: map[string][]Event{}, states: map[string]State{}, seen: map[[32]byte]struct{}{},
		subs: map[chan Update]struct{}{}, lastEvt: map[string]int64{}}
}

// Subscribe abonne un navigateur ; Unsubscribe le retire. Un abonné trop lent est coupé (il se resynchronise par instantané).
func (s *Store) Subscribe() chan Update {
	ch := make(chan Update, subscriberBuf)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan Update) {
	s.mu.Lock()
	if _, ok := s.subs[ch]; ok {
		delete(s.subs, ch)
		close(ch)
	}
	s.mu.Unlock()
}

func (s *Store) broadcast(u Update) {
	for ch := range s.subs {
		select {
		case ch <- u:
		default:
			delete(s.subs, ch)
			close(ch)
		}
	}
}

// remember dit si la ligne a déjà été vue (un expéditeur qui redémarre renvoie ce qu'il avait déjà envoyé).
func (s *Store) remember(raw []byte) bool {
	h := sha256.Sum256(raw)
	if _, dup := s.seen[h]; dup {
		return true
	}
	s.seen[h] = struct{}{}
	s.seenQ = append(s.seenQ, h)
	if len(s.seenQ) > maxSeen {
		delete(s.seen, s.seenQ[0])
		s.seenQ = s.seenQ[1:]
	}
	return false
}

// AddLine reçoit une ligne d'ingestion. Rend false si elle est refusée ou déjà connue.
func (s *Store) AddLine(raw []byte) bool {
	ev, st, ok := ParseLine(raw)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Un état n'est jamais dédoublonné : deux rapports identiques à la suite prouvent que la machine est encore là.
	if st == nil && s.remember(raw) {
		return false
	}
	nowMs := s.now().UnixMilli()
	if st != nil {
		st.ReceivedMs = nowMs
		s.states[st.Machine] = *st
		s.lastEvt[st.Machine] = nowMs
		cp := *st
		s.broadcast(Update{Kind: "state", State: &cp})
		return true
	}
	s.seq++
	ev.Seq, ev.RecvMs = s.seq, nowMs
	if m := ev.Machine(); m != "" {
		s.lastEvt[m] = nowMs
	}
	s.place(*ev)
	return true
}

func (s *Store) addToRequest(e Event) {
	if _, known := s.reqs[e.TraceID]; !known {
		s.order = append(s.order, e.TraceID)
		if len(s.order) > maxRequests {
			delete(s.reqs, s.order[0])
			s.order = s.order[1:]
		}
	}
	s.reqs[e.TraceID] = append(s.reqs[e.TraceID], e)
}

func (s *Store) publishRequest(id string) {
	v := BuildRequest(id, s.reqs[id], s.now())
	s.broadcast(Update{Kind: "request", Request: &v})
}

func isNoCertRequest(e Event) bool {
	return e.Component == "agent" && e.Stage == "request" && strings.Contains(e.Detail, "no client certificate")
}

// place range l'événement : dans sa requête s'il en porte une ; une poignée de main TLS refusée (qui n'en porte pas,
// la cellule ne l'a jamais vue comme requête) est rattachée à la requête « sans certificat » reçue à moins de 3 s,
// dans un sens comme dans l'autre. Le rapprochement se fait sur l'heure de RÉCEPTION par la console, pas sur les
// horloges des machines.
func (s *Store) place(e Event) {
	switch {
	case e.TraceID != "":
		s.addToRequest(e)
		if isNoCertRequest(e) {
			s.claimTransport(e)
		}
		s.publishRequest(e.TraceID)
	case e.Component == "transport":
		if id := s.findNoCertRequest(e.RecvMs); id != "" {
			e.TraceID = id
			s.addToRequest(e)
			s.publishRequest(id)
			return
		}
		s.addLoose(e)
	default:
		s.addLoose(e)
	}
}

func (s *Store) findNoCertRequest(recvMs int64) string {
	for i := len(s.order) - 1; i >= 0; i-- {
		id := s.order[i]
		evs := s.reqs[id]
		var hasReq, hasTLS bool
		for _, e := range evs {
			if isNoCertRequest(e) && abs(e.RecvMs-recvMs) <= attachWindow {
				hasReq = true
			}
			if e.Component == "transport" {
				hasTLS = true
			}
		}
		if hasReq && !hasTLS {
			return id
		}
	}
	return ""
}

func (s *Store) claimTransport(req Event) {
	keep := s.loose[:0]
	claimed := false
	for _, e := range s.loose {
		if !claimed && e.Component == "transport" && abs(e.RecvMs-req.RecvMs) <= attachWindow {
			e.TraceID = req.TraceID
			s.addToRequest(e)
			claimed = true
			continue
		}
		keep = append(keep, e)
	}
	s.loose = keep
}

func (s *Store) addLoose(e Event) {
	s.loose = append(s.loose, e)
	if len(s.loose) > maxLoose {
		s.loose = s.loose[1:]
	}
	v := looseView(e)
	s.broadcast(Update{Kind: "loose", Loose: &v})
}

func looseView(e Event) EventView {
	v := EventView{Seq: e.Seq, Machine: e.Machine(), Component: e.Component, Text: describe(e), Outcome: e.Outcome, Reason: e.Reason, RecvMs: e.RecvMs, TS: e.TS}
	if w, ok := Explain(e.Reason); ok {
		w := w
		v.Why = &w
	}
	return v
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// MachineView est l'état d'une machine tel qu'affiché : ce qu'elle rapporte, et depuis combien de temps.
type MachineView struct {
	Machine    string            `json:"machine"`
	Role       string            `json:"role"`
	Components []ComponentState  `json:"components"`
	Facts      map[string]string `json:"facts,omitempty"`
	AgeMs      int64             `json:"age_ms"` // -1 : jamais rapporté
	Status     string            `json:"status"` // up | degraded | down | unknown | idle
}

// staleAfterMs : au-delà, une machine qui ne rapporte plus est UNKNOWN, jamais « up ».
const staleAfterMs = 8000

// Snapshot est l'état complet envoyé à un navigateur qui se connecte.
type Snapshot struct {
	NowMs    int64                   `json:"now_ms"`
	Machines []MachineView           `json:"machines"`
	Requests []RequestView           `json:"requests"` // du plus récent au plus ancien
	Loose    []EventView             `json:"loose"`    // du plus récent au plus ancien
	Stats    map[string]SegmentStats `json:"stats"`
	Window   int                     `json:"window"`
}

func (s *Store) machineViews(nowMs int64) []MachineView {
	roles := map[string]string{"M1": "the cell", "M2": "the application server", "M3": "the agent"}
	var out []MachineView
	for _, m := range []string{"M1", "M2"} {
		v := MachineView{Machine: m, Role: roles[m], AgeMs: -1, Status: "unknown"}
		if st, ok := s.states[m]; ok {
			v.Components, v.Facts = st.Components, st.Facts
			v.AgeMs = nowMs - st.ReceivedMs
			if v.AgeMs <= staleAfterMs {
				v.Status = "up"
				for _, c := range st.Components {
					if c.Status == "down" {
						v.Status = "down"
					} else if c.Status == "degraded" && v.Status == "up" {
						v.Status = "degraded"
					}
				}
			}
		}
		out = append(out, v)
	}
	// M3 n'a pas de démon : elle n'est jamais « down », on dit seulement quand elle a agi pour la dernière fois.
	m3 := MachineView{Machine: "M3", Role: roles["M3"], AgeMs: -1, Status: "unknown"}
	if t, ok := s.lastEvt["M3"]; ok {
		m3.AgeMs, m3.Status = nowMs-t, "idle"
		m3.Components = []ComponentState{{Name: "agent", Status: "up", Detail: "last request seen"}}
	}
	return append(out, m3)
}

// Snapshot rend l'état courant.
func (s *Store) Snapshot(limit int) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if limit <= 0 || limit > maxRequests {
		limit = 200
	}
	snap := Snapshot{NowMs: now.UnixMilli(), Machines: s.machineViews(now.UnixMilli()), Window: statsWindow}
	for i := len(s.order) - 1; i >= 0 && len(snap.Requests) < limit; i-- {
		snap.Requests = append(snap.Requests, BuildRequest(s.order[i], s.reqs[s.order[i]], now))
	}
	for i := len(s.loose) - 1; i >= 0 && len(snap.Loose) < limit; i-- {
		snap.Loose = append(snap.Loose, looseView(s.loose[i]))
	}
	var done []RequestView
	for i := len(s.order) - 1; i >= 0 && len(done) < statsWindow; i-- {
		done = append(done, BuildRequest(s.order[i], s.reqs[s.order[i]], now))
	}
	snap.Stats = ComputeStats(done)
	return snap
}

// Request rend une requête par son identifiant.
func (s *Store) Request(id string) (RequestView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	evs, ok := s.reqs[id]
	if !ok {
		return RequestView{}, false
	}
	return BuildRequest(id, evs, s.now()), true
}

// SegmentStats est la distribution d'une durée sur la fenêtre.
type SegmentStats struct {
	N   int   `json:"n"`
	P50 int64 `json:"p50_us"`
	P95 int64 `json:"p95_us"`
	P99 int64 `json:"p99_us"`
	Max int64 `json:"max_us"`
}

func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p*float64(len(sorted))+0.999999) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// ComputeStats calcule p50/p95/p99/max de chaque durée, sur les requêtes données (« total » inclus).
func ComputeStats(reqs []RequestView) map[string]SegmentStats {
	by := map[string][]int64{}
	for _, r := range reqs {
		for k, v := range r.Segments {
			if v > 0 {
				by[k] = append(by[k], v)
			}
		}
		if r.TotalUs > 0 {
			by["total"] = append(by["total"], r.TotalUs)
		}
	}
	out := map[string]SegmentStats{}
	for k, vs := range by {
		sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
		out[k] = SegmentStats{N: len(vs), P50: percentile(vs, .50), P95: percentile(vs, .95), P99: percentile(vs, .99), Max: vs[len(vs)-1]}
	}
	return out
}
