package telemetry

// Tests de l'exporteur IPFIX de métadonnées passeport (T21).
//
// Couverture du critère d'acceptation de l'issue :
//   - records IPFIX émis pour chaque flux passeport avec les champs TBP
//     (jti, cellule) — round-trip encodage/décodage + réception UDP ;
//   - « métadonnées uniquement » prouvé STRUCTURELLEMENT (AST) : le
//     package n'importe rien qui touche aux paquets et n'ouvre aucune
//     socket RAW/d'écoute — sa seule sortie réseau est l'UDP émis ;
//   - les records alimentent le pipeline registre : chaque record devient
//     une feuille KindTelemetry hash-only (couture T22 = RecordSink).

import (
	"context"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Fakes & helpers
// ---------------------------------------------------------------------------

type fakeSource struct{ sessions []Session }

func (f *fakeSource) Snapshot() []Session { return f.sessions }

type sinkRecorder struct {
	records []Record
	err     error // si non nil : Feed échoue (panne registre simulée)
}

func (s *sinkRecorder) Feed(r Record) error {
	if s.err != nil {
		return s.err
	}
	s.records = append(s.records, r)
	return nil
}

type leafRecorder struct {
	leaves []registry.Leaf
	err    error
}

func (l *leafRecorder) Append(_ context.Context, leaf registry.Leaf) (uint64, error) {
	if l.err != nil {
		return 0, l.err
	}
	l.leaves = append(l.leaves, leaf)
	return uint64(len(l.leaves)), nil
}

type tripRecorder struct{ reasons []string }

func (t *tripRecorder) trip(reason string) { t.reasons = append(t.reasons, reason) }

func jtiOf(b byte) (j [16]byte) {
	for i := range j {
		j[i] = b
	}
	return
}

func newTestExporter(src SessionSource, sink RecordSink, now *atomic.Int64) *Exporter {
	e, err := NewExporter(ExporterOptions{
		CellID:   "cell-alpha-01",
		Source:   src,
		Sink:     sink,
		Interval: time.Second,
		Now:      func() time.Time { return time.UnixMilli(now.Load()) },
	})
	if err != nil {
		panic(err)
	}
	return e
}

// ---------------------------------------------------------------------------
// Décodeur IPFIX minimal (test uniquement) — vérifie le round-trip.
// ---------------------------------------------------------------------------

type decodedField struct {
	value []byte
}

type decodedRecord struct {
	octetDelta uint64
	ingressIf  uint32
	dstIPv4    [4]byte
	flowStart  uint64
	flowEnd    uint64
	jti        [16]byte
	cellID     string
	resource   string
	operation  string
}

type decodedMessage struct {
	version   uint16
	length    uint16
	exportSec uint32
	seq       uint32
	obsDomain uint32
	template  []struct {
		id         uint16
		size       uint16
		enterprise bool
		pen        uint32
	}
	records []decodedRecord
}

func readVarlen(t *testing.T, b []byte, off *int) []byte {
	t.Helper()
	l := int(b[*off])
	*off++
	if l == 255 {
		l = int(binary.BigEndian.Uint16(b[*off : *off+2]))
		*off += 2
	}
	v := b[*off : *off+l]
	*off += l
	return v
}

func parseMessage(t *testing.T, msg []byte) decodedMessage {
	t.Helper()
	var d decodedMessage
	if len(msg) < 16 {
		t.Fatalf("message trop court: %d", len(msg))
	}
	d.version = binary.BigEndian.Uint16(msg[0:2])
	d.length = binary.BigEndian.Uint16(msg[2:4])
	d.exportSec = binary.BigEndian.Uint32(msg[4:8])
	d.seq = binary.BigEndian.Uint32(msg[8:12])
	d.obsDomain = binary.BigEndian.Uint32(msg[12:16])
	if int(d.length) != len(msg) {
		t.Fatalf("longueur header %d ≠ datagramme %d", d.length, len(msg))
	}
	off := 16
	for off < len(msg) {
		setID := binary.BigEndian.Uint16(msg[off : off+2])
		setLen := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		body := msg[off+4 : off+setLen]
		switch setID {
		case templateSetID:
			o := 0
			tid := binary.BigEndian.Uint16(body[o : o+2])
			if tid != templateID {
				t.Fatalf("template ID %d ≠ %d", tid, templateID)
			}
			n := int(binary.BigEndian.Uint16(body[o+2 : o+4]))
			o += 4
			for i := 0; i < n; i++ {
				rawID := binary.BigEndian.Uint16(body[o : o+2])
				size := binary.BigEndian.Uint16(body[o+2 : o+4])
				o += 4
				f := struct {
					id         uint16
					size       uint16
					enterprise bool
					pen        uint32
				}{id: rawID &^ enterpriseBit, size: size, enterprise: rawID&enterpriseBit != 0}
				if f.enterprise {
					f.pen = binary.BigEndian.Uint32(body[o : o+4])
					o += 4
				}
				d.template = append(d.template, f)
			}
		case templateID:
			o := 0
			for o < len(body) {
				var r decodedRecord
				r.octetDelta = binary.BigEndian.Uint64(body[o : o+8])
				o += 8
				r.ingressIf = binary.BigEndian.Uint32(body[o : o+4])
				o += 4
				copy(r.dstIPv4[:], body[o:o+4])
				o += 4
				r.flowStart = binary.BigEndian.Uint64(body[o : o+8])
				o += 8
				r.flowEnd = binary.BigEndian.Uint64(body[o : o+8])
				o += 8
				copy(r.jti[:], body[o:o+16])
				o += 16
				r.cellID = string(readVarlen(t, body, &o))
				r.resource = string(readVarlen(t, body, &o))
				r.operation = string(readVarlen(t, body, &o))
				d.records = append(d.records, r)
			}
		default:
			t.Fatalf("set ID inconnu: %d", setID)
		}
		off += setLen
	}
	return d
}

// ---------------------------------------------------------------------------
// Configuration fail-closed.
// ---------------------------------------------------------------------------

func TestExporterOptionsFailClosed(t *testing.T) {
	src := &fakeSource{}
	sink := &sinkRecorder{}
	cases := []struct {
		name string
		opts ExporterOptions
		want error
	}{
		{"cellID manquant", ExporterOptions{Source: src, Sink: sink, Interval: time.Second}, ErrCellIDRequired},
		{"source manquante", ExporterOptions{CellID: "c", Sink: sink, Interval: time.Second}, ErrSourceRequired},
		{"sink manquant", ExporterOptions{CellID: "c", Source: src, Interval: time.Second}, ErrSinkRequired},
		{"intervalle nul", ExporterOptions{CellID: "c", Source: src, Sink: sink}, ErrIntervalInvalid},
		{"intervalle négatif", ExporterOptions{CellID: "c", Source: src, Sink: sink, Interval: -time.Second}, ErrIntervalInvalid},
	}
	for _, tc := range cases {
		if _, err := NewExporter(tc.opts); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, attendu %v", tc.name, err, tc.want)
		}
	}
	if _, err := NewTelemetryLeafSink("", make([]byte, 16), &leafRecorder{}, nil); !errors.Is(err, ErrCellIDRequired) {
		t.Errorf("leaf sink cellID: %v", err)
	}
	if _, err := NewTelemetryLeafSink("c", make([]byte, 8), &leafRecorder{}, nil); !errors.Is(err, ErrSaltTooShort) {
		t.Errorf("leaf sink sel court: %v", err)
	}
	if _, err := NewTelemetryLeafSink("c", make([]byte, 16), nil, nil); !errors.Is(err, ErrLeavesRequired) {
		t.Errorf("leaf sink registre: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Round-trip IPFIX : champs standards + champs TBP (jti, cellule).
// ---------------------------------------------------------------------------

func TestIPFIXRoundTrip(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x01), Resource: "10.20.30.40", Operation: "egress", Consumed: 1500},
		{JTI: jtiOf(0x02), Resource: "https://api.example.com/v1/messages", Operation: "POST", Consumed: 42},
	}}
	sink := &sinkRecorder{}
	now := &atomic.Int64{}
	now.Store(1_700_000_000_000)
	e := newTestExporter(src, sink, now)

	if n := e.ExportOnce(); n != 2 {
		t.Fatalf("records émis = %d, attendu 2", n)
	}

	// rejouer l'encodage du message pour inspection (le fil UDP est testé
	// plus bas — ici on valide le format directement)
	msg := encodeMessage(e.obsDomain, 0, now.Load()/1000, sink.records)
	d := parseMessage(t, msg)

	if d.version != ipfixVersion {
		t.Errorf("version = %d, attendu %d", d.version, ipfixVersion)
	}
	if d.obsDomain != e.obsDomain {
		t.Errorf("observationDomainID incohérent")
	}
	// le template porte les 4 champs entreprise avec le PEN TBP
	var ent int
	for _, f := range d.template {
		if f.enterprise {
			ent++
			if f.pen != EnterpriseNumber {
				t.Errorf("champ entreprise id=%d : PEN %d ≠ %d", f.id, f.pen, EnterpriseNumber)
			}
		}
	}
	if ent != 4 {
		t.Errorf("champs entreprise = %d, attendu 4 (jti, cell, resource, operation)", ent)
	}
	if len(d.template) != 9 {
		t.Errorf("champs template = %d, attendu 9", len(d.template))
	}

	if len(d.records) != 2 {
		t.Fatalf("records décodés = %d, attendu 2", len(d.records))
	}
	r0 := d.records[0]
	if r0.jti != jtiOf(0x01) || r0.cellID != "cell-alpha-01" {
		t.Errorf("champs TBP record 0 : jti=%x cell=%q", r0.jti, r0.cellID)
	}
	if r0.octetDelta != 1500 || r0.operation != "egress" {
		t.Errorf("métadonnées record 0 : delta=%d op=%q", r0.octetDelta, r0.operation)
	}
	if r0.dstIPv4 != [4]byte{10, 20, 30, 40} {
		t.Errorf("destinationIPv4Address = %v", r0.dstIPv4)
	}
	r1 := d.records[1]
	if r1.dstIPv4 != [4]byte{} {
		t.Errorf("ressource non-IPv4 : dst devrait être 0.0.0.0, ressource portée par tbp_resource")
	}
	if r1.resource != "https://api.example.com/v1/messages" {
		t.Errorf("tbp_resource record 1 = %q", r1.resource)
	}
	if r1.octetDelta != 42 {
		t.Errorf("delta record 1 = %d, attendu 42", r1.octetDelta)
	}
}

// ---------------------------------------------------------------------------
// Deltas par intervalle, sessions closes/disparues, delta nul.
// ---------------------------------------------------------------------------

func TestDeltasAcrossIntervals(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x01), Resource: "10.0.0.1", Operation: "egress", Consumed: 100},
	}}
	sink := &sinkRecorder{}
	now := &atomic.Int64{}
	now.Store(10_000)
	e := newTestExporter(src, sink, now)

	e.ExportOnce() // delta 100 (première observation)
	now.Store(11_000)
	src.sessions[0].Consumed = 350
	e.ExportOnce() // delta 250

	if len(sink.records) != 2 {
		t.Fatalf("records = %d, attendu 2", len(sink.records))
	}
	if sink.records[0].OctetDelta != 100 || sink.records[1].OctetDelta != 250 {
		t.Errorf("deltas = %d, %d — attendu 100, 250",
			sink.records[0].OctetDelta, sink.records[1].OctetDelta)
	}
	// la fenêtre du 2e record démarre à la fin du 1er
	if sink.records[1].FlowStart != sink.records[0].FlowEnd {
		t.Errorf("fenêtres non chaînées : %d → %d",
			sink.records[0].FlowEnd, sink.records[1].FlowStart)
	}

	// delta nul : pas de record, pas de feuille (§4.3)
	now.Store(12_000)
	if n := e.ExportOnce(); n != 0 {
		t.Errorf("delta nul : %d record(s) émis", n)
	}
	if len(sink.records) != 2 {
		t.Errorf("delta nul : %d feuilles", len(sink.records))
	}

	// session close avec un dernier delta : record final puis sortie du suivi
	now.Store(13_000)
	src.sessions[0].Consumed = 400
	src.sessions[0].Closed = true
	if n := e.ExportOnce(); n != 1 || sink.records[2].OctetDelta != 50 {
		t.Fatalf("clôture : n=%d delta=%d", n, sink.records[2].OctetDelta)
	}

	// session disparue du snapshot (purgée TTL) : sortie du suivi, aucune fuite
	src.sessions = nil
	now.Store(14_000)
	e.ExportOnce()
	if st := e.Stats(); st.Records != 3 {
		t.Errorf("records totaux = %d, attendu 3", st.Records)
	}
	if len(e.last) != 0 {
		t.Errorf("suivi résiduel : %d jti", len(e.last))
	}
}

// ---------------------------------------------------------------------------
// Chaque record = feuille KindTelemetry hash-only (§6.2) ; échec alarmé.
// ---------------------------------------------------------------------------

func TestRecordsBecomeTelemetryLeaves(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x07), Resource: "storage.artifacts", Operation: "append", Consumed: 2048},
	}}
	sink := &sinkRecorder{}
	now := &atomic.Int64{}
	now.Store(20_000)
	e := newTestExporter(src, sink, now)

	salt := []byte("sel-de-test-32-octets-pour-t21!!!")
	leaves := &leafRecorder{}
	leafSink, err := NewTelemetryLeafSink("cell-alpha-01", salt, leaves,
		func() time.Time { return time.UnixMilli(now.Load()) })
	if err != nil {
		t.Fatalf("NewTelemetryLeafSink: %v", err)
	}

	e.ExportOnce()
	if len(sink.records) != 1 {
		t.Fatalf("records = %d", len(sink.records))
	}
	if err := leafSink.Feed(sink.records[0]); err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if len(leaves.leaves) != 1 {
		t.Fatalf("feuilles = %d", len(leaves.leaves))
	}
	leaf := leaves.leaves[0]
	if leaf.Kind != registry.KindTelemetry {
		t.Errorf("kind = %d, attendu KindTelemetry", leaf.Kind)
	}
	if leaf.CellID != "cell-alpha-01" {
		t.Errorf("cellID feuille = %q", leaf.CellID)
	}
	// hash-only : le registre ne voit que sha256(sel ‖ record)
	want := registry.HashPayload(salt, telemetryRecord(sink.records[0]))
	if leaf.PayloadHash != want {
		t.Errorf("payload hash ≠ sha256(sel ‖ record) — la feuille n'est pas l'engagement attendu")
	}
	// et JAMAIS le contenu en clair : le jti lui-même n'apparaît que haché
	if leaf.PayloadHash == [32]byte{} {
		t.Errorf("payload hash nul")
	}
}

func TestLeafFailureAlarms(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x01), Resource: "r", Operation: "o", Consumed: 10},
	}}
	sink := &sinkRecorder{err: errors.New("registre plein")}
	trips := &tripRecorder{}
	now := &atomic.Int64{}
	now.Store(30_000)
	e, err := NewExporter(ExporterOptions{
		CellID: "cell-alpha-01", Source: src, Sink: sink, Interval: time.Second,
		OnTrip: trips.trip, Now: func() time.Time { return time.UnixMilli(now.Load()) },
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.ExportOnce()
	if len(trips.reasons) != 1 || trips.reasons[0] != pep.ReasonLeafWriteFailed {
		t.Errorf("alarmes = %v, attendu [%s]", trips.reasons, pep.ReasonLeafWriteFailed)
	}
	if st := e.Stats(); st.LeafFailures != 1 {
		t.Errorf("LeafFailures = %d", st.LeafFailures)
	}
}

// ---------------------------------------------------------------------------
// Émission UDP réelle vers un collecteur local.
// ---------------------------------------------------------------------------

func TestUDPCollectorReceivesMessage(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("collecteur: %v", err)
	}
	defer pc.Close()

	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x03), Resource: "192.0.2.1", Operation: "egress", Consumed: 777},
	}}
	sink := &sinkRecorder{}
	now := &atomic.Int64{}
	now.Store(1_700_000_123_000)
	e, err := NewExporter(ExporterOptions{
		CellID: "cell-alpha-01", Source: src, Sink: sink, Interval: time.Second,
		Collector: pc.LocalAddr().String(),
		Now:       func() time.Time { return time.UnixMilli(now.Load()) },
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}

	e.ExportOnce()
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("lecture collecteur: %v", err)
	}
	d := parseMessage(t, buf[:n])
	if len(d.records) != 1 || d.records[0].octetDelta != 777 {
		t.Fatalf("records collecteur = %+v", d.records)
	}
	if d.records[0].dstIPv4 != [4]byte{192, 0, 2, 1} {
		t.Errorf("dst = %v", d.records[0].dstIPv4)
	}

	// séquence RFC 7011 : le second cycle porte seq = records déjà émis
	src.sessions[0].Consumed = 1000
	now.Store(1_700_000_124_000)
	e.ExportOnce()
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("lecture collecteur (2): %v", err)
	}
	d = parseMessage(t, buf[:n])
	if d.seq != 1 {
		t.Errorf("seq = %d, attendu 1 (un record déjà émis)", d.seq)
	}
	if d.records[0].octetDelta != 223 {
		t.Errorf("delta = %d, attendu 223", d.records[0].octetDelta)
	}
}

func TestSendFailureCountedAndAlarmed(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x01), Resource: "r", Operation: "o", Consumed: 10},
	}}
	sink := &sinkRecorder{}
	trips := &tripRecorder{}
	now := &atomic.Int64{}
	now.Store(40_000)
	e, err := NewExporter(ExporterOptions{
		CellID: "cell-alpha-01", Source: src, Sink: sink, Interval: time.Second,
		Collector: "127.0.0.1:1", // rien n'écoute — l'envoi UDP ne bloque pas, mais une adresse injoignable doit rester comptée si erreur
		OnTrip:    trips.trip,
		Now:       func() time.Time { return time.UnixMilli(now.Load()) },
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	e.collector = "bad-address-no-port" // échec de résolution garanti
	e.ExportOnce()
	if st := e.Stats(); st.SendFailures != 1 {
		t.Errorf("SendFailures = %d", st.SendFailures)
	}
	if len(trips.reasons) != 1 || trips.reasons[0] != ReasonSendFailed {
		t.Errorf("alarmes = %v", trips.reasons)
	}
	// l'échec de transport n'empêche PAS la feuille (la preuve ne dépend
	// pas du collecteur)
	if len(sink.records) != 1 {
		t.Errorf("records feuilletés = %d malgré l'échec d'envoi", len(sink.records))
	}
}

// ---------------------------------------------------------------------------
// Bout en bout : source = registre de quotas T12 réel (D18).
// ---------------------------------------------------------------------------

func TestLedgerSourceEndToEnd(t *testing.T) {
	now := &atomic.Int64{}
	now.Store(1_700_000_000)
	leaves := &leafRecorder{}
	ledger, err := pep.NewQuotaLedger(pep.QuotaLedgerOptions{
		MaxPassports: 8,
		CellID:       "cell-alpha-01",
		Salt:         []byte("sel-de-test-32-octets-pour-t21!!!"),
		Leaves:       leaves,
		Now:          func() time.Time { return time.Unix(now.Load(), 0) },
	})
	if err != nil {
		t.Fatalf("NewQuotaLedger: %v", err)
	}
	jti := jtiOf(0x09)
	tok := &pep.Token{
		JTI: jti,
		Exp: now.Load() + 300,
		Quota: &pep.Quota{
			Resource:  "storage.artifacts",
			Operation: "append",
			VolumeMax: 1 << 20,
			WindowS:   60,
		},
	}
	counter, err := ledger.Open(tok)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := counter.Consume(4096); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	sink := &sinkRecorder{}
	ms := &atomic.Int64{}
	ms.Store(now.Load() * 1000)
	e := newTestExporter(LedgerSource(ledger), sink, ms)
	if n := e.ExportOnce(); n != 1 {
		t.Fatalf("records = %d", n)
	}
	r := sink.records[0]
	if r.JTI != jti {
		t.Errorf("jti = %x", r.JTI)
	}
	if r.Resource != "storage.artifacts" || r.Operation != "append" {
		t.Errorf("vecteur signé = %q/%q", r.Resource, r.Operation)
	}
	if r.OctetDelta != 4096 {
		t.Errorf("delta = %d, attendu 4096 (total monotone du compteur T12)", r.OctetDelta)
	}

	// le rechargement de fenêtre du quota ne casse PAS la monotonie
	now.Add(120) // fenêtre écoulée → remaining rechargé au prochain Consume
	ms.Store(now.Load() * 1000)
	if err := counter.Consume(100); err != nil {
		t.Fatalf("Consume après fenêtre: %v", err)
	}
	e.ExportOnce()
	if got := sink.records[1].OctetDelta; got != 100 {
		t.Errorf("delta après rechargement = %d, attendu 100 (jamais négatif)", got)
	}
}

// ---------------------------------------------------------------------------
// Borne du datagramme : au-delà de maxRecordsPerMsg, les records excédent-
// aires sont comptés (jamais de croissance silencieuse, §4.3).
// ---------------------------------------------------------------------------

func TestRecordCapCounted(t *testing.T) {
	sessions := make([]Session, 0, maxRecordsPerMsg+5)
	for i := 0; i < maxRecordsPerMsg+5; i++ {
		j := jtiOf(byte(i))
		j[15] = byte(i >> 8)
		sessions = append(sessions, Session{JTI: j, Resource: "r", Operation: "o", Consumed: 1})
	}
	src := &fakeSource{sessions: sessions}
	sink := &sinkRecorder{}
	now := &atomic.Int64{}
	now.Store(50_000)
	e := newTestExporter(src, sink, now)
	if n := e.ExportOnce(); n != maxRecordsPerMsg {
		t.Fatalf("émis = %d, attendu %d", n, maxRecordsPerMsg)
	}
	if st := e.Stats(); st.RecordsLost != 5 {
		t.Errorf("RecordsLost = %d, attendu 5 (comptés, pas silencieux)", st.RecordsLost)
	}
}

// ---------------------------------------------------------------------------
// Déterminisme (§11.3) : même record ⇒ mêmes octets de hash ; template figé.
// ---------------------------------------------------------------------------

func TestDeterministicEncoding(t *testing.T) {
	r := Record{
		JTI: jtiOf(0x0A), CellID: "cell-alpha-01", Resource: "res", Operation: "op",
		IngressIf: 3, OctetDelta: 99, FlowStart: 1000, FlowEnd: 2000,
		DstIPv4: [4]byte{1, 2, 3, 4}, HasDstIPv4: true,
	}
	a, b := telemetryRecord(r), telemetryRecord(r)
	if string(a) != string(b) {
		t.Fatal("telemetryRecord non déterministe")
	}
	if string(a[:5]) != "TBTM1" {
		t.Errorf("préfixe = %q", a[:5])
	}
	t1, t2 := encodeTemplateSet(), encodeTemplateSet()
	if string(t1) != string(t2) {
		t.Fatal("template non déterministe")
	}
	// le template est figé : set ID 2, longueur, template 256, 9 champs
	if binary.BigEndian.Uint16(t1[0:2]) != templateSetID {
		t.Errorf("set ID = %d", binary.BigEndian.Uint16(t1[0:2]))
	}
	if binary.BigEndian.Uint16(t1[4:6]) != templateID {
		t.Errorf("template ID = %d", binary.BigEndian.Uint16(t1[4:6]))
	}
	if n := binary.BigEndian.Uint16(t1[6:8]); n != 9 {
		t.Errorf("field count = %d, attendu 9", n)
	}
}

// ---------------------------------------------------------------------------
// REVUE STRUCTURELLE « métadonnées uniquement » (critère d'acceptation) :
// le package ne peut pas toucher au contenu des paquets — vérifié par AST,
// pas seulement par lecture.
//
//   - imports limités à une liste blanche (stdlib de sérialisation +
//     net/netip pour l'émission UDP + les packages TBP couture) : aucun
//     syscall, aucune bibliothèque de capture, pas d'unsafe ;
//   - aucun construct d'accès paquet : pas de ListenPacket/ListenIP/
//     ListenUDP, pas de RawConn/SyscallConn, pas d'AF_PACKET — le SEUL
//     usage réseau du package est net.ResolveUDPAddr + net.DialUDP +
//     Write (émission vers le collecteur) ;
//   - le type Record ne contient aucun champ d'octets de contenu : ses
//     seuls []byte-ish sont le jti (16 o, métadonnée signée) et les
//     adresses/chaînes de métadonnées.
//
// Les fichiers de TEST sont exclus du scan (le collecteur de test écoute
// légitimement en UDP).
// ---------------------------------------------------------------------------

func TestStructuralMetadataOnly(t *testing.T) {
	allowedImports := map[string]bool{
		"context": true, "crypto/sha256": true, "encoding/binary": true,
		"errors": true, "net": true, "net/netip": true, "sync": true, "time": true,
		// T22 : tri déterministe du top-k (§11.3) et stats atomiques (§5.3)
		// — purement locaux, aucun accès paquet.
		"sort": true, "sync/atomic": true,
		"github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep":      true,
		"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry": true,
	}
	// constructs réseau interdits : tout ce qui ÉCOUTE ou capture
	forbiddenNetSelectors := map[string]bool{
		"Listen": true, "ListenUDP": true, "ListenPacket": true,
		"ListenIP": true, "ListenUnixgram": true, "ListenTCP": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d fichiers)", err, len(files))
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		scanned++
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range node.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if !allowedImports[path] {
				t.Errorf("%s: import hors liste blanche : %s", f, path)
			}
			if strings.Contains(path, "syscall") || strings.Contains(path, "unsafe") ||
				strings.Contains(path, "pcap") || strings.Contains(path, "gopacket") {
				t.Errorf("%s: import d'accès paquet interdit : %s", f, path)
			}
		}
		ast.Inspect(node, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "net" {
				if forbiddenNetSelectors[sel.Sel.Name] {
					t.Errorf("%s: construct d'écoute/capture interdit : net.%s", f, sel.Sel.Name)
				}
			}
			if sel.Sel.Name == "SyscallConn" || sel.Sel.Name == "RawConn" {
				t.Errorf("%s: accès socket brute interdit : %s", f, sel.Sel.Name)
			}
			return true
		})
		// Record ne porte aucun champ de contenu : interdiction des champs
		// []byte hors jti (16 o fixe) — un futur champ « sample »/« payload »
		// ferait échouer ce test à la revue suivante.
		for _, decl := range node.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name.Name != "Record" {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok {
					continue
				}
				for _, field := range st.Fields.List {
					if at, ok := field.Type.(*ast.ArrayType); ok && at.Len == nil {
						t.Errorf("%s: Record.%s est un []byte — champ de contenu potentiel (§4.1-bis)",
							f, field.Names[0].Name)
					}
				}
			}
		}
	}
	if scanned == 0 {
		t.Fatal("aucun fichier scanné — l'assertion structurelle ne protège rien")
	}
}

// Run s'arrête proprement à l'annulation du contexte.
func TestRunStopsOnContextCancel(t *testing.T) {
	src := &fakeSource{sessions: []Session{
		{JTI: jtiOf(0x01), Resource: "r", Operation: "o", Consumed: 1},
	}}
	sink := &sinkRecorder{}
	now := &atomic.Int64{}
	now.Store(60_000)
	e, err := NewExporter(ExporterOptions{
		CellID: "c", Source: src, Sink: sink, Interval: 10 * time.Millisecond,
		Now: func() time.Time { return time.UnixMilli(now.Load()) },
	})
	if err != nil {
		t.Fatalf("NewExporter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run ne s'est pas arrêté à l'annulation du contexte")
	}
	if len(sink.records) == 0 {
		t.Error("aucun record émis pendant la boucle")
	}
}
