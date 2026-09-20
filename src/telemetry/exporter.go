package telemetry

// Exporteur IPFIX de métadonnées de flux passeport (T21, §4.1-bis + §6.2).
//
// Pour l'égress passant par un passeport, l'exporteur émet périodiquement
// un enregistrement de MÉTADONNÉES par session : octets par intervalle,
// destination (la ressource du vecteur quota SIGNÉ), fenêtre de mesure.
// Chaque enregistrement devient une feuille KindTelemetry du registre de
// la cellule (§6 — les feuilles de métadonnées alimentent le registre
// comme les feuilles de décision).
//
// PROSCRIPTION ABSOLUE (§4.1-bis) : aucune inspection du contenu des flux
// passeport. Ce package n'a STRUCTURELLEMENT pas accès aux paquets : sa
// seule source est le totalisateur monotone du compteur de quota (T12),
// sa seule sortie réseau est l'UDP vers le collecteur local. Il n'ouvre
// aucune socket RAW, ne copie aucun payload — assertion vérifiée par test
// (exporter_test.go, revue « métadonnées uniquement » de l'issue).
//
// D17 — encodeur IPFIX auto-porté (stdlib uniquement) : la brique est
// écrite ici plutôt qu'importée — intégralement auditable, zéro ajout au
// go.mod, déterminisme §11.3 maîtrisé. Format v10 : un template set
// (réémis à chaque message en v1 — le débit est faible et le collecteur
// n'a jamais à retenir d'état) suivi d'un data set.
//
// D18 — source = compteur T12, jamais de sonde paquets : l'interface
// SessionSource est alimentée par QuotaLedger.Snapshot() (totalisateur
// monotone — le delta par intervalle est toujours ≥ 0, même au
// rechargement de fenêtre de quota).
//
// D19 — chaque record = feuille KindTelemetry hash-only (§6.2) via la
// couture RecordSink : c'est AUSSI le point d'insertion de T22 —
// l'agrégation s'interposera derrière la même interface sans toucher
// l'exporteur.
//
// Le RYTHME n'est pas un champ du fil : il se dérive en post-traitement
// (octetDeltaCount / fenêtre) — l'anti-dribble est affaire de T23, sur
// métadonnées agrégées, jamais dans l'exporteur.
//
// Records à delta nul : une session vivante sans aucun quantum dans
// l'intervalle ne produit NI record NI feuille (sinon le registre est
// inondé de zéros — §4.3). Sa fenêtre de mesure couvre le trou : le
// post-traitement T23 lit un rythme lissé, jamais une perte de preuve —
// la clôture, elle, est déjà tracée par la feuille de coupure T12.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// EnterpriseNumber est le PEN porté par les champs TBP. 32473 = bloc
// documentation RFC 5615 — PLACEHOLDER en attendant l'assignation IANA
// d'un PEN TBP. Constante nommée : un seul endroit à changer.
const EnterpriseNumber uint32 = 32473

// Constantes du format IPFIX (RFC 7011) et du template TBP.
const (
	ipfixVersion     uint16 = 10
	templateSetID    uint16 = 2
	templateID       uint16 = 256
	enterpriseBit    uint16 = 0x8000
	variableLength   uint16 = 0xFFFF
	maxRecordsPerMsg        = 64 // borne le datagramme (§4.3 : pas de croissance)

	// Champs standards (IANA IPFIX IE registry).
	ieOctetDeltaCount        uint16 = 1   // unsigned64
	ieIngressInterface       uint16 = 10  // unsigned32
	ieDestinationIPv4Address uint16 = 12  // ipv4Address
	ieFlowStartMilliseconds  uint16 = 152 // dateTimeMilliseconds
	ieFlowEndMilliseconds    uint16 = 153 // dateTimeMilliseconds

	// Champs TBP (entreprise — EnterpriseNumber).
	ieTbpJTI       uint16 = 1 // 16 octets — clé de corrélation des feuilles
	ieTbpCellID    uint16 = 2 // string varlen
	ieTbpResource  uint16 = 3 // string varlen — destination AUTORITAIRE (vecteur signé)
	ieTbpOperation uint16 = 4 // string varlen
)

// Codes machine d'alarme de l'exporteur (couture OnTrip, pattern T14).
const (
	ReasonSendFailed = "telemetry-send-failed"
)

// Erreurs de configuration (fail-closed dès la construction).
var (
	ErrCellIDRequired  = errors.New("telemetry: cellID requis (§6.2 : records attribués)")
	ErrSourceRequired  = errors.New("telemetry: source de sessions requise (D18 : compteur T12)")
	ErrSinkRequired    = errors.New("telemetry: couture RecordSink requise (§6 : chaque record = feuille)")
	ErrIntervalInvalid = errors.New("telemetry: intervalle d'export > 0 requis")
	ErrSaltTooShort    = errors.New("telemetry: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	ErrLeavesRequired  = errors.New("telemetry: couture feuilles requise (§4.1-bis : télémétrie tracée)")
)

// Record est un enregistrement de métadonnées de flux passeport —
// MÉTADONNÉES UNIQUEMENT : aucun champ de contenu n'existe dans ce type
// (§4.1-bis, revue de code obligatoire de l'issue).
type Record struct {
	JTI        [16]byte // identifiant du passeport (corrélation des feuilles)
	CellID     string   // cellule d'origine
	Resource   string   // destination autoritaire = ressource du vecteur SIGNÉ
	Operation  string   // opération du vecteur signé
	DstIPv4    [4]byte  // destination si Resource est une IPv4 littérale, sinon zéros
	HasDstIPv4 bool     // DstIPv4 significatif
	IngressIf  uint32   // interface d'entrée (0 = non renseigné en v1 — le terminator T19 la fournira)
	OctetDelta uint64   // octets consommés dans la fenêtre de mesure
	FlowStart  int64    // début de la fenêtre de mesure (unix ms)
	FlowEnd    int64    // fin de la fenêtre de mesure (unix ms)
}

// Session est l'instantané de métadonnées d'une session passeport, tel
// que la source le fournit à l'exporteur (D18). Consumed est MONOTONE —
// jamais rechargé par les fenêtres de quota.
type Session struct {
	JTI       [16]byte
	Resource  string
	Operation string
	Consumed  uint64 // total monotone des quanta acceptés (T12)
	Closed    bool   // compteur coupé — dernier record possible
}

// SessionSource alimente l'exporteur en sessions vivantes — la couture
// du compteur T12. LedgerSource l'implémente pour pep.QuotaLedger.
type SessionSource interface {
	Snapshot() []Session
}

// RecordSink est la couture d'émission des records : feuilles registre
// (TelemetryLeafSink, §6) et, demain, pipeline d'agrégation T22 — même
// interface, l'exporteur ne change pas.
type RecordSink interface {
	Feed(Record) error
}

// ---------------------------------------------------------------------------
// TelemetryLeafSink — chaque record devient une feuille KindTelemetry
// hash-only (§6.2 : sha256(sel ‖ record), le sel reste chez le producteur).
// ---------------------------------------------------------------------------

// TelemetryLeafSink inscrit les records au registre de la cellule. Sûr
// pour un usage concurrent (la sérialisation est sans état).
type TelemetryLeafSink struct {
	cellID string
	salt   []byte
	leaves pep.LeafSink
	now    func() time.Time
}

// NewTelemetryLeafSink construit la couture feuilles. Fail-closed :
// cellID, sel ≥ 16 o et registre requis.
func NewTelemetryLeafSink(cellID string, salt []byte, leaves pep.LeafSink, now func() time.Time) (*TelemetryLeafSink, error) {
	if cellID == "" {
		return nil, ErrCellIDRequired
	}
	if len(salt) < 16 {
		return nil, ErrSaltTooShort
	}
	if leaves == nil {
		return nil, ErrLeavesRequired
	}
	if now == nil {
		now = time.Now
	}
	s := make([]byte, len(salt))
	copy(s, salt)
	return &TelemetryLeafSink{cellID: cellID, salt: s, leaves: leaves, now: now}, nil
}

// Feed inscrit la feuille du record. L'erreur est PROPAGÉE — l'exporteur
// la compte et l'alarme (jamais silencieux, §5.3).
func (s *TelemetryLeafSink) Feed(r Record) error {
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      s.cellID,
		PayloadHash: registry.HashPayload(s.salt, telemetryRecord(r)),
		Timestamp:   s.now().UnixNano(),
	}
	_, err := s.leaves.Append(context.Background(), leaf)
	return err
}

// telemetryRecord sérialise le record pour le hash de la feuille — layout
// fixe déterministe (§11.3) :
//
//	"TBTM1" ‖ jti(16) ‖ u8 len(cell) ‖ cell ‖ u16be len(resource) ‖ resource
//	‖ u16be len(operation) ‖ operation ‖ u64be octetDelta
//	‖ i64be flowStartMs ‖ i64be flowEndMs ‖ u32be ingressIf ‖ dstIPv4(4)
func telemetryRecord(r Record) []byte {
	rec := make([]byte, 0, 5+16+1+len(r.CellID)+2+len(r.Resource)+2+len(r.Operation)+8+8+8+4+4)
	rec = append(rec, "TBTM1"...)
	rec = append(rec, r.JTI[:]...)
	rec = append(rec, byte(len(r.CellID)))
	rec = append(rec, r.CellID...)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(r.Resource)))
	rec = append(rec, r.Resource...)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(r.Operation)))
	rec = append(rec, r.Operation...)
	rec = binary.BigEndian.AppendUint64(rec, r.OctetDelta)
	rec = binary.BigEndian.AppendUint64(rec, uint64(r.FlowStart))
	rec = binary.BigEndian.AppendUint64(rec, uint64(r.FlowEnd))
	rec = binary.BigEndian.AppendUint32(rec, r.IngressIf)
	rec = append(rec, r.DstIPv4[:]...)
	return rec
}

// ---------------------------------------------------------------------------
// LedgerSource — adaptateur D18 : pep.QuotaLedger → SessionSource.
// ---------------------------------------------------------------------------

type ledgerSource struct{ ledger *pep.QuotaLedger }

// LedgerSource branche l'exporteur sur le registre de quotas T12 : les
// instantanés de compteurs deviennent les sessions à instrumenter. Le
// total monotone ConsumedTotal garantit des deltas ≥ 0.
func LedgerSource(l *pep.QuotaLedger) SessionSource {
	return ledgerSource{ledger: l}
}

// Snapshot traduit les compteurs vivants en sessions. Aucun accès réseau,
// aucun paquet — des compteurs, rien d'autre (§4.1-bis).
func (s ledgerSource) Snapshot() []Session {
	snaps := s.ledger.Snapshot()
	out := make([]Session, 0, len(snaps))
	for _, p := range snaps {
		out = append(out, Session{
			JTI:       p.JTI,
			Resource:  p.Resource,
			Operation: p.Operation,
			Consumed:  p.Consumed,
			Closed:    p.Closed,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Exporter — boucle d'export, encodage IPFIX, envoi collecteur, feuilles.
// ---------------------------------------------------------------------------

// ExporterOptions paramètre l'exporteur. Fail-closed dès la configuration.
type ExporterOptions struct {
	// CellID identifie la cellule dans chaque record (tbp_cell_id) et
	// dérive l'observationDomainID. Requis.
	CellID string
	// Source est la couture des sessions passeport (D18 : compteur T12
	// via LedgerSource, ou toute source de métadonnées équivalente). Requis.
	Source SessionSource
	// Sink est la couture d'émission des records (D19 : TelemetryLeafSink
	// pour le registre, T22 pour l'agrégation). Requis.
	Sink RecordSink
	// Collector est l'adresse UDP du collecteur IPFIX local
	// ("10.99.99.x:4739"). Vide ⇒ pas d'envoi fil : les feuilles registre
	// restent produites (la preuve ne dépend pas du transport).
	Collector string
	// Interval est la période d'export de Run. > 0 requis.
	Interval time.Duration
	// IngressIf est l'identifiant d'interface d'entrée porté par les
	// records (0 en v1 — le câblage terminator T19 la fournira).
	IngressIf uint32
	// OnTrip est la couture d'alarme (T14) : échec d'envoi collecteur ou
	// d'écriture de feuille. Nil ⇒ pas d'alarme externe (les compteurs de
	// Stats restent la trace minimale).
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// ExporterStats agrège les compteurs de l'exporteur (observabilité §9.1).
type ExporterStats struct {
	Exports      uint64 // cycles d'export ayant produit un message
	Records      uint64 // records émis (fil + feuilles)
	SendFailures uint64 // échecs d'envoi UDP (comptés, alarmés — jamais silencieux)
	LeafFailures uint64 // échecs d'écriture de feuille (comptés, alarmés)
	SessionsSeen uint64 // sessions vues au moins une fois
	RecordsLost  uint64 // records au-delà de maxRecordsPerMsg (non émis — comptés)
}

// Exporter est l'exporteur IPFIX de métadonnées passeport. Sûr pour un
// usage concurrent (Run et ExportOnce ne se mélangent pas — un seul
// pilote à la fois).
type Exporter struct {
	cellID    string
	source    SessionSource
	sink      RecordSink
	collector string
	interval  time.Duration
	ingressIf uint32
	onTrip    func(reason string)
	now       func() time.Time
	obsDomain uint32

	mu         sync.Mutex
	last       map[[16]byte]uint64 // jti → dernier total consommé vu
	lastExport int64               // fin de la fenêtre précédente (unix ms, 0 = jamais)
	seq        uint32              // RFC 7011 : total de records émis
	stats      ExporterStats
}

// NewExporter construit l'exporteur. Fail-closed : cellID, source, sink
// et intervalle > 0 requis.
func NewExporter(opts ExporterOptions) (*Exporter, error) {
	if opts.CellID == "" {
		return nil, ErrCellIDRequired
	}
	if opts.Source == nil {
		return nil, ErrSourceRequired
	}
	if opts.Sink == nil {
		return nil, ErrSinkRequired
	}
	if opts.Interval <= 0 {
		return nil, ErrIntervalInvalid
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	sum := sha256.Sum256([]byte(opts.CellID))
	return &Exporter{
		cellID:    opts.CellID,
		source:    opts.Source,
		sink:      opts.Sink,
		collector: opts.Collector,
		interval:  opts.Interval,
		ingressIf: opts.IngressIf,
		onTrip:    opts.OnTrip,
		now:       now,
		obsDomain: binary.BigEndian.Uint32(sum[:4]),
		last:      make(map[[16]byte]uint64),
	}, nil
}

// Stats rapporte les compteurs courants (observabilité §9.1).
func (e *Exporter) Stats() ExporterStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stats
}

// Run boucle l'export à l'intervalle configuré jusqu'à annulation du
// contexte (arrêt propre : un dernier cycle n'est PAS forcé — la feuille
// de coupure T12 trace déjà les fins de session).
func (e *Exporter) Run(ctx context.Context) {
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.ExportOnce()
		}
	}
}

// ExportOnce exécute UN cycle : snapshot des sessions, deltas, message
// IPFIX (template + data) vers le collecteur, feuille par record.
// Retourne le nombre de records émis (fil + feuilles).
func (e *Exporter) ExportOnce() int {
	nowMs := e.now().UnixMilli()
	sessions := e.source.Snapshot()

	e.mu.Lock()
	start := e.lastExport
	if start == 0 {
		start = nowMs // première fenêtre : mesure ponctuelle
	}
	records := make([]Record, 0, len(sessions))
	seen := make(map[[16]byte]struct{}, len(sessions))
	for _, s := range sessions {
		seen[s.JTI] = struct{}{}
		prev := e.last[s.JTI]
		delta := s.Consumed - prev // Consumed est monotone : delta ≥ 0
		if _, known := e.last[s.JTI]; !known {
			e.stats.SessionsSeen++
		}
		if s.Closed {
			delete(e.last, s.JTI) // dernière mesure de la session
		} else {
			e.last[s.JTI] = s.Consumed
		}
		if delta == 0 {
			continue // session sans flux dans l'intervalle : pas de feuille (§4.3)
		}
		records = append(records, e.record(s, delta, start, nowMs))
	}
	// les sessions disparues du snapshot (purgées TTL) sortent du suivi
	for jti := range e.last {
		if _, ok := seen[jti]; !ok {
			delete(e.last, jti)
		}
	}
	e.lastExport = nowMs
	if len(records) == 0 {
		e.mu.Unlock()
		return 0
	}
	if len(records) > maxRecordsPerMsg {
		e.stats.RecordsLost += uint64(len(records) - maxRecordsPerMsg)
		records = records[:maxRecordsPerMsg]
	}
	seq := e.seq
	e.seq += uint32(len(records))
	e.mu.Unlock()

	// Le fil d'abord, les feuilles ensuite : les deux se font, l'ordre
	// n'engage pas la preuve (chaque feuille est indépendante).
	if e.collector != "" {
		msg := encodeMessage(e.obsDomain, seq, nowMs/1000, records)
		if err := e.send(msg); err != nil {
			e.mu.Lock()
			e.stats.SendFailures++
			e.mu.Unlock()
			e.trip(ReasonSendFailed)
		}
	}
	for _, r := range records {
		if err := e.sink.Feed(r); err != nil {
			e.mu.Lock()
			e.stats.LeafFailures++
			e.mu.Unlock()
			e.trip(pep.ReasonLeafWriteFailed)
		}
	}
	e.mu.Lock()
	e.stats.Exports++
	e.stats.Records += uint64(len(records))
	e.mu.Unlock()
	return len(records)
}

// record construit le Record d'une session : destination autoritaire =
// ressource du vecteur signé ; destinationIPv4Address uniquement si la
// ressource est une IPv4 littérale (sinon 0.0.0.0 — jamais d'invention).
func (e *Exporter) record(s Session, delta uint64, startMs, endMs int64) Record {
	r := Record{
		JTI:       s.JTI,
		CellID:    e.cellID,
		Resource:  s.Resource,
		Operation: s.Operation,
		IngressIf: e.ingressIf,
		// delta monotone du compteur T12 : jamais négatif par construction.
		OctetDelta: delta,
		FlowStart:  startMs,
		FlowEnd:    endMs,
	}
	if addr, err := netip.ParseAddr(s.Resource); err == nil && addr.Is4() {
		r.DstIPv4 = addr.As4()
		r.HasDstIPv4 = true
	}
	return r
}

// send expédie UN datagramme UDP vers le collecteur local — la SEULE
// sortie réseau du package (jamais d'écoute, jamais de socket brute).
func (e *Exporter) send(msg []byte) error {
	addr, err := net.ResolveUDPAddr("udp", e.collector)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(msg)
	return err
}

// trip alarme sur la couture T14 si configurée (les compteurs de Stats
// restent la trace minimale — jamais silencieux).
func (e *Exporter) trip(reason string) {
	if e.onTrip != nil {
		e.onTrip(reason)
	}
}

// ---------------------------------------------------------------------------
// Encodage IPFIX (RFC 7011) — D17 : auto-porté, stdlib, déterministe.
// ---------------------------------------------------------------------------

// templateFields décrit le template TBP (ID 256) : champs standards puis
// champs entreprise (bit haut + PEN), dans l'ordre du data record.
var templateFields = []struct {
	id         uint16
	size       uint16
	enterprise bool
}{
	{ieOctetDeltaCount, 8, false},
	{ieIngressInterface, 4, false},
	{ieDestinationIPv4Address, 4, false},
	{ieFlowStartMilliseconds, 8, false},
	{ieFlowEndMilliseconds, 8, false},
	{ieTbpJTI, 16, true},
	{ieTbpCellID, variableLength, true},
	{ieTbpResource, variableLength, true},
	{ieTbpOperation, variableLength, true},
}

// encodeMessage sérialise un message IPFIX complet : header, template set
// (réémis à chaque message en v1), data set des records. exportTime en
// secondes unix (header), fenêtres en millisecondes (champs).
func encodeMessage(obsDomain, seq uint32, exportTimeS int64, records []Record) []byte {
	template := encodeTemplateSet()
	data := encodeDataSet(records)
	total := 16 + len(template) + len(data)

	msg := make([]byte, 0, total)
	msg = binary.BigEndian.AppendUint16(msg, ipfixVersion)
	msg = binary.BigEndian.AppendUint16(msg, uint16(total))
	msg = binary.BigEndian.AppendUint32(msg, uint32(exportTimeS))
	msg = binary.BigEndian.AppendUint32(msg, seq)
	msg = binary.BigEndian.AppendUint32(msg, obsDomain)
	msg = append(msg, template...)
	msg = append(msg, data...)
	return msg
}

// encodeTemplateSet sérialise le template set (set ID 2, un template).
func encodeTemplateSet() []byte {
	body := make([]byte, 0, 4+len(templateFields)*8)
	body = binary.BigEndian.AppendUint16(body, templateID)
	body = binary.BigEndian.AppendUint16(body, uint16(len(templateFields)))
	for _, f := range templateFields {
		id := f.id
		if f.enterprise {
			id |= enterpriseBit
		}
		body = binary.BigEndian.AppendUint16(body, id)
		body = binary.BigEndian.AppendUint16(body, f.size)
		if f.enterprise {
			body = binary.BigEndian.AppendUint32(body, EnterpriseNumber)
		}
	}
	out := make([]byte, 0, 4+len(body))
	out = binary.BigEndian.AppendUint16(out, templateSetID)
	out = binary.BigEndian.AppendUint16(out, uint16(4+len(body)))
	return append(out, body...)
}

// encodeDataSet sérialise le data set (set ID = templateID) : les records
// dans l'ordre du template, champs varlen en longueur-préfixée RFC 7011
// (1 octet < 255, sinon 0xFF + uint16).
func encodeDataSet(records []Record) []byte {
	body := make([]byte, 0, len(records)*64)
	for _, r := range records {
		body = binary.BigEndian.AppendUint64(body, r.OctetDelta)
		body = binary.BigEndian.AppendUint32(body, r.IngressIf)
		body = append(body, r.DstIPv4[:]...)
		body = binary.BigEndian.AppendUint64(body, uint64(r.FlowStart))
		body = binary.BigEndian.AppendUint64(body, uint64(r.FlowEnd))
		body = append(body, r.JTI[:]...)
		body = appendVarlen(body, []byte(r.CellID))
		body = appendVarlen(body, []byte(r.Resource))
		body = appendVarlen(body, []byte(r.Operation))
	}
	out := make([]byte, 0, 4+len(body))
	out = binary.BigEndian.AppendUint16(out, templateID)
	out = binary.BigEndian.AppendUint16(out, uint16(4+len(body)))
	return append(out, body...)
}

// appendVarlen encode un champ de longueur variable (RFC 7011 §7).
func appendVarlen(b, v []byte) []byte {
	if len(v) < 255 {
		b = append(b, byte(len(v)))
	} else {
		b = append(b, 255)
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	}
	return append(b, v...)
}
