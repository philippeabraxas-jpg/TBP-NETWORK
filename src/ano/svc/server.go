// Package svc — le service ano (#178) : serveur HTTP (processus anod) et
// client (proxy de pepd).
//
// ano tourne dans un processus séparé et sandboxé, sur un socket Unix : c'est
// LUI qui détient la table jeton ↔ valeur, aucun autre composant ne l'a en
// mémoire. Il n'a aucun accès réseau. Les appelants s'authentifient par le
// jeton porteur signé par le broker :
//
//   - l'ouverture d'un échange (POST /v1/mask, /v1/mask-query) exige un jeton
//     AUTHENTIQUE ET FRAIS ; l'identifiant d'échange est le jti du jeton ;
//   - la reconstitution (POST /v1/unmask) et la fermeture (POST /v1/close)
//     exigent un jeton authentique, mais pas frais : une réponse lente d'une
//     machine externe reste reconstituable tant que l'échange vit (expiration
//     du jeton + ResponseGrace) ;
//   - un échange n'est joignable que par le jeton qui l'a ouvert (même jti) :
//     un pepd compromis ne lit que les échanges dont il tient le jeton.
//
// La porte « Reveal » (révélation à une machine exécutrice) n'est PAS ici :
// elle est réservée au broker après décision d'OPA (voir #178).
package svc

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	ano "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

const (
	// HeaderReport porte le rapport de l'opération (comptages seulement).
	HeaderReport = "X-Ano-Report"
	// DefaultResponseGrace prolonge la vie d'un échange au-delà de
	// l'expiration du jeton, pour laisser revenir la réponse externe.
	DefaultResponseGrace = 60 * time.Second
	maxResponseGrace     = 10 * time.Minute
	maxQueryBytes        = 8 << 10
)

// ServerOptions paramètre le serveur. Fail-closed dès la configuration.
type ServerOptions struct {
	// Ano : le moteur. Requis.
	Ano *ano.Ano
	// Verifier : vérification des jetons (trousseau épinglé). Requis.
	Verifier *pep.PossessionVerifier
	// ResponseGrace : vie de l'échange après l'expiration du jeton.
	// 0 ⇒ 60 s ; plafonné à 10 min.
	ResponseGrace time.Duration
	// MaxBody borne les corps reçus. 0 ⇒ ano.DefaultMaxPayloadBytes.
	MaxBody int64
}

// Server est le serveur HTTP d'ano.
type Server struct {
	a       *ano.Ano
	ver     *pep.PossessionVerifier
	grace   time.Duration
	maxBody int64
}

// NewServer construit le serveur.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Ano == nil {
		return nil, errors.New("ano/svc: moteur ano requis")
	}
	if opts.Verifier == nil {
		return nil, errors.New("ano/svc: vérificateur de jeton requis (aucun appel anonyme, §12)")
	}
	grace := opts.ResponseGrace
	if grace == 0 {
		grace = DefaultResponseGrace
	}
	if grace < 0 || grace > maxResponseGrace {
		return nil, errors.New("ano/svc: ResponseGrace hors bornes [0, 10 min]")
	}
	maxBody := opts.MaxBody
	if maxBody == 0 {
		maxBody = ano.DefaultMaxPayloadBytes
	}
	if maxBody < 0 {
		return nil, errors.New("ano/svc: MaxBody négatif")
	}
	return &Server{a: opts.Ano, ver: opts.Verifier, grace: grace, maxBody: maxBody}, nil
}

// Handler rend le mux du serveur.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/mask", s.handleMask)
	mux.HandleFunc("POST /v1/mask-query", s.handleMaskQuery)
	mux.HandleFunc("POST /v1/unmask", s.handleUnmask)
	mux.HandleFunc("POST /v1/close", s.handleClose)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]int{"exchanges": s.a.Exchanges()})
	})
	return mux
}

// wireReport est la forme JSON du rapport (comptages seulement).
type wireReport struct {
	Leaves           int `json:"leaves"`
	MaskedPath       int `json:"masked_path"`
	MaskedClassifier int `json:"masked_classifier"`
	MaskedDefault    int `json:"masked_default"`
	ClassifierFaults int `json:"classifier_faults"`
	Spans            int `json:"spans"`
	Restored         int `json:"restored"`
}

func toWire(r ano.Report) wireReport {
	return wireReport{
		Leaves: r.Leaves, MaskedPath: r.MaskedPath, MaskedClassifier: r.MaskedClassifier,
		MaskedDefault: r.MaskedDefault, ClassifierFaults: r.ClassifierFaults,
		Spans: r.Spans, Restored: r.Restored,
	}
}

func (w wireReport) add(o wireReport) wireReport {
	w.Leaves += o.Leaves
	w.MaskedPath += o.MaskedPath
	w.MaskedClassifier += o.MaskedClassifier
	w.MaskedDefault += o.MaskedDefault
	w.ClassifierFaults += o.ClassifierFaults
	w.Spans += o.Spans
	w.Restored += o.Restored
	return w
}

func (w wireReport) toPEP() pep.RewriteReport {
	return pep.RewriteReport(w)
}

// auth vérifie le jeton porteur et rend l'identifiant d'échange (jti hex).
func (s *Server) auth(w http.ResponseWriter, r *http.Request, fresh bool) (string, *pep.Token, bool) {
	h := r.Header.Get(pep.DefaultTokenHeader)
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		writeErr(w, http.StatusUnauthorized, "token-invalid")
		return "", nil, false
	}
	wire, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, prefix))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "token-invalid")
		return "", nil, false
	}
	tok, err := s.ver.Verify(wire)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "token-invalid")
		return "", nil, false
	}
	if fresh {
		if err := s.ver.Fresh(tok); err != nil {
			writeErr(w, http.StatusUnauthorized, "token-expired")
			return "", nil, false
		}
	}
	return hex.EncodeToString(tok.JTI[:]), tok, true
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unreadable")
		return nil, false
	}
	if int64(len(body)) > max {
		writeErr(w, http.StatusRequestEntityTooLarge, "too-large")
		return nil, false
	}
	return body, true
}

func (s *Server) open(w http.ResponseWriter, id string, tok *pep.Token) bool {
	expiry := time.Unix(tok.Exp, 0).Add(s.grace)
	if err := s.a.Open(id, expiry); err != nil {
		writeAnoErr(w, err)
		return false
	}
	return true
}

func (s *Server) handleMask(w http.ResponseWriter, r *http.Request) {
	id, tok, ok := s.auth(w, r, true)
	if !ok {
		return
	}
	body, ok := s.readBody(w, r, s.maxBody)
	if !ok || !s.open(w, id, tok) {
		return
	}
	out, rep, err := s.a.MaskJSON(r.Context(), id, body)
	if err != nil {
		writeAnoErr(w, err)
		return
	}
	writePayload(w, out, toWire(rep))
}

// handleMaskQuery masque les VALEURS d'une query string brute (les noms de
// paramètres restent visibles) ; chaque valeur est une feuille de chemin
// « query.<nom> » pour les règles.
func (s *Server) handleMaskQuery(w http.ResponseWriter, r *http.Request) {
	id, tok, ok := s.auth(w, r, true)
	if !ok {
		return
	}
	body, ok := s.readBody(w, r, maxQueryBytes)
	if !ok || !s.open(w, id, tok) {
		return
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "unparsable")
		return
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	masked := url.Values{}
	var total wireReport
	for _, n := range names {
		for _, v := range values[n] {
			mv, rep, err := s.a.MaskField(r.Context(), id, []string{"query", n}, v)
			if err != nil {
				writeAnoErr(w, err)
				return
			}
			masked.Add(n, mv)
			total = total.add(toWire(rep))
		}
	}
	writePayload(w, []byte(masked.Encode()), total)
}

func (s *Server) handleUnmask(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.auth(w, r, false)
	if !ok {
		return
	}
	body, ok := s.readBody(w, r, s.maxBody)
	if !ok {
		return
	}
	out, rep, err := s.a.Unmask(id, body)
	if err != nil {
		writeAnoErr(w, err)
		return
	}
	writePayload(w, out, toWire(rep))
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	id, _, ok := s.auth(w, r, false)
	if !ok {
		return
	}
	s.a.Close(id)
	w.WriteHeader(http.StatusNoContent)
}

func writePayload(w http.ResponseWriter, out []byte, rep wireReport) {
	if b, err := json.Marshal(rep); err == nil {
		w.Header().Set(HeaderReport, string(b))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr rend un code STABLE, jamais de détail (ni valeur, ni chemin).
func writeErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeAnoErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ano.ErrUnparsable):
		writeErr(w, http.StatusUnprocessableEntity, "unparsable")
	case errors.Is(err, ano.ErrReservedToken):
		writeErr(w, http.StatusUnprocessableEntity, "reserved-token")
	case errors.Is(err, ano.ErrUnknownPlaceholder):
		writeErr(w, http.StatusUnprocessableEntity, "unknown-placeholder")
	case errors.Is(err, ano.ErrTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, "too-large")
	case errors.Is(err, ano.ErrVaultSaturated), errors.Is(err, ano.ErrTooManyEntries):
		writeErr(w, http.StatusServiceUnavailable, "saturated")
	case errors.Is(err, ano.ErrExchangeUnknown):
		writeErr(w, http.StatusNotFound, "exchange-unknown")
	case errors.Is(err, ano.ErrBadExpiry):
		writeErr(w, http.StatusUnauthorized, "token-expired")
	default:
		writeErr(w, http.StatusInternalServerError, "internal")
	}
}
