package pep

// Proxy HTTP bloquant (T15, revue de sécurité #94).
//
// Deux constats liés dans l'issue #94, tous deux fermés par ce fichier :
//
//   - A6 (le PEP ne bloquait rien lui-même) : /v1/evaluate (listener.go)
//     est une API de VERDICTS — le blocage dépendait ENTIÈREMENT de
//     l'application appelante, qui devait interroger l'API PUIS respecter
//     la réponse. BlockingProxy REÇOIT le vrai trafic (c'est LUI que
//     nftables redirige, config/nftables/pep-redirect.nft) et ne
//     transmet au backend QUE si evaluate() l'autorise — le blocage
//     devient structurel, plus une convention.
//   - A9 (l'action est auto-déclarée) : /v1/evaluate reçoit {action,
//     resource} du CORPS JSON — rien ne lie cette étiquette à l'effet
//     réel. BlockingProxy dérive {action, resource} de la VRAIE requête
//     HTTP (méthode, chemin) via DeriveRequest — jamais d'un champ que
//     l'appelant pourrait remplir à sa guise.
//
// Honnêteté d'intégration (même doctrine que le commentaire de
// listener.go) : defaultDeriveRequest est une HEURISTIQUE GÉNÉRIQUE
// (méthode HTTP → classe d'action, chemin → ressource), pas une garantie
// sémantique — rien ne prouve qu'un GET n'a pas d'effet de bord côté
// backend. C'est un point de départ substituable (DeriveRequest), jamais
// une preuve. Une intégration par TYPE DE RESSOURCE — comme l'extension
// PostgreSQL existante, qui dispose d'un sceau d'objet réel (§4.4(2)) —
// reste la voie la PLUS fidèle quand elle existe ; ce proxy est
// l'alternative générique pour les backends HTTP qui n'en ont pas.
//
// Ce composant réutilise la MÊME chaîne de décision que /v1/evaluate
// (Listener.evaluate, extrait de handleEvaluate) — gate → validate →
// dry-run → passeport → OPA → posture — jamais une copie allégée qui
// sauterait OPA ou le quota en silence.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// DefaultTokenHeader est l'en-tête où defaultTokenFrom cherche le jeton
// porteur (schéma Bearer, RFC 6750) — remplaçable via
// ProxyOptions.TokenFrom.
const DefaultTokenHeader = "Authorization"

// ProxyOptions paramètre le proxy bloquant. Fail-closed dès la
// configuration.
type ProxyOptions struct {
	// Listener porte la chaîne de décision (T9, T11, T12, T15) — le
	// proxy s'appuie sur SA méthode evaluate(), jamais sur une copie.
	// Requis.
	Listener *Listener
	// Backend est le service RÉEL en amont — jamais atteint sur un deny
	// appliqué (closed) ni sur une requête mal formée. Requis.
	Backend *url.URL
	// DeriveRequest extrait {action, resource[, sceau]} de la VRAIE
	// requête HTTP. Nil ⇒ defaultDeriveRequest (voir l'en-tête de
	// fichier — une heuristique générique, substituable).
	DeriveRequest func(*http.Request) (Request, error)
	// TokenFrom extrait le jeton porteur (CWT/COSE_Sign1, base64) de la
	// requête. Nil ⇒ defaultTokenFrom (Authorization: Bearer <jeton>).
	TokenFrom func(*http.Request) (string, error)
	// OnProxyError couture une erreur de TRANSPORT vers le backend
	// (injoignable, timeout…) — jamais confondue avec un déni de
	// politique, qui a sa propre feuille via evaluate(). Nil ⇒
	// log.Printf.
	OnProxyError func(err error, req *http.Request)
}

// BlockingProxy est le proxy bloquant. Sûr pour un usage concurrent
// (délègue à *Listener, déjà concurrent-safe, et à
// httputil.ReverseProxy, documenté concurrent-safe).
type BlockingProxy struct {
	listener      *Listener
	backend       *url.URL
	rp            *httputil.ReverseProxy
	deriveRequest func(*http.Request) (Request, error)
	tokenFrom     func(*http.Request) (string, error)
}

// NewBlockingProxy construit le proxy. Fail-closed : listener et backend
// requis.
func NewBlockingProxy(opts ProxyOptions) (*BlockingProxy, error) {
	if opts.Listener == nil {
		return nil, errors.New("pep: listener requis (le proxy réutilise SA chaîne de décision, jamais une copie — §94)")
	}
	if opts.Backend == nil {
		return nil, errors.New("pep: backend requis (URL du service réel en amont)")
	}
	deriveRequest := opts.DeriveRequest
	if deriveRequest == nil {
		deriveRequest = defaultDeriveRequest
	}
	tokenFrom := opts.TokenFrom
	if tokenFrom == nil {
		tokenFrom = defaultTokenFrom
	}
	onProxyError := opts.OnProxyError
	if onProxyError == nil {
		onProxyError = func(err error, req *http.Request) {
			log.Printf("pep: proxy bloquant — erreur de transport vers le backend (%s %s): %v", req.Method, req.URL.Path, err)
		}
	}
	rp := httputil.NewSingleHostReverseProxy(opts.Backend)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		onProxyError(err, r)
		w.WriteHeader(http.StatusBadGateway)
	}
	return &BlockingProxy{
		listener:      opts.Listener,
		backend:       opts.Backend,
		rp:            rp,
		deriveRequest: deriveRequest,
		tokenFrom:     tokenFrom,
	}, nil
}

// ServeHTTP : dérive {action, resource} de la VRAIE requête (§94.A9),
// l'évalue via EXACTEMENT la chaîne de décision de /v1/evaluate
// (Listener.evaluate, §94.A6), et ne transmet au backend QUE si la
// posture l'autorise (monitor : toujours ; closed : seulement un allow
// appliqué). Une requête mal formée (jeton absent/illisible, méthode
// sans mapping) est refusée AVANT toute décision — aucune feuille,
// même doctrine que /v1/evaluate sur un corps illisible.
func (p *BlockingProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenB64, err := p.tokenFrom(r)
	if err != nil {
		http.Error(w, "jeton porteur absent ou illisible", http.StatusUnauthorized)
		return
	}
	wire, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		http.Error(w, "jeton base64 illisible", http.StatusUnauthorized)
		return
	}
	req, err := p.deriveRequest(r)
	if err != nil {
		http.Error(w, "requête non dérivable en action/ressource: "+err.Error(), http.StatusBadRequest)
		return
	}

	out := p.listener.evaluate(r.Context(), wire, req)
	w.Header().Set("X-TBP-Mode", p.listener.mode.Mode().String())
	w.Header().Set("X-TBP-Reason", out.Decision.Reason)
	if !out.Forwarded {
		http.Error(w, fmt.Sprintf("refusé par la politique (%s)", out.Decision.Reason), http.StatusForbidden)
		return
	}
	p.rp.ServeHTTP(w, r)
}

// defaultDeriveRequest : heuristique GÉNÉRIQUE (méthode HTTP → classe
// d'action, chemin → ressource) — voir l'avertissement d'honnêteté en
// en-tête de fichier. GET/HEAD/OPTIONS → "read" ; POST/PUT/PATCH →
// "write" ; DELETE → "delete" ; toute autre méthode est refusée AVANT
// évaluation — fail-closed : une méthode sans mapping connu n'a pas de
// sens à évaluer par défaut comme "read" (ce serait précisément
// l'auto-déclaration malhonnête que #94.A9 signale, déplacée ici).
func defaultDeriveRequest(r *http.Request) (Request, error) {
	var action string
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		action = "read"
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		action = "write"
	case http.MethodDelete:
		action = "delete"
	default:
		return Request{}, fmt.Errorf("méthode %q sans mapping action connu", r.Method)
	}
	return Request{Action: action, Resource: r.URL.Path}, nil
}

// defaultTokenFrom lit le jeton porteur dans l'en-tête Authorization
// (schéma Bearer, RFC 6750) — jamais un champ auto-déclaré dans le
// corps ou une query string (l'auto-déclaration est exactement ce que
// #94.A9 signale).
func defaultTokenFrom(r *http.Request) (string, error) {
	h := r.Header.Get(DefaultTokenHeader)
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", fmt.Errorf("en-tête %s: Bearer <jeton> requis", DefaultTokenHeader)
	}
	return strings.TrimPrefix(h, prefix), nil
}
