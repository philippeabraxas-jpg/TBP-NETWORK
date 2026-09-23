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
// Revue de sécurité post-#86 (issues #107, #108, #109) : évaluer contre
// une VRAIE requête ne sert à rien si ce qui est ensuite TRANSMIS au
// backend peut diverger de ce qui a été évalué, ou si le proxy lui-même
// fuit du matériel qui n'a rien à faire côté backend. Trois défauts
// fermés ici :
//
//   - #107 : la query string n'était PAS dans la ressource évaluée — un
//     jeton de lecture sur /reports laissait passer
//     GET /reports?action=delete_all sans que la query string soit
//     jamais vue par la décision. defaultDeriveRequest lie désormais
//     `resource` à r.URL.RequestURI() (chemin ET query string) : une
//     politique qui fait une correspondance EXACTE sur la ressource
//     distingue maintenant les deux — une correspondance par préfixe
//     reste un choix d'auteur de politique, comme le rappelle déjà
//     l'avertissement d'honnêteté ci-dessous.
//   - #108 : le corps n'était PAS du tout examiné — un jeton d'écriture
//     sur /transfer laissait passer n'importe quel montant.
//     defaultDeriveRequest scelle désormais le corps (SHA-256) dans
//     Request.ObjectSeal — le MÊME mécanisme de fidélité que
//     l'intégration PostgreSQL (§4.4(2)) : un jeton qui porte lui-même
//     un ObjectSeal (épinglé à l'émission) n'autorise alors que le
//     corps EXACT qu'il couvre (Validator, ReasonSealMismatch) — jamais
//     "n'importe quel corps pour cette classe d'action".
//   - #109 : le jeton TBP était transmis tel quel au backend, ET occupait
//     Authorization — le backend ne pouvait plus s'en servir pour SA
//     PROPRE authentification. DefaultTokenHeader n'est PLUS
//     Authorization mais X-TBP-Token (dédié), et ServeHTTP retire
//     TOUJOURS cet en-tête avant de transmettre — jamais vu du backend,
//     et Authorization reste entièrement disponible pour le backend.
//
// Honnêteté d'intégration (même doctrine que le commentaire de
// listener.go) : defaultDeriveRequest est une HEURISTIQUE GÉNÉRIQUE
// (méthode HTTP → classe d'action, chemin+query → ressource, hash du
// corps → sceau), pas une garantie sémantique — rien ne prouve qu'un GET
// n'a pas d'effet de bord côté backend, et le sceau du corps ne PROTÈGE
// que les jetons dont l'émetteur a choisi d'en épingler un. C'est un
// point de départ substituable (DeriveRequest), jamais une preuve. Une
// intégration par TYPE DE RESSOURCE — comme l'extension PostgreSQL
// existante, qui dispose d'un sceau d'objet réel épinglé à l'émission
// (§4.4(2)) — reste la voie la PLUS fidèle quand elle existe ; ce proxy
// est l'alternative générique pour les backends HTTP qui n'en ont pas.
//
// Ce composant réutilise la MÊME chaîne de décision que /v1/evaluate
// (Listener.evaluate, extrait de handleEvaluate) — gate → validate →
// dry-run → passeport → OPA → posture — jamais une copie allégée qui
// sauterait OPA ou le quota en silence.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// DefaultTokenHeader est l'en-tête où defaultTokenFrom cherche le jeton
// porteur (schéma Bearer, RFC 6750). PAS Authorization (revue de
// sécurité #109) : cet en-tête reste entièrement disponible pour
// l'authentification PROPRE du backend — le jeton TBP vit dans son en-
// tête dédié, jamais transmis (voir ServeHTTP). Remplaçable via
// ProxyOptions.TokenHeader/TokenFrom.
const DefaultTokenHeader = "X-TBP-Token"

// maxProxyBodySeal borne la mémoire consommée pour sceller le corps
// (#108) — un corps plus volumineux est refusé AVANT toute décision
// (jamais scellé partiellement : un sceau sur un préfixe tronqué serait
// un sceau sur autre chose que ce qui est réellement transmis).
const maxProxyBodySeal = 1 << 20 // 1 MiB

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
	// DeriveRequest extrait {action, resource, sceau} de la VRAIE
	// requête HTTP. Nil ⇒ defaultDeriveRequest (voir l'en-tête de
	// fichier — une heuristique générique, substituable).
	DeriveRequest func(*http.Request) (Request, error)
	// TokenFrom extrait le jeton porteur (CWT/COSE_Sign1, base64) de la
	// requête. Nil ⇒ lecture de TokenHeader (Bearer).
	TokenFrom func(*http.Request) (string, error)
	// TokenHeader est l'en-tête portant le jeton TBP — utilisé par le
	// TokenFrom par défaut ET systématiquement RETIRÉ de la requête
	// avant transmission au backend (revue de sécurité #109), que
	// TokenFrom soit personnalisé ou non. "" ⇒ DefaultTokenHeader. Un
	// TokenFrom personnalisé qui lit un AUTRE en-tête doit prévoir sa
	// propre suppression (ex. en enveloppant ServeHTTP) — ce champ ne
	// retire que celui-ci.
	TokenHeader string
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
	tokenHeader   string
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
	tokenHeader := opts.TokenHeader
	if tokenHeader == "" {
		tokenHeader = DefaultTokenHeader
	}
	tokenFrom := opts.TokenFrom
	if tokenFrom == nil {
		tokenFrom = tokenFromHeader(tokenHeader)
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
		tokenHeader:   tokenHeader,
	}, nil
}

// ServeHTTP : dérive {action, resource, sceau} de la VRAIE requête
// (§94.A9, §107, §108), l'évalue via EXACTEMENT la chaîne de décision de
// /v1/evaluate (Listener.evaluate, §94.A6), et ne transmet au backend QUE
// si la posture l'autorise (monitor : toujours ; closed : seulement un
// allow appliqué). Une requête mal formée (jeton absent/illisible,
// méthode sans mapping, corps trop volumineux pour être scellé) est
// refusée AVANT toute décision — aucune feuille, même doctrine que
// /v1/evaluate sur un corps illisible. L'en-tête portant le jeton TBP
// est TOUJOURS retiré avant transmission (§109) — que la requête soit
// finalement transmise ou non, pour qu'aucun chemin ne le laisse fuiter.
func (p *BlockingProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenB64, err := p.tokenFrom(r)
	r.Header.Del(p.tokenHeader) // #109 : jamais transmis, sur AUCUN chemin de sortie
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
// d'action, chemin+query → ressource, hash du corps → sceau) — voir
// l'avertissement d'honnêteté en en-tête de fichier. GET/HEAD/OPTIONS →
// "read" ; POST/PUT/PATCH → "write" ; DELETE → "delete" ; toute autre
// méthode est refusée AVANT évaluation — fail-closed : une méthode sans
// mapping connu n'a pas de sens à évaluer par défaut comme "read" (ce
// serait précisément l'auto-déclaration malhonnête que #94.A9 signale,
// déplacée ici).
//
// Resource = r.URL.RequestURI() (§107) : chemin ET query string, jamais
// le chemin seul — une politique qui fait une correspondance EXACTE
// distingue alors "/reports" de "/reports?action=delete_all".
//
// ObjectSeal = SHA-256(corps) quand le corps est non vide (§108) : le
// corps est lu ICI puis REMPLACÉ par un lecteur qui rend les mêmes
// octets — la transmission ultérieure au backend (ServeHTTP) voit
// exactement ce qui a été scellé, jamais un corps qui aurait pu diverger
// entre l'évaluation et la transmission. Un corps au-delà de
// maxProxyBodySeal est refusé plutôt que scellé sur un préfixe tronqué
// (un sceau partiel serait un sceau sur autre chose que ce qui est
// réellement transmis).
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
	req := Request{Action: action, Resource: r.URL.RequestURI()}
	if r.Body != nil && r.Body != http.NoBody {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxProxyBodySeal+1))
		if err != nil {
			return Request{}, fmt.Errorf("corps illisible: %w", err)
		}
		_ = r.Body.Close()
		if len(body) > maxProxyBodySeal {
			return Request{}, fmt.Errorf("corps > %d octets — trop volumineux pour être scellé (§108)", maxProxyBodySeal)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		if len(body) > 0 {
			seal := sha256.Sum256(body)
			req.ObjectSeal = &seal
		}
	}
	return req, nil
}

// tokenFromHeader rend un TokenFrom qui lit le jeton porteur dans header
// (schéma Bearer, RFC 6750) — jamais un champ auto-déclaré dans le corps
// ou une query string (l'auto-déclaration est exactement ce que #94.A9
// signale).
func tokenFromHeader(header string) func(*http.Request) (string, error) {
	return func(r *http.Request) (string, error) {
		h := r.Header.Get(header)
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			return "", fmt.Errorf("en-tête %s: Bearer <jeton> requis", header)
		}
		return strings.TrimPrefix(h, prefix), nil
	}
}

// defaultTokenFrom lit le jeton porteur dans DefaultTokenHeader — voir
// tokenFromHeader.
func defaultTokenFrom(r *http.Request) (string, error) {
	return tokenFromHeader(DefaultTokenHeader)(r)
}
