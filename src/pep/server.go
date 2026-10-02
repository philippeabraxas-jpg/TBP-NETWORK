package pep

// Bornes de lecture des serveurs HTTP de la cellule (issue #209, red team
// R-16). Un serveur Go sans ReadTimeout laisse un client qui envoie les
// en-têtes puis cale sur le corps tenir une goroutine et une connexion
// indéfiniment ; sans borne de corps, il peut aussi y verser des Gio.
// Les deux se règlent ICI, une fois, pour pepd ET brokerd : pas de serveur
// construit à la main avec ses propres oublis.

import (
	"errors"
	"io"
	"net/http"
	"time"

	strictjson "github.com/philippeabraxas-jpg/TBP-NETWORK/src/strictjson"
)

// maxEvaluateBodyBytes borne le corps de /v1/evaluate et /v1/passport/consume.
// Dérivée du pire message LÉGITIME : jeton de MaxTokenWireSize octets (base64
// ≈ 1,4 Kio), action ≤ 255 et ressource ≤ 1024 avec l'échappement JSON le plus
// défavorable (6 octets par caractère ≈ 7,7 Kio), sceau 2 × 1024 hex en marge,
// enveloppe JSON. TestLimitFitsTheLargestLegitimateRequest verrouille que la
// borne ne refuse jamais ce pire cas.
const maxEvaluateBodyBytes = 16 << 10

// maxAdminBodyBytes borne les corps du plan d'administration (/v1/mode,
// /v1/failclosed/clear) : une preuve de quorum, quelques centaines d'octets par
// signataire.
const maxAdminBodyBytes = 64 << 10

// ServerTimeouts regroupe les délais d'un serveur. Zéro = pas de borne (réservé
// aux serveurs qui relaient de longs flux, voir le proxy bloquant).
type ServerTimeouts struct {
	ReadHeader time.Duration // lecture des en-têtes (slowloris)
	Read       time.Duration // lecture de la requête entière, corps compris
	Idle       time.Duration // connexion persistante inactive
}

// DefaultServerTimeouts : plan de données et d'administration. Une décision
// tient en millisecondes (§9.1) ; 10 s de lecture laissent une large marge à
// un client lent légitime sans lui permettre de tenir la connexion.
var DefaultServerTimeouts = ServerTimeouts{
	ReadHeader: 5 * time.Second,
	Read:       10 * time.Second,
	Idle:       60 * time.Second,
}

// NewServer construit un http.Server avec les délais demandés.
func NewServer(h http.Handler, t ServerTimeouts) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		IdleTimeout:       t.Idle,
	}
}

// decodeBoundedJSON lit le corps JSON de r en au plus limit octets et le décode STRICTEMENT (#289, suite
// de #241/#274) : clé en double, champ inconnu ou de casse inexacte, contenu après l'objet et UTF-8
// invalide sont refusés — ce qu'un proxy, un WAF ou un journal lit doit être ce que pepd applique. Rend
// false après avoir écrit la réponse : 413 si la borne est dépassée, 400 sinon, avec le détail que le
// client peut lire pour corriger son corps (code stable, clé fautive bornée, noms exacts acceptés —
// jamais le contenu de la requête).
func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "corps trop volumineux"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "corps JSON illisible", "detail": strictjson.Detail{Code: "body-unreadable"}})
		return false
	}
	if err := strictjson.Decode(body, dst); err != nil {
		var detail any
		if se, ok := strictjson.As(err); ok {
			detail = se.Detail
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "corps JSON illisible", "detail": detail})
		return false
	}
	return true
}
