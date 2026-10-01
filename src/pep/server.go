package pep

// Bornes de lecture des serveurs HTTP de la cellule (issue #209, red team
// R-16). Un serveur Go sans ReadTimeout laisse un client qui envoie les
// en-têtes puis cale sur le corps tenir une goroutine et une connexion
// indéfiniment ; sans borne de corps, il peut aussi y verser des Gio.
// Les deux se règlent ICI, une fois, pour pepd ET brokerd : pas de serveur
// construit à la main avec ses propres oublis.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

func decodeJSON(r io.Reader, dst any) error { return json.NewDecoder(r).Decode(dst) }

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

// decodeBoundedJSON lit le corps JSON de r en au plus limit octets. Rend false
// après avoir écrit la réponse : 413 si la borne est dépassée, 400 sinon.
func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	if err := decodeJSON(http.MaxBytesReader(w, r.Body, limit), dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "corps trop volumineux"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "corps JSON illisible"})
		return false
	}
	return true
}
