package pep

// Issue #209 (red team R-16) : les routes de pepd ne bornaient pas le corps
// des requêtes — `json.NewDecoder(r.Body)` lit tout avant de vérifier quoi que
// ce soit, et la taille du jeton n'était contrôlée qu'APRÈS le décodage JSON et
// base64. Un client de la cellule pouvait donc tenir de la mémoire avec un
// corps arbitraire. Chaque test provoque cette faute précise.

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// bodyOfSize rend un corps JSON valide de EXACTEMENT n octets dont une valeur
// de chaîne porte la masse : c'est ce que le décodeur doit lire en entier avant
// de pouvoir conclure (des espaces APRÈS l'objet ne seraient jamais lus).
func bodyOfSize(t *testing.T, prefix, suffix string, n int) string {
	t.Helper()
	fill := n - len(prefix) - len(suffix)
	if fill < 0 {
		t.Fatalf("enveloppe (%d) plus grande que la cible (%d)", len(prefix)+len(suffix), n)
	}
	return prefix + strings.Repeat("A", fill) + suffix
}

func postRaw(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s : %v", path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// Un corps d'un Mio sur chaque route de pepd est refusé en 413, sans être traité.
func TestOversizedBodiesAreRefusedWith413(t *testing.T) {
	f := newListenerFixture(t, true)
	for name, tc := range map[string]struct {
		srv  *httptest.Server
		path string
		body string
	}{
		"evaluate": {f.srv, "/v1/evaluate", bodyOfSize(t, `{"action":"read","resource":"doc-1","token":"`, `"}`, 1<<20)},
		"consume":  {f.srv, "/v1/passport/consume", bodyOfSize(t, `{"n":1,"token":"`, `"}`, 1<<20)},
		"mode":     {f.adminSrv, "/v1/mode", bodyOfSize(t, `{"mode":"closed","expiry":1,"signatures":[],"x":"`, `"}`, 1<<20)},
	} {
		resp := postRaw(t, tc.srv, tc.path, tc.body)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Errorf("%s : statut %d pour un corps de 1 Mio, veut 413 (R-16)", name, resp.StatusCode)
		}
	}
}

// Bord exact : maxEvaluateBodyBytes passe, +1 est refusé.
func TestBodyLimitBoundary(t *testing.T) {
	f := newListenerFixture(t, true)
	at := bodyOfSize(t, `{"action":"read","resource":"doc-1","token":"`, `"}`, maxEvaluateBodyBytes)
	if resp := postRaw(t, f.srv, "/v1/evaluate", at); resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatalf("un corps de %d octets (la limite) est refusé en 413", maxEvaluateBodyBytes)
	}
	over := bodyOfSize(t, `{"action":"read","resource":"doc-1","token":"`, `"}`, maxEvaluateBodyBytes+1)
	if resp := postRaw(t, f.srv, "/v1/evaluate", over); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("limite + 1 : statut %d, veut 413", resp.StatusCode)
	}
}

// La borne ne refuse AUCUN message légitime de taille maximale : jeton de
// MaxTokenWireSize octets, action 255, ressource 1024, sceau, le tout avec
// l'échappement JSON le plus défavorable (\u00XX = 6 octets par caractère).
func TestLimitFitsTheLargestLegitimateRequest(t *testing.T) {
	token := base64.StdEncoding.EncodeToString(make([]byte, MaxTokenWireSize))
	worst := func(n int) string { return strings.Repeat(`\u0001`, n) }
	body := fmt.Sprintf(`{"token":%q,"action":"%s","resource":"%s","object_seal":%q}`,
		token, worst(255), worst(maxResourceLen), strings.Repeat("a", 2*MaxSealObjectLen))
	if len(body) > maxEvaluateBodyBytes {
		t.Fatalf("la plus grande requête légitime (%d octets) dépasse la borne %d — la borne refuserait du trafic valide", len(body), maxEvaluateBodyBytes)
	}
	f := newListenerFixture(t, true)
	if resp := postRaw(t, f.srv, "/v1/evaluate", body); resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Fatal("requête légitime de taille maximale refusée en 413")
	}
}

// Serveur durci : un client qui envoie les en-têtes puis cale sur le corps est
// coupé au ReadTimeout, au lieu de tenir une goroutine indéfiniment.
func TestHardenedServerCutsAStalledBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handled := make(chan struct{}, 1)
	srv := NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // lit le corps entier
		handled <- struct{}{}
	}), ServerTimeouts{ReadHeader: time.Second, Read: 300 * time.Millisecond, Idle: time.Second})
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// En-têtes complets, Content-Length 1000, un seul octet de corps, puis silence.
	_, _ = fmt.Fprintf(conn, "POST /x HTTP/1.1\r\nHost: t\r\nContent-Length: 1000\r\n\r\nX")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, rerr := io.ReadAll(conn) // rend la main quand le serveur ferme la connexion
	if time.Since(start) > 2*time.Second {
		t.Fatalf("connexion tenue %s malgré un ReadTimeout de 300 ms", time.Since(start))
	}
	if nerr, ok := rerr.(net.Error); ok && nerr.Timeout() {
		t.Fatal("le serveur n'a pas coupé le client dont le corps est calé (R-16)")
	}
}

func TestDefaultServerTimeoutsAreAllSet(t *testing.T) {
	d := DefaultServerTimeouts
	if d.ReadHeader <= 0 || d.Read <= 0 || d.Idle <= 0 {
		t.Fatalf("délais par défaut incomplets : %+v", d)
	}
	srv := NewServer(http.NotFoundHandler(), d)
	if srv.ReadHeaderTimeout != d.ReadHeader || srv.ReadTimeout != d.Read || srv.IdleTimeout != d.Idle {
		t.Fatalf("serveur construit sans les délais demandés : %+v", srv)
	}
}
