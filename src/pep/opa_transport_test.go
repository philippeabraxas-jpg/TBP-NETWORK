package pep

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newUnixOPAStub sert un faux OPA sur un socket Unix réel — la seule
// façon de tester SO_PEERCRED est une vraie connexion socket (le noyau
// rapporte l'UID, rien à simuler côté test).
func newUnixOPAStub(t *testing.T) (sockPath string, closeFn func()) {
	t.Helper()
	sockPath = filepath.Join(t.TempDir(), "opa.sock")
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":{"allow":true}}`))
	})}
	go srv.Serve(lis)
	return sockPath, func() { srv.Close() }
}

// TestOPAUnixTransportAcceptsExpectedPeer : preuve POSITIVE — le pair
// réel (le processus de test lui-même, qui sert le stub) tourne sous
// os.Getuid() ; le transport doit l'accepter.
func TestOPAUnixTransportAcceptsExpectedPeer(t *testing.T) {
	sock, closeFn := newUnixOPAStub(t)
	defer closeFn()

	tr, err := NewOPAUnixTransport(sock, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("NewOPAUnixTransport: %v", err)
	}
	hc := &http.Client{Transport: tr}
	resp, err := hc.Get("http://opa/v1/data/tbp/allow")
	if err != nil {
		t.Fatalf("GET via socket unix: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("statut=%d, veut 200 (pair attendu accepté)", resp.StatusCode)
	}
}

// TestOPAUnixTransportRejectsWrongPeerUID : preuve NON-VACUE côté échec —
// un UID attendu manifestement différent du pair réel doit être refusé.
// C'est exactement l'attaque #92.A3 : un imposteur qui occupe le socket
// sous une identité différente d'OPA doit échouer la connexion, jamais
// être servi comme si c'était OPA.
func TestOPAUnixTransportRejectsWrongPeerUID(t *testing.T) {
	sock, closeFn := newUnixOPAStub(t)
	defer closeFn()

	wrongUID := uint32(os.Getuid()) + 999999 // manifestement différent du pair réel
	tr, err := NewOPAUnixTransport(sock, wrongUID)
	if err != nil {
		t.Fatalf("NewOPAUnixTransport: %v", err)
	}
	hc := &http.Client{Transport: tr}
	_, err = hc.Get("http://opa/v1/data/tbp/allow")
	if err == nil {
		t.Fatal("connexion acceptée malgré un UID pair inattendu — imposteur #92.A3 non détecté")
	}
}

func TestOPAUnixTransportEmptyPathRejected(t *testing.T) {
	if _, err := NewOPAUnixTransport("", 0); err == nil {
		t.Fatal("chemin de socket vide accepté")
	}
}

// TestOPAUnixTransportRealHTTPRoundTrip : le transport reste un
// http.Transport utilisable normalement — vérifié via httptest pour
// s'assurer qu'aucune régression sur le round-trip HTTP standard
// n'accompagne le dial personnalisé (témoin de non-régression, pas une
// preuve de sécurité).
func TestOPAUnixTransportRealHTTPRoundTrip(t *testing.T) {
	sock, closeFn := newUnixOPAStub(t)
	defer closeFn()
	tr, err := NewOPAUnixTransport(sock, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("NewOPAUnixTransport: %v", err)
	}
	hc := &http.Client{Transport: tr}
	req := httptest.NewRequest(http.MethodPost, "http://opa/v1/data/tbp/allow", nil)
	req.RequestURI = ""
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("POST via socket unix: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("statut=%d, veut 200", resp.StatusCode)
	}
}
