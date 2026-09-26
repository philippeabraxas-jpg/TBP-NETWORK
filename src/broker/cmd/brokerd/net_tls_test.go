package main

// net_tls_test.go — revue de sécurité #124. Preuves d'exécution NON
// VACUOLES contre de VRAIS certificats Ed25519 générés ici (même patron
// que deploy/selftest/opa.go pour la signature de bundle §106) et une
// VRAIE poignée de main TLS — jamais un mock du package crypto/tls.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// genCert émet un certificat Ed25519 auto-signé si parent/parentKey sont
// nil (utilisé pour la CA elle-même), sinon signé par parent/parentKey
// (feuille serveur ou client). isCA distingue une autorité d'une feuille.
func genCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", cn, err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if !isCA {
		tmpl.DNSNames = []string{"127.0.0.1", "localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	signerCert, signerKey := tmpl, priv
	if parent != nil {
		signerCert, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signerKey)
	if err != nil {
		t.Fatalf("CreateCertificate(%s): %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %v", cn, err)
	}
	return cert, priv, der
}

func writePEM(t *testing.T, dir, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("écriture %s: %v", path, err)
	}
	return path
}

func writeKeyPEM(t *testing.T, dir, name string, key ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return writePEM(t, dir, name, "PRIVATE KEY", der)
}

// brokerTLSFixture provisionne une CA de test, un certificat serveur
// signé par elle, et un certificat client signé par elle — plus un
// certificat client signé par une AUTRE CA (imposteur), pour les témoins
// négatifs.
type brokerTLSFixture struct {
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCert     tls.Certificate // signé par la bonne CA, CN "agent-test"
	wrongCACert    tls.Certificate // signé par une AUTRE CA — doit être refusé à la poignée de main
	otherValidCert tls.Certificate // signé par la BONNE CA, CN "agent-other" — poignée de main OK, mais ne doit jamais pouvoir se déclarer "agent-1" (revue #162/#163)
}

func newBrokerTLSFixture(t *testing.T) *brokerTLSFixture {
	t.Helper()
	dir := t.TempDir()

	caCert, caKey, caDER := genCert(t, "tbp-test-ca", true, nil, nil)
	caFile := writePEM(t, dir, "ca.pem", "CERTIFICATE", caDER)

	_, serverKey, serverDER := genCert(t, "brokerd-test", false, caCert, caKey)
	serverCertFile := writePEM(t, dir, "server.pem", "CERTIFICATE", serverDER)
	serverKeyFile := writeKeyPEM(t, dir, "server.key.pem", serverKey)

	_, clientKey, clientDER := genCert(t, "agent-test", false, caCert, caKey)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (client): %v", err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair (client): %v", err)
	}

	// Imposteur : une CA DIFFÉRENTE, jamais installée comme
	// TBP_BROKER_TLS_CLIENT_CA_FILE — son certificat client doit être
	// refusé à la poignée de main.
	wrongCACert, wrongCAKey, _ := genCert(t, "tbp-test-wrong-ca", true, nil, nil)
	_, wrongClientKey, wrongClientDER := genCert(t, "agent-imposteur", false, wrongCACert, wrongCAKey)
	wrongClientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongClientDER})
	wrongClientKeyDER, err := x509.MarshalPKCS8PrivateKey(wrongClientKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (imposteur): %v", err)
	}
	wrongClientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: wrongClientKeyDER})
	wrongCert, err := tls.X509KeyPair(wrongClientCertPEM, wrongClientKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair (imposteur): %v", err)
	}

	// Autre agent LÉGITIME : signé par la BONNE CA (poignée de main
	// acceptée), mais CN différent de "agent-test" — le témoin direct de
	// la revue #162/#163 : une identité de transport authentifiée mais
	// NON liée au subject déclaré doit être refusée par le broker
	// lui-même, pas seulement par la vérification TLS.
	_, otherKey, otherDER := genCert(t, "agent-other", false, caCert, caKey)
	otherCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER})
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (autre agent): %v", err)
	}
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherKeyDER})
	otherCert, err := tls.X509KeyPair(otherCertPEM, otherKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair (autre agent): %v", err)
	}

	return &brokerTLSFixture{
		caFile:         caFile,
		serverCertFile: serverCertFile,
		serverKeyFile:  serverKeyFile,
		clientCert:     clientCert,
		wrongCACert:    wrongCert,
		otherValidCert: otherCert,
	}
}

// ---------------------------------------------------------------------------
// buildBrokerTLSConfig : unités isolées, fail-closed sur chaque fichier.
// ---------------------------------------------------------------------------

func TestBuildBrokerTLSConfigOK(t *testing.T) {
	fx := newBrokerTLSFixture(t)
	cfg, err := buildBrokerTLSConfig(fx.serverCertFile, fx.serverKeyFile, fx.caFile)
	if err != nil {
		t.Fatalf("configuration valide refusée: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth=%v, veut RequireAndVerifyClientCert (mTLS obligatoire, #124)", cfg.ClientAuth)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion=%v, veut TLS 1.3", cfg.MinVersion)
	}
}

func TestBuildBrokerTLSConfigMissingServerCert(t *testing.T) {
	fx := newBrokerTLSFixture(t)
	if _, err := buildBrokerTLSConfig(filepath.Join(t.TempDir(), "absent.pem"), fx.serverKeyFile, fx.caFile); err == nil {
		t.Fatal("certificat serveur absent accepté")
	}
}

func TestBuildBrokerTLSConfigMissingClientCA(t *testing.T) {
	fx := newBrokerTLSFixture(t)
	if _, err := buildBrokerTLSConfig(fx.serverCertFile, fx.serverKeyFile, filepath.Join(t.TempDir(), "absent.pem")); err == nil {
		t.Fatal("autorité cliente absente acceptée")
	}
}

func TestBuildBrokerTLSConfigMalformedClientCA(t *testing.T) {
	fx := newBrokerTLSFixture(t)
	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("pas du PEM"), 0o600); err != nil {
		t.Fatalf("écriture: %v", err)
	}
	if _, err := buildBrokerTLSConfig(fx.serverCertFile, fx.serverKeyFile, badCA); err == nil {
		t.Fatal("autorité cliente mal formée acceptée")
	}
}

// ---------------------------------------------------------------------------
// loadConfig : les quatre variables réseau sont requises ENSEMBLE.
// ---------------------------------------------------------------------------

func TestLoadConfigNetworkListenerRequiresAllFour(t *testing.T) {
	fx := newBrokerTLSFixture(t)
	base := validConfigEnv()
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"adresse seule", map[string]string{"TBP_BROKER_LISTEN_ADDR": "127.0.0.1:0"}},
		{"cert seul", map[string]string{"TBP_BROKER_TLS_CERT_FILE": fx.serverCertFile}},
		{"trois sur quatre", map[string]string{
			"TBP_BROKER_LISTEN_ADDR":   "127.0.0.1:0",
			"TBP_BROKER_TLS_CERT_FILE": fx.serverCertFile,
			"TBP_BROKER_TLS_KEY_FILE":  fx.serverKeyFile,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validConfigEnv()
			for k, v := range base {
				env[k] = v
			}
			for k, v := range tc.env {
				env[k] = v
			}
			if _, err := loadConfig(mapGetenv(env), statPresent); err == nil {
				t.Fatal("configuration réseau partielle acceptée — #124 non fermé")
			}
		})
	}
}

func TestLoadConfigNetworkListenerAllFourAccepted(t *testing.T) {
	fx := newBrokerTLSFixture(t)
	env := validConfigEnv()
	env["TBP_BROKER_LISTEN_ADDR"] = "127.0.0.1:0"
	env["TBP_BROKER_TLS_CERT_FILE"] = fx.serverCertFile
	env["TBP_BROKER_TLS_KEY_FILE"] = fx.serverKeyFile
	env["TBP_BROKER_TLS_CLIENT_CA_FILE"] = fx.caFile
	cfg, err := loadConfig(mapGetenv(env), statPresent)
	if err != nil {
		t.Fatalf("configuration réseau complète refusée: %v", err)
	}
	if cfg.netListenAddr != "127.0.0.1:0" {
		t.Fatalf("netListenAddr=%q", cfg.netListenAddr)
	}
}

func TestLoadConfigNetworkListenerAbsentByDefault(t *testing.T) {
	cfg, err := loadConfig(mapGetenv(validConfigEnv()), statPresent)
	if err != nil {
		t.Fatalf("config valide refusée: %v", err)
	}
	if cfg.netListenAddr != "" {
		t.Fatalf("netListenAddr=%q, veut vide (Unix uniquement par défaut)", cfg.netListenAddr)
	}
}

// ---------------------------------------------------------------------------
// Bout en bout : une VRAIE poignée de main TLS, un VRAI jeton émis.
// ---------------------------------------------------------------------------

// TestBrokerdNetworkMTLSEndToEnd : preuve NON VACUE directe de #124 — un
// agent qui ne tourne PAS sur la même machine (ici : un client HTTP qui
// ne passe QUE par TCP+TLS, jamais par le socket Unix) obtient un jeton
// réel via le plan de données réseau.
func TestBrokerdNetworkMTLSEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	tlsFx := newBrokerTLSFixture(t)

	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			fmt.Fprintf(w, `{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":%q}}}}`, fx.env["TBP_POLICY_ID"])
			return
		}
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	fx.env["TBP_BROKER_TLS_CERT_FILE"] = tlsFx.serverCertFile
	fx.env["TBP_BROKER_TLS_KEY_FILE"] = tlsFx.serverKeyFile
	fx.env["TBP_BROKER_TLS_CLIENT_CA_FILE"] = tlsFx.caFile

	// run() ouvre son propre listener ; on ne peut pas sonder un port
	// choisi dynamiquement (":0") de façon fiable avant de l'avoir
	// ouvert, donc TBP_BROKER_LISTEN_ADDR fixe un port EXPLICITE ici
	// pour rendre le test déterministe.
	fx.env["TBP_BROKER_LISTEN_ADDR"] = "127.0.0.1:18443"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock) // le socket Unix sert de témoin "démarrage terminé"

	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(tlsFx.caFile)
	if err != nil {
		t.Fatalf("lecture CA: %v", err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA de test illisible")
	}

	// 1. Agent LÉGITIME (certificat signé par la bonne CA) : jeton émis.
	legitClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsFx.clientCert},
				RootCAs:      caPool,
				ServerName:   "localhost",
			},
		},
		Timeout: 10 * time.Second,
	}
	body, _ := json.Marshal(map[string]string{"subject": "agent-1", "intent": `{"action":"read","resource":"doc-1","class":0}`})
	resp, err := legitClient.Post("https://127.0.0.1:18443/v1/actions", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("agent légitime refusé au transport TLS: %v", err)
	}
	defer resp.Body.Close()
	var res actionResp
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("décodage: %v", err)
	}
	if !res.Allow || res.Token == "" {
		t.Fatalf("agent légitime sur mTLS: jeton non émis: %+v", res)
	}

	// 2. AUCUN certificat client : rejeté à la poignée de main TLS — la
	// requête HTTP n'atteint même pas le mux applicatif.
	noCertClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: "localhost"},
		},
		Timeout: 5 * time.Second,
	}
	if _, err := noCertClient.Post("https://127.0.0.1:18443/v1/actions", "application/json", strings.NewReader(string(body))); err == nil {
		t.Fatal("connexion SANS certificat client acceptée — mTLS non appliqué, #124 non fermé")
	}

	// 3. Certificat client signé par une AUTRE CA (imposteur) : rejeté à
	// la poignée de main — jamais un jeton pour un pair non authentifié.
	imposteurClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsFx.wrongCACert},
				RootCAs:      caPool,
				ServerName:   "localhost",
			},
		},
		Timeout: 5 * time.Second,
	}
	if _, err := imposteurClient.Post("https://127.0.0.1:18443/v1/actions", "application/json", strings.NewReader(string(body))); err == nil {
		t.Fatal("connexion avec certificat d'une AUTRE autorité acceptée — #124 non fermé")
	}

	// 4. Le socket Unix continue de servir en parallèle — les deux
	// transports coexistent, aucun n'exclut l'autre.
	hc := unixClient(t, sock)
	res2 := postAction(t, hc, "agent-2", `{"action":"read","resource":"doc-2","class":0}`)
	if !res2.Allow {
		t.Fatalf("socket Unix non fonctionnel alors que le réseau est actif: %+v", res2)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestBrokerdNetworkSubjectBoundToTransportIdentity : preuve NON VACUE
// directe de la revue #162/#163 — distincte de TestBrokerdNetworkMTLSEndToEnd,
// qui ne prouve que l'authentification du TRANSPORT (une CA différente ou
// l'absence de certificat sont refusées à la poignée de main). Ici, les
// TROIS clients présentent un certificat VALIDE signé par la bonne CA —
// la poignée de main TLS réussit systématiquement — et seule la
// vérification applicative (subject ↔ CN) doit faire la différence.
func TestBrokerdNetworkSubjectBoundToTransportIdentity(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	tlsFx := newBrokerTLSFixture(t)

	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			fmt.Fprintf(w, `{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":%q}}}}`, fx.env["TBP_POLICY_ID"])
			return
		}
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	fx.env["TBP_BROKER_TLS_CERT_FILE"] = tlsFx.serverCertFile
	fx.env["TBP_BROKER_TLS_KEY_FILE"] = tlsFx.serverKeyFile
	fx.env["TBP_BROKER_TLS_CLIENT_CA_FILE"] = tlsFx.caFile
	fx.env["TBP_BROKER_LISTEN_ADDR"] = "127.0.0.1:18444" // port distinct de TestBrokerdNetworkMTLSEndToEnd

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock)

	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(tlsFx.caFile)
	if err != nil {
		t.Fatalf("lecture CA: %v", err)
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("CA de test illisible")
	}
	post := func(cert tls.Certificate, subject string) actionResp {
		t.Helper()
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caPool, ServerName: "localhost"},
			},
			Timeout: 10 * time.Second,
		}
		body, _ := json.Marshal(map[string]string{"subject": subject, "intent": `{"action":"read","resource":"doc-1","class":0}`})
		resp, err := client.Post("https://127.0.0.1:18444/v1/actions", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("poignée de main TLS refusée alors que le certificat est valide (subject=%s): %v", subject, err)
		}
		defer resp.Body.Close()
		var res actionResp
		if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
			t.Fatalf("décodage: %v", err)
		}
		return res
	}

	// 1. Certificat "agent-test" déclarant "agent-1" (registre : "agent-1"
	// → transport_identity="agent-test") : identité de transport LIÉE au
	// subject déclaré — jeton émis.
	res := post(tlsFx.clientCert, "agent-1")
	if !res.Allow || res.Token == "" {
		t.Fatalf("agent-1/agent-test (lien correct) refusé : %+v", res)
	}

	// 2. MÊME certificat "agent-test", valide, déclarant "agent-2" —
	// "agent-2" n'a AUCUNE transport_identity enregistrée (provisionné
	// socket Unix uniquement, newRunFixture) : refus, quel que soit le
	// certificat présenté — jamais un repli permissif.
	res = post(tlsFx.clientCert, "agent-2")
	if res.Allow || res.Reason != "agent-transport-unbound" {
		t.Fatalf("agent-2 sans transport_identity accepté sur le réseau : allow=%v reason=%q, veut deny/agent-transport-unbound (#163)", res.Allow, res.Reason)
	}

	// 3. Certificat DIFFÉRENT mais tout aussi VALIDE (CN "agent-other",
	// signé par la MÊME bonne CA — la poignée de main TLS réussit)
	// déclarant "agent-1" : c'est le témoin central de #162/#163 — une
	// identité de transport authentifiée avec succès mais qui n'est PAS
	// celle enregistrée pour ce subject doit être refusée par le broker
	// lui-même, pas seulement acceptée parce que le certificat est valide.
	res = post(tlsFx.otherValidCert, "agent-1")
	if res.Allow || res.Reason != "agent-transport-unbound" {
		t.Fatalf("agent-1 réclamé par un certificat valide MAIS différent (agent-other) accepté : allow=%v reason=%q — BOLA/Broken Authentication (#162) non fermé", res.Allow, res.Reason)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}
