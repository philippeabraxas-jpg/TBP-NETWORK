// anod est le démon d'anonymisation de la cellule (issue #178) : il détient
// la table jeton ↔ valeur et ne parle qu'à travers un socket Unix. Il n'a
// AUCUN accès réseau (unit systemd : PrivateNetwork, AF_UNIX seulement) et ne
// journalise jamais de valeur.
//
// Ses appelants (le proxy bloquant de pepd) s'authentifient par le jeton
// porteur signé par le broker ; voir src/ano/svc.
//
// Configuration par variables d'environnement :
//
//	TBP_ANO_SOCKET            socket d'écoute (défaut /run/tbp/ano.sock, 0660)
//	TBP_KEYRING_FILE          requis — trousseau de l'émetteur, JSON
//	                          {"kid_hex": "pubkey_ed25519_hex"} (§12, épinglé) :
//	                          même format que pepd
//	TBP_ANO_RULES_FILE        requis — règles de détection (chemins garder /
//	                          masquer, motifs RE2), voir src/ano/rules.go.
//	                          Sans règle, tout champ non gardé est masqué
//	TBP_ANO_CLASSIFIER_SOCKET optionnel — socket Unix d'une IA locale de type
//	                          JEV qui tranche oui/non pour les champs ambigus
//	                          (contrat : src/ano/classifier_socket.go). Absent ⇒
//	                          default-deny
//	TBP_ANO_CLASSIFIER_TIMEOUT_MS  délai par appel au classifieur, 1–100
//	                          (défaut 5). Un retard masque le champ
//	TBP_ANO_RESPONSE_GRACE_S  vie d'un échange après l'expiration de son jeton,
//	                          pour la réponse externe (défaut 60, max 600)
//	TBP_ANO_MAX_EXCHANGES     échanges vivants maximum (défaut 1024)
//	TBP_ANO_MAX_ENTRIES       entrées maximum par échange (défaut 1024)
//
// Doctrine §1 : le moindre défaut de configuration est FATAL au démarrage.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	ano "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano"
	svc "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano/svc"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

const (
	defaultSocket     = "/run/tbp/ano.sock"
	readHeaderTimeout = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		log.Fatalf("anod: %v", err)
	}
}

type config struct {
	socket            string
	keyring           map[[16]byte]ed25519.PublicKey
	rules             *ano.Rules
	classifierSocket  string
	classifierTimeout time.Duration
	grace             time.Duration
	maxExchanges      int
	maxEntries        int
}

func envInt(getenv func(string) string, name string, def, min, max int) (int, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s: entier dans [%d, %d] requis, reçu %q", name, min, max, v)
	}
	return n, nil
}

func loadConfig(getenv func(string) string) (config, error) {
	var cfg config
	cfg.socket = getenv("TBP_ANO_SOCKET")
	if cfg.socket == "" {
		cfg.socket = defaultSocket
	}
	kr, err := loadKeyring(getenv("TBP_KEYRING_FILE"))
	if err != nil {
		return cfg, fmt.Errorf("TBP_KEYRING_FILE: %w", err)
	}
	cfg.keyring = kr
	rulesPath := getenv("TBP_ANO_RULES_FILE")
	if rulesPath == "" {
		return cfg, errors.New("TBP_ANO_RULES_FILE requis (des règles vides sont un choix explicite : le fichier doit exister)")
	}
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return cfg, fmt.Errorf("TBP_ANO_RULES_FILE: %w", err)
	}
	if cfg.rules, err = ano.ParseRules(data); err != nil {
		return cfg, fmt.Errorf("TBP_ANO_RULES_FILE: %w", err)
	}
	cfg.classifierSocket = getenv("TBP_ANO_CLASSIFIER_SOCKET")
	ms, err := envInt(getenv, "TBP_ANO_CLASSIFIER_TIMEOUT_MS", 5, 1, 100)
	if err != nil {
		return cfg, err
	}
	cfg.classifierTimeout = time.Duration(ms) * time.Millisecond
	gs, err := envInt(getenv, "TBP_ANO_RESPONSE_GRACE_S", int(svc.DefaultResponseGrace/time.Second), 0, 600)
	if err != nil {
		return cfg, err
	}
	cfg.grace = time.Duration(gs) * time.Second
	if cfg.maxExchanges, err = envInt(getenv, "TBP_ANO_MAX_EXCHANGES", ano.DefaultMaxExchanges, 1, 1<<20); err != nil {
		return cfg, err
	}
	if cfg.maxEntries, err = envInt(getenv, "TBP_ANO_MAX_ENTRIES", ano.DefaultMaxEntries, 1, 1<<20); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// loadKeyring lit le trousseau épinglé (même format que pepd).
func loadKeyring(path string) (map[[16]byte]ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("chemin de fichier requis")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("trousseau vide (§12)")
	}
	kr := make(map[[16]byte]ed25519.PublicKey, len(raw))
	for kidHex, pubHex := range raw {
		kid, err := hex.DecodeString(kidHex)
		if err != nil || len(kid) != 16 {
			return nil, fmt.Errorf("kid %q illisible (hex 16 octets)", kidHex)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("clé %q illisible (Ed25519)", kidHex)
		}
		var k [16]byte
		copy(k[:], kid)
		kr[k] = ed25519.PublicKey(pub)
	}
	return kr, nil
}

// listenUnix ouvre le socket d'écoute (0660). Un fichier existant qui n'est
// pas un socket n'est jamais supprimé.
func listenUnix(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("répertoire du socket: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s existe et n'est pas un socket — refus de l'écraser", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

func run(ctx context.Context, getenv func(string) string) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	opts := ano.Options{
		Rules:                 cfg.rules,
		ClassifierTimeout:     cfg.classifierTimeout,
		MaxExchanges:          cfg.maxExchanges,
		MaxEntriesPerExchange: cfg.maxEntries,
		// jamais de valeur dans une alarme : seulement la raison
		OnTrip: func(reason string) { log.Printf("anod: alarme %s", reason) },
	}
	if cfg.classifierSocket != "" {
		opts.Classifier = ano.NewSocketClassifier(cfg.classifierSocket)
	}
	engine, err := ano.New(opts)
	if err != nil {
		return err
	}
	ver, err := pep.NewPossessionVerifier(cfg.keyring, nil)
	if err != nil {
		return err
	}
	srv, err := svc.NewServer(svc.ServerOptions{Ano: engine, Verifier: ver, ResponseGrace: cfg.grace})
	if err != nil {
		return err
	}
	lis, err := listenUnix(cfg.socket)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: readHeaderTimeout}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()
	mode := "default-deny (sans classifieur)"
	if cfg.classifierSocket != "" {
		mode = "classifieur local " + cfg.classifierSocket
	}
	log.Printf("anod: en écoute sur unix://%s — %s", cfg.socket, mode)
	if err := httpSrv.Serve(lis); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
