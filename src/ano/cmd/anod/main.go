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
// Démarrage mesuré (#272) — anod est la dernière ligne avant la sortie des données : ses
// règles, son trousseau et son binaire sont mesurés comme ceux de pepd et de brokerd
// (registry.ProvisioningGuard, issue #192) :
//
//	TBP_CELL_ID               requis — identité de la cellule (entre dans le témoin)
//	TBP_SALT                  requis — sel des feuilles de provisionnement, hex ≥ 32
//	                          caractères (§6.2, ne quitte jamais la cellule)
//	TBP_REGISTRY_DIR          requis — journal PROPRE à anod (clé de cellule, feuilles de
//	                          genèse / démarrage / transition / refus)
//	TBP_PROVISIONING_WITNESS_FILE  requis — témoin signé, HORS de TBP_REGISTRY_DIR
//	TBP_AUDIT_RECORDS         requis — journal chiffré du clair des feuilles d'anod (#275,
//	                          #271 : `tbp-audit verify`)
//	TBP_AUDIT_RECORDS_KEY_FILE  requis — sa clé (0600 ; `tbp-audit keygen`)
//	TBP_QUORUM_KEYRING_FILE   requis — trousseau des contrôleurs (quorum), même format que
//	                          TBP_KEYRING_FILE ; mesuré comme fichier d'AUTORITÉ
//	TBP_QUORUM_MIN            requis — k : signatures distinctes d'une preuve de transition
//	TBP_PROVISIONING_TRANSITION_PROOF_FILE  optionnel — preuve de quorum d'un changement
//	                          DÉLIBÉRÉ (règles, trousseau, binaire, réglages) : le refus de
//	                          démarrage annonce la condition à signer
//	TBP_PROVISIONING_EXTRA_FILES  optionnel — « nom=chemin,… » de fichiers à mesurer en plus
//
// Mesuré : le fichier de règles, le trousseau d'émetteurs, le trousseau de contrôleurs, le
// binaire d'anod, les réglages qui décident ce qui sort (classifieur, délais, bornes) et k.
// Modifier l'un d'eux entre deux démarrages — retirer un motif, élargir keep_paths, brancher
// un classifieur — est REFUSÉ sans preuve de quorum liée à (état attesté, état cible).
//
// Doctrine §1 : le moindre défaut de configuration est FATAL au démarrage.
package main

import (
	"context"
	"crypto/ed25519"
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
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const (
	defaultSocket     = "/run/tbp/ano.sock"
	readHeaderTimeout = 5 * time.Second
)

func main() {
	// #264 : recalcul de la condition de transition hors de la machine contrôlée — rien n'est démarré.
	if len(os.Args) > 1 && os.Args[1] == pep.PrintConditionFlag {
		os.Exit(printProvisioningCondition(os.Args[2:], os.Getenv, os.Stdout, os.Stderr))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		log.Fatalf("anod: %v", err)
	}
}

type config struct {
	socket      string
	keyring     map[[16]byte]ed25519.PublicKey
	keyringPath string
	rules       *ano.Rules
	rulesPath   string
	// démarrage mesuré (#272)
	cellID            string
	salt              []byte
	registryDir       string
	witnessFile       string
	auditRecords      string // journal chiffré du clair des feuilles (#275, #271)
	auditKeyFile      string
	quorumKeyringPath string
	quorumKeyring     map[[16]byte]ed25519.PublicKey
	quorumMin         int
	proofFile         string
	extraFiles        string
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
	cfg.keyringPath = getenv("TBP_KEYRING_FILE")
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
	cfg.rulesPath = rulesPath
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
	if err := loadProvisioningConfig(getenv, &cfg); err != nil {
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
	// même décodeur STRICT que pepd et le provisionnement (revue tierce 4.4)
	return pep.ParseKeyring(data)
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
	// Démarrage mesuré (#272) AVANT tout le reste : anod n'engage ni moteur ni socket tant que ses
	// règles, son trousseau et son binaire ne sont pas conformes au témoin.
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("binaire d'anod introuvable (mesure #272): %w", err)
	}
	cellLog, signer, verifier, err := openRegistry(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := cellLog.Close(closeCtx); err != nil {
			log.Printf("anod: fermeture du registre: %v", err)
		}
	}()
	// Journal d'enregistrements (#275) : le clair de chaque feuille d'anod, vérifiable avec
	// `tbp-audit verify`. REQUIS : un anod dont les feuilles ne seraient pas vérifiables ne démarre pas.
	journal, err := registry.OpenRecordStoreFiles(cfg.auditRecords, cfg.auditKeyFile)
	if err != nil {
		return fmt.Errorf("journal d'audit (#275): %w", err)
	}
	defer journal.Close()
	if err := setupProvisioning(ctx, cfg, binary, signer, verifier, cellLog, journal); err != nil {
		return fmt.Errorf("provisionnement: %w", err)
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
