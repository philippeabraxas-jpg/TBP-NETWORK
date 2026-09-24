// brokerd est le démon broker de la cellule (T37, issue #74) : il
// ASSEMBLE les bibliothèques existantes en un service installable — comme
// pepd (T15) assemble le PEP. Aucune logique métier n'est ajoutée ici :
// toute la chaîne de décision vit dans src/broker (T33), le fencing dans
// src/cluster (T29), le registre dans src/registry (T7).
//
// Pile assemblée :
//
//	CellLog propre (T7, clé note créée/rechargée) → OPA (T11) →
//	Tracker d'époques (T29, epoch0 accepté au démarrage — SEULEMENT si
//	TBP_CLUSTER_MEMBERS porte ≥ 2 cellules ; mode mono-cellule sinon,
//	issue #97) → QuorumGate classe W (§7.5) → ContractStore (T30) →
//	[Enveloppe §4.1-bis, optionnelle] → Issuer (T33, clé de dev — §12) →
//	Broker → serveur HTTP sur socket Unix (déploiement v1).
//
// Le serveur expose AUSSI trois lectures de supervision (GET-only) :
// /v1/supervision/stats, /v1/supervision/epoch, /v1/supervision/arbitration.
// Ce sont des handlers d'assemblage qui sérialisent ce que les méthodes
// publiques des briques rendent déjà — zéro modification de bibliothèque
// (D109). Séparées du plan de données depuis la revue de sécurité #95
// (finding A10) : socket Unix DÉDIÉ (TBP_BROKER_ADMIN_SOCKET), jamais le
// socket que POST /v1/actions écoute — l'accès au socket EST le contrôle
// d'accès, doctrine déjà posée pour la console T34c. L'exposition réseau
// inter-cellules est une autre issue (T35).
//
// Configuration par variables d'environnement (toutes requises sauf
// mention contraire) :
//
//	TBP_CELL_ID             identité de la cellule (ex. cell-a)
//	TBP_SALT                sel des feuilles, hex ≥ 32 caractères (§6.2 —
//	                        ne quitte JAMAIS la cellule)
//	TBP_POLICY_ID           hash du bundle de règles, hex 64 (§3, épinglé)
//	TBP_REGISTRY_DIR        répertoire du CellLog du broker (sa propre
//	                        chaîne — le broker feuille comme toute cellule)
//	TBP_OPA_ENDPOINT        URL de décision OPA (T11) — requis : le broker
//	                        n'émet rien sans arbitrage des règles
//	TBP_OPA_SOCKET          chemin du socket Unix d'OPA — REQUIS avec
//	                        TBP_OPA_EXPECTED_UID (revue de sécurité #92,
//	                        A3 : transport authentifié par SO_PEERCRED, un
//	                        OPA en TCP non authentifié est indétectable
//	                        d'un imposteur) sauf TBP_OPA_INSECURE_TCP_DEV=1
//	                        déclaré EXPLICITEMENT (dev/lab uniquement)
//	TBP_OPA_EXPECTED_UID    UID attendu du processus OPA, requis avec
//	                        TBP_OPA_SOCKET — vérifié à CHAQUE connexion
//	                        par le noyau (SO_PEERCRED), jamais déclaré
//	                        par le pair
//	TBP_OPA_INSECURE_TCP_DEV  exempte EXPLICITEMENT du transport Unix
//	                        authentifié (§92.A3) — dev/lab uniquement ;
//	                        revue #113 : refusé au démarrage sauf sentinel
//	                        devmode.DefaultSentinelPath présent (fichier à
//	                        chemin FIXE, hors de ce fichier d'environnement)
//	TBP_OPA_REVISION_CHECK_INTERVAL_MS  optionnel — période de vérification
//	                        périodique que la révision RÉELLEMENT servie
//	                        par OPA correspond à TBP_POLICY_ID épinglé
//	                        (§92.A5, spec §10.3). Défaut 10000 (10 s) ;
//	                        vérifiée aussi UNE FOIS, synchrone, avant que
//	                        le broker ne serve — un écart y refuse le
//	                        démarrage
//	TBP_TRANSLATOR          "structured" — seule valeur admise en v1
//	                        (le traducteur langage naturel est T24/T25)
//	Custody de l'émetteur (§12) — EXACTEMENT un des deux mécanismes,
//	jamais les deux, jamais aucun (revue de sécurité #90, point 5) :
//	TBP_ISSUER_SEED_FILE    seed Ed25519 de l'émetteur, hex 64, fichier
//	                        0600 — CUSTODY DEV UNIQUEMENT (labo/CI) ;
//	                        revue #113 : jusqu'ici acceptée SANS AUCUN
//	                        drapeau dev dédié — désormais soumise au même
//	                        sentinel devmode.DefaultSentinelPath que
//	                        TBP_OPA_INSECURE_TCP_DEV ci-dessus
//	TBP_ISSUER_PKCS11_MODULE       chemin du module PKCS#11 (.so) — HSM
//	                        réel ou SoftHSM2 ; la clé privée ne quitte
//	                        jamais le module (broker.PKCS11Signer)
//	TBP_ISSUER_PKCS11_TOKEN_LABEL  étiquette du jeton portant la clé
//	TBP_ISSUER_PKCS11_KEY_LABEL    étiquette de la paire de clés Ed25519
//	                        dans le jeton (provisionnée hors-bande, §12 :
//	                        la cérémonie de genèse, pas ce démon)
//	TBP_ISSUER_PKCS11_PIN_FILE     PIN utilisateur du jeton, fichier 0600
//	                        (même exigence de custody que la seed de dev)
//	TBP_GENESIS_DIR         répertoire de genèse (scripts/genesis) —
//	                        manifest.json (contrôleurs, toujours requis :
//	                        sert le quorum classe W, §7.5) ; epoch0.json
//	                        requis SEULEMENT si TBP_CLUSTER_MEMBERS porte
//	                        ≥ 2 cellules (voir ci-dessous, issue #97)
//	TBP_QUORUM_MIN          M du quorum M-of-N (défaut 2, ≤ N contrôleurs)
//	TBP_CLUSTER_MEMBERS     cellules autorisées à porter l'autorité,
//	                        séparées par des virgules — DOIT contenir
//	                        TBP_CELL_ID. Une SEULE cellule ⇒ mode
//	                        mono-cellule (issue #97, décision actée pour
//	                        #86) : aucun bail d'époque, aucun epoch0.json
//	                        requis — le fencing (§7.2) n'a rien à
//	                        arbitrer entre une cellule et elle-même. ≥ 2
//	                        cellules ⇒ fencing complet, epoch0.json requis
//	TBP_OPERATOR_KEYS_FILE  JSON ["pubkey_ed25519_hex", …] ≥ 1 — clés
//	                        d'opérateurs du store de contrats (T30)
//	TBP_ENVELOPE_ENDPOINT   optionnel — règle d'enveloppe §4.1-bis ;
//	                        absent ⇒ toute demande de passeport refusée
//	                        (envelope-unverified, doctrine existante)
//	TBP_BROKER_SOCKET       plan de DONNÉES : POST /v1/actions — défaut
//	                        /run/tbp/broker.sock
//	TBP_BROKER_ADMIN_SOCKET plan d'ADMINISTRATION (revue de sécurité #95,
//	                        finding A10) : GET /v1/supervision/{stats,epoch,
//	                        arbitration} — défaut /run/tbp/broker-admin.sock.
//	                        Socket SÉPARÉ du plan de données, jamais
//	                        multiplexé dessus.
//	Transport réseau du plan de données (revue de sécurité #124) —
//	optionnel, absent par défaut (Unix uniquement, comportement
//	historique) ; si l'un des quatre champs suivants est présent, les
//	QUATRE sont requis ENSEMBLE (net_tls.go) :
//	TBP_BROKER_LISTEN_ADDR     adresse d'écoute réseau (ex. :8444) — un
//	                        agent qui ne tourne pas sur la même machine que
//	                        le broker en a besoin pour obtenir un jeton.
//	TBP_BROKER_TLS_CERT_FILE, TBP_BROKER_TLS_KEY_FILE  certificat/clé
//	                        serveur PEM.
//	TBP_BROKER_TLS_CLIENT_CA_FILE  autorité de certification PEM des
//	                        clients — mTLS exclusivement : un pair sans
//	                        certificat, ou avec un certificat signé par
//	                        une autre autorité, est rejeté à la poignée de
//	                        main (TLS 1.3 minimum). Aucune échappatoire
//	                        TCP en clair n'est offerte ici — contrairement
//	                        à TBP_OPA_INSECURE_TCP_DEV, un plan de données
//	                        qui émet des jetons de gouvernance n'a pas de
//	                        variante dev/lab moins sûre.
//
// Doctrine §1 : le moindre défaut de configuration est FATAL au démarrage
// — un broker à moitié configuré émettrait des décisions à moitié
// contrôlées, ce qui est pire que pas de broker.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	devmode "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devmode"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// defaultBrokerSocket est l'écoute par défaut du plan de DONNÉES
// (POST /v1/actions) du déploiement v1 (socket Unix de cellule, 0660 —
// broker.ListenUnix).
const defaultBrokerSocket = "/run/tbp/broker.sock"

// defaultBrokerAdminSocket est l'écoute par défaut du plan
// d'ADMINISTRATION (revue de sécurité #95) : GET /v1/supervision/*.
const defaultBrokerAdminSocket = "/run/tbp/broker-admin.sock"

// readHeaderTimeout borne la lecture des en-têtes (même doctrine que le
// serveur broker — slowloris).
const readHeaderTimeout = 5 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv, os.Stat); err != nil {
		log.Fatalf("brokerd: %v", err)
	}
}

// config est la configuration validée du démon — loadConfig ne rend QUE
// des valeurs complètes et cohérentes (fail-closed §1).
type config struct {
	cellID      string
	salt        []byte
	policyID    [32]byte
	registryDir string
	opaEndpoint string
	// Transport OPA durci (revue de sécurité #92, finding A3) : EXACTEMENT
	// un des deux — opaSocket+opaExpectedUID (Unix + SO_PEERCRED) OU
	// opaInsecureTCPDev (TCP non authentifié, dev/lab EXPLICITE).
	opaSocket           string
	opaExpectedUID      uint32
	opaInsecureTCPDev   bool
	opaRevisionInterval time.Duration // 0 ⇒ défaut du watcher (§92.A5)
	// Custody de l'émetteur (§12) : EXACTEMENT un des deux mécanismes.
	// issuerSeedFile ("" ⇒ HSM) : seed Ed25519 DEV, fichier 0600 — labo/CI
	// uniquement. Les quatre champs issuerPKCS11* ("" ⇒ dev), tous requis
	// ensemble : custody HSM réelle (revue de sécurité #90, point 5) — la
	// clé privée ne quitte jamais le module PKCS#11.
	issuerSeedFile       string
	issuerPKCS11Module   string
	issuerPKCS11Token    string
	issuerPKCS11KeyLabel string
	issuerPKCS11PINFile  string
	genesisDir           string
	quorumMin            int
	members              []string
	operatorKeysFile     string
	envelopeEndpoint     string // "" = enveloppe non câblée (doctrine existante)
	socketPath           string // plan de données : POST /v1/actions
	adminSocketPath      string // plan d'administration (revue #95) : GET /v1/supervision/*
	// Transport réseau du plan de données (revue de sécurité #124) :
	// optionnel — "" ⇒ Unix uniquement (comportement historique, valeur
	// par défaut). Si netListenAddr est non vide, les trois champs TLS
	// suivants sont TOUS requis ensemble : mTLS est la SEULE forme
	// d'exposition réseau offerte, jamais un TCP en clair (§12/§95 :
	// même doctrine de transport authentifié que le socket Unix+SO_PEERCRED
	// d'OPA, §92.A3 — ici la preuve d'identité est le certificat client).
	netListenAddr      string
	netTLSCertFile     string
	netTLSKeyFile      string
	netTLSClientCAFile string
}

// loadConfig lit et valide TOUTE la configuration — la moindre pièce
// manquante ou invalide est une erreur, avant tout effet de bord. stat
// n'est consulté QUE si un drapeau « dev » (revue #113) est actif — voir
// devEscapeHatchFlags ci-dessous.
func loadConfig(getenv func(string) string, stat func(string) (os.FileInfo, error)) (*config, error) {
	cellID, err := envRequired(getenv, "TBP_CELL_ID")
	if err != nil {
		return nil, err
	}
	salt, err := envHex(getenv, "TBP_SALT", 16)
	if err != nil {
		return nil, err
	}
	policyBytes, err := envHex(getenv, "TBP_POLICY_ID", 32)
	if err != nil {
		return nil, err
	}
	var policy [32]byte
	copy(policy[:], policyBytes)
	registryDir, err := envRequired(getenv, "TBP_REGISTRY_DIR")
	if err != nil {
		return nil, err
	}
	opaEndpoint, err := envRequired(getenv, "TBP_OPA_ENDPOINT")
	if err != nil {
		return nil, err
	}
	// Transport OPA durci (revue de sécurité #92, A3) : EXACTEMENT un des
	// deux mécanismes — jamais les deux, jamais aucun sans déclaration
	// EXPLICITE du dev/lab non authentifié.
	opaSocket := getenv("TBP_OPA_SOCKET")
	opaInsecureTCPDev := getenv("TBP_OPA_INSECURE_TCP_DEV") == "1"
	var opaExpectedUID uint32
	switch {
	case opaSocket != "" && opaInsecureTCPDev:
		return nil, errors.New("TBP_OPA_SOCKET et TBP_OPA_INSECURE_TCP_DEV sont mutuellement exclusifs (§92.A3)")
	case opaSocket == "" && !opaInsecureTCPDev:
		return nil, errors.New("TBP_OPA_SOCKET+TBP_OPA_EXPECTED_UID requis (revue de sécurité #92, A3 : OPA authentifié par SO_PEERCRED) — TBP_OPA_INSECURE_TCP_DEV=1 pour l'exempter EXPLICITEMENT (dev/lab uniquement, jamais en production)")
	case opaSocket != "":
		uidStr, uerr := envRequired(getenv, "TBP_OPA_EXPECTED_UID")
		if uerr != nil {
			return nil, uerr
		}
		uid, perr := strconv.ParseUint(uidStr, 10, 32)
		if perr != nil {
			return nil, fmt.Errorf("TBP_OPA_EXPECTED_UID invalide %q: %w", uidStr, perr)
		}
		opaExpectedUID = uint32(uid)
	}
	opaRevisionInterval := time.Duration(0)
	if s := getenv("TBP_OPA_REVISION_CHECK_INTERVAL_MS"); s != "" {
		ms, perr := strconv.Atoi(s)
		if perr != nil || ms <= 0 {
			return nil, fmt.Errorf("TBP_OPA_REVISION_CHECK_INTERVAL_MS invalide %q (entier > 0 attendu)", s)
		}
		opaRevisionInterval = time.Duration(ms) * time.Millisecond
	}
	if tr := getenv("TBP_TRANSLATOR"); tr != "structured" {
		return nil, fmt.Errorf("TBP_TRANSLATOR=%q refusé — seul \"structured\" est assemblé en v1 (traducteur langage naturel : T24/T25)", tr)
	}
	// Custody de l'émetteur (§12) : EXACTEMENT un des deux mécanismes —
	// jamais les deux (ambiguïté de custody), jamais aucun (fail-closed).
	issuerSeedFile := getenv("TBP_ISSUER_SEED_FILE")
	pkcs11Module := getenv("TBP_ISSUER_PKCS11_MODULE")
	pkcs11Token := getenv("TBP_ISSUER_PKCS11_TOKEN_LABEL")
	pkcs11KeyLabel := getenv("TBP_ISSUER_PKCS11_KEY_LABEL")
	pkcs11PINFile := getenv("TBP_ISSUER_PKCS11_PIN_FILE")
	usingPKCS11 := pkcs11Module != "" || pkcs11Token != "" || pkcs11KeyLabel != "" || pkcs11PINFile != ""
	switch {
	case issuerSeedFile != "" && usingPKCS11:
		return nil, errors.New("TBP_ISSUER_SEED_FILE et TBP_ISSUER_PKCS11_* sont mutuellement exclusifs — un seul mécanisme de custody par cellule (§12)")
	case issuerSeedFile == "" && !usingPKCS11:
		return nil, errors.New("custody de l'émetteur requise : TBP_ISSUER_SEED_FILE (dev) OU TBP_ISSUER_PKCS11_MODULE+TOKEN_LABEL+KEY_LABEL+PIN_FILE (HSM, §12, revue #90 point 5)")
	case usingPKCS11 && (pkcs11Module == "" || pkcs11Token == "" || pkcs11KeyLabel == "" || pkcs11PINFile == ""):
		return nil, errors.New("TBP_ISSUER_PKCS11_MODULE, _TOKEN_LABEL, _KEY_LABEL et _PIN_FILE sont tous requis ensemble")
	}
	if err := devmode.RequireDeclared(devmode.DefaultSentinelPath, stat, devEscapeHatchFlags(opaInsecureTCPDev, issuerSeedFile)); err != nil {
		return nil, err
	}
	genesisDir, err := envRequired(getenv, "TBP_GENESIS_DIR")
	if err != nil {
		return nil, err
	}
	quorumMin := 2
	if s := getenv("TBP_QUORUM_MIN"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return nil, fmt.Errorf("TBP_QUORUM_MIN invalide %q", s)
		}
		quorumMin = n
	}
	var members []string
	raw := getenv("TBP_CLUSTER_MEMBERS")
	if raw == "" {
		return nil, errors.New("TBP_CLUSTER_MEMBERS requis (cellules autorisées à porter l'autorité, §7.2)")
	}
	seen := map[string]bool{}
	for _, m := range strings.Split(raw, ",") {
		m = strings.TrimSpace(m)
		if m == "" || seen[m] {
			return nil, fmt.Errorf("TBP_CLUSTER_MEMBERS : membre vide ou en double dans %q", raw)
		}
		seen[m] = true
		members = append(members, m)
	}
	if !seen[cellID] {
		return nil, fmt.Errorf("TBP_CELL_ID %q absent de TBP_CLUSTER_MEMBERS — une cellule hors roster ne peut pas servir (§7.2)", cellID)
	}
	operatorKeysFile, err := envRequired(getenv, "TBP_OPERATOR_KEYS_FILE")
	if err != nil {
		return nil, err
	}
	socketPath := getenv("TBP_BROKER_SOCKET")
	if socketPath == "" {
		socketPath = defaultBrokerSocket
	}
	adminSocketPath := getenv("TBP_BROKER_ADMIN_SOCKET")
	if adminSocketPath == "" {
		adminSocketPath = defaultBrokerAdminSocket
	}
	// Transport réseau du plan de données (revue #124) : optionnel, mais
	// EXACTEMENT « absent » ou « les quatre présents ensemble » — jamais
	// une adresse d'écoute sans mTLS pleinement configuré, jamais un
	// certificat orphelin sans adresse. Aucune échappatoire TCP en clair
	// n'est offerte ici (contrairement à TBP_OPA_INSECURE_TCP_DEV) : le
	// plan de données du broker émet des jetons de gouvernance, jamais
	// exposable sans authentification mutuelle.
	netListenAddr := getenv("TBP_BROKER_LISTEN_ADDR")
	netTLSCertFile := getenv("TBP_BROKER_TLS_CERT_FILE")
	netTLSKeyFile := getenv("TBP_BROKER_TLS_KEY_FILE")
	netTLSClientCAFile := getenv("TBP_BROKER_TLS_CLIENT_CA_FILE")
	switch {
	case netListenAddr == "" && netTLSCertFile == "" && netTLSKeyFile == "" && netTLSClientCAFile == "":
		// Écoute réseau désactivée — Unix uniquement, comportement historique.
	case netListenAddr != "" && netTLSCertFile != "" && netTLSKeyFile != "" && netTLSClientCAFile != "":
		// Configuration complète — validée plus loin (chargement réel des
		// fichiers) au moment de construire le listener.
	default:
		return nil, errors.New("TBP_BROKER_LISTEN_ADDR, TBP_BROKER_TLS_CERT_FILE, TBP_BROKER_TLS_KEY_FILE et TBP_BROKER_TLS_CLIENT_CA_FILE sont requis ENSEMBLE (revue de sécurité #124) — l'écoute réseau est mTLS ou absente, jamais partiellement configurée")
	}
	return &config{
		cellID:               cellID,
		salt:                 salt,
		policyID:             policy,
		registryDir:          registryDir,
		opaEndpoint:          opaEndpoint,
		opaSocket:            opaSocket,
		opaExpectedUID:       opaExpectedUID,
		opaInsecureTCPDev:    opaInsecureTCPDev,
		opaRevisionInterval:  opaRevisionInterval,
		issuerSeedFile:       issuerSeedFile,
		issuerPKCS11Module:   pkcs11Module,
		issuerPKCS11Token:    pkcs11Token,
		issuerPKCS11KeyLabel: pkcs11KeyLabel,
		issuerPKCS11PINFile:  pkcs11PINFile,
		genesisDir:           genesisDir,
		quorumMin:            quorumMin,
		members:              members,
		operatorKeysFile:     operatorKeysFile,
		envelopeEndpoint:     getenv("TBP_ENVELOPE_ENDPOINT"),
		socketPath:           socketPath,
		adminSocketPath:      adminSocketPath,
		netListenAddr:        netListenAddr,
		netTLSCertFile:       netTLSCertFile,
		netTLSKeyFile:        netTLSKeyFile,
		netTLSClientCAFile:   netTLSClientCAFile,
	}, nil
}

// devEscapeHatchFlags rassemble les échappatoires « dev » actives de
// brokerd pour la revue de sécurité #113 : TBP_OPA_INSECURE_TCP_DEV
// (comme pepd) ET TBP_ISSUER_SEED_FILE — contrairement aux deux
// échappatoires OPA (#92), la seed de dev était jusqu'ici acceptée SANS
// AUCUN drapeau dédié, seule sa présence suffisait à choisir la custody
// dev plutôt que HSM.
func devEscapeHatchFlags(opaInsecureTCPDev bool, issuerSeedFile string) []string {
	var active []string
	if opaInsecureTCPDev {
		active = append(active, "TBP_OPA_INSECURE_TCP_DEV")
	}
	if issuerSeedFile != "" {
		active = append(active, "TBP_ISSUER_SEED_FILE")
	}
	return active
}

// run assemble la pile et sert jusqu'à l'annulation du contexte.
func run(ctx context.Context, getenv func(string) string, stat func(string) (os.FileInfo, error)) error {
	cfg, err := loadConfig(getenv, stat)
	if err != nil {
		return err
	}

	// Registre propre du broker (T7) : sa chaîne, sa clé de checkpoint —
	// le broker feuille comme toute cellule (§7.1).
	if err := os.MkdirAll(cfg.registryDir, 0o700); err != nil {
		return fmt.Errorf("registry dir: %w", err)
	}
	signer, vkey, err := loadOrGenerateCellKey(cfg.registryDir, cfg.cellID)
	if err != nil {
		return err
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		return fmt.Errorf("note verifier: %w", err)
	}
	cellLog, err := registry.Open(ctx, registry.Options{
		Dir: cfg.registryDir, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("cell log: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := cellLog.Close(closeCtx); err != nil {
			log.Printf("brokerd: fermeture du registre: %v", err)
		}
	}()

	onTrip := func(reason string) { log.Printf("brokerd: ALARME: %s", reason) }

	// Transport OPA durci (revue de sécurité #92, A3) : Unix + SO_PEERCRED
	// (nominal) ou TCP non authentifié (dev/lab, EXPLICITEMENT déclaré par
	// loadConfig — jamais un défaut silencieux).
	var opaHC *http.Client
	if cfg.opaSocket != "" {
		tr, terr := pep.NewOPAUnixTransport(cfg.opaSocket, cfg.opaExpectedUID)
		if terr != nil {
			return terr
		}
		opaHC = &http.Client{Transport: tr}
	} else {
		log.Printf("brokerd: OPA en TCP NON authentifié (TBP_OPA_INSECURE_TCP_DEV=1, revue #92.A3) — DEV/LAB UNIQUEMENT, jamais en production : un imposteur qui occupe ce port est indétectable")
	}

	// Arbitrage des règles (T11) — requis : pas d'émission sans règles.
	opaClient, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint:   cfg.opaEndpoint,
		HTTPClient: opaHC,
		CellID:     cfg.cellID,
		Salt:       cfg.salt,
		Leaves:     cellLog,
		OnTrip:     onTrip,
	})
	if err != nil {
		return err
	}

	// Watcher de révision OPA (revue de sécurité #92, A5) construit ICI
	// (aucun effet de bord — Check() n'est appelé, PLUS BAS, qu'une fois
	// tout le reste de l'assemblage validé : un OPA injoignable ne doit
	// jamais masquer un défaut de configuration antérieur — genèse,
	// quorum, custody — dans le message d'erreur rendu).
	opaRevisionWatcher, err := pep.NewOPARevisionWatcher(pep.OPARevisionWatcherOptions{
		Endpoint:   cfg.opaEndpoint,
		Expected:   hex.EncodeToString(cfg.policyID[:]),
		HTTPClient: opaHC,
		Interval:   cfg.opaRevisionInterval,
		CellID:     cfg.cellID,
		Salt:       cfg.salt,
		Leaves:     cellLog,
		OnTrip:     onTrip,
	})
	if err != nil {
		return err
	}

	// Manifest de genèse → contrôleurs épinglés (T3, hors-bande) : sert
	// TOUJOURS le quorum classe W (§7.5) ci-dessous, quelle que soit
	// l'échelle — un seul jeu de clés, une seule cérémonie.
	controllers, err := loadGenesisControllers(filepath.Join(cfg.genesisDir, "manifest.json"))
	if err != nil {
		return err
	}
	if cfg.quorumMin > len(controllers) {
		return fmt.Errorf("TBP_QUORUM_MIN=%d > %d contrôleurs du manifest — un quorum impossible est un refus de démarrage", cfg.quorumMin, len(controllers))
	}

	// Fencing d'époque (T29, §7.2-§7.3) : résout UN problème précis —
	// empêcher que deux cellules revendiquent l'autorité en même temps.
	// Avec UNE seule cellule dans TBP_CLUSTER_MEMBERS, ce conflit ne peut
	// structurellement pas se produire : rien à arbitrer entre une
	// cellule et elle-même. Mode mono-cellule (décision actée pour #86,
	// correctif de la revue #97) : pas de tracker, pas d'epoch0 à
	// importer, pas de bail à renouveler — donc rien qui expire. En
	// scale ≥ 2 cellules, le fencing s'applique sans changement : le bail
	// (10-300 s, §7.2) protège contre un split-brain réel, et son
	// renouvellement reste un chantier séparé (#97 : ne PAS allonger le
	// TTL pour compenser l'absence de renouvellement — ce serait élargir
	// la fenêtre où une autorité révoquée reste acceptée, une régression
	// de sécurité pour corriger un bug de disponibilité).
	var tracker *cluster.Tracker
	var epochs broker.EpochProvider
	if len(cfg.members) == 1 {
		epochs = broker.StaticEpoch(0)
		log.Printf("brokerd: TBP_CLUSTER_MEMBERS ne porte que %s — mode mono-cellule (issue #97), aucun bail d'époque", cfg.cellID)
	} else {
		tracker, err = cluster.NewTracker(cluster.TrackerConfig{
			CellID:      cfg.cellID,
			Salt:        cfg.salt,
			Leaves:      cellLog,
			Controllers: controllers,
			Quorum:      cfg.quorumMin,
			Members:     cfg.members,
			OnAlarm:     onTrip,
		})
		if err != nil {
			return fmt.Errorf("tracker: %w", err)
		}
		epoch0, err := os.ReadFile(filepath.Join(cfg.genesisDir, "epoch0.json"))
		if err != nil {
			return fmt.Errorf("epoch0: %w", err)
		}
		if err := tracker.Accept(ctx, epoch0); err != nil {
			return fmt.Errorf("epoch0 refusé par le tracker (la genèse ne correspond pas au manifest ?): %w", err)
		}
		epochs = tracker
	}

	// Quorum classe W (§7.5) : mêmes contrôleurs épinglés, K = M.
	quorumGate, err := cluster.NewQuorumGate(cluster.QuorumGateConfig{
		CellID:      cfg.cellID,
		Salt:        cfg.salt,
		Leaves:      cellLog,
		Controllers: controllers,
		K:           cfg.quorumMin,
		PolicyID:    cfg.policyID,
	})
	if err != nil {
		return fmt.Errorf("quorum gate: %w", err)
	}

	// Store de contrats de plan (T30) : clés d'opérateurs épinglées.
	operatorKeys, err := loadOperatorKeys(cfg.operatorKeysFile)
	if err != nil {
		return err
	}
	contracts, err := pep.NewContractStore(pep.ContractOptions{
		CellID:       cfg.cellID,
		PolicyID:     cfg.policyID,
		OperatorKeys: operatorKeys,
		Salt:         cfg.salt,
		Leaves:       cellLog,
	})
	if err != nil {
		return fmt.Errorf("contract store: %w", err)
	}

	// Enveloppe §4.1-bis : les deux briques ENSEMBLE ou pas du tout
	// (BrokerOptions le garantit déjà — ici c'est la config qui décide).
	var envelope *broker.HTTPEnvelopeEvaluator
	var envelopeLedger *broker.EnvelopeLedger
	if cfg.envelopeEndpoint != "" {
		envelopeLedger, err = broker.NewEnvelopeLedger(4096, onTrip)
		if err != nil {
			return err
		}
		envelope, err = broker.NewHTTPEnvelopeEvaluator(broker.HTTPEnvelopeOptions{
			Endpoint: cfg.envelopeEndpoint,
			OnTrip:   onTrip,
		})
		if err != nil {
			return err
		}
	}

	// Émetteur (T33) : seed Ed25519 DEV (labo/CI) OU custody HSM réelle
	// via PKCS#11 (§12, revue de sécurité #90 point 5 — la clé privée ne
	// quitte jamais le module). loadIssuer choisit selon la config validée.
	issuer, signerCloser, err := loadIssuer(cfg)
	if err != nil {
		return err
	}
	if signerCloser != nil {
		defer func() {
			if cerr := signerCloser.Close(); cerr != nil {
				log.Printf("brokerd: fermeture du signataire PKCS#11: %v", cerr)
			}
		}()
	}

	// Révision de politique servie par OPA (revue de sécurité #92, A5) :
	// vérifiée UNE FOIS ici — tout le reste de l'assemblage est déjà
	// validé à ce point — puis PÉRIODIQUEMENT en arrière-plan.
	opaRevisionWatcher.Check(ctx)
	if opaRevisionWatcher.Mismatch() {
		return fmt.Errorf("brokerd: révision OPA non vérifiée au démarrage (%s) — refus (§92.A5)", opaRevisionWatcher.Reason())
	}
	go opaRevisionWatcher.Run(ctx)

	brk, err := broker.NewBroker(broker.BrokerOptions{
		CellID:     cfg.cellID,
		Salt:       cfg.salt,
		Leaves:     cellLog,
		OPA:        opaClient,
		Translator: broker.StructuredTranslator{},
		Issuer:     issuer,
		Epochs:     epochs,
		Quorum:     quorumGate,
		Contract:   contracts,
		Envelope:   envelope,
		Ledger:     envelopeLedger,
		OnTrip:     onTrip,
	})
	if err != nil {
		return fmt.Errorf("broker: %w", err)
	}
	srv, err := broker.NewServer(broker.ServerOptions{Broker: brk})
	if err != nil {
		return err
	}

	// Mux du plan de DONNÉES (D109) : uniquement la porte d'actions du
	// serveur broker — l'agent qui atteint ce socket n'a aucune route de
	// supervision.
	dataMux := http.NewServeMux()
	dataMux.Handle("POST /v1/actions", srv.Handler())

	// Mux du plan d'ADMINISTRATION (revue de sécurité #95, finding A10) :
	// trois lectures de supervision GET-only qui sérialisent l'état public
	// des briques — aucune bibliothèque modifiée, aucune route mutante
	// ajoutée (les patterns de méthode Go 1.22 rendent 405 aux autres
	// méthodes, même doctrine que la console T34c). Socket SÉPARÉ du plan
	// de données (ci-dessous) — l'accès au socket EST le contrôle d'accès.
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /v1/supervision/stats", func(w http.ResponseWriter, _ *http.Request) {
		st, err := brk.Stats() // lecture locale — l'erreur est structurellement nil (D110)
		if err != nil {
			http.Error(w, `{"error":"source indisponible"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, newStatsView(st))
	})
	adminMux.HandleFunc("GET /v1/supervision/epoch", func(w http.ResponseWriter, _ *http.Request) {
		if tracker == nil {
			// Mode mono-cellule (issue #97) : honnête sur l'absence de
			// fencing plutôt que de simuler un epochView avec des champs
			// de bail vides ou trompeurs (not_before/expires_at n'ont
			// aucun sens sans tracker).
			writeJSON(w, http.StatusOK, monoEpochView{Mode: "mono-cellule", Epoch: 0, Authority: cfg.cellID})
			return
		}
		st, err := tracker.Status() // lecture locale — erreur structurellement nil
		if err != nil {
			http.Error(w, `{"error":"source indisponible"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, newEpochView(st))
	})
	adminMux.HandleFunc("GET /v1/supervision/arbitration", func(w http.ResponseWriter, _ *http.Request) {
		view, err := newArbitrationView(contracts)
		if err != nil {
			http.Error(w, `{"error":"source indisponible"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, view)
	})

	if err := os.MkdirAll(filepath.Dir(cfg.socketPath), 0o750); err != nil {
		return fmt.Errorf("socket dir: %w", err)
	}
	lis, err := broker.ListenUnix(cfg.socketPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.adminSocketPath), 0o750); err != nil {
		return fmt.Errorf("admin socket dir: %w", err)
	}
	adminLis, err := broker.ListenUnix(cfg.adminSocketPath)
	if err != nil {
		return fmt.Errorf("plan d'administration: %w", err)
	}
	// Transport réseau optionnel du plan de données (revue #124) — mTLS
	// exclusivement, voir net_tls.go. nil si TBP_BROKER_LISTEN_ADDR est
	// absent : le broker reste Unix-only, comportement historique.
	var netLis net.Listener
	if cfg.netListenAddr != "" {
		tlsConfig, err := buildBrokerTLSConfig(cfg.netTLSCertFile, cfg.netTLSKeyFile, cfg.netTLSClientCAFile)
		if err != nil {
			return fmt.Errorf("plan de données réseau (mTLS, revue #124): %w", err)
		}
		netLis, err = tls.Listen("tcp", cfg.netListenAddr, tlsConfig)
		if err != nil {
			return fmt.Errorf("plan de données réseau (écoute %s): %w", cfg.netListenAddr, err)
		}
	}
	httpSrv := &http.Server{Handler: dataMux, ReadHeaderTimeout: readHeaderTimeout}
	adminSrv := &http.Server{Handler: adminMux, ReadHeaderTimeout: readHeaderTimeout}
	go func() {
		<-ctx.Done()
		// Même budget d'arrêt que le serveur broker (30 s) : une requête
		// interrompue au milieu de la chaîne laisserait une feuille sans
		// jeton, ou pire un jeton sans feuille.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx) // ferme AUSSI netLis (même *http.Server)
		_ = adminSrv.Shutdown(shutdownCtx)
	}()
	epoch, authority := 0, cfg.cellID
	if tracker != nil {
		epochSt, err := tracker.Status() // lecture locale — erreur structurellement nil
		if err != nil {
			return fmt.Errorf("état d'époque au démarrage: %w", err)
		}
		epoch, authority = epochSt.Epoch, epochSt.Authority
	}
	adminErr := make(chan error, 1)
	go func() {
		adminErr <- adminSrv.Serve(adminLis)
	}()
	netErr := make(chan error, 1)
	if netLis != nil {
		go func() {
			netErr <- httpSrv.Serve(netLis)
		}()
		log.Printf("brokerd: cellule %s en écoute sur unix://%s ET mtls://%s (époque %d, autorité %s) ; administration sur unix://%s",
			cfg.cellID, cfg.socketPath, cfg.netListenAddr, epoch, authority, cfg.adminSocketPath)
	} else {
		netErr <- nil
		log.Printf("brokerd: cellule %s en écoute sur unix://%s (époque %d, autorité %s) ; administration sur unix://%s",
			cfg.cellID, cfg.socketPath, epoch, authority, cfg.adminSocketPath)
	}
	if err := httpSrv.Serve(lis); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if err := <-adminErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if err := <-netErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// — Vues JSON de supervision (contrat stable snake_case ; les types
// internes ne sont pas sérialisés directement, même doctrine que la
// console T34c) —

type statsView struct {
	Requests            uint64 `json:"requests"`
	Allows              uint64 `json:"allows"`
	Denies              uint64 `json:"denies"`
	TranslationFailures uint64 `json:"translation_failures"`
	EnvelopeEvals       uint64 `json:"envelope_evals"`
	EnvelopeDenies      uint64 `json:"envelope_denies"`
	QuorumDenies        uint64 `json:"quorum_denies"`
	PlanDenies          uint64 `json:"plan_denies"`
	IssuanceFailures    uint64 `json:"issuance_failures"`
	LeafFailures        uint64 `json:"leaf_failures"`
}

func newStatsView(st broker.BrokerStats) statsView {
	return statsView{
		Requests:            st.Requests,
		Allows:              st.Allows,
		Denies:              st.Denies,
		TranslationFailures: st.TranslationFailures,
		EnvelopeEvals:       st.EnvelopeEvals,
		EnvelopeDenies:      st.EnvelopeDenies,
		QuorumDenies:        st.QuorumDenies,
		PlanDenies:          st.PlanDenies,
		IssuanceFailures:    st.IssuanceFailures,
		LeafFailures:        st.LeafFailures,
	}
}

type epochView struct {
	Epoch             int       `json:"epoch"`
	Authority         string    `json:"authority"`
	NotBefore         time.Time `json:"not_before"`
	ExpiresAt         time.Time `json:"expires_at"`
	Quarantined       []string  `json:"quarantined"`
	AutoFailoversHour int       `json:"auto_failovers_hour"`
}

// monoEpochView est la vue rendue en mode mono-cellule (issue #97) — pas
// de bail, pas de fencing : des champs not_before/expires_at à zéro
// seraient lisibles comme « bail déjà expiré » par un lecteur de
// epochView, donc un type dédié plutôt qu'un epochView à moitié rempli.
type monoEpochView struct {
	Mode      string `json:"mode"`
	Epoch     int    `json:"epoch"`
	Authority string `json:"authority"`
}

func newEpochView(st cluster.TrackerStatus) epochView {
	quar := append([]string(nil), st.Quarantined...)
	sort.Strings(quar) // sortie déterministe (même doctrine que la console)
	return epochView{
		Epoch:             st.Epoch,
		Authority:         st.Authority,
		NotBefore:         st.NotBefore.UTC(),
		ExpiresAt:         st.ExpiresAt.UTC(),
		Quarantined:       quar,
		AutoFailoversHour: st.AutoFailoversHour,
	}
}

type pendingPlanView struct {
	Hash        string    `json:"hash"`
	SubmittedAt time.Time `json:"submitted_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Steps       int       `json:"steps"`
}

type arbitrationView struct {
	PolicyID string            `json:"policy_id"`
	Pending  []pendingPlanView `json:"pending"`
}

func newArbitrationView(contracts *pep.ContractStore) (arbitrationView, error) {
	snap, err := contracts.Snapshot() // lecture locale — erreur structurellement nil
	if err != nil {
		return arbitrationView{}, err
	}
	view := arbitrationView{
		PolicyID: hex.EncodeToString(sliceOf(contracts.PolicyID())),
		Pending:  make([]pendingPlanView, 0, len(snap)),
	}
	for _, p := range snap {
		view.Pending = append(view.Pending, pendingPlanView{
			Hash:        hex.EncodeToString(sliceOf(p.Hash)),
			SubmittedAt: p.SubmittedAt.UTC(),
			ExpiresAt:   p.ExpiresAt.UTC(),
			Steps:       p.Steps,
		})
	}
	return view, nil
}

func sliceOf(a [32]byte) []byte {
	b := make([]byte, 32)
	copy(b, a[:])
	return b
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // vues bornées par construction
}

// — Chargements fail-closed —

func envRequired(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s requis", name)
	}
	return v, nil
}

func envHex(getenv func(string) string, name string, minBytes int) ([]byte, error) {
	s, err := envRequired(getenv, name)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) < minBytes {
		return nil, fmt.Errorf("%s : hex ≥ %d octets requis", name, minBytes)
	}
	return b, nil
}

// genesisManifest est la partie lue du manifest de genèse
// (scripts/genesis — pubkeys hex, ordre = key_id à partir de 1).
type genesisManifest struct {
	PubKeys []string `json:"pubkeys"`
}

// loadGenesisControllers charge le trousseau ÉPINGLÉ des contrôleurs
// (§3.2 : distribué hors-bande à la genèse, jamais résolu dynamiquement).
func loadGenesisControllers(path string) (map[int]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest de genèse: %w", err)
	}
	var mf genesisManifest
	if err := json.Unmarshal(data, &mf); err != nil {
		return nil, fmt.Errorf("manifest de genèse JSON: %w", err)
	}
	if len(mf.PubKeys) == 0 {
		return nil, errors.New("manifest de genèse sans clé de contrôleur (§3.2)")
	}
	controllers := make(map[int]ed25519.PublicKey, len(mf.PubKeys))
	for i, pubHex := range mf.PubKeys {
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("manifest: clé contrôleur %d illisible (Ed25519 hex)", i+1)
		}
		controllers[i+1] = ed25519.PublicKey(pub) // key_id 1-basé (genèse)
	}
	return controllers, nil
}

// loadOperatorKeys charge le trousseau d'opérateurs du store de contrats
// (T30) : JSON ["pubkey_ed25519_hex", …], ≥ 1, sans doublon.
func loadOperatorKeys(path string) ([]ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clés d'opérateurs: %w", err)
	}
	var raw []string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("clés d'opérateurs JSON: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("clés d'opérateurs : liste vide — le store de contrats exige ≥ 1 opérateur (T30)")
	}
	seen := map[string]bool{}
	keys := make([]ed25519.PublicKey, 0, len(raw))
	for _, pubHex := range raw {
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("clé d'opérateur %q illisible (Ed25519 hex)", pubHex)
		}
		if seen[pubHex] {
			return nil, fmt.Errorf("clé d'opérateur %q en double", pubHex)
		}
		seen[pubHex] = true
		keys = append(keys, ed25519.PublicKey(pub))
	}
	return keys, nil
}

// loadIssuer construit l'émetteur — EXACTEMENT un des deux mécanismes de
// custody (§12, loadConfig les a déjà rendus mutuellement exclusifs) :
// seed de dev (labo/CI) ou HSM réel via PKCS#11 (revue de sécurité #90,
// point 5). Rend aussi le Closer du signataire (non nil UNIQUEMENT pour
// PKCS#11 — la session doit être fermée à l'arrêt du démon) ; le
// signataire lui-même n'est JAMAIS retourné directement : Issuer est le
// seul point qui le consomme (§12 : la clé ne doit transiter que par la
// couture Signer, jamais être manipulée ailleurs).
func loadIssuer(cfg *config) (*broker.Issuer, io.Closer, error) {
	if cfg.issuerSeedFile != "" {
		signer, err := loadDevSigner(cfg.issuerSeedFile)
		if err != nil {
			return nil, nil, err
		}
		issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: cfg.cellID, Signer: signer, PolicyID: cfg.policyID})
		return issuer, nil, err
	}
	signer, err := loadPKCS11Signer(cfg)
	if err != nil {
		return nil, nil, err
	}
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: cfg.cellID, Signer: signer, PolicyID: cfg.policyID})
	if err != nil {
		_ = signer.Close()
		return nil, nil, err
	}
	return issuer, signer, nil
}

// loadDevSigner charge la seed de dev (custody §12 — DEV/labo P1
// UNIQUEMENT). Le fichier est vérifié 0600 : une seed lisible par
// d'autres que le démon est une faute de custody, pas un réglage.
func loadDevSigner(seedFile string) (*broker.DevSigner, error) {
	st, err := os.Stat(seedFile)
	if err != nil {
		return nil, fmt.Errorf("seed émetteur: %w", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		return nil, fmt.Errorf("seed émetteur: permissions %04o — 0600 exigé (custody §12)", perm)
	}
	data, err := os.ReadFile(seedFile)
	if err != nil {
		return nil, fmt.Errorf("seed émetteur: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed émetteur: hex %d octets requis (Ed25519)", ed25519.SeedSize)
	}
	return broker.NewDevSigner(seed)
}

// loadPKCS11Signer charge le PIN (fichier 0600, même exigence de custody
// que la seed de dev) et ouvre le signataire HSM (revue de sécurité #90,
// point 5) : la clé privée d'émission ne quitte jamais le module.
//
// Durcissement du PIN (revue de sécurité #114) : le fichier 0600 protège
// contre une lecture par un autre utilisateur du système, mais reste un
// SECRET EN CLAIR sur disque — ni scellé, ni dérivé, ni lu depuis un canal
// plus restreint que le reste de la configuration. Honnêteté d'intégration
// (même doctrine que le commentaire d'en-tête de proxy.go) : effacer le
// tampon `data` ci-dessous après usage réduit la durée de vie de la copie
// BRUTE lue du fichier, mais ne protège PAS la chaîne Go `pin` elle-même
// (les chaînes Go sont immuables — impossible de l'effacer une fois créée
// sans `unsafe`, que ce fichier n'utilise pas). Une déploiement réel
// devrait préférer, quand le HSM/l'environnement le permet : un chemin
// d'authentification protégé PKCS#11 (pavé PIN physique, CKF_PROTECTED_
// AUTHENTICATION_PATH, aucun secret ne transite par ce process), ou à
// défaut un identifiant de créance géré par le superviseur de service
// (p. ex. `LoadCredential=` systemd, un tmpfs dédié effacé à l'arrêt)
// plutôt qu'un fichier persistant sur disque comme ici.
func loadPKCS11Signer(cfg *config) (*broker.PKCS11Signer, error) {
	st, err := os.Stat(cfg.issuerPKCS11PINFile)
	if err != nil {
		return nil, fmt.Errorf("PIN PKCS#11: %w", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		return nil, fmt.Errorf("PIN PKCS#11: permissions %04o — 0600 exigé (custody §12)", perm)
	}
	data, err := os.ReadFile(cfg.issuerPKCS11PINFile)
	if err != nil {
		return nil, fmt.Errorf("PIN PKCS#11: %w", err)
	}
	pin := strings.TrimSpace(string(data))
	for i := range data {
		data[i] = 0
	}
	if pin == "" {
		return nil, errors.New("PIN PKCS#11: fichier vide")
	}
	return broker.NewPKCS11Signer(broker.PKCS11SignerOptions{
		ModulePath: cfg.issuerPKCS11Module,
		TokenLabel: cfg.issuerPKCS11Token,
		KeyLabel:   cfg.issuerPKCS11KeyLabel,
		PIN:        pin,
	})
}

// loadOrGenerateCellKey charge la clef note du CellLog (T3) ou la génère
// au premier démarrage : clef signante 0600 (registry.SaveSignerKey), clef
// de vérification en clair à côté. Toute incohérence (clef présente mais
// illisible) est fatale — fail-closed (§1). Même motif que pepd (T15) :
// duplication d'assemblage assumée plutôt qu'un package partagé pour 40
// lignes.
func loadOrGenerateCellKey(dir, cellID string) (note.Signer, string, error) {
	vkeyPath := filepath.Join(dir, "cell_log.vkey")
	signer, err := registry.LoadSigner(dir)
	if err == nil {
		vkeyB, rerr := os.ReadFile(vkeyPath)
		if rerr != nil {
			return nil, "", fmt.Errorf("clef de vérification illisible: %w", rerr)
		}
		return signer, string(vkeyB), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	skey, vkey, gerr := registry.GenerateCellKey(cellID)
	if gerr != nil {
		return nil, "", gerr
	}
	if serr := registry.SaveSignerKey(dir, skey); serr != nil {
		return nil, "", serr
	}
	if werr := os.WriteFile(vkeyPath, []byte(vkey), 0o644); werr != nil {
		return nil, "", werr
	}
	ns, nerr := note.NewSigner(skey)
	if nerr != nil {
		return nil, "", nerr
	}
	return ns, vkey, nil
}
