// pepd est le démon PEP (T15) : le process en écoute sur le port local
// que suppose la redirection nftables (config/nftables/pep-redirect.nft,
// PEP_PORT=8443). Il assemble la pile complète de la cellule :
//
//	FailClosed (T14, point unique) → Validator (T9, gate étape 0) →
//	AntiReplay (T10) → QuotaLedger (T12) → ClockWatchdog (T13) →
//	[OPA (T11)] → ModeController (T15, monitor d'abord §5.3) →
//	Listener HTTP (T15) → feuilles au CellLog (T7, checkpoints Ed25519).
//
// Configuration par variables d'environnement (toutes requises sauf
// mention contraire) :
//
//	TBP_CELL_ID        identité de la cellule (ex. tbp/registry/cell-alpha-01)
//	TBP_SALT           sel des feuilles, hex ≥ 32 caractères (§6.2 — ne
//	                   quitte JAMAIS la cellule)
//	TBP_KEYRING_FILE   JSON {"kid_hex": "pubkey_ed25519_hex"} (§12, épinglé)
//	TBP_POLICY_ID      hash de la politique locale, hex 64 (§3)
//	TBP_REGISTRY_DIR   répertoire du CellLog (la clé note y est créée au
//	                   premier démarrage, rechargée ensuite)
//	TBP_LISTEN_ADDR    défaut ":8443" (le PEP_PORT de la règle nftables)
//	TBP_OPA_ENDPOINT   optionnel — sidecar OPA (T11) consulté après validation
//	TBP_QUORUM_MIN     signatures exigées pour les actes gouvernés
//	                   (bascule de posture, levée classe W) — défaut 2.
//	                   Vérifieur PAR COMPTAGE : la crypto de quorum est une
//	                   phase ultérieure ; la couture est déjà là (T14).
//	TBP_DURABILITY     modèle de durabilité du chemin de décision (T38,
//	                   issue #71) : « async-bounded » (DÉFAUT — verdict à
//	                   l'acceptation de la feuille, fenêtre d'opposabilité
//	                   bornée, coupure fail-closed) ou « sync » (preuve
//	                   publiée avant verdict — plancher structurel ~150 ms
//	                   POSIX, hors budget §9.1, conservé pour mesure).
//	TBP_DURABILITY_WINDOW_MS  fenêtre d'opposabilité en millisecondes —
//	                   défaut 1000, plancher 4× l'intervalle de checkpoint
//	                   (sous le plancher : refus de démarrer, coupures
//	                   parasites garanties).
//
// Doctrine §5.3 : le démon démarre TOUJOURS en mode monitor — jamais
// closed au premier déploiement, ni au redémarrage. La bascule closed
// passe par POST /v1/mode, gouvernée par quorum et tracée au registre.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("pepd: %v", err)
	}
}

func run() error {
	cellID, err := envRequired("TBP_CELL_ID")
	if err != nil {
		return err
	}
	salt, err := envHex("TBP_SALT", 16)
	if err != nil {
		return err
	}
	policyID, err := envHex("TBP_POLICY_ID", 32)
	if err != nil {
		return err
	}
	var policy [32]byte
	copy(policy[:], policyID)
	keyring, err := loadKeyring(os.Getenv("TBP_KEYRING_FILE"))
	if err != nil {
		return err
	}
	regDir, err := envRequired("TBP_REGISTRY_DIR")
	if err != nil {
		return err
	}
	listenAddr := os.Getenv("TBP_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8443" // PEP_PORT de config/nftables/pep-redirect.nft
	}
	quorumMin := 2
	if s := os.Getenv("TBP_QUORUM_MIN"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return fmt.Errorf("TBP_QUORUM_MIN invalide %q", s)
		}
		quorumMin = n
	}
	durabilityAsync, durabilityWindow, err := durabilityFromEnv(os.Getenv)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Registre de la cellule (T7) : checkpoints signés Ed25519 ; la clé
	// note est créée au premier démarrage puis rechargée (§12).
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		return fmt.Errorf("registry dir: %w", err)
	}
	signer, vkey, err := loadOrGenerateCellKey(regDir, cellID)
	if err != nil {
		return err
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		return fmt.Errorf("note verifier: %w", err)
	}
	cellLog, err := registry.Open(ctx, registry.Options{
		Dir: regDir, Signer: signer, Verifier: verifier,
	})
	if err != nil {
		return fmt.Errorf("cell log: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := cellLog.Close(closeCtx); err != nil {
			log.Printf("pepd: fermeture du registre: %v", err)
		}
	}()

	// Puits de feuilles du chemin de DÉCISION (T38, issue #71) : async
	// borné par défaut — verdict à l'acceptation de la feuille, fenêtre
	// d'opposabilité bornée, coupure fail-closed (ErrDurabilityCut → deny
	// « leaf-write-failed », le chemin T9 existant) ; « sync » conserve
	// l'ancien chemin (preuve publiée avant verdict — plancher structurel
	// ~150 ms POSIX, hors budget §9.1). Les écritures ADMINISTRATIVES
	// (T5, T14, quota, horloge, posture) restent synchrones dans les deux
	// cas : rares, et leur opposabilité prime sur leur latence.
	decisionLeaves := pep.LeafSink(cellLog)
	var asyncWriter *registry.AsyncWriter
	if durabilityAsync {
		asyncWriter, err = registry.NewAsyncWriter(cellLog, registry.AsyncOptions{
			CellID: cellID,
			Salt:   salt,
			Window: durabilityWindow,
			OnTrip: func(detail string) {
				log.Printf("pepd: ALARME durabilité registre — coupure fail-closed (%s)", detail)
			},
			OnClear: func() {
				log.Printf("pepd: durabilité registre — rattrapage tracé, coupure levée")
			},
		})
		if err != nil {
			return err
		}
		// Fermé AVANT le CellLog (defer LIFO : ce defer s'exécute avant
		// celui du registre) : le tracker vide sa file, le shutdown
		// tessera publie le reste.
		defer func() {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := asyncWriter.Close(closeCtx); err != nil {
				log.Printf("pepd: fermeture du writer async: %v", err)
			}
		}()
		decisionLeaves = asyncWriter
		windowLog := durabilityWindow
		if windowLog == 0 {
			windowLog = registry.DefaultOpposabilityWindow
		}
		log.Printf("pepd: durabilité async bornée (fenêtre %v) — chemin de décision T38", windowLog)
	} else {
		log.Printf("pepd: durabilité SYNCHRONE (preuve avant verdict, plancher ~150 ms POSIX — hors §9.1, mode mesure)")
	}

	// Point unique fail-closed (T14) — tous les détecteurs y basculent.
	failClosed, err := pep.NewFailClosed(pep.FailClosedOptions{
		CellID:  cellID,
		Salt:    salt,
		Leaves:  cellLog,
		OnAlarm: func(name string) { log.Printf("pepd: ALARME fail-closed: %s", name) },
	})
	if err != nil {
		return err
	}
	for _, cond := range []struct {
		name  string
		class pep.Class
	}{
		{pep.ReasonOPATimeout, pep.ClassI},
		{pep.ReasonOPAUnreachable, pep.ClassI},
		{pep.ReasonOPAError, pep.ClassI},
		{pep.ReasonOPABadResponse, pep.ClassI},
		{pep.ReasonClockSkew, pep.ClassI},
		{pep.TripReasonJTISaturated, pep.ClassI},
		{pep.TripReasonQuotaSaturated, pep.ClassI},
		{pep.CondRegistryDiskHigh, pep.ClassI},
		{pep.CondAnchorLag, pep.ClassW},
	} {
		if err := failClosed.Register(cond.name, cond.class); err != nil {
			return err
		}
	}

	// Briques T10/T12/T13 — chaque alarme devient une bascule du point
	// unique (adaptateur OnTrip, T14).
	antiReplay, err := pep.NewAntiReplay(pep.AntiReplayOptions{
		Capacity: 65536,
		OnTrip:   failClosed.OnTrip(),
	})
	if err != nil {
		return err
	}
	ledger, err := pep.NewQuotaLedger(pep.QuotaLedgerOptions{
		MaxPassports: 4096,
		CellID:       cellID,
		Salt:         salt,
		Leaves:       cellLog,
		OnTrip:       failClosed.OnTrip(),
	})
	if err != nil {
		return err
	}
	watchdog, err := pep.NewClockWatchdog(pep.ClockOptions{
		LocalIssuer: cellID, // en dégradé : seuls les jetons locaux-signés passent
		CellID:      cellID,
		Salt:        salt,
		Leaves:      cellLog,
		OnTrip:      failClosed.OnTrip(),
	})
	if err != nil {
		return err
	}
	go watchdog.Run(ctx) // poll ntp_adjtime toutes les secondes (défaut §6.2)

	// Validateurs et arbitrage.
	validator, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:     cellID,
		Keyring:    keyring,
		PolicyID:   policy,
		Salt:       salt,
		Leaves:     decisionLeaves,
		AntiReplay: antiReplay,
		Quota:      ledger,
		Gate:       failClosed,
	})
	if err != nil {
		return err
	}
	var opaClient *pep.OPAClient
	if endpoint := os.Getenv("TBP_OPA_ENDPOINT"); endpoint != "" {
		opaClient, err = pep.NewOPAClient(pep.OPAOptions{
			Endpoint: endpoint,
			CellID:   cellID,
			Salt:     salt,
			Leaves:   cellLog,
			OnTrip:   failClosed.OnTrip(),
		})
		if err != nil {
			return err
		}
	}

	// Posture (§5.3) : TOUJOURS monitor au démarrage ; bascules gouvernées
	// par quorum (vérificateur par comptage — crypto de quorum : phase
	// ultérieure, couture déjà en place).
	quorum := func(_ string, proof pep.QuorumProof) bool {
		return len(proof.Signers) >= quorumMin
	}
	mode, err := pep.NewModeController(pep.ModeOptions{
		CellID:       cellID,
		Salt:         salt,
		Leaves:       cellLog,
		OnAlarm:      func(name string) { log.Printf("pepd: ALARME posture: %s", name) },
		VerifyQuorum: quorum,
	})
	if err != nil {
		return err
	}
	failClosed.SetQuorumVerifier(quorum)

	listener, err := pep.NewListener(pep.ListenerOptions{
		Validator: validator,
		Mode:      mode,
		Ledger:    ledger,
		OPA:       opaClient,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           listener.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("pepd: cellule %s en écoute sur %s (mode monitor — §5.3)", cellID, listenAddr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func envRequired(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s requis", name)
	}
	return v, nil
}

// durabilityFromEnv résout le modèle de durabilité du chemin de décision
// (T38, issue #71). Fail-closed : une valeur inconnue est une erreur de
// démarrage, jamais un mode par défaut silencieusement choisi — sauf
// l'absence, qui vaut « async-bounded » (l'arbitrage de l'issue).
func durabilityFromEnv(getenv func(string) string) (async bool, window time.Duration, err error) {
	switch mode := getenv("TBP_DURABILITY"); mode {
	case "", "async-bounded":
		async = true
	case "sync":
		async = false
	default:
		return false, 0, fmt.Errorf("TBP_DURABILITY invalide %q (async-bounded|sync)", mode)
	}
	window = registry.DefaultOpposabilityWindow
	if s := getenv("TBP_DURABILITY_WINDOW_MS"); s != "" {
		ms, perr := strconv.Atoi(s)
		if perr != nil || ms < 1 {
			return false, 0, fmt.Errorf("TBP_DURABILITY_WINDOW_MS invalide %q (entier ≥ 1)", s)
		}
		window = time.Duration(ms) * time.Millisecond
	}
	return async, window, nil
}

func envHex(name string, minBytes int) ([]byte, error) {
	s, err := envRequired(name)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) < minBytes {
		return nil, fmt.Errorf("%s : hex ≥ %d octets requis", name, minBytes)
	}
	return b, nil
}

// loadKeyring charge le trousseau épinglé (§12) : JSON {"kid_hex":
// "pubkey_ed25519_hex"}. Aucune résolution dynamique.
func loadKeyring(path string) (map[[16]byte]ed25519.PublicKey, error) {
	if path == "" {
		return nil, errors.New("TBP_KEYRING_FILE requis")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("keyring JSON: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("keyring vide (§12)")
	}
	keyring := make(map[[16]byte]ed25519.PublicKey, len(raw))
	for kidHex, pubHex := range raw {
		kid, err := hex.DecodeString(kidHex)
		if err != nil || len(kid) != 16 {
			return nil, fmt.Errorf("keyring: kid %q illisible (hex 16 octets)", kidHex)
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyring: clé %q illisible (Ed25519)", kidHex)
		}
		var k [16]byte
		copy(k[:], kid)
		keyring[k] = ed25519.PublicKey(pub)
	}
	return keyring, nil
}

// loadOrGenerateCellKey charge la clef note du CellLog (T3) ou la génère
// au premier démarrage : clef signante 0600 (registry.SaveSignerKey), clef
// de vérification en clair à côté pour reconstruire le Verifier. Toute
// incohérence (clef présente mais illisible) est fatale — fail-closed (§1).
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
