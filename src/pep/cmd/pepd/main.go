// pepd est le démon PEP (T15) : le process en écoute sur le port local
// que suppose la redirection nftables (config/nftables/pep-redirect.nft,
// PEP_PORT=8443). Il assemble la pile complète de la cellule :
//
//	CellLog (T7, checkpoints Ed25519) → [Measured boot (T31, §6.3), avant
//	le service — issue #96] → FailClosed (T14, point unique) →
//	Validator (T9, gate étape 0) → AntiReplay (T10) → QuotaLedger (T12) →
//	ClockWatchdog (T13) → [OPA (T11)] → ModeController (T15, monitor
//	d'abord §5.3) → Listener HTTP (T15) → feuilles au CellLog.
//	[Proxy bloquant (T15, revue de sécurité #94), optionnel] — reçoit le
//	vrai trafic et ne transmet au backend QUE sur un verdict appliqué.
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
//	TBP_LISTEN_ADDR    défaut ":8443" (le PEP_PORT de la règle nftables) —
//	                   plan de DONNÉES uniquement (§5.3, revue #95) :
//	                   /v1/evaluate, /v1/passport/consume
//	TBP_ADMIN_SOCKET   optionnel — socket Unix du plan d'ADMINISTRATION
//	                   (revue de sécurité #95, finding A10) : /v1/mode,
//	                   /healthz. Défaut /run/tbp/pepd-admin.sock, permissions
//	                   0660 (même doctrine que le socket brokerd : l'accès
//	                   au socket EST le contrôle d'accès). JAMAIS sur le
//	                   canal TCP de l'agent.
//	TBP_OPA_ENDPOINT   sidecar OPA (T11) consulté après validation — REQUIS
//	                   (revue de sécurité #92, A2 : l'arbitrage OPA est
//	                   obligatoire) sauf TBP_OPA_DISABLED_DEV_UNSAFE=1
//	                   déclaré EXPLICITEMENT (dev/lab uniquement, jamais
//	                   en production)
//	TBP_OPA_SOCKET     chemin du socket Unix d'OPA — REQUIS avec
//	                   TBP_OPA_EXPECTED_UID (§92.A3 : transport authentifié
//	                   par SO_PEERCRED, un OPA en TCP non authentifié est
//	                   indétectable d'un imposteur) sauf
//	                   TBP_OPA_INSECURE_TCP_DEV=1 déclaré EXPLICITEMENT
//	TBP_OPA_EXPECTED_UID  UID attendu du processus OPA, requis avec
//	                   TBP_OPA_SOCKET — vérifié à CHAQUE connexion par le
//	                   noyau (SO_PEERCRED), jamais déclaré par le pair
//	TBP_OPA_INSECURE_TCP_DEV  exempte EXPLICITEMENT du transport Unix
//	                   authentifié (§92.A3) — dev/lab uniquement, jamais
//	                   en production : un imposteur sur le port TCP d'OPA
//	                   devient indétectable
//	TBP_OPA_REVISION_CHECK_INTERVAL_MS  optionnel — période de vérification
//	                   périodique que la révision RÉELLEMENT servie par
//	                   OPA correspond à TBP_POLICY_ID épinglé (§92.A5,
//	                   spec §10.3). Défaut 10000 (10 s) ; vérifiée aussi
//	                   UNE FOIS, de façon SYNCHRONE, avant que la cellule
//	                   ne serve — un écart y refuse le démarrage
//	TBP_OPA_DISABLED_DEV_UNSAFE  désactive OPA EXPLICITEMENT (§92.A2) —
//	                   dev/lab uniquement, jamais en production : aucun
//	                   arbitrage de règles, mutuellement exclusif avec
//	                   TBP_OPA_ENDPOINT
//	TBP_QUORUM_MIN     signatures Ed25519 DISTINCTES exigées pour les actes
//	                   gouvernés (bascule de posture, levée classe W) —
//	                   défaut 2. Vérifié cryptographiquement contre
//	                   TBP_QUORUM_KEYRING_FILE (revue de sécurité #89 :
//	                   l'ancien vérifieur comptait des identités déclarées
//	                   sans aucune signature).
//	TBP_QUORUM_KEYRING_FILE  trousseau de contrôleurs épinglé (§12) pour la
//	                   preuve de quorum : JSON {"kid_hex": "pubkey_ed25519_hex"},
//	                   même format que TBP_KEYRING_FILE. Requis (fail-closed :
//	                   sans lui, AUCUNE bascule de posture n'est possible).
//	TBP_CELL_BROKER_SOCKET  optionnel — socket Unix du brokerd co-localisé
//	                   (deploy/apercu.md : même rôle « Cell »), lu en direct
//	                   pour l'époque VÉRIFIÉE (§7.2-§7.3, revue #90 point 2).
//	                   Absent ⇒ FixedEpoch(0), choix EXPLICITE du scale 1
//	                   (cellule unique, aucun fencing) — jamais un défaut
//	                   silencieux.
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
//	Measured boot (T31, §6.3 — revue de sécurité #96) — ACTIF PAR DÉFAUT
//	depuis la revue de sécurité #112 (issue #86) : TPM/HSM réel non
//	tranché (issue #32), mais l'ABSENCE de toute mesure n'est plus un
//	défaut silencieux :
//	TBP_MEASURED_BOOT_MANIFEST_FILE  requis, sauf
//	                   TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1 déclaré
//	                   EXPLICITEMENT (dev/lab uniquement, jamais en
//	                   production, revue #112 — même doctrine que
//	                   TBP_OPA_DISABLED_DEV_UNSAFE). Présent ⇒ les six
//	                   variables suivantes deviennent requises ensemble.
//	                   Fichier du dernier manifeste publié (créé au
//	                   premier démarrage — genèse TOFU). DOIT résider
//	                   HORS de TBP_REGISTRY_DIR (vérifié au démarrage,
//	                   issue #111) : sous TBP_REGISTRY_DIR, effacer le
//	                   registre effacerait aussi ce témoin indépendant de
//	                   redémarrage avec lui.
//	TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE  désactive measured boot
//	                   EXPLICITEMENT (revue #112) — dev/lab uniquement,
//	                   jamais en production : aucune protection contre un
//	                   binaire/config/bundle altéré au démarrage.
//	TBP_MEASURED_BOOT_ROOT_FILE      fichier hex(64) de la racine mesurée —
//	                   stand-in DEV/TEST UNIQUEMENT (registry.FileRootMeasurer),
//	                   jamais en gouvernance réelle.
//	TBP_MEASURED_BOOT_EXPECTED_ROOT  racine de référence, hex 64 caractères.
//	TBP_MEASURED_BOOT_POLICY_BUNDLE, _OPA_CONFIG, _BROKER_BINARY,
//	TBP_MEASURED_BOOT_AI_CONTAINER   chemins des quatre artefacts mesurés
//	                   (§6.3) — un écart avec le manifeste engagé refuse le
//	                   démarrage, trace une feuille, alarme (T14).
//	TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE  fichier de preuve de quorum
//	                   (revue #112 — remplace l'ancien drapeau
//	                   TBP_MEASURED_BOOT_TRANSITION=1, sans quorum) : k
//	                   signatures Ed25519 distinctes du MÊME trousseau de
//	                   contrôleurs que POST /v1/mode (TBP_QUORUM_KEYRING_FILE,
//	                   §89/§105), déclarant un changement de composant
//	                   DÉLIBÉRÉ pour CE démarrage — engage une nouvelle
//	                   référence au lieu de vérifier contre l'ancienne.
//	                   Jamais automatique, jamais sur la seule foi d'un
//	                   drapeau texte.
//	TBP_PROXY_ADDR     optionnel (revue de sécurité #94, finding A6) —
//	                   adresse d'écoute du proxy BLOQUANT : contrairement
//	                   à TBP_LISTEN_ADDR (API de verdicts, l'appelant doit
//	                   interroger PUIS respecter la réponse), ce port REÇOIT
//	                   le vrai trafic et ne transmet au backend QUE sur un
//	                   verdict appliqué favorable — le blocage devient
//	                   structurel. Absent ⇒ proxy désactivé, pepd reste une
//	                   API de verdicts pure (comportement historique).
//	TBP_PROXY_BACKEND  requis avec TBP_PROXY_ADDR — URL http(s) absolue du
//	                   service RÉEL en amont.
//
// Doctrine §5.3 : le démon démarre en mode monitor au PREMIER déploiement
// (jamais closed). Revue de sécurité #93 (attaque par rétrogradation) : à
// tout REDÉMARRAGE (clé de registre déjà présente), le démon démarre en
// posture REFUSÉE — refus total de tout trafic, même un allow — jusqu'à
// ce qu'un quorum reconfirme EXPLICITEMENT une posture (monitor ou
// closed) via POST /v1/mode. Un process qui revient de crash ne "se
// réveille" donc plus jamais dans la posture qu'il avait avant, ni en
// monitor par défaut silencieux : la reconfirmation est elle-même un
// acte gouverné, tracé au registre comme toute bascule.
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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	devmode "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devmode"
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
		return fmt.Errorf("TBP_KEYRING_FILE: %w", err)
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
	quorumKeyring, err := loadKeyring(os.Getenv("TBP_QUORUM_KEYRING_FILE"))
	if err != nil {
		return fmt.Errorf("TBP_QUORUM_KEYRING_FILE: %w", err)
	}
	durabilityAsync, durabilityWindow, err := durabilityFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	if err := checkDevEscapeHatches(os.Getenv, os.Stat); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Registre de la cellule (T7) : checkpoints signés Ed25519 ; la clé
	// note est créée au premier démarrage puis rechargée (§12).
	//
	// isRestart (revue de sécurité #93) DOIT être établi AVANT
	// loadOrGenerateCellKey, qui CRÉE le fichier au premier démarrage —
	// sa présence à cet instant précis distingue le premier déploiement
	// (absent) d'un redémarrage (déjà présent), le signal que
	// ModeController.StartRefused exige pour refuser tout trafic tant
	// qu'un quorum n'a pas reconfirmé explicitement une posture.
	if err := os.MkdirAll(regDir, 0o700); err != nil {
		return fmt.Errorf("registry dir: %w", err)
	}
	isRestart, err := detectRestart(regDir, os.Getenv("TBP_MEASURED_BOOT_MANIFEST_FILE"))
	if err != nil {
		return err
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

	// Measured boot (T31, issue #32) — revue de sécurité #96 : AVANT
	// d'ouvrir le service de la cellule (point d'intégration documenté,
	// src/registry/README.md). Actif PAR DÉFAUT depuis la revue de
	// sécurité #112 (issue #86) — voir measured_boot.go : l'ancien défaut
	// « désactivé » laissait passer un binaire/config/bundle altéré au
	// démarrage sans qu'aucun opérateur n'ait rien décidé explicitement.
	if err := setupMeasuredBoot(ctx, cellID, salt, signer, verifier, cellLog, quorumKeyring, quorumMin, os.Getenv); err != nil {
		return err
	}

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

	// Antirejeu PERSISTANT de la preuve de quorum (revue de sécurité #105) :
	// même frontière de custody que cell_log.key — le plancher de
	// fraîcheur par condition doit survivre à un redémarrage, sinon une
	// ancienne preuve « monitor » capturée une fois reste rejouable après
	// un simple kill/redémarrage, annulant #93.
	quorumState := pep.NewFileQuorumStateStore(filepath.Join(regDir, "quorum_state.json"))

	// Point unique fail-closed (T14) — tous les détecteurs y basculent.
	failClosed, err := pep.NewFailClosed(pep.FailClosedOptions{
		CellID:      cellID,
		Salt:        salt,
		Leaves:      cellLog,
		QuorumState: quorumState,
		OnAlarm:     func(name string) { log.Printf("pepd: ALARME fail-closed: %s", name) },
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

	// Source d'époque (§7.2 — revue de sécurité #90, point 2) : jamais la
	// requête (le champ a été retiré du protocole). TBP_CELL_BROKER_SOCKET
	// absent ⇒ FixedEpoch(0), choix EXPLICITE du scale 1 (cellule unique,
	// aucun fencing possible, donc rien à révoquer). Présent ⇒ lecture live
	// de l'époque VÉRIFIÉE par le tracker de la cellule via le brokerd
	// co-localisé (scale 3, §7.3), jamais un cache qui fige une demi-vérité.
	var epochs pep.EpochSource = pep.FixedEpoch(0)
	if sock := os.Getenv("TBP_CELL_BROKER_SOCKET"); sock != "" {
		src := newBrokerEpochSource(sock, nil)
		probeCtx, cancel := context.WithTimeout(ctx, epochSourceHTTPTimeout)
		err := src.Probe(probeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("source d'époque (TBP_CELL_BROKER_SOCKET=%s) injoignable au démarrage: %w", sock, err)
		}
		go src.Run(ctx)
		epochs = src
		log.Printf("pepd: époque lue en direct de brokerd sur unix://%s (scale 3, §7.3)", sock)
	} else {
		log.Printf("pepd: époque fixée à 0 (TBP_CELL_BROKER_SOCKET absent — scale 1, cellule unique, aucun fencing)")
	}

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
		Epochs:     epochs,
	})
	if err != nil {
		return err
	}
	// Arbitrage OPA (T11) durci — revue de sécurité #92 : obligatoire
	// (A2), transport authentifié par SO_PEERCRED (A3), révision vérifiée
	// au démarrage puis périodiquement (A5). Voir opa_setup.go.
	opa, err := setupOPA(ctx, cellID, salt, policy, cellLog, failClosed.OnTrip(), os.Getenv)
	if err != nil {
		return err
	}
	opaClient := opa.client
	if opa.watcher != nil {
		go opa.watcher.Run(ctx)
	}

	// Posture (§5.3) : TOUJOURS monitor au démarrage ; bascules gouvernées
	// par quorum CRYPTOGRAPHIQUE — k signatures Ed25519 distinctes d'un
	// trousseau de contrôleurs épinglé (§12), jamais un comptage
	// d'identités déclarées par l'appelant (revue de sécurité #89 : sous
	// l'ancien vérifieur, quiconque joignait le port de données pouvait
	// couper l'application des règles en inventant des noms).
	quorum, err := pep.NewSignatureQuorumVerifier(cellID, quorumKeyring, quorumMin, pep.DefaultQuorumProofTTL, nil)
	if err != nil {
		return fmt.Errorf("quorum: %w", err)
	}
	mode, err := pep.NewModeController(pep.ModeOptions{
		CellID:       cellID,
		Salt:         salt,
		Leaves:       cellLog,
		OnAlarm:      func(name string) { log.Printf("pepd: ALARME posture: %s", name) },
		VerifyQuorum: quorum,
		QuorumState:  quorumState,
		StartRefused: isRestart, // revue de sécurité #93 : jamais au premier déploiement
	})
	if err != nil {
		return err
	}
	if isRestart {
		log.Printf("pepd: redémarrage détecté — posture REFUSÉE (§93) jusqu'à reconfirmation explicite par quorum via POST /v1/mode")
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

	// Plan de données (agent gouverné) : /v1/evaluate, /v1/passport/consume
	// — TCP, redirigé par nftables (PEP_PORT, config/nftables/pep-redirect.nft).
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           listener.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	// Plan d'ADMINISTRATION (revue de sécurité #95, finding A10) :
	// /v1/mode (bascule de posture) et /healthz — socket Unix SÉPARÉ,
	// jamais sur le canal de l'agent. Doctrine déjà établie pour la
	// console de supervision (T34c) : l'accès au socket EST le contrôle
	// d'accès.
	adminSocket := os.Getenv("TBP_ADMIN_SOCKET")
	if adminSocket == "" {
		adminSocket = defaultAdminSocket
	}
	adminLis, err := listenUnix(adminSocket)
	if err != nil {
		return fmt.Errorf("plan d'administration: %w", err)
	}
	adminSrv := &http.Server{
		Handler:           listener.AdminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Proxy bloquant (revue de sécurité #94) : OPTIONNEL — désactivé sauf
	// déclaration explicite de TBP_PROXY_ADDR+TBP_PROXY_BACKEND. Sans lui,
	// pepd reste ce qu'il a toujours été : une API de verdicts (§4.1,
	// honnêteté d'intégration documentée dans listener.go) — le blocage
	// reste alors l'affaire de l'appelant (ou d'un hook par type de
	// ressource, comme l'extension PostgreSQL). Avec lui, pepd REÇOIT le
	// vrai trafic (c'est lui que nftables redirige) et ne transmet au
	// backend QUE sur un verdict appliqué favorable — le blocage devient
	// structurel.
	var proxySrv *http.Server
	if proxyAddr := os.Getenv("TBP_PROXY_ADDR"); proxyAddr != "" {
		backendRaw, err := envRequired("TBP_PROXY_BACKEND")
		if err != nil {
			return fmt.Errorf("TBP_PROXY_ADDR requiert TBP_PROXY_BACKEND (§94): %w", err)
		}
		backend, err := url.Parse(backendRaw)
		if err != nil || backend.Scheme == "" || backend.Host == "" {
			return fmt.Errorf("pepd: TBP_PROXY_BACKEND invalide %q (URL http(s) absolue requise)", backendRaw)
		}
		proxy, err := pep.NewBlockingProxy(pep.ProxyOptions{Listener: listener, Backend: backend})
		if err != nil {
			return fmt.Errorf("pepd: proxy bloquant (§94): %w", err)
		}
		proxySrv = &http.Server{
			Addr:              proxyAddr,
			Handler:           proxy,
			ReadHeaderTimeout: 5 * time.Second,
		}
		log.Printf("pepd: proxy bloquant (§94) en écoute sur %s → backend %s", proxyAddr, backend)
	}

	adminErr := make(chan error, 1)
	proxyErr := make(chan error, 1)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = adminSrv.Shutdown(shutdownCtx)
		if proxySrv != nil {
			_ = proxySrv.Shutdown(shutdownCtx)
		}
	}()
	go func() {
		adminErr <- adminSrv.Serve(adminLis)
	}()
	if proxySrv != nil {
		go func() { proxyErr <- proxySrv.ListenAndServe() }()
	} else {
		close(proxyErr)
	}
	log.Printf("pepd: cellule %s en écoute sur %s (mode monitor — §5.3) ; administration sur unix://%s", cellID, listenAddr, adminSocket)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if err := <-adminErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if err := <-proxyErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// defaultAdminSocket est le chemin par défaut du plan d'administration
// (revue de sécurité #95) quand TBP_ADMIN_SOCKET n'est pas fourni.
const defaultAdminSocket = "/run/tbp/pepd-admin.sock"

// listenUnix ouvre le socket Unix du plan d'administration : permissions
// 0660 (même doctrine que broker.ListenUnix — l'accès au socket EST le
// contrôle d'accès). Duplication d'assemblage assumée plutôt qu'un
// package partagé pour ces ~15 lignes (précédent déjà posé par
// loadOrGenerateCellKey, dupliqué entre pepd et brokerd).
func listenUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("pepd: chemin de socket d'administration vide refusé")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("pepd: suppression du socket résiduel : %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("pepd: répertoire du socket d'administration : %w", err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("pepd: écoute unix %s : %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("pepd: permissions du socket d'administration : %w", err)
	}
	return lis, nil
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

// checkDevEscapeHatches ferme la revue de sécurité #113 : TBP_OPA_DISABLED_DEV_UNSAFE
// et TBP_OPA_INSECURE_TCP_DEV (tous deux réévalués plus loin par setupOPA)
// ne dépendaient QUE d'une variable du MÊME fichier d'environnement que
// celui qu'ils contournent — quiconque peut écrire ce fichier pouvait donc,
// seul, désarmer silencieusement OPA. devmode.RequireDeclared exige un
// second signal INDÉPENDANT (sentinel de fichier à chemin fixe, jamais lu
// depuis l'environnement) et trace une ALARME haute priorité si les deux
// sont réunis — jamais un simple log discret.
func checkDevEscapeHatches(getenv func(string) string, stat func(string) (os.FileInfo, error)) error {
	var active []string
	if getenv("TBP_OPA_DISABLED_DEV_UNSAFE") == "1" {
		active = append(active, "TBP_OPA_DISABLED_DEV_UNSAFE")
	}
	if getenv("TBP_OPA_INSECURE_TCP_DEV") == "1" {
		active = append(active, "TBP_OPA_INSECURE_TCP_DEV")
	}
	if getenv("TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE") == "1" {
		active = append(active, "TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE")
	}
	return devmode.RequireDeclared(devmode.DefaultSentinelPath, stat, active)
}

// detectRestart établit isRestart (revue de sécurité #93) : DOIT être
// appelé AVANT loadOrGenerateCellKey, qui CRÉE cell_log.key au premier
// démarrage — sa présence à cet instant précis distingue le premier
// déploiement (absent) d'un redémarrage (déjà présent), le signal que
// ModeController.StartRefused exige pour refuser tout trafic tant qu'un
// quorum n'a pas reconfirmé explicitement une posture.
//
// Revue de sécurité post-#86 (issue #111) : effacer ou déplacer
// TBP_REGISTRY_DIR fait disparaître cell_log.key avec lui — un attaquant
// (ou une erreur d'exploitation) qui contrôle CE répertoire rétrograde
// ainsi silencieusement un redémarrage en « premier déploiement » (§93
// contourné), ET détruit au passage la preuve locale que ce contournement
// a eu lieu. Le manifeste measured boot (measured_boot.go, désormais actif
// par défaut — revue #112) vit à un chemin INDÉPENDANT
// (measuredBootManifestFile) : sa seule EXISTENCE, même quand
// cell_log.key a disparu, est un second témoin de redémarrage que le même
// effacement du registre ne touche pas — à condition qu'il ne soit pas
// LUI-MÊME sous regDir, ce qui annulerait entièrement la protection
// (vérifié ci-dessous).
func detectRestart(regDir, measuredBootManifestFile string) (bool, error) {
	isRestart := false
	if _, statErr := os.Stat(filepath.Join(regDir, "cell_log.key")); statErr == nil {
		isRestart = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("pepd: détection redémarrage (§93): %w", statErr)
	}
	if measuredBootManifestFile == "" {
		return isRestart, nil
	}
	absReg, err := filepath.Abs(regDir)
	if err != nil {
		return false, fmt.Errorf("pepd: TBP_REGISTRY_DIR: %w", err)
	}
	absMB, err := filepath.Abs(measuredBootManifestFile)
	if err != nil {
		return false, fmt.Errorf("pepd: TBP_MEASURED_BOOT_MANIFEST_FILE: %w", err)
	}
	if rel, err := filepath.Rel(absReg, absMB); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false, fmt.Errorf("pepd: TBP_MEASURED_BOOT_MANIFEST_FILE (%s) est SOUS TBP_REGISTRY_DIR (%s) — effacer le registre effacerait aussi le témoin de redémarrage measured boot avec lui, annulant la protection du §111 ; choisissez un chemin hors de TBP_REGISTRY_DIR", measuredBootManifestFile, regDir)
	}
	if _, statErr := os.Stat(measuredBootManifestFile); statErr == nil {
		isRestart = true
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("pepd: détection redémarrage via measured boot (§111): %w", statErr)
	}
	return isRestart, nil
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
		return nil, errors.New("chemin de fichier requis")
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
