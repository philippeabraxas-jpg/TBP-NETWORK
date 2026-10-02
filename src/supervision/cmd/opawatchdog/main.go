// opawatchdog est le SUPERVISEUR qui redémarre OPA quand il est bloqué (issue #275). Le PEP signale (« opa-stalled »,
// GET /v1/supervision/opa sur les sockets d'administration de pepd et de brokerd) ; il ne redémarre jamais OPA lui-même
// (séparation des privilèges). Ce démon lit ces statuts et, si TOUTES les sources lisibles disent « stalled » pendant
// TBP_OPAWD_CONFIRM relevés consécutifs, exécute `systemctl restart <unité OPA>` — sous un utilisateur dédié, sans
// capacité, avec une règle polkit limitée à cette unité et ce verbe. Chaque redémarrage décidé est FEUILLÉ avant d'être
// exécuté, dans la chaîne propre du chien de garde (comme le moniteur de supervision, §7.1) : pas de feuille, pas de
// redémarrage. Voir watchdog.go pour la doctrine et les bornes.
//
// Configuration par variables d'environnement (doctrine §1 : une valeur illisible ou hors bornes est fatale au démarrage) :
//
//	TBP_OPAWD_CELL_ID          requis — la cellule dont OPA est redémarré (identité portée par les feuilles)
//	TBP_OPAWD_LOG_ID           requis — identité de la chaîne PROPRE du chien de garde (ex. opawd-cell-a)
//	TBP_OPAWD_REGISTRY_DIR     requis — répertoire du CellLog du chien de garde (sa chaîne, sa clé de checkpoint)
//	TBP_OPAWD_AUDIT_RECORDS    requis — journal chiffré du clair des feuilles (#275 ; `tbp-audit verify`)
//	TBP_OPAWD_AUDIT_RECORDS_KEY_FILE  requis — sa clé (0600 ; `tbp-audit keygen`)
//	TBP_OPAWD_SOURCES          requis — sockets d'administration, « nom=/chemin.sock », séparés par des virgules
//	                           (ex. pepd=/run/tbp/pepd-admin.sock,brokerd=/run/tbp/brokerd-admin.sock)
//	TBP_OPAWD_UNIT             unité OPA à redémarrer — défaut tbp-opa.service
//	TBP_OPAWD_POLL_MS          cadence des relevés — défaut 1000, [250, 30000]
//	TBP_OPAWD_CONFIRM          relevés « stalled » consécutifs avant redémarrage — défaut 3, [1, 60]
//	TBP_OPAWD_COOLDOWN_S       repos après une tentative — défaut 30, [5, 3600]
//	TBP_OPAWD_MAX_PER_HOUR     tentatives par heure glissante — défaut 3, [1, 60] ; épuisé = escalade humaine
//	TBP_OPAWD_SYSTEMCTL        chemin ABSOLU de systemctl — défaut /usr/bin/systemctl
//	TBP_OPAWD_DRY_RUN          « 1 » : journalise la décision sans redémarrer (calibrage)
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Getenv); err != nil {
		log.Fatalf("opawatchdog: %v", err)
	}
}

type config struct {
	set       Settings
	poll      time.Duration
	systemctl string

	cellID, logID, registryDir, auditRecords, auditKeyFile string
}

func run(ctx context.Context, getenv func(string) string) error {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return err
	}
	// Chaîne PROPRE du chien de garde (§7.1) : il feuille comme toute cellule, sa clé de checkpoint reste chez lui.
	if err := os.MkdirAll(cfg.registryDir, 0o700); err != nil {
		return fmt.Errorf("registry dir: %w", err)
	}
	signer, vkey, err := loadOrGenerateCellKey(cfg.registryDir, cfg.logID)
	if err != nil {
		return err
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		return fmt.Errorf("note verifier: %w", err)
	}
	wdLog, err := registry.Open(ctx, registry.Options{Dir: cfg.registryDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return fmt.Errorf("registre du chien de garde: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := wdLog.Close(closeCtx); err != nil {
			log.Printf("opawatchdog: fermeture du registre: %v", err)
		}
	}()
	// REQUIS : un chien de garde dont les redémarrages ne seraient pas vérifiables ne démarre pas.
	auditStore, err := registry.OpenRecordStoreFiles(cfg.auditRecords, cfg.auditKeyFile)
	if err != nil {
		return fmt.Errorf("journal d'audit (#275): %w", err)
	}
	defer auditStore.Close()

	w, err := NewWatchdog(cfg.set, SocketStatusFetcher(),
		SystemctlRestarter{Path: cfg.systemctl, Timeout: 30 * time.Second},
		&leafRecorder{sink: wdLog, journal: auditStore, logID: cfg.logID, cellID: cfg.cellID, now: time.Now}, nil, log.Printf)
	if err != nil {
		return err
	}
	log.Printf("opawatchdog: démarré — unité=%s sources=%d confirm=%d cooldown=%s max/heure=%d dry-run=%v",
		cfg.set.Unit, len(cfg.set.Sources), cfg.set.Confirm, cfg.set.Cooldown, cfg.set.MaxPerHour, cfg.set.DryRun)
	w.Run(ctx, cfg.poll)
	return nil
}

// leafRecorder feuille les constats du chien de garde dans sa chaîne propre (supervision.WriteAlert : journal d'abord).
type leafRecorder struct {
	sink    registry.LeafAppender
	journal *registry.RecordStore
	logID   string
	cellID  string
	now     func() time.Time
}

func (r *leafRecorder) Record(ctx context.Context, event, verdict byte, reason string, detail []byte) error {
	_, err := supervision.WriteAlert(ctx, r.sink, r.journal, r.logID, r.now(), event, r.cellID, verdict, reason, detail)
	return err
}

// loadOrGenerateCellKey : même patron que supervisord/pepd/brokerd (dupliqué volontairement — chaque démon possède sa clé).
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

func envRequired(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s requis", name)
	}
	return v, nil
}

func loadConfig(getenv func(string) string) (*config, error) {
	cellID, err := envRequired(getenv, "TBP_OPAWD_CELL_ID")
	if err != nil {
		return nil, err
	}
	logID, err := envRequired(getenv, "TBP_OPAWD_LOG_ID")
	if err != nil {
		return nil, err
	}
	registryDir, err := envRequired(getenv, "TBP_OPAWD_REGISTRY_DIR")
	if err != nil {
		return nil, err
	}
	auditRecords, err := envRequired(getenv, "TBP_OPAWD_AUDIT_RECORDS")
	if err != nil {
		return nil, fmt.Errorf("%w (#275 : un redémarrage doit rester vérifiable, tbp-audit verify)", err)
	}
	auditKeyFile, err := envRequired(getenv, "TBP_OPAWD_AUDIT_RECORDS_KEY_FILE")
	if err != nil {
		return nil, err
	}
	srcs, err := parseSources(getenv("TBP_OPAWD_SOURCES"))
	if err != nil {
		return nil, err
	}
	unit := getenv("TBP_OPAWD_UNIT")
	if unit == "" {
		unit = "tbp-opa.service"
	}
	if err := validUnit(unit); err != nil {
		return nil, fmt.Errorf("TBP_OPAWD_UNIT : %w", err)
	}
	pollMS, err := envInt(getenv, "TBP_OPAWD_POLL_MS", 1000, 250, 30000)
	if err != nil {
		return nil, err
	}
	confirm, err := envInt(getenv, "TBP_OPAWD_CONFIRM", 3, 1, 60)
	if err != nil {
		return nil, err
	}
	coolS, err := envInt(getenv, "TBP_OPAWD_COOLDOWN_S", 30, 5, 3600)
	if err != nil {
		return nil, err
	}
	maxH, err := envInt(getenv, "TBP_OPAWD_MAX_PER_HOUR", 3, 1, 60)
	if err != nil {
		return nil, err
	}
	sysctl := getenv("TBP_OPAWD_SYSTEMCTL")
	if sysctl == "" {
		sysctl = "/usr/bin/systemctl"
	}
	if !filepath.IsAbs(sysctl) {
		return nil, fmt.Errorf("TBP_OPAWD_SYSTEMCTL doit être un chemin absolu : %q", sysctl)
	}
	dry := false
	switch v := getenv("TBP_OPAWD_DRY_RUN"); v {
	case "", "0":
	case "1":
		dry = true
	default:
		return nil, fmt.Errorf("TBP_OPAWD_DRY_RUN : « 1 » ou « 0 » attendu, reçu %q", v)
	}
	return &config{
		cellID: cellID, logID: logID, registryDir: registryDir, auditRecords: auditRecords, auditKeyFile: auditKeyFile,
		set: Settings{Sources: srcs, Unit: unit, Confirm: confirm, Cooldown: time.Duration(coolS) * time.Second,
			MaxPerHour: maxH, DryRun: dry},
		poll:      time.Duration(pollMS) * time.Millisecond,
		systemctl: sysctl,
	}, nil
}

func parseSources(s string) ([]Source, error) {
	if s == "" {
		return nil, fmt.Errorf("TBP_OPAWD_SOURCES requis (nom=/chemin.sock,…)")
	}
	var out []Source
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		name, sock, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || name == "" || sock == "" {
			return nil, fmt.Errorf("TBP_OPAWD_SOURCES : « nom=/chemin.sock » attendu, reçu %q", part)
		}
		if !filepath.IsAbs(sock) || filepath.Clean(sock) != sock {
			return nil, fmt.Errorf("TBP_OPAWD_SOURCES : chemin de socket absolu et propre exigé, reçu %q", sock)
		}
		if seen[name] {
			return nil, fmt.Errorf("TBP_OPAWD_SOURCES : nom en double %q", name)
		}
		seen[name] = true
		out = append(out, Source{Name: name, Socket: sock})
	}
	return out, nil
}

func envInt(getenv func(string) string, name string, def, lo, hi int) (int, error) {
	s := getenv(name)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s invalide %q (entier dans [%d, %d] attendu)", name, s, lo, hi)
	}
	return n, nil
}
