package main

// provisioning.go — le démarrage mesuré d'anod (#272).
//
// anod décide ce qui sort de la cellule : ses règles (chemins gardés / masqués, motifs), son
// classifieur et son trousseau d'émetteurs. Les modifier entre deux démarrages — retirer un
// motif, élargir keep_paths, brancher un classifieur, ajouter un émetteur — laissait fuir des
// données qui auraient dû être masquées, sans alarme ni preuve : le démarrage mesuré de pepd et
// de brokerd (#192) ne couvrait pas anod, qui redémarre indépendamment d'eux.
//
// anod utilise la MÊME brique (registry.ProvisioningGuard) avec SON témoin et SA condition de
// preuve (« provisioning-transition-anod ») : la preuve d'un démon ne vaut jamais pour un autre.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const conditionProvisioningTransition = "provisioning-transition-anod"

func envRequiredString(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s requis", name)
	}
	return v, nil
}

// loadProvisioningConfig lit et valide la configuration du démarrage mesuré — fail-closed : aucune
// valeur par défaut, aucune échappatoire « dev » (anod n'a pas de TBP_PROVISIONING_DISABLED_DEV_UNSAFE).
func loadProvisioningConfig(getenv func(string) string, cfg *config) error {
	var err error
	if cfg.cellID, err = envRequiredString(getenv, "TBP_CELL_ID"); err != nil {
		return err
	}
	saltHex, err := envRequiredString(getenv, "TBP_SALT")
	if err != nil {
		return err
	}
	if len(saltHex) < 32 || len(saltHex)%2 != 0 {
		return errors.New("TBP_SALT : hex ≥ 32 caractères requis (§6.2)")
	}
	salt := make([]byte, len(saltHex)/2)
	for i := range salt {
		b, err := strconv.ParseUint(saltHex[2*i:2*i+2], 16, 8)
		if err != nil {
			return errors.New("TBP_SALT : hexadécimal invalide")
		}
		salt[i] = byte(b)
	}
	cfg.salt = salt
	if cfg.registryDir, err = envRequiredString(getenv, "TBP_REGISTRY_DIR"); err != nil {
		return err
	}
	if cfg.witnessFile, err = envRequiredString(getenv, "TBP_PROVISIONING_WITNESS_FILE"); err != nil {
		return fmt.Errorf("%w (#272 : les règles, le trousseau et le binaire d'anod sont mesurés au démarrage)", err)
	}
	if cfg.quorumKeyringPath, err = envRequiredString(getenv, "TBP_QUORUM_KEYRING_FILE"); err != nil {
		return err
	}
	if cfg.quorumKeyring, err = loadKeyring(cfg.quorumKeyringPath); err != nil {
		return fmt.Errorf("TBP_QUORUM_KEYRING_FILE: %w", err)
	}
	if cfg.quorumMin, err = envInt(getenv, "TBP_QUORUM_MIN", 0, 1, len(cfg.quorumKeyring)); err != nil {
		return err
	}
	if getenv("TBP_QUORUM_MIN") == "" {
		return errors.New("TBP_QUORUM_MIN requis (k : signatures distinctes d'une preuve de transition)")
	}
	cfg.proofFile = getenv("TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	cfg.extraFiles = getenv("TBP_PROVISIONING_EXTRA_FILES")
	return nil
}

// settingsContent est la forme canonique des RÉGLAGES d'anod qui décident ce qui sort : un
// classifieur ajouté, un délai ou une borne changés modifient le condensé mesuré. Le chemin du
// socket d'écoute n'y est pas (il ne change pas ce qui est masqué).
func settingsContent(cfg config) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "ano-settings=1\nclassifier-socket=%s\nclassifier-timeout-ms=%d\nresponse-grace-s=%d\nmax-exchanges=%d\nmax-entries=%d\n",
		cfg.classifierSocket, cfg.classifierTimeout/time.Millisecond, int(cfg.grace/time.Second), cfg.maxExchanges, cfg.maxEntries)
	return []byte(b.String())
}

// provisioningFiles : ce qu'anod charge, dérivé de SA configuration (jamais d'une liste que
// l'opérateur peut oublier de remplir).
func provisioningFiles(cfg config, binary string) ([]registry.ProvisioningFile, error) {
	extra, err := registry.ParseProvisioningExtra(cfg.extraFiles)
	if err != nil {
		return nil, fmt.Errorf("TBP_PROVISIONING_EXTRA_FILES : %w", err)
	}
	return append([]registry.ProvisioningFile{
		{Name: "ano-rules", Path: cfg.rulesPath},
		{Name: "issuer-keyring", Path: cfg.keyringPath},
		{Name: pep.ProvisioningQuorumKeyringName, Path: cfg.quorumKeyringPath, Authority: true},
		{Name: "anod-binary", Path: binary},
		{Name: "ano-settings", Content: settingsContent(cfg)},
		// k : changer TBP_QUORUM_MIN par l'environnement diverge du témoin, et la transition n'est
		// autorisée que par le k ATTESTÉ (#224). anod n'a pas de topologie multi-cellule.
		{Name: pep.ProvisioningQuorumSettingsName, Content: pep.QuorumSettings(cfg.quorumMin, "anod")},
	}, extra...), nil
}

// setupProvisioning mesure et atteste. Toute erreur est fatale : anod ne sert rien tant que ses
// règles ne sont pas conformes au témoin (ou qu'une transition prouvée ne les a pas engagées).
func setupProvisioning(ctx context.Context, cfg config, binary string, signer note.Signer, verifier note.Verifier, cellLog *registry.CellLog) error {
	files, err := provisioningFiles(cfg, binary)
	if err != nil {
		return err
	}
	g, err := registry.NewProvisioningGuard(registry.ProvisioningGuardOptions{
		CellID: cfg.cellID, Component: "anod", Files: files,
		WitnessFile: cfg.witnessFile, RegistryDir: cfg.registryDir,
		Signer: signer, Verifier: verifier,
		Leaves: cellLog, Log: cellLog, Salt: cfg.salt,
		AuthorizeTransition: pep.NewProvisioningAuthorizer(conditionProvisioningTransition, cfg.cellID, cfg.quorumKeyring, cfg.quorumMin, cfg.proofFile),
		OnTrip:              func(reason string) { log.Printf("anod: ALARME provisionnement: %s", reason) },
	})
	if err != nil {
		return err
	}
	if err := g.Check(ctx); err != nil {
		return err
	}
	log.Printf("anod: provisionnement conforme au témoin (%s) — %d fichiers de confiance mesurés (#272)", cfg.witnessFile, len(files))
	return nil
}

// openRegistry ouvre le journal propre à anod (clé de cellule générée au premier démarrage).
func openRegistry(ctx context.Context, cfg config) (*registry.CellLog, note.Signer, note.Verifier, error) {
	if err := os.MkdirAll(cfg.registryDir, 0o700); err != nil {
		return nil, nil, nil, fmt.Errorf("registry dir: %w", err)
	}
	signer, vkey, err := registry.LoadOrGenerateCellKey(cfg.registryDir, cfg.cellID)
	if err != nil {
		return nil, nil, nil, err
	}
	verifier, err := registry.NewVerifier(vkey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("note verifier: %w", err)
	}
	cellLog, err := registry.Open(ctx, registry.Options{Dir: cfg.registryDir, Signer: signer, Verifier: verifier})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cell log: %w", err)
	}
	return cellLog, signer, verifier, nil
}
