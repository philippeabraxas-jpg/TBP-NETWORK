package main

// provisioning.go — mesure des fichiers de provisionnement de brokerd (issue #192).
//
// brokerd lit lui-même les fichiers qui portent l'essentiel de la confiance de la
// cellule : registre d'agents (classe, quota), clés d'opérateurs (approbation de
// plans), registre de skills, manifeste de genèse (contrôleurs du quorum),
// autorité de certification des clients mTLS. Le démarrage mesuré de pepd ne mesure
// que le BINAIRE de brokerd. Ici brokerd atteste ce qu'il charge, avec la brique
// commune registry.ProvisioningGuard :
//
//   - la liste est DÉRIVÉE de sa configuration (un opérateur ne peut pas l'oublier) ;
//     TBP_PROVISIONING_EXTRA_FILES ajoute, ne remplace pas ;
//   - premier démarrage : condensé engagé dans un témoin signé (TBP_PROVISIONING_WITNESS_FILE,
//     hors de TBP_REGISTRY_DIR) ; ensuite toute divergence REFUSE le démarrage ;
//   - changement délibéré : TBP_PROVISIONING_TRANSITION_PROOF_FILE, une preuve de quorum
//     (même mécanique et même TBP_QUORUM_MIN que la classe W : k = 1 à l'échelle 1 —
//     l'administrateur seul signe —, k-of-n au-dessus). C'est LE réglage d'échelle.
//   - désactivation : TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1, dev/labo, refusée sans la
//     sentinelle /etc/tbp/DEV_ENVIRONMENT (#113).

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"path/filepath"

	"golang.org/x/mod/sumdb/note"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// conditionProvisioningTransition lie la preuve de quorum à CE démon : une preuve
// pour pepd ne vaut jamais pour brokerd, ni pour une bascule de posture.
const conditionProvisioningTransition = "provisioning-transition-brokerd"

// loadProvisioningConfig lit les variables du provisionnement. Fail-closed : sans
// témoin, refus de démarrer, sauf déclaration EXPLICITE de l'échappatoire dev.
func loadProvisioningConfig(getenv func(string) string, disabled bool) (witness, proof string, extra []registry.ProvisioningFile, err error) {
	witness = getenv("TBP_PROVISIONING_WITNESS_FILE")
	proof = getenv("TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	switch {
	case disabled && witness != "":
		return "", "", nil, errors.New("TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1 et TBP_PROVISIONING_WITNESS_FILE sont contradictoires (issue #192) — un seul des deux")
	case disabled:
		return "", "", nil, nil
	case witness == "":
		return "", "", nil, errors.New("TBP_PROVISIONING_WITNESS_FILE requis (issue #192 : les fichiers de confiance sont mesurés au démarrage) — ou déclarer EXPLICITEMENT TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1 (dev/labo uniquement, jamais en production)")
	}
	extra, err = registry.ParseProvisioningExtra(getenv("TBP_PROVISIONING_EXTRA_FILES"))
	if err != nil {
		return "", "", nil, fmt.Errorf("TBP_PROVISIONING_EXTRA_FILES : %w", err)
	}
	return witness, proof, extra, nil
}

// provisioningFiles rend la liste que brokerd charge, dérivée de sa configuration.
func provisioningFiles(cfg *config) []registry.ProvisioningFile {
	files := []registry.ProvisioningFile{
		{Name: "operator-keys", Path: cfg.operatorKeysFile},
		{Name: "agent-registry", Path: cfg.agentRegistryFile},
		{Name: "genesis-manifest", Path: filepath.Join(cfg.genesisDir, "manifest.json"), Authority: true},
	}
	if cfg.skillRegistryFile != "" {
		files = append(files, registry.ProvisioningFile{Name: "skill-registry", Path: cfg.skillRegistryFile})
	}
	if cfg.netTLSClientCAFile != "" {
		// l'autorité qui décide QUELS certificats valent identité d'agent
		files = append(files, registry.ProvisioningFile{Name: "tls-client-ca", Path: cfg.netTLSClientCAFile})
	}
	// l'ÉCHELLE : k du quorum et topologie, engagés dans le témoin (issue #224) — abaisser
	// TBP_QUORUM_MIN par l'environnement diverge désormais, et ne s'autorise que par k ATTESTÉ.
	topology := "mono"
	if cfg.topology {
		topology = "multi"
	}
	files = append(files, registry.ProvisioningFile{Name: "quorum-settings", Content: pep.QuorumSettings(cfg.quorumMin, topology)})
	return append(files, cfg.provExtra...)
}

// setupProvisioning est appelé juste après l'ouverture du journal de brokerd.
// Toute erreur est fatale.
func setupProvisioning(ctx context.Context, cfg *config, cellLog *registry.CellLog, signer note.Signer, verifier note.Verifier, onTrip func(string)) error {
	if cfg.provDisabled {
		log.Printf("brokerd: mesure du provisionnement désactivée EXPLICITEMENT (TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1, issue #192) — DEV/LABO UNIQUEMENT, jamais en production : une édition hors-bande de agents.json, des clés d'opérateurs ou du registre de skills passe sans alarme")
		return nil
	}
	// Preuve vérifiée contre les contrôleurs du manifeste ATTESTÉ (octets du témoin),
	// jamais contre le manifeste courant (issue #218) ; repli TOFU sans témoin antérieur.
	var authorize func(prev map[string][]byte) error
	if cfg.provProofFile != "" {
		path := cfg.provProofFile
		manifest := filepath.Join(cfg.genesisDir, "manifest.json")
		authorize = func(prev map[string][]byte) error {
			k := cfg.quorumMin
			if raw, ok := prev["quorum-settings"]; ok {
				attestedK, err := pep.ParseQuorumSettings(raw)
				if err != nil {
					return fmt.Errorf("réglages de quorum attestés illisibles: %w", err)
				}
				k = attestedK // k ATTESTÉ, pas celui de l'environnement (#224)
			}
			var controllers map[int]ed25519.PublicKey
			var err error
			if raw, ok := prev["genesis-manifest"]; ok {
				controllers, err = parseGenesisControllers(raw)
				if err != nil {
					return fmt.Errorf("manifeste de genèse attesté illisible: %w", err)
				}
			} else if controllers, err = loadGenesisControllers(manifest); err != nil {
				return err
			}
			keyring := make(map[[16]byte]ed25519.PublicKey, len(controllers))
			for _, pub := range controllers {
				keyring[pep.KeyIDFromPublicKey(pub)] = pub
			}
			return pep.VerifyQuorumProofFile(path, conditionProvisioningTransition, cfg.cellID, keyring, k)
		}
	}
	g, err := registry.NewProvisioningGuard(registry.ProvisioningGuardOptions{
		CellID: cfg.cellID, Component: "brokerd",
		Files:       provisioningFiles(cfg),
		WitnessFile: cfg.provWitnessFile, RegistryDir: cfg.registryDir,
		Signer: signer, Verifier: verifier,
		Leaves: cellLog, Log: cellLog, Salt: cfg.salt,
		AuthorizeTransition: authorize,
		OnTrip:              onTrip,
	})
	if err != nil {
		return err
	}
	if err := g.Check(ctx); err != nil {
		return err
	}
	log.Printf("brokerd: provisionnement conforme au témoin (%s) — %d fichiers de confiance mesurés (issue #192)", cfg.provWitnessFile, len(provisioningFiles(cfg)))
	return nil
}
