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
//
// Les RÈGLES servies (issue #313) : le bundle, la configuration de l'OPA qui le sert et
// TBP_POLICY_ID sont dans le témoin. Sans cela, à l'échelle 2 (OPA propre à la machine de brokerd,
// pas de pepd mesuré à côté), changer les règles ne laissait aucune preuve de quorum : le surveillant
// de révision (#92-A5) ne compare qu'une ÉTIQUETTE (--revision) à TBP_POLICY_ID, lui-même lu dans
// l'environnement, et une configuration OPA qui cesse de vérifier la signature n'était mesurée nulle
// part. Changer l'un des trois est une transition autorisée par k contrôleurs ATTESTÉS ; la procédure
// est celle d'une opération froide de toute la cellule (tout arrêter, changer, tout redémarrer).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
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

// Noms, dans le témoin, des entrées qui portent les règles servies (issue #313).
const (
	provisioningPolicyBundleName = "policy-bundle"
	provisioningOPAConfigName    = "opa-config"
	provisioningPolicyIDName     = "policy-id"
)

// loadProvisioningPolicyPaths lit les deux artefacts de règles que brokerd mesure (issue #313) : le bundle
// signé servi par l'OPA de brokerd et la configuration de cet OPA (le fichier de configuration, ou à défaut
// le fichier qui décrit son lancement — vérification de signature comprise). Requis dès que la mesure est
// active : un oubli ne doit pas laisser les règles hors du témoin (même doctrine que les autres fichiers).
func loadProvisioningPolicyPaths(getenv func(string) string, disabled bool) (bundle, opaConfig string, err error) {
	if disabled {
		return "", "", nil
	}
	bundle = getenv("TBP_PROVISIONING_POLICY_BUNDLE")
	opaConfig = getenv("TBP_PROVISIONING_OPA_CONFIG")
	switch {
	case bundle == "":
		return "", "", errors.New("TBP_PROVISIONING_POLICY_BUNDLE requis (issue #313 : le bundle de règles servi par l'OPA de brokerd est mesuré — un changement de règles est une transition de quorum)")
	case opaConfig == "":
		return "", "", errors.New("TBP_PROVISIONING_OPA_CONFIG requis (issue #313 : la configuration de l'OPA de brokerd est mesurée — une configuration qui cesse de vérifier la signature du bundle est une transition de quorum)")
	}
	return bundle, opaConfig, nil
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
	if cfg.mirror.enabled {
		// la racine de confiance des reçus de promotion (le fichier d'ANCRES, lui, change à chaque fenêtre et
		// porte sa propre signature de quorum, vérifiée contre le manifeste de genèse ci-dessus)
		files = append(files, registry.ProvisioningFile{Name: "mirror-cell-keys", Path: cfg.mirror.cellKeysFile})
	}
	// les RÈGLES servies (issue #313) : le bundle et la configuration de l'OPA par leur contenu, et
	// TBP_POLICY_ID, lu dans l'environnement, par sa valeur — comme quorum-settings, pour qu'il ne
	// puisse ni changer entre deux démarrages sans que la mesure le voie, ni autoriser son propre changement.
	files = append(files,
		registry.ProvisioningFile{Name: provisioningPolicyBundleName, Path: cfg.policyBundleFile},
		registry.ProvisioningFile{Name: provisioningOPAConfigName, Path: cfg.opaConfigFile},
		registry.ProvisioningFile{Name: provisioningPolicyIDName, Content: []byte(hex.EncodeToString(cfg.policyID[:]))},
	)
	// l'ÉCHELLE : k du quorum et topologie, engagés dans le témoin (issue #224) — abaisser
	// TBP_QUORUM_MIN par l'environnement diverge désormais, et ne s'autorise que par k ATTESTÉ.
	topology := "mono"
	if cfg.topology {
		topology = "multi"
	}
	files = append(files, registry.ProvisioningFile{Name: "quorum-settings", Content: pep.QuorumSettings(cfg.quorumMin, topology)})
	// la POSTURE : les interrupteurs de sécurité (arbitrage, garde du traducteur, file d'admission OPA…) — une dérive
	// diverge comme TBP_QUORUM_MIN (revue tierce, 4.6)
	files = append(files, registry.ProvisioningFile{Name: pep.ProvisioningPostureName, Content: cfg.posture})
	return append(files, cfg.provExtra...)
}

// brokerdPosture : les interrupteurs de sécurité de brokerd, dérivés de valeurs DÉJÀ validées par loadConfig (les mêmes
// que celles qui configurent le démon). Pas les réglages fins (TTL, tailles, durées).
func brokerdPosture(tuning pep.OPATuning, guard translatorGuardConfig, arb arbitrationConfig, translator string) []byte {
	p := pep.Posture{}
	p["arbitration"] = pep.OnOff(arb.enabled) // active : ouvre un chemin d'admission d'une demande dégradée sur signature d'opérateur
	p["translator-guard"] = pep.OnOff(guard.enabled)
	p["translator"] = translator
	p.OPAPosture(tuning)
	return p.Bytes()
}

// printProvisioningCondition recalcule la condition de transition à signer (#264) : même configuration
// que le démon (loadConfig), mêmes fichiers (provisioningFiles), copie du témoin ; n'écrit rien. Rend le
// code de sortie.
func printProvisioningCondition(args []string, getenv func(string) string, stat func(string) (os.FileInfo, error), stdout, stderr io.Writer) int {
	a, err := pep.ParsePrintConditionArgs(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "brokerd:", err)
		return 2
	}
	verifier, err := pep.CellVerifierFromFile(a.CellVKey)
	if err != nil {
		fmt.Fprintln(stderr, "brokerd:", err)
		return 2
	}
	cfg, err := loadConfig(getenv, stat)
	if err != nil {
		fmt.Fprintln(stderr, "brokerd:", err)
		return 2
	}
	if cfg.provDisabled {
		fmt.Fprintln(stderr, "brokerd: mesure du provisionnement désactivée (TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1) : aucune condition")
		return 2
	}
	pv, err := registry.PreviewProvisioning(provisioningFiles(cfg), cfg.provWitnessFile, cfg.cellID, "brokerd", verifier)
	if err != nil {
		fmt.Fprintln(stderr, "brokerd:", err)
		return 1
	}
	pep.WriteProvisioningPreview(stdout, conditionProvisioningTransition, "brokerd", pv)
	return 0
}

// setupProvisioning est appelé juste après l'ouverture du journal de brokerd.
// Toute erreur est fatale.
func setupProvisioning(ctx context.Context, cfg *config, cellLog *registry.CellLog, journal *registry.RecordStore, signer note.Signer, verifier note.Verifier, onTrip func(string)) error {
	if cfg.provDisabled {
		log.Printf("brokerd: mesure du provisionnement désactivée EXPLICITEMENT (TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1, issue #192) — DEV/LABO UNIQUEMENT, jamais en production : une édition hors-bande de agents.json, des clés d'opérateurs ou du registre de skills passe sans alarme")
		return nil
	}
	// Preuve vérifiée contre les contrôleurs du manifeste ATTESTÉ (octets du témoin),
	// jamais contre le manifeste courant (issue #218) ; repli TOFU sans témoin antérieur.
	// La preuve est liée à l'état de départ ET à l'état cible (issue #236) : toujours
	// une fermeture, même sans fichier de preuve, pour que le refus dise QUELLE
	// condition signer (« ce qu'on voit est ce qu'on signe »).
	manifest := filepath.Join(cfg.genesisDir, "manifest.json")
	authorize := func(prev map[string][]byte, from, to [32]byte) error {
		cond := pep.TransitionCondition(conditionProvisioningTransition, from, to)
		if cfg.provProofFile == "" {
			return fmt.Errorf("aucune preuve de transition (TBP_PROVISIONING_TRANSITION_PROOF_FILE) ; condition à signer : %s", cond)
		}
		verr := func() error {
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
			return pep.VerifyQuorumProofFile(cfg.provProofFile, cond, cfg.cellID, keyring, k)
		}()
		if verr != nil {
			return fmt.Errorf("%w ; condition à signer : %s", verr, cond)
		}
		return nil
	}
	g, err := registry.NewProvisioningGuard(registry.ProvisioningGuardOptions{
		CellID: cfg.cellID, Component: "brokerd",
		Files:       provisioningFiles(cfg),
		WitnessFile: cfg.provWitnessFile, RegistryDir: cfg.registryDir,
		Signer: signer, Verifier: verifier,
		Leaves: cellLog, Journal: journal, Log: cellLog, Salt: cfg.salt,
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
