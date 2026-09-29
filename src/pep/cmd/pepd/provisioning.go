package main

// provisioning.go — mesure des fichiers de provisionnement de pepd (issue #192).
//
// pepd épingle deux trousseaux qui sont des racines de confiance : celui des
// ÉMETTEURS de jetons (TBP_KEYRING_FILE) et celui des CONTRÔLEURS du quorum
// (TBP_QUORUM_KEYRING_FILE). Y ajouter une clé suffit à forger des jetons ou à
// basculer la posture — sans alarme, le démarrage mesuré (T31) ne les couvrant pas.
// Même brique que brokerd (registry.ProvisioningGuard) : la liste est dérivée de la
// configuration, un changement délibéré exige une preuve de quorum (k = TBP_QUORUM_MIN :
// 1 à l'échelle 1), la désactivation est une échappatoire dev sous sentinelle (#113).
//
// pepd et brokerd ont chacun leur témoin (TBP_PROVISIONING_WITNESS_FILE distinct) et
// leur condition de preuve : la preuve d'un démon ne vaut jamais pour l'autre.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"

	"golang.org/x/mod/sumdb/note"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const conditionProvisioningTransition = "provisioning-transition-pepd"

// provisioningInputs regroupe ce que setupProvisioning lit de la configuration.
type provisioningInputs struct {
	cellID, regDir                 string
	salt                           []byte
	keyringFile, quorumKeyringFile string
	quorumKeyring                  map[[16]byte]ed25519.PublicKey
	quorumMin                      int
}

// setupProvisioning est appelé juste après l'ouverture du journal de pepd, AVANT le
// démarrage mesuré (dont la genèse écrit des feuilles : la taille du journal sert ici à
// reconnaître un premier démarrage). Toute erreur est fatale.
func setupProvisioning(ctx context.Context, in provisioningInputs, signer note.Signer, verifier note.Verifier, cellLog *registry.CellLog, getenv func(string) string) error {
	if getenv("TBP_PROVISIONING_DISABLED_DEV_UNSAFE") == "1" {
		if getenv("TBP_PROVISIONING_WITNESS_FILE") != "" {
			return errors.New("TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1 et TBP_PROVISIONING_WITNESS_FILE sont contradictoires (issue #192) — un seul des deux")
		}
		log.Printf("pepd: mesure du provisionnement désactivée EXPLICITEMENT (TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1, issue #192) — DEV/LABO UNIQUEMENT, jamais en production : un trousseau d'émetteurs ou de contrôleurs modifié hors-bande passe sans alarme")
		return nil
	}
	witness := getenv("TBP_PROVISIONING_WITNESS_FILE")
	if witness == "" {
		return errors.New("TBP_PROVISIONING_WITNESS_FILE requis (issue #192 : les trousseaux épinglés sont mesurés au démarrage) — ou déclarer EXPLICITEMENT TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1 (dev/labo uniquement, jamais en production)")
	}
	extra, err := registry.ParseProvisioningExtra(getenv("TBP_PROVISIONING_EXTRA_FILES"))
	if err != nil {
		return fmt.Errorf("TBP_PROVISIONING_EXTRA_FILES : %w", err)
	}
	files := append([]registry.ProvisioningFile{
		{Name: "issuer-keyring", Path: in.keyringFile},
		{Name: "quorum-keyring", Path: in.quorumKeyringFile},
	}, extra...)

	var authorize func() error
	if proof := getenv("TBP_PROVISIONING_TRANSITION_PROOF_FILE"); proof != "" {
		authorize = func() error {
			return pep.VerifyQuorumProofFile(proof, conditionProvisioningTransition, in.cellID, in.quorumKeyring, in.quorumMin)
		}
	}
	g, err := registry.NewProvisioningGuard(registry.ProvisioningGuardOptions{
		CellID: in.cellID, Component: "pepd", Files: files,
		WitnessFile: witness, RegistryDir: in.regDir,
		Signer: signer, Verifier: verifier,
		Leaves: cellLog, Log: cellLog, Salt: in.salt,
		AuthorizeTransition: authorize,
		OnTrip:              func(reason string) { log.Printf("pepd: ALARME provisionnement: %s", reason) },
	})
	if err != nil {
		return err
	}
	if err := g.Check(ctx); err != nil {
		return err
	}
	log.Printf("pepd: provisionnement conforme au témoin (%s) — %d fichiers de confiance mesurés (issue #192)", witness, len(files))
	return nil
}
