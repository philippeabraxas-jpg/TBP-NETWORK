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
	"io"
	"log"
	"strconv"

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
	// topology : « mono » ou « multi » (TBP_TOPOLOGY) — avec quorumMin, les réglages qui font
	// l'échelle, engagés dans le témoin (issue #224).
	topology string
	// posture : les interrupteurs de sécurité engagés dans le témoin (security-posture, revue tierce 4.6).
	posture []byte
	// journal : journal d'enregistrements (#275) — le clair des feuilles de provisionnement.
	journal *registry.RecordStore
}

// pepdPosture dérive de l'environnement les interrupteurs de sécurité de pepd, avec les MÊMES lecteurs que le démon (une
// valeur illisible est une erreur, jamais un défaut). Partagé par le démarrage et par le recalcul hors machine (#264).
func pepdPosture(getenv func(string) string) ([]byte, error) {
	p := pep.Posture{}
	p["ano-proxy"] = pep.OnOff(getenv("TBP_PROXY_ANO_SOCKET") != "") // le retirer désactive l'anonymisation
	p["opa"] = pep.OnOff(getenv("TBP_OPA_DISABLED_DEV_UNSAFE") != "1")
	trip, err := opaTripAfter(getenv)
	if err != nil {
		return nil, err
	}
	p["opa-trip-after"] = strconv.Itoa(trip) // le relever affaiblit le verrou T14
	probes, _, err := opaAutoClearConfig(getenv)
	if err != nil {
		return nil, err
	}
	p["opa-autoclear"] = pep.OnOff(probes > 0) // 0 = levée manuelle seulement, le profil le plus strict
	tuning, err := pep.OPATuningFromEnv(getenv)
	if err != nil {
		return nil, fmt.Errorf("pepd: %w", err)
	}
	p.OPAPosture(tuning)
	tele, err := telemetryFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	p["telemetry"] = pep.OnOff(tele.enabled) // détection d'exfiltration au compte-gouttes (anti-dribble)
	async, _, err := durabilityFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	if async {
		p["durability"] = "async-bounded"
	} else {
		p["durability"] = "sync"
	}
	return p.Bytes(), nil
}

// pepdProvisioningFiles : ce que pepd mesure, dérivé de SA configuration. Partagé par le démarrage
// (setupProvisioning) et par le recalcul de la condition hors machine (#264) : une seule liste.
func pepdProvisioningFiles(in provisioningInputs, getenv func(string) string) ([]registry.ProvisioningFile, error) {
	extra, err := registry.ParseProvisioningExtra(getenv("TBP_PROVISIONING_EXTRA_FILES"))
	if err != nil {
		return nil, fmt.Errorf("TBP_PROVISIONING_EXTRA_FILES : %w", err)
	}
	return append([]registry.ProvisioningFile{
		{Name: "issuer-keyring", Path: in.keyringFile},
		{Name: "quorum-keyring", Path: in.quorumKeyringFile, Authority: true},
		// l'ÉCHELLE : k du quorum et topologie. Abaisser TBP_QUORUM_MIN par l'environnement
		// divergerait du témoin ; la transition n'est autorisée que par k ATTESTÉ (#224).
		{Name: "quorum-settings", Content: pep.QuorumSettings(in.quorumMin, in.topology)},
		// la POSTURE : les interrupteurs de sécurité (ano, verrou OPA, file d'admission, télémétrie, durabilité) — une
		// dérive diverge comme TBP_QUORUM_MIN (revue tierce, 4.6)
		{Name: pep.ProvisioningPostureName, Content: in.posture},
	}, extra...), nil
}

// provisioningInputsFromEnv relit de l'environnement ce que run() passe à setupProvisioning (mêmes
// variables, mêmes défauts : TBP_QUORUM_MIN vaut 2 sans valeur). Un test compare le résultat à celui
// du démon pour que cette copie ne dérive jamais.
func provisioningInputsFromEnv(getenv func(string) string) (provisioningInputs, error) {
	var in provisioningInputs
	var err error
	if in.cellID = getenv("TBP_CELL_ID"); in.cellID == "" {
		return in, errors.New("TBP_CELL_ID requis")
	}
	in.keyringFile = getenv("TBP_KEYRING_FILE")
	in.quorumKeyringFile = getenv("TBP_QUORUM_KEYRING_FILE")
	in.quorumMin = 2
	if s := getenv("TBP_QUORUM_MIN"); s != "" {
		n, aerr := strconv.Atoi(s)
		if aerr != nil || n < 1 {
			return in, fmt.Errorf("TBP_QUORUM_MIN invalide %q", s)
		}
		in.quorumMin = n
	}
	multi, err := topologyFromEnv(getenv)
	if err != nil {
		return in, err
	}
	in.topology = topologyName(multi)
	if in.posture, err = pepdPosture(getenv); err != nil {
		return in, err
	}
	return in, nil
}

// printProvisioningCondition recalcule les conditions de transition à signer (#264) — provisionnement ET,
// si le démarrage mesuré est actif, le démarrage mesuré : mêmes fichiers que le démon, copie du témoin ;
// n'écrit rien. Rend le code de sortie.
func printProvisioningCondition(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	a, err := pep.ParsePrintConditionArgs(args, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "pepd:", err)
		return 2
	}
	verifier, err := pep.CellVerifierFromFile(a.CellVKey)
	if err != nil {
		fmt.Fprintln(stderr, "pepd:", err)
		return 2
	}
	in, err := provisioningInputsFromEnv(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "pepd:", err)
		return 2
	}
	if getenv("TBP_PROVISIONING_DISABLED_DEV_UNSAFE") == "1" {
		fmt.Fprintln(stderr, "pepd: mesure du provisionnement désactivée (TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1) : aucune condition")
		return 2
	}
	files, err := pepdProvisioningFiles(in, getenv)
	if err != nil {
		fmt.Fprintln(stderr, "pepd:", err)
		return 2
	}
	witness := getenv("TBP_PROVISIONING_WITNESS_FILE")
	pv, err := registry.PreviewProvisioning(files, witness, in.cellID, "pepd", verifier)
	if err != nil {
		fmt.Fprintln(stderr, "pepd:", err)
		return 1
	}
	pep.WriteProvisioningPreview(stdout, conditionProvisioningTransition, "pepd", pv)
	if manifest := getenv("TBP_MEASURED_BOOT_MANIFEST_FILE"); manifest != "" {
		fmt.Fprintln(stdout)
		if err := printMeasuredBootCondition(stdout, manifest, getenv, verifier); err != nil {
			fmt.Fprintln(stderr, "pepd:", err)
			return 1
		}
	}
	return 0
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
	files, err := pepdProvisioningFiles(in, getenv)
	if err != nil {
		return err
	}

	// La preuve de transition est vérifiée contre le trousseau de contrôleurs ATTESTÉ
	// (celui du témoin, avant l'édition), jamais contre le fichier courant : sinon
	// l'attaquant qui édite le fichier y ajoute ses clés et signe sa propre transition
	// (issue #218). Sans témoin antérieur (premier démarrage, ré-engagement après perte
	// du témoin) il n'y a pas d'attesté : repli TOFU sur le trousseau courant.
	//
	// La preuve est liée à l'état de départ ET à l'état cible (issue #236) : toujours
	// une fermeture, même sans fichier de preuve, pour que le refus dise QUELLE
	// condition signer (« ce qu'on voit est ce qu'on signe »).
	proof := getenv("TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	authorize := func(prev map[string][]byte, from, to [32]byte) error {
		cond := pep.TransitionCondition(conditionProvisioningTransition, from, to)
		if proof == "" {
			return fmt.Errorf("aucune preuve de transition (TBP_PROVISIONING_TRANSITION_PROOF_FILE) ; condition à signer : %s", cond)
		}
		verr := func() error {
			keyring, k := in.quorumKeyring, in.quorumMin
			if raw, ok := prev["quorum-keyring"]; ok {
				attested, err := parseKeyring(raw)
				if err != nil {
					return fmt.Errorf("trousseau de contrôleurs attesté illisible: %w", err)
				}
				keyring = attested
			}
			// k est LUI AUSSI celui qui était attesté : sinon l'attaquant qui abaisse
			// TBP_QUORUM_MIN dans l'environnement autorise sa transition avec une seule clé (#224).
			if raw, ok := prev["quorum-settings"]; ok {
				attestedK, err := pep.ParseQuorumSettings(raw)
				if err != nil {
					return fmt.Errorf("réglages de quorum attestés illisibles: %w", err)
				}
				k = attestedK
			}
			return pep.VerifyQuorumProofFile(proof, cond, in.cellID, keyring, k)
		}()
		if verr != nil {
			return fmt.Errorf("%w ; condition à signer : %s", verr, cond)
		}
		return nil
	}
	g, err := registry.NewProvisioningGuard(registry.ProvisioningGuardOptions{
		CellID: in.cellID, Component: "pepd", Files: files,
		WitnessFile: witness, RegistryDir: in.regDir,
		Signer: signer, Verifier: verifier,
		Leaves: cellLog, Journal: in.journal, Log: cellLog, Salt: in.salt,
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
