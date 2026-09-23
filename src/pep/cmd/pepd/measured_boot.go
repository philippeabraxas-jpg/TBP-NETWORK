package main

// Measured boot (T31, issue #32 — §6.3) branché dans le cycle de vie de
// pepd (revue de sécurité #96 : la couture registry.CheckBoot existait
// depuis T31 mais aucun démon ne l'appelait — measured boot codé, jamais
// exécuté, donc aucune protection réelle). Point d'intégration documenté
// (src/registry/README.md) : AVANT que la cellule n'ouvre son service.
//
// Revue de sécurité post-#86 (issue #112) : deux défauts fermés ici.
//
//   - ACTIF PAR DÉFAUT désormais (était : désactivé par défaut si
//     TBP_MEASURED_BOOT_MANIFEST_FILE absent — un déploiement qui
//     oubliait simplement de le configurer tournait sans AUCUNE
//     protection, silencieusement). TBP_MEASURED_BOOT_MANIFEST_FILE
//     absent refuse maintenant de démarrer, sauf déclaration EXPLICITE
//     de TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1 (même doctrine que
//     TBP_OPA_DISABLED_DEV_UNSAFE, revue #92) — dev/lab uniquement,
//     jamais en production. Le pilote matériel TPM/HSM réel reste une
//     décision de déploiement à trancher (issue #32 elle-même le dit) ;
//     registry.FileRootMeasurer est un stand-in DEV/TEST UNIQUEMENT,
//     jamais en gouvernance réelle — mais l'ABSENCE de toute mesure
//     n'est plus un défaut silencieux.
//   - la RÉ-ENGAGEMENT de référence (TBP_MEASURED_BOOT_TRANSITION=1,
//     un simple drapeau texte) exige maintenant une PREUVE DE QUORUM
//     cryptographique (TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE — k
//     signatures Ed25519 distinctes du MÊME trousseau de contrôleurs que
//     POST /v1/mode, §89/§105) : un simple accès en écriture à
//     l'environnement du process ne suffit plus, seul, à faire accepter
//     n'importe quel état courant comme nouvelle référence de confiance.
//
// Comportements, une fois actif :
//
//   - premier démarrage (aucun manifeste persisté) : GENÈSE — l'état
//     courant (composants + racine) est mesuré et engagé comme référence
//     (confiance à la première utilisation, assumée et documentée — même
//     scission dev-stub/matériel réel que DevSigner, StaticEpoch) ;
//   - démarrages suivants : CheckBoot confronte l'état mesuré à la
//     référence engagée — toute divergence refuse le démarrage, trace une
//     feuille de refus, alarme (T14). Un changement de composant
//     DÉLIBÉRÉ (mise à jour de bundle, de config OPA…) doit être déclaré
//     via TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE, quorum vérifié, pour
//     ré-engager une nouvelle référence — jamais un ré-alignement
//     silencieux, jamais sur la seule foi d'un drapeau.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/mod/sumdb/note"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// setupMeasuredBoot est appelé juste après l'ouverture du CellLog, avant
// tout le reste de l'assemblage de pepd. Retourner une erreur est fatal :
// un démarrage refusé par measured boot n'a pas de repli.
func setupMeasuredBoot(ctx context.Context, cellID string, salt []byte, signer note.Signer, verifier note.Verifier, cellLog *registry.CellLog, quorumKeyring map[[16]byte]ed25519.PublicKey, quorumMin int, getenv func(string) string) error {
	manifestFile := getenv("TBP_MEASURED_BOOT_MANIFEST_FILE")
	if manifestFile == "" {
		if getenv("TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE") == "1" {
			log.Printf("pepd: measured boot désactivé EXPLICITEMENT (TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1, revue #112) — DEV/LAB UNIQUEMENT, jamais en production : aucune protection contre un binaire/config/bundle altéré au démarrage")
			return nil
		}
		return fmt.Errorf("pepd: TBP_MEASURED_BOOT_MANIFEST_FILE requis (measured boot actif par défaut, revue #112) — ou déclarer EXPLICITEMENT TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1 (dev/lab uniquement, jamais en production)")
	}

	rootFile, err := envRequiredFrom(getenv, "TBP_MEASURED_BOOT_ROOT_FILE")
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}
	expectedRootHex, err := envRequiredFrom(getenv, "TBP_MEASURED_BOOT_EXPECTED_ROOT")
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}
	expectedRootBytes, err := hex.DecodeString(expectedRootHex)
	if err != nil || len(expectedRootBytes) != 32 {
		return fmt.Errorf("measured boot: TBP_MEASURED_BOOT_EXPECTED_ROOT: hex 64 caractères requis")
	}
	var expectedRoot [32]byte
	copy(expectedRoot[:], expectedRootBytes)

	paths, err := loadComponentPaths(getenv)
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}

	last, err := loadPersistedManifest(manifestFile)
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}

	m, err := registry.NewManifester(registry.ManifestOptions{
		CellID:   cellID,
		Signer:   signer,
		Verifier: verifier,
		Leaves:   cellLog,
		Salt:     salt,
		Last:     last,
		OnTrip:   func(reason string) { log.Printf("pepd: ALARME measured boot: %s", reason) },
	})
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}

	if last == nil {
		sm, err := genesisMeasuredBoot(ctx, cellLog, m, paths)
		if err != nil {
			return fmt.Errorf("measured boot: %w", err)
		}
		if err := persistManifest(manifestFile, sm); err != nil {
			return fmt.Errorf("measured boot: %w", err)
		}
		log.Printf("pepd: measured boot — genèse écrite (%s) : premier démarrage enregistré comme référence (TOFU dev-stub, §32)", manifestFile)
		return nil
	}

	if proofPath := getenv("TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE"); proofPath != "" {
		if err := verifyMeasuredBootTransitionProof(proofPath, cellID, quorumKeyring, quorumMin); err != nil {
			return fmt.Errorf("measured boot: transition refusée (§112) : %w", err)
		}
		sm, err := transitionMeasuredBoot(ctx, cellLog, m, paths)
		if err != nil {
			return fmt.Errorf("measured boot: %w", err)
		}
		if err := persistManifest(manifestFile, sm); err != nil {
			return fmt.Errorf("measured boot: %w", err)
		}
		log.Printf("pepd: measured boot — transition enregistrée (quorum de contrôleurs vérifié, §112 — plus un simple drapeau)")
		return nil
	}

	rm := registry.FileRootMeasurer{Path: rootFile}
	if err := registry.CheckBoot(ctx, m, rm, expectedRoot, paths); err != nil {
		return fmt.Errorf("measured boot: démarrage refusé (état divergent du manifeste attendu) : %w", err)
	}
	log.Printf("pepd: measured boot — état conforme au manifeste attendu")
	return nil
}

func loadComponentPaths(getenv func(string) string) (registry.ComponentPaths, error) {
	var paths registry.ComponentPaths
	fields := []struct {
		name string
		dst  *string
	}{
		{"TBP_MEASURED_BOOT_POLICY_BUNDLE", &paths.PolicyBundle},
		{"TBP_MEASURED_BOOT_OPA_CONFIG", &paths.OPAConfig},
		{"TBP_MEASURED_BOOT_BROKER_BINARY", &paths.BrokerBinary},
		{"TBP_MEASURED_BOOT_AI_CONTAINER", &paths.AIContainer},
	}
	for _, f := range fields {
		v, err := envRequiredFrom(getenv, f.name)
		if err != nil {
			return registry.ComponentPaths{}, err
		}
		*f.dst = v
	}
	return paths, nil
}

// envRequiredFrom est envRequired (main.go) mais sur une couture getenv
// injectable — measured boot est testé sans toucher l'environnement du
// process (même patron que durabilityFromEnv).
func envRequiredFrom(getenv func(string) string, name string) (string, error) {
	v := getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s requis", name)
	}
	return v, nil
}

// measuredBootTransitionProofFile est la forme JSON du fichier de preuve
// pointé par TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE — MÊME forme que le
// corps de POST /v1/mode (ModeChangeRequest, listener.go) : k signatures
// Ed25519 distinctes du trousseau de contrôleurs épinglé (§12,
// TBP_QUORUM_KEYRING_FILE), sur pep.QuorumMessage("measured-boot-
// transition", cellID, expiry). Un fichier, pas un POST HTTP : la
// transition se décide AU DÉMARRAGE, avant que le listener HTTP
// n'existe.
type measuredBootTransitionProofFile struct {
	Expiry     int64                           `json:"expiry"`
	Signatures []measuredBootTransitionSigWire `json:"signatures"`
}

type measuredBootTransitionSigWire struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// reasonMeasuredBootTransition est la condition liée par la signature —
// distincte de "mode-monitor"/"mode-closed" (§89/§105) : une preuve de
// quorum pour BASCULER la posture ne doit jamais valoir, par accident de
// forme, comme preuve pour RÉ-ENGAGER la référence measured boot, et
// inversement.
const reasonMeasuredBootTransition = "measured-boot-transition"

// verifyMeasuredBootTransitionProof lit et vérifie le fichier de preuve de
// quorum d'une transition measured boot (revue de sécurité #112) : sans
// cette preuve VALIDE, aucune ré-engagement de référence n'a lieu — un
// simple accès en écriture à l'environnement du process (l'ancien
// TBP_MEASURED_BOOT_TRANSITION=1) ne suffit plus.
func verifyMeasuredBootTransitionProof(path, cellID string, quorumKeyring map[[16]byte]ed25519.PublicKey, quorumMin int) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("preuve de transition illisible (%s): %w", path, err)
	}
	var pf measuredBootTransitionProofFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("preuve de transition (%s) mal formée: %w", path, err)
	}
	sigs := make([]pep.QuorumSignature, 0, len(pf.Signatures))
	for _, s := range pf.Signatures {
		kid, err := hex.DecodeString(s.KeyID)
		if err != nil || len(kid) != 16 {
			return fmt.Errorf("preuve de transition: key_id illisible (hex 16 octets)")
		}
		sig, err := hex.DecodeString(s.Signature)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("preuve de transition: signature illisible (hex 64 octets Ed25519)")
		}
		var kidArr [16]byte
		copy(kidArr[:], kid)
		sigs = append(sigs, pep.QuorumSignature{KeyID: kidArr, Signature: sig})
	}
	verify, err := pep.NewSignatureQuorumVerifier(cellID, quorumKeyring, quorumMin, pep.DefaultQuorumProofTTL, nil)
	if err != nil {
		return fmt.Errorf("quorum: %w", err)
	}
	proof := pep.QuorumProof{Expiry: time.Unix(pf.Expiry, 0), Signatures: sigs}
	if !verify(reasonMeasuredBootTransition, proof) {
		return errors.New("preuve de quorum rejetée (signatures insuffisantes, invalides, ou expirées — §112)")
	}
	return nil
}

// loadPersistedManifest lit le dernier manifeste publié — absence de
// fichier ⇒ premier démarrage (nil, pas d'erreur) ; toute autre erreur
// (fichier illisible, forme ou signature invalide) est fatale.
func loadPersistedManifest(path string) (*registry.SignedManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("manifeste persisté illisible (%s): %w", path, err)
	}
	sm, err := registry.ParseSignedManifest(data)
	if err != nil {
		return nil, fmt.Errorf("manifeste persisté (%s): %w", path, err)
	}
	return &sm, nil
}

// persistManifest écrit l'artefact publié — tmp + rename : jamais de
// fichier à moitié écrit lisible par un démarrage suivant.
func persistManifest(path string, sm registry.SignedManifest) error {
	data, err := registry.MarshalSignedManifest(sm)
	if err != nil {
		return fmt.Errorf("sérialisation du manifeste: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("écriture du manifeste: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("renommage du manifeste: %w", err)
	}
	return nil
}

func genesisMeasuredBoot(ctx context.Context, cellLog *registry.CellLog, m *registry.Manifester, paths registry.ComponentPaths) (registry.SignedManifest, error) {
	head, _, err := cellLog.Head(ctx)
	if err != nil {
		return registry.SignedManifest{}, fmt.Errorf("tête de chaîne illisible: %w", err)
	}
	st, err := registry.MeasureComponents(paths)
	if err != nil {
		return registry.SignedManifest{}, fmt.Errorf("mesure des composants: %w", err)
	}
	st.ChainHead = head
	return m.Genesis(ctx, 0, st)
}

func transitionMeasuredBoot(ctx context.Context, cellLog *registry.CellLog, m *registry.Manifester, paths registry.ComponentPaths) (registry.SignedManifest, error) {
	head, _, err := cellLog.Head(ctx)
	if err != nil {
		return registry.SignedManifest{}, fmt.Errorf("tête de chaîne illisible: %w", err)
	}
	st, err := registry.MeasureComponents(paths)
	if err != nil {
		return registry.SignedManifest{}, fmt.Errorf("mesure des composants: %w", err)
	}
	st.ChainHead = head
	return m.Transition(ctx, 0, st)
}
