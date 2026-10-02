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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/mod/sumdb/note"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// setupMeasuredBoot est appelé juste après l'ouverture du CellLog, avant
// tout le reste de l'assemblage de pepd. Retourner une erreur est fatal :
// un démarrage refusé par measured boot n'a pas de repli.
func setupMeasuredBoot(ctx context.Context, cellID string, salt []byte, signer note.Signer, verifier note.Verifier, cellLog *registry.CellLog, journal *registry.RecordStore, quorumKeyring map[[16]byte]ed25519.PublicKey, quorumMin int, getenv func(string) string) error {
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
		Journal:  journal,
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

	// La preuve de transition est liée à l'état de départ (manifeste attendu) ET à
	// l'état cible mesuré (issue #236) : elle ne vaut que pour CETTE paire. Un état
	// inchangé n'a besoin d'aucune preuve (contrôle de démarrage ordinaire) ; une
	// preuve laissée en place ne ré-engage donc rien d'autre que ce qu'elle a signé.
	var hint string // condition à signer, ajoutée au refus pour que l'opérateur sache quoi signer
	if cur, ok := m.State(); ok {
		if target, merr := registry.MeasureComponents(paths); merr == nil && measuredStateDigest(cur) != measuredStateDigest(target) {
			cond := pep.TransitionCondition(reasonMeasuredBootTransition, measuredStateDigest(cur), measuredStateDigest(target))
			hint = " ; condition à signer : " + cond
			if proofPath := getenv("TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE"); proofPath != "" {
				verr := verifyMeasuredBootTransitionProof(proofPath, cond, cellID, quorumKeyring, quorumMin)
				if verr == nil {
					sm, err := transitionMeasuredBoot(ctx, cellLog, m, paths)
					if err != nil {
						return fmt.Errorf("measured boot: %w", err)
					}
					if err := persistManifest(manifestFile, sm); err != nil {
						return fmt.Errorf("measured boot: %w", err)
					}
					log.Printf("pepd: measured boot — transition enregistrée (quorum de contrôleurs vérifié sur l'état cible, §112/#236 — plus un simple drapeau)")
					return nil
				}
				// Preuve invalide pour CET état : refus. CheckBoot écrit la feuille de
				// refus et l'alarme (la divergence est réelle) ; l'erreur rendue est
				// toujours celle de la preuve, jamais un succès.
				_ = registry.CheckBoot(ctx, m, registry.FileRootMeasurer{Path: rootFile}, expectedRoot, paths)
				return fmt.Errorf("measured boot: transition refusée (§112) : %w%s", verr, hint)
			}
		}
	}

	rm := registry.FileRootMeasurer{Path: rootFile}
	if err := registry.CheckBoot(ctx, m, rm, expectedRoot, paths); err != nil {
		return fmt.Errorf("measured boot: démarrage refusé (état divergent du manifeste attendu) : %w%s", err, hint)
	}
	log.Printf("pepd: measured boot — état conforme au manifeste attendu")
	return nil
}

// printMeasuredBootCondition recalcule la condition « measured-boot-transition|from|to » (#264) : l'état
// ATTESTÉ est celui du manifeste persisté (signature vérifiée avec la clé publique de la cellule), l'état
// CIBLE est mesuré sur les quatre composants (mêmes variables, même mesure que le démarrage).
func printMeasuredBootCondition(w io.Writer, manifestFile string, getenv func(string) string, verifier note.Verifier) error {
	paths, err := loadComponentPaths(getenv)
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}
	target, err := registry.MeasureComponents(paths)
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}
	to := measuredStateDigest(target)
	last, err := loadPersistedManifest(manifestFile)
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}
	fmt.Fprintf(w, "component=pepd-measured-boot\n")
	if last == nil {
		fmt.Fprintf(w, "state=no-manifest\nfrom=%x\nto=%x\npas de manifeste attesté : premier démarrage (genèse, aucune preuve)\n", [32]byte{}, to)
		return nil
	}
	if !verifier.Verify(last.Record, last.Signature) {
		return fmt.Errorf("measured boot: manifeste persisté %s : signature invalide (clé publique de la cellule ?)", manifestFile)
	}
	rec, err := registry.ParseManifestRecord(last.Record)
	if err != nil {
		return fmt.Errorf("measured boot: %w", err)
	}
	from := measuredStateDigest(rec.State)
	if from == to {
		fmt.Fprintf(w, "state=conforming\nfrom=%x\nto=%x\naucune transition à signer : l'état mesuré est celui du manifeste attesté\n", from, to)
		return nil
	}
	fmt.Fprintf(w, "state=divergent\nfrom=%x\nto=%x\ncondition=%s\n", from, to, pep.TransitionCondition(reasonMeasuredBootTransition, from, to))
	return nil
}

// measuredStateDigest est le condensé des quatre composants mesurés (bundle de
// règles, config OPA, binaire broker, conteneur IA) — SANS la tête de chaîne, qui
// bouge à chaque feuille écrite et ne décrit pas ce que les contrôleurs approuvent.
func measuredStateDigest(st registry.ManifestState) [32]byte {
	h := sha256.New()
	h.Write([]byte("TBPM1"))
	h.Write(st.PolicyID[:])
	h.Write(st.OPAConfigHash[:])
	h.Write(st.BrokerHash[:])
	h.Write(st.AIContainerHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
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

// measuredBootTransitionProofFile / measuredBootTransitionSigWire : forme JSON du
// fichier de preuve (TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE), identique à celle
// que lit pep.VerifyQuorumProofFile — les tests de ce paquet la fabriquent avec.
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
func verifyMeasuredBootTransitionProof(path, condition, cellID string, quorumKeyring map[[16]byte]ed25519.PublicKey, quorumMin int) error {
	if err := pep.VerifyQuorumProofFile(path, condition, cellID, quorumKeyring, quorumMin); err != nil {
		return fmt.Errorf("preuve de transition : %w", err)
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
