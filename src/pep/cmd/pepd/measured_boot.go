package main

// Measured boot (T31, issue #32 — §6.3) branché dans le cycle de vie de
// pepd (revue de sécurité #96 : la couture registry.CheckBoot existait
// depuis T31 mais aucun démon ne l'appelait — measured boot codé, jamais
// exécuté, donc aucune protection réelle). Point d'intégration documenté
// (src/registry/README.md) : AVANT que la cellule n'ouvre son service.
//
// Désactivé par défaut (TBP_MEASURED_BOOT_MANIFEST_FILE absent) — le
// pilote matériel TPM/HSM réel reste une décision de déploiement à
// trancher (issue #32 elle-même le dit) ; registry.FileRootMeasurer est un
// stand-in DEV/TEST UNIQUEMENT, jamais en gouvernance réelle. Une fois
// activé, deux comportements :
//
//   - premier démarrage (aucun manifeste persisté) : GENÈSE — l'état
//     courant (composants + racine) est mesuré et engagé comme référence
//     (confiance à la première utilisation, assumée et documentée — même
//     scission dev-stub/matériel réel que DevSigner, StaticEpoch) ;
//   - démarrages suivants : CheckBoot confronte l'état mesuré à la
//     référence engagée — toute divergence refuse le démarrage, trace une
//     feuille de refus, alarme (T14). Un changement de composant
//     DÉLIBÉRÉ (mise à jour de bundle, de config OPA…) doit être déclaré
//     explicitement (TBP_MEASURED_BOOT_TRANSITION=1) pour ré-engager une
//     nouvelle référence — jamais un ré-alignement silencieux.

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"golang.org/x/mod/sumdb/note"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// setupMeasuredBoot est appelé juste après l'ouverture du CellLog, avant
// tout le reste de l'assemblage de pepd. Retourner une erreur est fatal :
// un démarrage refusé par measured boot n'a pas de repli.
func setupMeasuredBoot(ctx context.Context, cellID string, salt []byte, signer note.Signer, verifier note.Verifier, cellLog *registry.CellLog, getenv func(string) string) error {
	manifestFile := getenv("TBP_MEASURED_BOOT_MANIFEST_FILE")
	if manifestFile == "" {
		log.Printf("pepd: measured boot désactivé (TBP_MEASURED_BOOT_MANIFEST_FILE absent, issue #96) — aucune protection contre un binaire/config/bundle altéré au démarrage")
		return nil
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

	if getenv("TBP_MEASURED_BOOT_TRANSITION") == "1" {
		sm, err := transitionMeasuredBoot(ctx, cellLog, m, paths)
		if err != nil {
			return fmt.Errorf("measured boot: %w", err)
		}
		if err := persistManifest(manifestFile, sm); err != nil {
			return fmt.Errorf("measured boot: %w", err)
		}
		log.Printf("pepd: measured boot — transition enregistrée (changement de composant déclaré explicitement par l'opérateur)")
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
