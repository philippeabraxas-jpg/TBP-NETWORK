// measured_boot.go — T31 (issue #32) : measured boot (§6.3, phase 1).
//
// « Measured boot : la racine du nœud est mesurée par le TPM/HSM au
// démarrage. » (§6.3)
//
// Ce fichier livre la COUTURE et la SÉMANTIQUE fail-closed, pas le driver
// matériel : la disponibilité TPM sur le matériel du pilote P1 est une
// décision de déploiement à trancher avant de s'engager sur un mécanisme
// (texte de l'issue #32 elle-même) — même scission dev-stub / matériel
// réel différé que SoftHSM (T3), StaticEpoch (T33), DevSigner (T33).
//
// Sémantique : au démarrage, la cellule mesure sa racine (couture
// RootMeasurer) et les hashes des composants déployés (paquets signés, §1),
// puis confronte au manifeste ATTENDU — le dernier manifeste signé de la
// chaîne (Manifester.State). Toute divergence ou impossibilité de mesure =
// démarrage refusé + feuille KindManifest event=refuse + alarme T14 :
// jamais un passage silencieux (critère 2 de #32). Le boot réussi laisse
// sa feuille event=boot (§4.1 : chaque événement de manifeste est tracé).
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// RootMeasurer est la couture de mesure de la racine du nœud (TPM/HSM).
// L'implémentation de production lira la quote/les PCR du TPM de la
// plateforme pilote ; l'erreur fait partie du contrat : une mesure
// impossible est un refus de démarrage, jamais une valeur de repli.
type RootMeasurer interface {
	MeasureRoot(ctx context.Context) (rootHash [32]byte, err error)
}

// FileRootMeasurer est un RootMeasurer DEV/TEST UNIQUEMENT — même
// restriction que SoftHSM (§12) : il lit la « mesure » dans un fichier
// (hex, 64 caractères). Il ne PROUVE rien sur la machine ; il existe pour
// câbler et tester la sémantique fail-closed en attendant la décision
// matérielle du pilote P1. Jamais en gouvernance réelle.
type FileRootMeasurer struct {
	Path string // fichier contenant le hash hex (64 caractères) de la racine mesurée
}

// MeasureRoot lit le hash de racine depuis le fichier. Toute erreur de
// lecture ou de forme est une faute de mesure (fail-closed côté CheckBoot).
func (f FileRootMeasurer) MeasureRoot(_ context.Context) ([32]byte, error) {
	var root [32]byte
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return root, fmt.Errorf("registre: mesure de racine illisible : %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(b) != 32 {
		return root, fmt.Errorf("registre: mesure de racine mal formée (hex 64 attendu)")
	}
	copy(root[:], b)
	return root, nil
}

// ComponentPaths désigne les artefacts déployés dont le hash entre dans le
// manifeste (§6.3 : « le hash est celui du paquet signé »). Les quatre sont
// requis : un chemin vide est une faute de mesure (fail-closed), pas un
// composant « passé ».
type ComponentPaths struct {
	PolicyBundle string // bundle de règles signé (policy_id)
	OPAConfig    string // configuration OPA déployée
	BrokerBinary string // binaire broker déployé
	AIContainer  string // image/conteneur IA local déployé
}

// HashFile calcule le SHA-256 d'un artefact (lecture streamée — les images
// de conteneur ne tiennent pas nécessairement en mémoire).
func HashFile(path string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, fmt.Errorf("registre: artefact %q illisible : %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, fmt.Errorf("registre: lecture de %q : %w", path, err)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// MeasureComponents mesure les quatre composants déployés. ChainHead n'est
// PAS mesuré ici (c'est un état du log, capturé au moment des transitions —
// voir ManifestState) ; le champ rendu est nul.
func MeasureComponents(paths ComponentPaths) (ManifestState, error) {
	var st ManifestState
	if paths.PolicyBundle == "" || paths.OPAConfig == "" || paths.BrokerBinary == "" || paths.AIContainer == "" {
		return st, fmt.Errorf("registre: ComponentPaths incomplet — les quatre artefacts sont requis (§6.3)")
	}
	var err error
	if st.PolicyID, err = HashFile(paths.PolicyBundle); err != nil {
		return st, err
	}
	if st.OPAConfigHash, err = HashFile(paths.OPAConfig); err != nil {
		return st, err
	}
	if st.BrokerHash, err = HashFile(paths.BrokerBinary); err != nil {
		return st, err
	}
	if st.AIContainerHash, err = HashFile(paths.AIContainer); err != nil {
		return st, err
	}
	return st, nil
}

// CheckBoot est le contrôle de measured boot (critère 2 de #32) : la
// racine mesurée est confrontée à la référence provisionnée, et les
// composants mesurés au manifeste attendu (dernier manifeste signé). Toute
// divergence — conteneur IA modifié, broker modifié, config OPA modifiée,
// racine inattendue — ou impossibilité de mesure = refus de démarrage,
// feuille de refus, alarme. Le manifeste attendu absent (pas de genèse) ou
// la référence de racine nulle (non provisionnée) sont des refus : le
// fail-closed vaut aussi pour la configuration (§1).
//
// À appeler AVANT d'ouvrir le service de la cellule (point d'intégration :
// démarrage de pepd — voir src/registry/README.md).
func CheckBoot(ctx context.Context, m *Manifester, rm RootMeasurer, expectedRoot [32]byte, paths ComponentPaths) error {
	if m == nil || rm == nil {
		return errors.New("registre: CheckBoot exige le Manifester et le RootMeasurer (fail-closed)")
	}
	st, ok := m.State()
	if !ok {
		return m.writeRefusalLocked(ctx, [32]byte{}, "boot-no-manifest", ErrBootNoManifest)
	}
	if expectedRoot == ([32]byte{}) {
		return m.writeRefusalLocked(ctx, m.lastHash(), "boot-misconfiguration", ErrBootMisconfiguration)
	}

	root, err := rm.MeasureRoot(ctx)
	if err != nil {
		m.trip("manifest-boot-fault")
		return m.writeRefusalLocked(ctx, m.lastHash(), "boot-measurement-fault", ErrBootMeasurement)
	}
	if root != expectedRoot {
		m.trip("manifest-boot-divergence")
		return m.writeRefusalLocked(ctx, m.lastHash(), "boot-divergence", ErrBootDivergence)
	}

	measured, err := MeasureComponents(paths)
	if err != nil {
		m.trip("manifest-boot-fault")
		return m.writeRefusalLocked(ctx, m.lastHash(), "boot-measurement-fault", ErrBootMeasurement)
	}
	// Comparaison des QUATRE composants — ChainHead exclue par construction
	// (elle avance avec chaque feuille ; c'est une ancre d'audit, pas un
	// invariant de boot — voir ManifestState).
	if measured.PolicyID != st.PolicyID ||
		measured.OPAConfigHash != st.OPAConfigHash ||
		measured.BrokerHash != st.BrokerHash ||
		measured.AIContainerHash != st.AIContainerHash {
		m.trip("manifest-boot-divergence")
		return m.writeRefusalLocked(ctx, m.lastHash(), "boot-divergence", ErrBootDivergence)
	}

	// Boot conforme : tracé (§4.1). Feuille impossible = démarrage refusé
	// (pas de preuve, pas d'état attesté — doctrine T9/T11/T29/T30).
	hash := m.lastHash()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.writeLeafLocked(ctx, manifestEventBoot, hash, 1, "ok"); err != nil {
		m.trip("manifest-leaf-fault")
		return ErrManifestLeafFault
	}
	return nil
}

// lastHash rend le sceau du manifeste committed courant (zéros si aucun) —
// appelé sans verrou par CheckBoot, qui ne tient pas m.mu : on reprend le
// verrou le temps de la lecture.
func (m *Manifester) lastHash() [32]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.initialized {
		return [32]byte{}
	}
	return HashManifest(m.lastRecord)
}
