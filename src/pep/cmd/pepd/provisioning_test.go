package main

// provisioning_test.go — mesure des trousseaux épinglés de pepd (issue #192).

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type provFixture struct {
	*measuredBootFixture
	keyring, quorumKeyring string
	witness                string
	topology               string // « mono » par défaut
}

func newProvFixture(t *testing.T) *provFixture {
	t.Helper()
	fx := newMeasuredBootFixture(t)
	base := filepath.Dir(fx.manifest)
	pf := &provFixture{
		measuredBootFixture: fx,
		keyring:             filepath.Join(base, "keyring.json"),
		quorumKeyring:       filepath.Join(base, "quorum-keyring.json"),
		witness:             filepath.Join(base, "pepd-provisioning.json"),
	}
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// le trousseau de contrôleurs est un VRAI trousseau : la preuve de transition est
	// vérifiée contre son contenu attesté (#218)
	pf.writeQuorumKeyring(t, fx.quorumKeyring)
	fx.env["TBP_PROVISIONING_WITNESS_FILE"] = pf.witness
	return pf
}

func (pf *provFixture) writeQuorumKeyring(t *testing.T, kr map[[16]byte]ed25519.PublicKey) {
	t.Helper()
	raw := map[string]string{}
	for kid, pub := range kr {
		raw[hex.EncodeToString(kid[:])] = hex.EncodeToString(pub)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf.quorumKeyring, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (pf *provFixture) setup(t *testing.T) error {
	t.Helper()
	signer, err := registry.LoadSigner(pf.regDir)
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := os.ReadFile(filepath.Join(pf.regDir, "cell_log.vkey"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := registry.NewVerifier(string(vkey))
	if err != nil {
		t.Fatal(err)
	}
	return setupProvisioning(pf.ctx, provisioningInputs{
		cellID: pf.cellID, regDir: pf.regDir, salt: pf.salt,
		keyringFile: pf.keyring, quorumKeyringFile: pf.quorumKeyring,
		quorumKeyring: pf.measuredBootFixture.quorumKeyring, quorumMin: pf.quorumMin, topology: pf.topology,
	}, signer, verifier, pf.cellLog, pf.getenv)
}

func (pf *provFixture) proof(t *testing.T, condition string, n int) {
	t.Helper()
	expiry := time.Now().Add(60 * time.Second)
	msg := pep.QuorumMessage(condition, pf.cellID, expiry)
	var sigs []measuredBootTransitionSigWire
	i := 0
	for kid, priv := range pf.quorumPrivs {
		if i >= n {
			break
		}
		sigs = append(sigs, measuredBootTransitionSigWire{KeyID: hex.EncodeToString(kid[:]), Signature: hex.EncodeToString(ed25519.Sign(priv, msg))})
		i++
	}
	data, err := json.Marshal(measuredBootTransitionProofFile{Expiry: expiry.Unix(), Signatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(pf.witness), "prov-proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pf.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = path
}

func TestPepdProvisioningRequiredByDefault(t *testing.T) {
	pf := newProvFixture(t)
	pf.env["TBP_PROVISIONING_WITNESS_FILE"] = ""
	if err := pf.setup(t); err == nil || !strings.Contains(err.Error(), "TBP_PROVISIONING_WITNESS_FILE requis") {
		t.Fatalf("témoin absent accepté : %v", err)
	}
	pf.env["TBP_PROVISIONING_DISABLED_DEV_UNSAFE"] = "1"
	if err := pf.setup(t); err != nil {
		t.Fatalf("échappatoire dev déclarée refusée : %v", err)
	}
	pf.env["TBP_PROVISIONING_WITNESS_FILE"] = pf.witness
	if err := pf.setup(t); err == nil || !strings.Contains(err.Error(), "contradictoires") {
		t.Fatalf("configuration contradictoire acceptée : %v", err)
	}
}

func TestPepdDevEscapeHatchRequiresTheSentinel(t *testing.T) {
	env := map[string]string{"TBP_PROVISIONING_DISABLED_DEV_UNSAFE": "1"}
	getenv := func(k string) string { return env[k] }
	statAbsent := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	if err := checkDevEscapeHatches(getenv, statAbsent); err == nil {
		t.Fatal("désactivation du provisionnement acceptée sans sentinelle d'environnement de dev (#113)")
	}
	if err := checkDevEscapeHatches(func(string) string { return "" }, statAbsent); err != nil {
		t.Fatalf("aucun drapeau dev, refus à tort : %v", err)
	}
}

func TestPepdRefusesToStartOnEditedKeyring(t *testing.T) {
	pf := newProvFixture(t)
	if err := pf.setup(t); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	if err := pf.setup(t); err != nil {
		t.Fatalf("redémarrage sans modification refusé : %v", err)
	}
	// on ajoute la clé de l'attaquant au trousseau des émetteurs
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := pf.setup(t)
	if err == nil || !strings.Contains(err.Error(), "issuer-keyring") || strings.Contains(err.Error(), "quorum-keyring") {
		t.Fatalf("trousseau d'émetteurs modifié accepté, ou mauvais fichier accusé : %v", err)
	}
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// idem pour le trousseau des contrôleurs du quorum
	if err := os.WriteFile(pf.quorumKeyring, []byte(`{"00":"aa","02":"cc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pf.setup(t); err == nil || !strings.Contains(err.Error(), "quorum-keyring") {
		t.Fatalf("trousseau de contrôleurs modifié accepté : %v", err)
	}
}

func TestPepdProvisioningTransitionNeedsAPepdQuorumProof(t *testing.T) {
	pf := newProvFixture(t)
	if err := pf.setup(t); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb"}`), 0o600); err != nil { // rotation légitime
		t.Fatal(err)
	}
	// preuve d'un AUTRE usage (transition du démarrage mesuré) : refusée
	pf.proof(t, reasonMeasuredBootTransition, pf.quorumMin)
	if err := pf.setup(t); err == nil {
		t.Fatal("une preuve de transition du démarrage mesuré vaut transition de provisionnement")
	}
	// preuve de brokerd : refusée
	pf.proof(t, "provisioning-transition-brokerd", pf.quorumMin)
	if err := pf.setup(t); err == nil {
		t.Fatal("la preuve de brokerd vaut pour pepd")
	}
	// quorum insuffisant : refusé
	pf.proof(t, conditionProvisioningTransition, pf.quorumMin-1)
	if err := pf.setup(t); err == nil {
		t.Fatal("quorum insuffisant accepté")
	}
	// preuve valide : acceptée, et la nouvelle référence tient sans preuve
	pf.proof(t, conditionProvisioningTransition, pf.quorumMin)
	if err := pf.setup(t); err != nil {
		t.Fatalf("transition avec preuve valide refusée : %v", err)
	}
	delete(pf.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := pf.setup(t); err != nil {
		t.Fatalf("nouvelle référence non retenue : %v", err)
	}
}

// Faille trouvée en préparant #199 : une transition du trousseau de quorum était
// autorisée par une preuve vérifiée contre le trousseau MODIFIÉ — celui que
// l'attaquant vient d'éditer. Qui peut écrire TBP_QUORUM_KEYRING_FILE ajoute ses
// propres clés, signe une preuve avec elles, et la mesure l'« autorise » : la
// protection du trousseau le plus sensible était vide. La preuve doit être
// vérifiée contre le trousseau tel qu'il était ATTESTÉ par le témoin.
func TestPepdKeyringTransitionCannotBeSelfAuthorized(t *testing.T) {
	pf := newProvFixture(t)
	legit := pf.measuredBootFixture.quorumKeyring
	if err := pf.setup(t); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}

	// L'attaquant ajoute assez de SES clés pour atteindre k, et signe avec elles.
	forged := map[[16]byte]ed25519.PublicKey{}
	for k, v := range legit {
		forged[k] = v
	}
	attackerPrivs := map[[16]byte]ed25519.PrivateKey{}
	for i := 0; i < pf.quorumMin; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		kid := pep.KeyIDFromPublicKey(pub)
		forged[kid], attackerPrivs[kid] = pub, priv
	}
	pf.writeQuorumKeyring(t, forged)
	expiry := time.Now().Add(60 * time.Second)
	msg := pep.QuorumMessage(conditionProvisioningTransition, pf.cellID, expiry)
	var sigs []measuredBootTransitionSigWire
	for kid, priv := range attackerPrivs {
		sigs = append(sigs, measuredBootTransitionSigWire{KeyID: hex.EncodeToString(kid[:]), Signature: hex.EncodeToString(ed25519.Sign(priv, msg))})
	}
	data, err := json.Marshal(measuredBootTransitionProofFile{Expiry: expiry.Unix(), Signatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(filepath.Dir(pf.witness), "forged-proof.json")
	if err := os.WriteFile(proofPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pf.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proofPath

	// main chargerait le trousseau ÉDITÉ : c'est ce que reçoit setupProvisioning.
	pf.measuredBootFixture.quorumKeyring = forged
	if err := pf.setup(t); err == nil {
		t.Fatal("un trousseau de quorum édité par l'attaquant a été « autorisé » par une preuve qu'il a lui-même signée")
	}

	// Cas voisin autorisé : les VRAIS contrôleurs (le trousseau attesté) signent la
	// même transition.
	pf.proof(t, conditionProvisioningTransition, pf.quorumMin)
	if err := pf.setup(t); err != nil {
		t.Fatalf("transition signée par le quorum ATTESTÉ refusée : %v", err)
	}
}

// --- procédure de secours (issue #199, deploy/recovery.md) -----------------------

// proofBy écrit une preuve de transition signée par EXACTEMENT ces clés.
func (pf *provFixture) proofBy(t *testing.T, condition string, privs ...ed25519.PrivateKey) {
	t.Helper()
	expiry := time.Now().Add(60 * time.Second)
	msg := pep.QuorumMessage(condition, pf.cellID, expiry)
	var sigs []measuredBootTransitionSigWire
	for _, priv := range privs {
		kid := pep.KeyIDFromPublicKey(priv.Public().(ed25519.PublicKey))
		sigs = append(sigs, measuredBootTransitionSigWire{KeyID: hex.EncodeToString(kid[:]), Signature: hex.EncodeToString(ed25519.Sign(priv, msg))})
	}
	data, err := json.Marshal(measuredBootTransitionProofFile{Expiry: expiry.Unix(), Signatures: sigs})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(pf.witness), "recovery-proof.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	pf.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = path
}

// useQuorum installe un trousseau de contrôleurs (fichier + ce que main chargerait) et k.
func (pf *provFixture) useQuorum(t *testing.T, k int, privs ...ed25519.PrivateKey) {
	t.Helper()
	kr := map[[16]byte]ed25519.PublicKey{}
	for _, p := range privs {
		pub := p.Public().(ed25519.PublicKey)
		kr[pep.KeyIDFromPublicKey(pub)] = pub
	}
	pf.writeQuorumKeyring(t, kr)
	pf.measuredBootFixture.quorumKeyring = kr
	pf.quorumMin = k
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// Une clé de contrôleur perdue avec k-sur-n (3 contrôleurs, k = 2) : les deux restants
// signent le remplacement ; la clé perdue ne compte plus pour rien d'ultérieur.
func TestPepdLostControllerKeyIsRotatedByTheRemainingQuorum(t *testing.T) {
	pf := newProvFixture(t)
	a, b, lost := newKey(t), newKey(t), newKey(t)
	pf.useQuorum(t, 2, a, b, lost)
	if err := pf.setup(t); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}

	// rotation : la clé perdue est remplacée par une neuve, signée par A et B
	d := newKey(t)
	pf.useQuorum(t, 2, a, b, d)
	pf.proofBy(t, conditionProvisioningTransition, a, b)
	if err := pf.setup(t); err != nil {
		t.Fatalf("rotation signée par les 2 contrôleurs restants refusée : %v", err)
	}
	delete(pf.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := pf.setup(t); err != nil {
		t.Fatalf("nouvelle référence non retenue : %v", err)
	}

	// la clé perdue ne vaut plus : une transition ultérieure signée par elle + A est
	// refusée (une seule signature valide pour k = 2) ; A + D est acceptée.
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pf.proofBy(t, conditionProvisioningTransition, lost, a)
	if err := pf.setup(t); err == nil {
		t.Fatal("la clé de contrôleur perdue (retirée du trousseau) compte encore dans le quorum")
	}
	pf.proofBy(t, conditionProvisioningTransition, a, d)
	if err := pf.setup(t); err != nil {
		t.Fatalf("A + la clé de remplacement refusés : %v", err)
	}

	// et une seule des deux clés restantes ne suffit pas pour k = 2 (cas voisin refusé)
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb","02":"cc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pf.proofBy(t, conditionProvisioningTransition, a)
	if err := pf.setup(t); err == nil {
		t.Fatal("1 signature acceptée pour k = 2")
	}
}

// Perte du quorum (échelle 1 : k = 1, la clé de l'administrateur est perdue) : plus
// personne ne peut signer, par conception. La reprise est un acte d'installation de
// l'administrateur de la machine — nouvelle clé, ancien témoin mis de côté — et non une
// transition autorisée par l'ancien quorum.
func TestPepdLostQuorumIsRecoveredByReEngagement(t *testing.T) {
	pf := newProvFixture(t)
	lost := newKey(t)
	pf.useQuorum(t, 1, lost)
	if err := pf.setup(t); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}

	// nouvelle clé, nouveau trousseau, preuve signée par la nouvelle clé : refusée tant
	// que l'ancien témoin est là (la preuve est vérifiée contre le trousseau ATTESTÉ)
	fresh := newKey(t)
	pf.useQuorum(t, 1, fresh)
	pf.proofBy(t, conditionProvisioningTransition, fresh)
	if err := pf.setup(t); err == nil {
		t.Fatal("un trousseau remplacé a été autorisé par la nouvelle clé, sans l'ancien quorum")
	}

	// l'ancien témoin est mis de côté (preuve matérielle, pas supprimé) : ré-engagement
	if err := os.Rename(pf.witness, pf.witness+".perdu"); err != nil {
		t.Fatal(err)
	}
	if err := pf.setup(t); err != nil {
		t.Fatalf("ré-engagement signé par la nouvelle clé refusé : %v", err)
	}
	delete(pf.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := pf.setup(t); err != nil {
		t.Fatalf("nouvelle référence non retenue : %v", err)
	}

	// l'ancienne clé ne vaut plus rien
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pf.proofBy(t, conditionProvisioningTransition, lost)
	if err := pf.setup(t); err == nil {
		t.Fatal("l'ancienne clé (perdue) autorise encore une transition")
	}
	pf.proofBy(t, conditionProvisioningTransition, fresh)
	if err := pf.setup(t); err != nil {
		t.Fatalf("la nouvelle clé n'autorise pas une transition : %v", err)
	}
}

// --- k du quorum attesté (issue #224) -----------------------------------------------

// Abaisser TBP_QUORUM_MIN dans l'environnement entre deux démarrages affaiblissait tous les
// actes gouvernés sans alarme : une seule clé de contrôleur (compromise, ou la moins bien gardée)
// suffisait, y compris pour la transition de provisionnement. k est maintenant engagé dans le
// témoin, et la transition n'est autorisée que par le k ATTESTÉ.
func TestPepdLoweringQuorumMinByEnvironmentIsRefused(t *testing.T) {
	pf := newProvFixture(t)
	pf.topology = "mono"
	a, b := newKey(t), newKey(t)
	pf.useQuorum(t, 2, a, b)
	if err := pf.setup(t); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	if err := pf.setup(t); err != nil {
		t.Fatalf("redémarrage à k identique refusé : %v", err)
	}

	// l'attaquant édite l'environnement : k = 1, et une seule clé signe sa « transition »
	pf.quorumMin = 1
	if err := pf.setup(t); err == nil {
		t.Fatal("k abaissé par l'environnement accepté sans preuve")
	}
	pf.proofBy(t, conditionProvisioningTransition, a)
	if err := pf.setup(t); err == nil {
		t.Fatal("k abaissé de 2 à 1 AUTORISÉ par une seule signature : la preuve a été vérifiée avec le k de l'environnement")
	}

	// cas voisin : l'abaissement légitime, signé par le quorum ATTESTÉ (k = 2)
	pf.proofBy(t, conditionProvisioningTransition, a, b)
	if err := pf.setup(t); err != nil {
		t.Fatalf("abaissement signé par le quorum attesté refusé : %v", err)
	}
	// et le nouveau k tient sans preuve
	delete(pf.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := pf.setup(t); err != nil {
		t.Fatalf("nouveau k non retenu : %v", err)
	}
}

// La topologie fait partie de l'échelle : la changer est une transition, pas un réglage libre.
func TestPepdTopologyChangeIsAGovernedTransition(t *testing.T) {
	pf := newProvFixture(t)
	a, b := newKey(t), newKey(t)
	pf.useQuorum(t, 2, a, b)
	pf.topology = "mono"
	if err := pf.setup(t); err != nil {
		t.Fatal(err)
	}
	pf.topology = "multi"
	if err := pf.setup(t); err == nil {
		t.Fatal("changement de topologie accepté sans preuve")
	}
	pf.proofBy(t, conditionProvisioningTransition, a, b)
	if err := pf.setup(t); err != nil {
		t.Fatalf("changement de topologie signé par le quorum refusé : %v", err)
	}
}
