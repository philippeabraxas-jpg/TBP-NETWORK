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
		quorumKeyring: pf.measuredBootFixture.quorumKeyring, quorumMin: pf.quorumMin,
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
