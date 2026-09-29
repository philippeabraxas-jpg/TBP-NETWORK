package main

// provisioning_test.go — mesure des fichiers de provisionnement de brokerd
// (issue #192). Chaque refus a son cas voisin accepté.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// --- configuration -----------------------------------------------------------

func TestProvisioningConfigFailClosed(t *testing.T) {
	env := validConfigEnv()
	delete(env, "TBP_PROVISIONING_WITNESS_FILE")
	if _, err := loadConfig(mapGetenv(env), statPresent); err == nil || !strings.Contains(err.Error(), "TBP_PROVISIONING_WITNESS_FILE requis") {
		t.Fatalf("témoin absent accepté : %v", err)
	}

	// l'échappatoire dev EXIGE la sentinelle (#113)
	env["TBP_PROVISIONING_DISABLED_DEV_UNSAFE"] = "1"
	if _, err := loadConfig(mapGetenv(env), statAbsent); err == nil {
		t.Fatal("désactivation acceptée sans sentinelle d'environnement de dev")
	}
	cfg, err := loadConfig(mapGetenv(env), statPresent)
	if err != nil {
		t.Fatalf("désactivation déclarée avec sentinelle refusée : %v", err)
	}
	if !cfg.provDisabled || cfg.provWitnessFile != "" {
		t.Fatalf("état = %+v", cfg)
	}

	// contradictoire : témoin ET désactivation
	env["TBP_PROVISIONING_WITNESS_FILE"] = "/var/lib/tbp/w.json"
	if _, err := loadConfig(mapGetenv(env), statPresent); err == nil || !strings.Contains(err.Error(), "contradictoires") {
		t.Fatalf("configuration contradictoire acceptée : %v", err)
	}
}

func TestProvisioningExtraFilesParsing(t *testing.T) {
	env := validConfigEnv()
	env["TBP_PROVISIONING_EXTRA_FILES"] = "/etc/tbp/ano-rules.json, rules=/etc/tbp/other.json ,"
	cfg, err := loadConfig(mapGetenv(env), statPresent)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.provExtra) != 2 ||
		cfg.provExtra[0].Name != "extra:/etc/tbp/ano-rules.json" || cfg.provExtra[0].Path != "/etc/tbp/ano-rules.json" ||
		cfg.provExtra[1].Name != "extra:rules" || cfg.provExtra[1].Path != "/etc/tbp/other.json" {
		t.Fatalf("extras mal lus : %+v", cfg.provExtra)
	}
	env["TBP_PROVISIONING_EXTRA_FILES"] = "nom="
	if _, err := loadConfig(mapGetenv(env), statPresent); err == nil {
		t.Fatal("entrée sans chemin acceptée")
	}
}

// brokerd DÉRIVE la liste de sa configuration : un opérateur ne peut pas
// « oublier » le registre d'agents.
func TestProvisioningFilesAreDerivedFromTheConfiguration(t *testing.T) {
	cfg, err := loadConfig(mapGetenv(validConfigEnv()), statPresent)
	if err != nil {
		t.Fatal(err)
	}
	names := func() map[string]string {
		m := map[string]string{}
		for _, f := range provisioningFiles(cfg) {
			m[f.Name] = f.Path
		}
		return m
	}
	got := names()
	for _, want := range []string{"operator-keys", "agent-registry", "genesis-manifest"} {
		if got[want] == "" {
			t.Errorf("%s absent de la liste mesurée : %v", want, got)
		}
	}
	if got["agent-registry"] != "/etc/tbp/agents.json" || got["genesis-manifest"] != "/etc/tbp/genesis/manifest.json" {
		t.Errorf("chemins = %v", got)
	}
	if _, ok := got["skill-registry"]; ok {
		t.Error("registre de skills mesuré alors qu'il n'est pas configuré")
	}
	if _, ok := got["tls-client-ca"]; ok {
		t.Error("CA cliente mesurée alors que l'écoute réseau est absente")
	}
	cfg.skillRegistryFile = "/etc/tbp/skills.json"
	cfg.netTLSClientCAFile = "/etc/tbp/ca.pem"
	got = names()
	if got["skill-registry"] != "/etc/tbp/skills.json" || got["tls-client-ca"] != "/etc/tbp/ca.pem" {
		t.Errorf("fichiers optionnels non mesurés : %v", got)
	}
}

// --- de bout en bout (vraie pile brokerd, vrais redémarrages) ------------------

// startStubOPA sert le minimum qu'exige le démarrage : allow + la révision épinglée.
func startStubOPA(t *testing.T, policyID string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			_, _ = w.Write([]byte(`{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":"` + policyID + `"}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// boot lance brokerd, attend qu'il serve, puis l'arrête : nil = il a démarré.
func boot(t *testing.T, fx *runFixture, sock string) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	up := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(sock); err == nil {
				close(up)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	select {
	case err := <-runErr:
		cancel()
		return err // refusé avant de servir
	case <-up:
		cancel()
		return <-runErr
	case <-time.After(20 * time.Second):
		cancel()
		t.Fatal("brokerd ne démarre ni ne refuse")
		return nil
	}
}

// signProof écrit une preuve de quorum pour UNE condition, signée par les n premiers contrôleurs.
func signProof(t *testing.T, fx *runFixture, path, condition string, n int) {
	t.Helper()
	expiry := time.Now().Add(60 * time.Second)
	msg := pep.QuorumMessage(condition, "cell-a", expiry)
	type sig struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}
	pf := struct {
		Expiry     int64 `json:"expiry"`
		Signatures []sig `json:"signatures"`
	}{Expiry: expiry.Unix()}
	for i := 0; i < n; i++ {
		kid := pep.KeyIDFromPublicKey(fx.controllerPrivs[i].Public().(ed25519.PublicKey))
		pf.Signatures = append(pf.Signatures, sig{KeyID: hex.EncodeToString(kid[:]), Signature: hex.EncodeToString(ed25519.Sign(fx.controllerPrivs[i], msg))})
	}
	data, err := json.Marshal(pf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerdRefusesToStartOnEditedProvisioningFile(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL

	original, err := os.ReadFile(fx.agentsFile)
	if err != nil {
		t.Fatal(err)
	}

	// 1. premier démarrage : genèse du témoin
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	if _, err := os.Stat(fx.env["TBP_PROVISIONING_WITNESS_FILE"]); err != nil {
		t.Fatalf("témoin non écrit : %v", err)
	}

	// 2. redémarrage inchangé : accepté (cas voisin)
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("redémarrage sans modification refusé : %v", err)
	}

	// 3. l'attaque de l'issue #192 : agent-1 passe d'une classe à une autre
	edited := strings.Replace(string(original), `"class":3`, `"class":0`, 1)
	if edited == string(original) {
		edited = string(original) + " " // au minimum un octet de plus
	}
	if err := os.WriteFile(fx.agentsFile, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	err = boot(t, fx, sock)
	if err == nil {
		t.Fatal("brokerd a démarré avec un registre d'agents modifié hors-bande")
	}
	if !strings.Contains(err.Error(), "agent-registry") || !strings.Contains(err.Error(), "divergents") {
		t.Fatalf("refus sans nommer le fichier : %v", err)
	}

	// 4. état d'origine restauré : repart
	if err := os.WriteFile(fx.agentsFile, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("état d'origine restauré mais démarrage refusé : %v", err)
	}
}

func TestBrokerdProvisioningTransitionNeedsAQuorumProof(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	original, _ := os.ReadFile(fx.agentsFile)
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	// changement légitime : on ajoute un agent
	if err := os.WriteFile(fx.agentsFile, []byte(strings.Replace(string(original), "{", `{"agent-9":{"class":3},`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	proof := filepath.Join(filepath.Dir(fx.env["TBP_PROVISIONING_WITNESS_FILE"]), "transition-proof.json")
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof

	// sans fichier de preuve : refusé
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("transition acceptée sans preuve")
	}
	// preuve insuffisante (1 signature, k = 2) : refusée
	signProof(t, fx, proof, conditionProvisioningTransition, 1)
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("transition acceptée avec 1 signature pour k = 2")
	}
	// preuve pour une AUTRE condition (bascule de posture) : refusée
	signProof(t, fx, proof, "mode-closed", 2)
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("une preuve de bascule de posture vaut transition de provisionnement")
	}
	// preuve pour pepd : refusée (condition liée au démon)
	signProof(t, fx, proof, "provisioning-transition-pepd", 2)
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("la preuve de pepd vaut pour brokerd")
	}
	// preuve valide (k = 2 signatures distinctes, bonne condition) : acceptée
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("transition avec preuve valide refusée : %v", err)
	}
	// la nouvelle référence tient SANS preuve
	delete(fx.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("nouvelle référence non retenue : %v", err)
	}
}

func TestBrokerdErasedWitnessOnUsedRegistryIsRefused(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	if err := boot(t, fx, sock); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fx.env["TBP_PROVISIONING_WITNESS_FILE"]); err != nil {
		t.Fatal(err)
	}
	// c'est le trou #111 : sans témoin, un fichier édité serait re-engagé comme « premier démarrage »
	if err := os.WriteFile(fx.agentsFile, []byte(`{"agent-1":{"class":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := boot(t, fx, sock)
	if err == nil || !strings.Contains(err.Error(), "témoin de provisionnement absent") {
		t.Fatalf("témoin effacé + fichier édité accepté : %v", err)
	}
}

func TestBrokerdDevEscapeHatchDisablesTheCheck(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	delete(fx.env, "TBP_PROVISIONING_WITNESS_FILE")
	fx.env["TBP_PROVISIONING_DISABLED_DEV_UNSAFE"] = "1"
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("échappatoire dev déclarée : %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(fx.agentsFile), "provisioning-witness.json")); err == nil {
		t.Fatal("un témoin a été écrit alors que la mesure est désactivée")
	}
}
