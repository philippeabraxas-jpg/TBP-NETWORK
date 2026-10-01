package main

// provisioning_test.go — mesure des fichiers de provisionnement de brokerd
// (issue #192). Chaque refus a son cas voisin accepté.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
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

// TestBrokerdRefusesToStartOnOneByteChangeInEachMeasuredFile : critère de #192 —
// « éditer un octet de CHAQUE fichier ⇒ démarrage refusé ». Un seul octet (un retour
// à la ligne, qui laisse chaque fichier syntaxiquement valide) sur chacun des cinq
// fichiers que brokerd dérive de sa configuration, avec toutes les briques
// optionnelles actives (registre de skills, écoute mTLS). Chaque refus nomme SON
// fichier et aucun autre ; le cas voisin (état restauré) repart.
func TestBrokerdRefusesToStartOnOneByteChangeInEachMeasuredFile(t *testing.T) {
	files := []struct {
		name string
		path func(fx *runFixture, tls *brokerTLSFixture, skills string) string
	}{
		{"operator-keys", func(fx *runFixture, _ *brokerTLSFixture, _ string) string { return fx.opsFile }},
		{"agent-registry", func(fx *runFixture, _ *brokerTLSFixture, _ string) string { return fx.agentsFile }},
		{"genesis-manifest", func(fx *runFixture, _ *brokerTLSFixture, _ string) string {
			return filepath.Join(fx.genDir, "manifest.json")
		}},
		{"skill-registry", func(_ *runFixture, _ *brokerTLSFixture, skills string) string { return skills }},
		{"tls-client-ca", func(_ *runFixture, tls *brokerTLSFixture, _ string) string { return tls.caFile }},
	}
	all := []string{"operator-keys", "agent-registry", "genesis-manifest", "skill-registry", "tls-client-ca"}

	for i, tc := range files {
		// nom court : le chemin des sockets Unix est borné (≈108 octets) et
		// t.TempDir() y met le nom du sous-test
		t.Run(fmt.Sprintf("f%d", i), func(t *testing.T) {
			t.Logf("fichier mesuré : %s", tc.name)
			sock := filepath.Join(t.TempDir(), "broker.sock")
			fx := newRunFixture(t, sock)
			tlsFx := newBrokerTLSFixture(t)
			fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL

			skills := filepath.Join(t.TempDir(), "skills.json")
			if err := os.WriteFile(skills, []byte(`{"read":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"low"}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			fx.env["TBP_SKILL_REGISTRY_FILE"] = skills
			fx.env["TBP_BROKER_LISTEN_ADDR"] = "127.0.0.1:0"
			fx.env["TBP_BROKER_TLS_CERT_FILE"] = tlsFx.serverCertFile
			fx.env["TBP_BROKER_TLS_KEY_FILE"] = tlsFx.serverKeyFile
			fx.env["TBP_BROKER_TLS_CLIENT_CA_FILE"] = tlsFx.caFile

			target := tc.path(fx, tlsFx, skills)
			original, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}

			if err := boot(t, fx, sock); err != nil {
				t.Fatalf("premier démarrage : %v", err)
			}
			if err := boot(t, fx, sock); err != nil {
				t.Fatalf("redémarrage sans modification refusé : %v", err)
			}

			// UN octet de plus
			if err := os.WriteFile(target, append(append([]byte{}, original...), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			err = boot(t, fx, sock)
			if err == nil {
				t.Fatalf("brokerd a démarré alors que %s a changé d'un octet", tc.name)
			}
			if !strings.Contains(err.Error(), "modifié(s) : "+tc.name) {
				t.Fatalf("le refus ne nomme pas %s : %v", tc.name, err)
			}
			for _, other := range all {
				if other != tc.name && strings.Contains(err.Error(), other) {
					t.Fatalf("le refus accuse aussi %s, inchangé : %v", other, err)
				}
			}

			// cas voisin : l'état d'origine, octet pour octet, repart
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := boot(t, fx, sock); err != nil {
				t.Fatalf("état d'origine restauré mais démarrage refusé : %v", err)
			}
		})
	}
}

// Issue #218 : la preuve de transition était vérifiée contre le manifeste de genèse
// COURANT — celui que l'attaquant vient d'éditer. Il y ajoute ses clés, signe avec
// elles, et la mesure « l'autorise ». La preuve doit être vérifiée contre les
// contrôleurs du manifeste tel qu'il était ATTESTÉ.
func TestBrokerdManifestTransitionCannotBeSelfAuthorized(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	manifest := filepath.Join(fx.genDir, "manifest.json")
	legit, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}

	// l'attaquant ajoute k clés à lui au manifeste et signe avec elles
	var mf genesisManifest
	if err := json.Unmarshal(legit, &mf); err != nil {
		t.Fatal(err)
	}
	var attackerPrivs []ed25519.PrivateKey
	for i := 0; i < 2; i++ { // k = 2
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		mf.PubKeys = append(mf.PubKeys, hex.EncodeToString(pub))
		attackerPrivs = append(attackerPrivs, priv)
	}
	forged, _ := json.Marshal(mf)
	if err := os.WriteFile(manifest, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	proof := filepath.Join(filepath.Dir(fx.env["TBP_PROVISIONING_WITNESS_FILE"]), "transition-proof.json")
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof
	saved := fx.controllerPrivs
	fx.controllerPrivs = attackerPrivs
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	fx.controllerPrivs = saved
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("un manifeste de genèse édité par l'attaquant a été « autorisé » par une preuve qu'il a lui-même signée")
	}

	// cas voisin : les contrôleurs ATTESTÉS signent la même transition
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("transition signée par le quorum attesté refusée : %v", err)
	}
}

// --- procédure de secours (issue #199, deploy/recovery.md) -----------------------

// writeManifest réécrit le manifeste de genèse avec ces clés publiques, dans CET ordre.
func writeManifest(t *testing.T, fx *runFixture, pubs ...ed25519.PublicKey) {
	t.Helper()
	var mf genesisManifest
	for _, p := range pubs {
		mf.PubKeys = append(mf.PubKeys, hex.EncodeToString(p))
	}
	data, _ := json.Marshal(mf)
	if err := os.WriteFile(filepath.Join(fx.genDir, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func pubs(privs []ed25519.PrivateKey) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, p := range privs {
		out = append(out, p.Public().(ed25519.PublicKey))
	}
	return out
}

// Un contrôleur sur trois est perdu (2-sur-3). Le manifeste est réécrit EN PLACE (la
// clé perdue est remplacée au même rang : key_id indexe le manifeste) et la transition est
// signée par les deux contrôleurs restants, vérifiés contre le manifeste ATTESTÉ.
func TestBrokerdLostControllerKeyIsReplacedInPlace(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	proof := filepath.Join(filepath.Dir(fx.env["TBP_PROVISIONING_WITNESS_FILE"]), "transition-proof.json")
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof

	lost := fx.controllerPrivs[2] // le rang 3 ne signe pas l'epoch0 (rangs 1 et 2)
	_, fresh, _ := ed25519.GenerateKey(nil)
	fx.controllerPrivs = []ed25519.PrivateKey{fx.controllerPrivs[0], fx.controllerPrivs[1], fresh}
	writeManifest(t, fx, pubs(fx.controllerPrivs)...)
	signProof(t, fx, proof, conditionProvisioningTransition, 2) // rangs 1 et 2 : les contrôleurs restants
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("remplacement en place signé par les 2 contrôleurs restants refusé : %v", err)
	}
	delete(fx.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("nouvelle référence non retenue : %v", err)
	}

	// la clé perdue ne vaut plus : une transition ultérieure (remplacer encore le rang 3)
	// signée par elle + le rang 1 est refusée ; signée par le rang 1 + le rang 2, acceptée.
	_, fresh2, _ := ed25519.GenerateKey(nil)
	old := append([]ed25519.PrivateKey(nil), fx.controllerPrivs...)
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof
	writeManifest(t, fx, old[0].Public().(ed25519.PublicKey), old[1].Public().(ed25519.PublicKey), fresh2.Public().(ed25519.PublicKey))
	fx.controllerPrivs = []ed25519.PrivateKey{old[0], lost}
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("la clé de contrôleur perdue (retirée du manifeste) compte encore dans le quorum")
	}
	fx.controllerPrivs = []ed25519.PrivateKey{old[0], old[1]}
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("rangs 1 et 2 refusés : %v", err)
	}
}

// Remplacer un rang qui a signé l'epoch0 invalide l'epoch0 : il faut le re-signer par les
// contrôleurs restants (scripts/genesis renew) — sans quoi le démarrage est refusé.
func TestBrokerdEpoch0SignerReplacedNeedsResign(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	proof := filepath.Join(filepath.Dir(fx.env["TBP_PROVISIONING_WITNESS_FILE"]), "transition-proof.json")
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof
	signProof(t, fx, proof, conditionProvisioningTransition, 2) // rangs 1 et 2, attestés

	_, fresh, _ := ed25519.GenerateKey(nil)
	signers := []ed25519.PrivateKey{fx.controllerPrivs[0], fresh, fx.controllerPrivs[2]} // le rang 2 est remplacé
	writeManifest(t, fx, pubs(signers)...)
	if err := boot(t, fx, sock); err == nil || !strings.Contains(err.Error(), "epoch0") {
		t.Fatalf("epoch0 signé par une clé retirée accepté, ou autre cause : %v", err)
	}
	// k contrôleurs du NOUVEAU manifeste re-signent l'epoch0 : le démarrage repart
	reSigned := signEpochPayload(t, signers, 2, 2, cluster.EpochPayload{
		N: 0, Authority: "cell-a", IssuedAt: time.Now().UTC().Format(time.RFC3339), TTLSeconds: 60,
	})
	if err := os.WriteFile(filepath.Join(fx.genDir, "epoch0.json"), reSigned, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("epoch0 re-signé pour le nouveau manifeste refusé : %v", err)
	}
}

// Retirer un contrôleur EN DÉCALANT les rangs casse les signatures (key_id indexe le
// manifeste) : le démarrage est refusé même avec une preuve de transition valide. D'où la
// consigne du guide : remplacer en place, ne jamais supprimer ni réordonner.
func TestBrokerdRemovingAControllerByShiftingRanksIsRefused(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("premier démarrage : %v", err)
	}
	proof := filepath.Join(filepath.Dir(fx.env["TBP_PROVISIONING_WITNESS_FILE"]), "transition-proof.json")
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	writeManifest(t, fx, pubs(fx.controllerPrivs[1:])...) // supprime le rang 1 : les rangs glissent
	err := boot(t, fx, sock)
	if err == nil || !strings.Contains(err.Error(), "epoch0") {
		t.Fatalf("manifeste aux rangs décalés accepté, ou autre cause : %v", err)
	}
}

// Abaisser TBP_QUORUM_MIN dans l'environnement (2 → 1) affaiblissait tous les actes gouvernés
// sans alarme (issue #224). k est engagé dans le témoin ; la transition n'est autorisée que par
// le k ATTESTÉ, pas par celui que l'attaquant vient d'écrire.
func TestBrokerdLoweringQuorumMinByEnvironmentIsRefused(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	fx.env["TBP_OPA_ENDPOINT"] = startStubOPA(t, fx.env["TBP_POLICY_ID"]).URL
	if err := boot(t, fx, sock); err != nil { // k = 2 (genèse 2-sur-3)
		t.Fatalf("premier démarrage : %v", err)
	}
	proof := filepath.Join(filepath.Dir(fx.env["TBP_PROVISIONING_WITNESS_FILE"]), "transition-proof.json")
	fx.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = proof

	fx.env["TBP_QUORUM_MIN"] = "1"
	if err := boot(t, fx, sock); err == nil {
		t.Fatal("k abaissé par l'environnement accepté sans preuve")
	}
	signProof(t, fx, proof, conditionProvisioningTransition, 1) // une seule signature : suffit pour k = 1, pas pour l'attesté
	err := boot(t, fx, sock)
	if err == nil {
		t.Fatal("k abaissé de 2 à 1 AUTORISÉ par une seule signature : la preuve a été vérifiée avec le k de l'environnement")
	}

	// cas voisin : l'abaissement légitime, signé par le quorum attesté (2 signatures)
	signProof(t, fx, proof, conditionProvisioningTransition, 2)
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("abaissement signé par le quorum attesté refusé : %v", err)
	}
	delete(fx.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := boot(t, fx, sock); err != nil {
		t.Fatalf("nouveau k non retenu : %v", err)
	}
}
