package main

// provisioning_test.go — le démarrage mesuré d'anod (#272) : ses règles, son trousseau, ses réglages
// et k sont engagés dans un témoin ; toute divergence entre deux démarrages est REFUSÉE sans preuve
// de quorum liée à (état attesté, état cible).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// boot rejoue le chemin de démarrage d'anod jusqu'à la mesure incluse (jamais le service) :
// configuration → journal propre → setupProvisioning. Le journal est refermé : un démarrage = un processus.
func boot(t *testing.T, te *testEnv) error {
	t.Helper()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return bootWith(t, te, bin)
}

// bootWith : comme boot, avec le binaire à mesurer donné (un faux binaire que le test peut éditer).
func bootWith(t *testing.T, te *testEnv, bin string) error {
	t.Helper()
	ctx := context.Background()
	cfg, err := loadConfig(te.env.get)
	if err != nil {
		return err
	}
	cellLog, signer, verifier, err := openRegistry(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		_ = cellLog.Close(cctx)
	}()
	journal, err := registry.OpenRecordStoreFiles(cfg.auditRecords, cfg.auditKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	return setupProvisioning(ctx, cfg, bin, signer, verifier, cellLog, journal)
}

func (te *testEnv) write(t *testing.T, key, content string) {
	t.Helper()
	if err := os.WriteFile(te.env[key], []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const rulesV1 = `{"keep_paths":["action"],"mask_paths":["account"]}`
const rulesV2 = `{"keep_paths":["action","account"],"mask_paths":[]}` // fuite : le compte n'est plus masqué

// conditionOf extrait « condition à signer : … » du refus (« ce qu'on voit est ce qu'on signe », #236).
func conditionOf(t *testing.T, err error) string {
	t.Helper()
	const marker = "condition à signer : "
	if err == nil {
		t.Fatal("pas de refus : rien à signer")
	}
	i := strings.Index(err.Error(), marker)
	if i < 0 {
		t.Fatalf("le refus n'annonce pas la condition à signer : %v", err)
	}
	return strings.Fields(err.Error()[i+len(marker):])[0]
}

// signProof écrit une preuve de quorum signée par les contrôleurs donnés sur la condition.
func (te *testEnv) signProof(t *testing.T, condition string, signers ...ed25519.PrivateKey) string {
	t.Helper()
	expiry := time.Now().Add(60 * time.Second)
	msg := pep.QuorumMessage(condition, te.env["TBP_CELL_ID"], expiry)
	type sig struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}
	proof := struct {
		Expiry     int64 `json:"expiry"`
		Signatures []sig `json:"signatures"`
	}{Expiry: expiry.Unix()}
	for _, k := range signers {
		kid := pep.KeyIDFromPublicKey(k.Public().(ed25519.PublicKey))
		proof.Signatures = append(proof.Signatures, sig{hex.EncodeToString(kid[:]), hex.EncodeToString(ed25519.Sign(k, msg))})
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(te.dir, "proof-"+hex.EncodeToString(raw[len(raw)-8:])+".json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenesisThenConformingRestartStarts(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	if _, err := os.Stat(te.env["TBP_PROVISIONING_WITNESS_FILE"]); err != nil {
		t.Fatalf("pas de témoin après la genèse : %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := boot(t, te); err != nil {
			t.Fatalf("redémarrage conforme %d : %v", i+1, err)
		}
	}
}

// Chaque pièce qui décide ce qui sort est mesurée : l'éditer entre deux démarrages est refusé, le
// refus nomme la pièce (jamais son contenu), et rétablir l'état attesté redémarre.
func TestEachMeasuredPieceIsRefusedWhenEdited(t *testing.T) {
	cases := []struct {
		name, piece string
		edit        func(t *testing.T, te *testEnv) (restore func())
	}{
		{"règles (fuite : le compte n'est plus masqué)", "ano-rules", func(t *testing.T, te *testEnv) func() {
			te.write(t, "TBP_ANO_RULES_FILE", rulesV2)
			return func() { te.write(t, "TBP_ANO_RULES_FILE", rulesV1) }
		}},
		{"trousseau d'émetteurs", "issuer-keyring", func(t *testing.T, te *testEnv) func() {
			orig, _ := os.ReadFile(te.env["TBP_KEYRING_FILE"])
			te.write(t, "TBP_KEYRING_FILE", string(keyringJSON(t, controllerKey(9))))
			return func() { te.write(t, "TBP_KEYRING_FILE", string(orig)) }
		}},
		{"trousseau de contrôleurs (clé de l'attaquant ajoutée)", "quorum-keyring", func(t *testing.T, te *testEnv) func() {
			orig, _ := os.ReadFile(te.env["TBP_QUORUM_KEYRING_FILE"])
			te.write(t, "TBP_QUORUM_KEYRING_FILE", string(keyringJSON(t, te.ctl[0], te.ctl[1], controllerKey(66))))
			return func() { te.write(t, "TBP_QUORUM_KEYRING_FILE", string(orig)) }
		}},
		{"classifieur branché", "ano-settings", func(t *testing.T, te *testEnv) func() {
			te.env["TBP_ANO_CLASSIFIER_SOCKET"] = "/run/evil/classifier.sock"
			return func() { delete(te.env, "TBP_ANO_CLASSIFIER_SOCKET") }
		}},
		{"borne d'entrées", "ano-settings", func(t *testing.T, te *testEnv) func() {
			te.env["TBP_ANO_MAX_ENTRIES"] = "1000000"
			return func() { delete(te.env, "TBP_ANO_MAX_ENTRIES") }
		}},
		{"k abaissé dans l'environnement", "quorum-settings", func(t *testing.T, te *testEnv) func() {
			te.env["TBP_QUORUM_MIN"] = "1"
			return func() { te.env["TBP_QUORUM_MIN"] = "2" }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			te := newTestEnv(t)
			if err := boot(t, te); err != nil {
				t.Fatalf("genèse : %v", err)
			}
			restore := c.edit(t, te)
			err := boot(t, te)
			if err == nil {
				t.Fatal("démarrage accepté malgré la pièce modifiée — fuite silencieuse")
			}
			if !strings.Contains(err.Error(), c.piece) {
				t.Fatalf("le refus ne nomme pas %q : %v", c.piece, err)
			}
			if strings.Contains(err.Error(), "account") || strings.Contains(err.Error(), "evil") {
				t.Fatalf("le refus laisse fuir un contenu : %v", err)
			}
			restore()
			if err := boot(t, te); err != nil {
				t.Fatalf("état attesté rétabli, démarrage refusé : %v", err)
			}
		})
	}
}

// Un changement DÉLIBÉRÉ passe par une preuve de quorum liée à (état attesté, état cible), vérifiée
// contre le trousseau et le k ATTESTÉS — et ne se rejoue pas.
func TestDeliberateChangeNeedsAQuorumProofBoundToTheStates(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatal(err)
	}
	te.write(t, "TBP_ANO_RULES_FILE", rulesV2)
	refusal := boot(t, te)
	cond := conditionOf(t, refusal)
	if !strings.HasPrefix(cond, conditionProvisioningTransition+"|from=") || !strings.Contains(cond, "|to=") {
		t.Fatalf("condition annoncée %q : doit lier (départ, cible) sous %s", cond, conditionProvisioningTransition)
	}

	bad := map[string]string{
		"un seul contrôleur sur k = 2":                    te.signProof(t, cond, te.ctl[0]),
		"le même contrôleur deux fois":                    te.signProof(t, cond, te.ctl[0], te.ctl[0]),
		"la condition de pepd (jamais celle d'anod)":      te.signProof(t, strings.Replace(cond, conditionProvisioningTransition, "provisioning-transition-pepd", 1), te.ctl[0], te.ctl[1]),
		"la condition de brokerd":                         te.signProof(t, strings.Replace(cond, conditionProvisioningTransition, "provisioning-transition-brokerd", 1), te.ctl[0], te.ctl[1]),
		"un autre état cible":                             te.signProof(t, cond[:len(cond)-4]+"0000", te.ctl[0], te.ctl[1]),
		"des clés hors trousseau (l'attaquant seul)":      te.signProof(t, cond, controllerKey(66), controllerKey(67)),
		"un contrôleur légitime + une clé de l'attaquant": te.signProof(t, cond, te.ctl[0], controllerKey(66)),
	}
	for name, p := range bad {
		te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = p
		if err := boot(t, te); err == nil {
			t.Errorf("%s : transition acceptée", name)
		}
	}

	// la bonne preuve : k = 2 contrôleurs, sur LA condition annoncée
	te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = te.signProof(t, cond, te.ctl[0], te.ctl[1])
	if err := boot(t, te); err != nil {
		t.Fatalf("transition prouvée refusée : %v", err)
	}
	// le nouvel état est ATTESTÉ : il redémarre sans preuve
	delete(te.env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE")
	if err := boot(t, te); err != nil {
		t.Fatalf("redémarrage après transition : %v", err)
	}
	// et la preuve ne ramène pas à l'état précédent (liée à la paire, #236)
	te.write(t, "TBP_ANO_RULES_FILE", rulesV1)
	if err := boot(t, te); err == nil {
		t.Fatal("retour à l'ancien état accepté sans nouvelle preuve")
	}
	te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = te.signProof(t, cond, te.ctl[0], te.ctl[1])
	if err := boot(t, te); err == nil {
		t.Fatal("la preuve de l'aller a servi pour le retour (rejeu)")
	}
}

// Abaisser k par l'environnement ne légitime pas sa propre transition : la preuve se vérifie contre le
// k ATTESTÉ (2), pas contre celui de l'environnement (1) — #224.
func TestLoweringKDoesNotAuthorizeItself(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatal(err)
	}
	te.env["TBP_QUORUM_MIN"] = "1"
	cond := conditionOf(t, boot(t, te))
	te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = te.signProof(t, cond, te.ctl[0]) // une signature : k = 1 selon l'environnement
	if err := boot(t, te); err == nil {
		t.Fatal("k abaissé par l'environnement, autorisé par UNE signature : l'attaquant a signé sa propre transition")
	}
	te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = te.signProof(t, cond, te.ctl[0], te.ctl[1]) // k attesté = 2
	if err := boot(t, te); err != nil {
		t.Fatalf("transition signée par le k attesté refusée : %v", err)
	}
}

// Ajouter une clé au trousseau de contrôleurs puis signer avec elle ne passe pas : la preuve est
// vérifiée contre le trousseau ATTESTÉ, jamais contre le fichier que l'attaquant vient d'éditer (#218).
func TestEditedControllerKeyringCannotAuthorizeItself(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatal(err)
	}
	evil1, evil2 := controllerKey(66), controllerKey(67)
	te.write(t, "TBP_QUORUM_KEYRING_FILE", string(keyringJSON(t, te.ctl[0], te.ctl[1], evil1, evil2)))
	cond := conditionOf(t, boot(t, te))
	te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = te.signProof(t, cond, evil1, evil2)
	if err := boot(t, te); err == nil {
		t.Fatal("l'attaquant a ajouté ses clés au trousseau puis signé sa propre transition")
	}
}

// Effacer le témoin n'autorise pas un « premier démarrage » : le journal d'anod n'est pas vide.
func TestErasedWitnessIsNotAFirstBoot(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(te.env["TBP_PROVISIONING_WITNESS_FILE"]); err != nil {
		t.Fatal(err)
	}
	te.write(t, "TBP_ANO_RULES_FILE", rulesV2) // l'attaquant efface le témoin PUIS édite
	if err := boot(t, te); err == nil {
		t.Fatal("témoin effacé + règles éditées : démarrage accepté comme une genèse")
	}
}

// run() ne sert rien tant que la mesure n'est pas conforme : ni moteur, ni socket.
func TestRunServesNothingOnDivergence(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatal(err)
	}
	te.write(t, "TBP_ANO_RULES_FILE", rulesV2)
	// un délai : si la mesure était sautée, anod SERVIRAIT — le test doit alors échouer proprement
	// au lieu de figer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := run(ctx, te.env.get)
	if err == nil || !strings.Contains(err.Error(), "ano-rules") {
		t.Fatalf("run : %v, veut un refus nommant ano-rules", err)
	}
	if _, serr := net.Dial("unix", te.env["TBP_ANO_SOCKET"]); serr == nil {
		t.Fatal("un socket d'anod répond alors que le démarrage a été refusé")
	}
	if _, serr := os.Stat(te.env["TBP_ANO_SOCKET"]); serr == nil {
		t.Fatal("le socket a été créé avant la mesure")
	}
}

// Le binaire d'anod est mesuré : un binaire remplacé entre deux démarrages est refusé (comme le
// binaire du broker dans le démarrage mesuré de pepd).
func TestAnodBinaryIsMeasured(t *testing.T) {
	te := newTestEnv(t)
	bin := filepath.Join(te.dir, "anod-fake")
	if err := os.WriteFile(bin, []byte("anod v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := bootWith(t, te, bin); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	if err := bootWith(t, te, bin); err != nil {
		t.Fatalf("redémarrage conforme : %v", err)
	}
	if err := os.WriteFile(bin, []byte("anod v1 + porte dérobée"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := bootWith(t, te, bin); err == nil || !strings.Contains(err.Error(), "anod-binary") {
		t.Fatalf("binaire remplacé : %v, veut un refus nommant anod-binary", err)
	}
}

// --- recalcul hors démon de la condition à signer (#264) ------------------------

// previewOf lance `anod -print-provisioning-condition` comme un contrôleur sur son poste : même
// environnement, une COPIE du témoin, la clé publique de la cellule. Rend sortie clé=valeur et code.
func previewOf(t *testing.T, te *testEnv, vkey string, extra ...string) (map[string]string, int, string) {
	t.Helper()
	var out, errb strings.Builder
	code := printProvisioningCondition(append([]string{"-cell-vkey", vkey}, extra...), te.env.get, &out, &errb)
	kv := map[string]string{}
	for _, line := range strings.Split(out.String(), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && !strings.Contains(k, " ") {
			kv[k] = v
		}
	}
	return kv, code, errb.String()
}

func (te *testEnv) cellVKey() string {
	return filepath.Join(te.env["TBP_REGISTRY_DIR"], "cell_log.vkey")
}

// La condition imprimée par `-print-provisioning-condition` est, au caractère près, celle que le démon
// annonce en refusant ; un octet d'une pièce relue la change ; la signer autorise le démarrage.
func TestPrintedConditionIsTheOneTheDaemonRefusesWith(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	kv, code, stderr := previewOf(t, te, te.cellVKey())
	if code != 0 || kv["state"] != "conforming" || kv["condition"] != "" {
		t.Fatalf("état conforme : code=%d %v %s", code, kv, stderr)
	}
	witnessBefore, _ := os.ReadFile(te.env["TBP_PROVISIONING_WITNESS_FILE"])

	te.write(t, "TBP_ANO_RULES_FILE", rulesV2)
	fromDaemon := conditionOf(t, boot(t, te))
	kv, code, stderr = previewOf(t, te, te.cellVKey())
	if code != 0 || kv["state"] != "divergent" {
		t.Fatalf("état divergent : code=%d %v %s", code, kv, stderr)
	}
	if kv["condition"] != fromDaemon {
		t.Fatalf("condition recalculée ≠ condition du démon :\n recalculée %s\n démon      %s", kv["condition"], fromDaemon)
	}
	if !strings.Contains(kv["changed"], "ano-rules") || strings.Contains(kv["changed"], "ano-settings") {
		t.Fatalf("pièce modifiée mal désignée : %v", kv)
	}
	if after, _ := os.ReadFile(te.env["TBP_PROVISIONING_WITNESS_FILE"]); string(after) != string(witnessBefore) {
		t.Fatal("le recalcul a modifié le témoin")
	}

	// mutant : un octet de plus dans les règles ⇒ autre cible, autre condition ; départ inchangé
	te.write(t, "TBP_ANO_RULES_FILE", rulesV2+" ")
	kv2, _, _ := previewOf(t, te, te.cellVKey())
	if kv2["to"] == kv["to"] || kv2["condition"] == kv["condition"] {
		t.Fatal("un octet modifié n'a pas changé la condition à signer")
	}
	if kv2["from"] != kv["from"] {
		t.Fatal("l'état de départ doit rester celui du témoin")
	}
	// les réglages sont dans la mesure : la condition recalculée change avec TBP_ANO_MAX_ENTRIES
	te.write(t, "TBP_ANO_RULES_FILE", rulesV2)
	te.env["TBP_ANO_MAX_ENTRIES"] = "1000000"
	kv3, _, _ := previewOf(t, te, te.cellVKey())
	if kv3["to"] == kv["to"] {
		t.Fatal("les réglages ne comptent pas dans la condition recalculée")
	}
	delete(te.env, "TBP_ANO_MAX_ENTRIES")

	// signer la condition RECALCULÉE (jamais lue sur la machine contrôlée) autorise le démarrage
	kv, _, _ = previewOf(t, te, te.cellVKey())
	te.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = te.signProof(t, kv["condition"], te.ctl[0], te.ctl[1])
	if err := boot(t, te); err != nil {
		t.Fatalf("preuve sur la condition recalculée refusée : %v", err)
	}
}

// Le binaire fait partie de la mesure : `-binary` désigne celui que le contrôleur a relu.
func TestPrintConditionMeasuresTheBinaryGiven(t *testing.T) {
	te := newTestEnv(t)
	bin := filepath.Join(te.dir, "anod-bin")
	if err := os.WriteFile(bin, []byte("binaire v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := bootWith(t, te, bin); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	if kv, code, _ := previewOf(t, te, te.cellVKey(), "-binary", bin); code != 0 || kv["state"] != "conforming" {
		t.Fatalf("binaire inchangé : %d %v", code, kv)
	}
	if err := os.WriteFile(bin, []byte("binaire v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	fromDaemon := conditionOf(t, bootWith(t, te, bin))
	kv, code, _ := previewOf(t, te, te.cellVKey(), "-binary", bin)
	if code != 0 || kv["state"] != "divergent" || !strings.Contains(kv["changed"], "anod-binary") || kv["condition"] != fromDaemon {
		t.Fatalf("binaire modifié : code=%d %v (démon %s)", code, kv, fromDaemon)
	}
}

func TestPrintConditionRefusesWhatItCannotVerify(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatal(err)
	}
	if _, code, stderr := previewOf(t, te, te.cellVKey()); code != 0 {
		t.Fatalf("recalcul nominal refusé : %s", stderr)
	}
	var out, errb strings.Builder
	if code := printProvisioningCondition(nil, te.env.get, &out, &errb); code != 2 || out.Len() != 0 {
		t.Errorf("sans -cell-vkey : code=%d sortie=%q", code, out.String())
	}
	if _, code, _ := previewOf(t, te, filepath.Join(te.dir, "absent.vkey")); code != 2 {
		t.Errorf("clé absente : code=%d", code)
	}
	otherKey := filepath.Join(te.dir, "other.vkey")
	if _, vk, err := registry.GenerateCellKey("cell-a"); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(otherKey, []byte(vk), 0o600); err != nil {
		t.Fatal(err)
	}
	if kv, code, _ := previewOf(t, te, otherKey); code != 1 || kv["condition"] != "" {
		t.Errorf("témoin vérifié avec une autre clé : code=%d %v", code, kv)
	}
	w := te.env["TBP_PROVISIONING_WITNESS_FILE"]
	raw, _ := os.ReadFile(w)
	if err := os.WriteFile(w, []byte(strings.Replace(string(raw), `"record":"5442`, `"record":"5443`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if kv, code, _ := previewOf(t, te, te.cellVKey()); code != 1 || kv["condition"] != "" {
		t.Errorf("témoin altéré : code=%d %v", code, kv)
	}
}

// --- journal d'enregistrements (#275) -------------------------------------------

// Les feuilles de provisionnement d'anod laissent leur clair dans le journal (genèse, refus), vérifiable
// avec `tbp-audit verify` ; et sans journal configuré, anod ne démarre pas.
func TestAnodProvisioningLeavesAreJournaledAndJournalIsRequired(t *testing.T) {
	te := newTestEnv(t)
	if err := boot(t, te); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	key, err := registry.LoadRecordKey(te.env["TBP_AUDIT_RECORDS_KEY_FILE"])
	if err != nil {
		t.Fatal(err)
	}
	recs, err := registry.ReadRecords(te.env["TBP_AUDIT_RECORDS"], key)
	if err != nil || len(recs) != 1 || !strings.HasPrefix(string(recs[0].Record), "TBPL3") || recs[0].VerifyHash() != nil {
		t.Fatalf("genèse non journalisée : %d enregistrements, err=%v", len(recs), err)
	}
	// un refus laisse aussi son clair
	te.write(t, "TBP_ANO_RULES_FILE", rulesV2)
	if err := boot(t, te); err == nil {
		t.Fatal("règles modifiées acceptées")
	}
	if recs, err = registry.ReadRecords(te.env["TBP_AUDIT_RECORDS"], key); err != nil || len(recs) != 2 || !strings.HasPrefix(string(recs[1].Record), "TBPL3") {
		t.Fatalf("le refus ne laisse pas son clair : %d enregistrements (err=%v)", len(recs), err)
	}

	// le journal est requis : sans lui, la configuration est refusée avant tout
	for _, v := range []string{"TBP_AUDIT_RECORDS", "TBP_AUDIT_RECORDS_KEY_FILE"} {
		te2 := newTestEnv(t)
		delete(te2.env, v)
		if _, err := loadConfig(te2.env.get); err == nil || !strings.Contains(err.Error(), v) {
			t.Errorf("%s absent : %v", v, err)
		}
	}
}
