package main

// print_condition_test.go — #264 : la condition de transition recalculée HORS du démon
// (`pepd -print-provisioning-condition -cell-vkey cell_log.vkey`) est celle que le démon annonce en
// refusant, et change avec un octet de ce que le contrôleur a relu.

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

// printFixture : l'environnement d'un contrôleur qui recalcule — les MÊMES variables que le démon.
func newPrintFixture(t *testing.T) *provFixture {
	t.Helper()
	pf := newProvFixture(t)
	pf.topology = "mono"
	pf.env["TBP_CELL_ID"] = pf.cellID
	pf.env["TBP_KEYRING_FILE"] = pf.keyring
	pf.env["TBP_QUORUM_KEYRING_FILE"] = pf.quorumKeyring
	pf.env["TBP_QUORUM_MIN"] = "2"
	pf.env["TBP_TOPOLOGY"] = "mono"
	return pf
}

func (pf *provFixture) vkeyPath() string { return filepath.Join(pf.regDir, "cell_log.vkey") }

// preview rend la sortie du recalcul : clé=valeur par bloc (le provisionnement puis, s'il y a lieu, le
// démarrage mesuré), plus le code de sortie.
func (pf *provFixture) preview(t *testing.T, vkey string, args ...string) (prov, boot map[string]string, code int, stderr string) {
	t.Helper()
	var out, errb strings.Builder
	code = printProvisioningCondition(append([]string{"-cell-vkey", vkey}, args...), pf.getenv, &out, &errb)
	parse := func(block string) map[string]string {
		kv := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && !strings.Contains(k, " ") {
				kv[k] = v
			}
		}
		return kv
	}
	blocks := strings.SplitN(out.String(), "\n\n", 2)
	prov = parse(blocks[0])
	if len(blocks) == 2 {
		boot = parse(blocks[1])
	}
	return prov, boot, code, errb.String()
}

func TestPepdPrintedProvisioningConditionIsTheOneTheDaemonRefusesWith(t *testing.T) {
	pf := newPrintFixture(t)
	delete(pf.env, "TBP_MEASURED_BOOT_MANIFEST_FILE") // provisionnement seul
	if err := pf.setup(t); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	witnessBefore, _ := os.ReadFile(pf.witness)

	prov, boot, code, stderr := pf.preview(t, pf.vkeyPath())
	if code != 0 || prov["state"] != "conforming" || prov["condition"] != "" || boot != nil {
		t.Fatalf("état conforme : code=%d %v %v %s", code, prov, boot, stderr)
	}

	// le contrôleur a relu le trousseau : on l'édite (clé de l'attaquant), le démon refuse
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	refusal := pf.setup(t)
	if refusal == nil {
		t.Fatal("pas de refus")
	}
	fromDaemon := conditionFromRefusal(t, refusal, conditionProvisioningTransition)
	prov, _, code, stderr = pf.preview(t, pf.vkeyPath())
	if code != 0 || prov["state"] != "divergent" {
		t.Fatalf("état divergent : code=%d %v %s", code, prov, stderr)
	}
	if prov["condition"] != fromDaemon {
		t.Fatalf("condition recalculée ≠ condition du démon :\n recalculée %s\n démon      %s", prov["condition"], fromDaemon)
	}
	if !strings.Contains(prov["changed"], "issuer-keyring") || strings.Contains(prov["changed"], "quorum-keyring") {
		t.Fatalf("pièce modifiée mal désignée : %v", prov)
	}
	if after, _ := os.ReadFile(pf.witness); string(after) != string(witnessBefore) {
		t.Fatal("le recalcul a modifié le témoin")
	}

	// mutant : un octet de plus ⇒ autre cible, autre condition
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prov2, _, _, _ := pf.preview(t, pf.vkeyPath())
	if prov2["to"] == prov["to"] || prov2["condition"] == prov["condition"] || prov2["from"] != prov["from"] {
		t.Fatalf("un octet modifié : to/condition inchangés ou départ déplacé : %v / %v", prov, prov2)
	}

	// les RÉGLAGES sont dans la mesure : abaisser k ou changer la topologie change la condition recalculée,
	// et chaque fois c'est celle que le démon refuse avec
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(){
		"k abaissé": func() { pf.env["TBP_QUORUM_MIN"] = "1"; pf.quorumMin = 1 },
		"topologie": func() { pf.env["TBP_TOPOLOGY"] = "multi"; pf.topology = "multi" },
	} {
		edit()
		daemon := conditionFromRefusal(t, pf.setup(t), conditionProvisioningTransition)
		printed, _, code, stderr := pf.preview(t, pf.vkeyPath())
		if code != 0 || printed["condition"] != daemon {
			t.Errorf("%s : recalculée %q ≠ démon %q (%s)", name, printed["condition"], daemon, stderr)
		}
		if !strings.Contains(printed["changed"], "quorum-settings") {
			t.Errorf("%s : pièce modifiée mal désignée : %v", name, printed)
		}
		pf.env["TBP_QUORUM_MIN"], pf.quorumMin = "2", 2
		pf.env["TBP_TOPOLOGY"], pf.topology = "mono", "mono"
	}

	// signer la condition RECALCULÉE (pas celle lue sur la machine contrôlée) autorise le démarrage
	if err := os.WriteFile(pf.keyring, []byte(`{"00":"aa","01":"bb"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prov, _, _, _ = pf.preview(t, pf.vkeyPath())
	pf.proofOn(t, prov["condition"], 2)
	if err := pf.setup(t); err != nil {
		t.Fatalf("preuve sur la condition recalculée refusée : %v", err)
	}
}

// Le démarrage mesuré a sa propre condition, recalculée de la même façon : état attesté = manifeste
// persisté (signature vérifiée), cible = les quatre composants relus.
func TestPepdPrintedMeasuredBootConditionIsTheOneTheDaemonRefusesWith(t *testing.T) {
	pf := newPrintFixture(t)
	if err := pf.setup(t); err != nil {
		t.Fatalf("genèse du provisionnement : %v", err)
	}
	if err := pf.run(t); err != nil {
		t.Fatalf("genèse du démarrage mesuré : %v", err)
	}
	_, boot, code, stderr := pf.preview(t, pf.vkeyPath())
	if code != 0 || boot["state"] != "conforming" || boot["condition"] != "" {
		t.Fatalf("démarrage mesuré conforme : code=%d %v %s", code, boot, stderr)
	}

	if err := os.WriteFile(pf.componentPaths[2], []byte("binaire du broker mis à jour"), 0o600); err != nil {
		t.Fatal(err)
	}
	refusal := pf.run(t)
	if refusal == nil {
		t.Fatal("pas de refus")
	}
	fromDaemon := conditionFromRefusal(t, refusal, reasonMeasuredBootTransition)
	prov, boot, code, stderr := pf.preview(t, pf.vkeyPath())
	if code != 0 || prov["state"] != "conforming" || boot["state"] != "divergent" {
		t.Fatalf("états : code=%d %v %v %s", code, prov, boot, stderr)
	}
	if boot["condition"] != fromDaemon {
		t.Fatalf("condition recalculée ≠ condition du démon :\n recalculée %s\n démon      %s", boot["condition"], fromDaemon)
	}
	if !strings.HasPrefix(boot["condition"], reasonMeasuredBootTransition+"|from=") {
		t.Fatalf("base inattendue : %s", boot["condition"])
	}

	// mutant : un octet de plus dans le composant relu
	if err := os.WriteFile(pf.componentPaths[2], []byte("binaire du broker mis à jour."), 0o600); err != nil {
		t.Fatal(err)
	}
	_, boot2, _, _ := pf.preview(t, pf.vkeyPath())
	if boot2["to"] == boot["to"] || boot2["condition"] == boot["condition"] || boot2["from"] != boot["from"] {
		t.Fatalf("un octet modifié n'a pas changé la condition : %v / %v", boot, boot2)
	}

	// signer la condition recalculée autorise la transition
	if err := os.WriteFile(pf.componentPaths[2], []byte("binaire du broker mis à jour"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, boot, _, _ = pf.preview(t, pf.vkeyPath())
	pf.measuredProof(t, boot["condition"])
	if err := pf.run(t); err != nil {
		t.Fatalf("preuve sur la condition recalculée refusée : %v", err)
	}
}

func TestPepdPrintConditionRefusesWhatItCannotVerify(t *testing.T) {
	pf := newPrintFixture(t)
	if err := pf.setup(t); err != nil {
		t.Fatal(err)
	}
	if err := pf.run(t); err != nil {
		t.Fatal(err)
	}
	if _, _, code, stderr := pf.preview(t, pf.vkeyPath()); code != 0 {
		t.Fatalf("recalcul nominal refusé : %s", stderr)
	}
	var out, errb strings.Builder
	if code := printProvisioningCondition(nil, pf.getenv, &out, &errb); code != 2 || out.Len() != 0 {
		t.Errorf("sans -cell-vkey : code=%d sortie=%q", code, out.String())
	}
	if _, _, code, _ := pf.preview(t, filepath.Join(t.TempDir(), "absent.vkey")); code != 2 {
		t.Errorf("clé absente : code=%d", code)
	}
	other := filepath.Join(t.TempDir(), "other.vkey")
	if _, vk, err := registry.GenerateCellKey(pf.cellID); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(other, []byte(vk), 0o600); err != nil {
		t.Fatal(err)
	}
	if prov, _, code, _ := pf.preview(t, other); code != 1 || prov["condition"] != "" {
		t.Errorf("témoin vérifié avec la clé d'une autre cellule : code=%d %v", code, prov)
	}
	// manifeste persisté altéré : le démarrage mesuré ne se laisse pas recalculer sur une copie falsifiée
	raw, _ := os.ReadFile(pf.manifest)
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sig := []byte(m["signature"]) // un nibble retourné : toujours de l'hexadécimal valide, mais plus la signature
	if sig[0] == '0' {
		sig[0] = '1'
	} else {
		sig[0] = '0'
	}
	m["signature"] = string(sig)
	forged, _ := json.Marshal(m)
	if err := os.WriteFile(pf.manifest, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, boot, code, stderr := pf.preview(t, pf.vkeyPath()); code != 1 || boot["condition"] != "" || !strings.Contains(stderr, "signature invalide") {
		t.Errorf("manifeste falsifié : code=%d %v %s", code, boot, stderr)
	}
}

// Le recalcul relit TBP_QUORUM_MIN et la topologie comme le démon (défaut k = 2, valeurs invalides
// refusées) : une dérive ferait signer au contrôleur une condition que le démon ne demande pas.
func TestPepdProvisioningInputsFromEnv(t *testing.T) {
	base := map[string]string{
		"TBP_CELL_ID": "cell-a", "TBP_KEYRING_FILE": "/k.json", "TBP_QUORUM_KEYRING_FILE": "/q.json", "TBP_TOPOLOGY": "mono",
	}
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for kk, vv := range base {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	in, err := provisioningInputsFromEnv(get(base))
	if err != nil || in.cellID != "cell-a" || in.keyringFile != "/k.json" || in.quorumKeyringFile != "/q.json" || in.quorumMin != 2 || in.topology != topologyName(false) {
		t.Fatalf("défauts : %+v, %v", in, err)
	}
	if in, err := provisioningInputsFromEnv(get(with("TBP_QUORUM_MIN", "3"))); err != nil || in.quorumMin != 3 {
		t.Fatalf("k = 3 : %+v, %v", in, err)
	}
	if in, err := provisioningInputsFromEnv(get(with("TBP_TOPOLOGY", "multi"))); err != nil || in.topology != topologyName(true) {
		t.Fatalf("multi : %+v, %v", in, err)
	}
	for name, m := range map[string]map[string]string{
		"k non numérique": with("TBP_QUORUM_MIN", "deux"),
		"k nul":           with("TBP_QUORUM_MIN", "0"),
		"topologie vide":  with("TBP_TOPOLOGY", ""),
		"cellule absente": with("TBP_CELL_ID", ""),
	} {
		if _, err := provisioningInputsFromEnv(get(m)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	// la liste des fichiers est celle du démon : mêmes noms, autorité sur le trousseau de contrôleurs
	files, err := pepdProvisioningFiles(provisioningInputs{keyringFile: "/k", quorumKeyringFile: "/q", quorumMin: 2, topology: "mono", posture: []byte("telemetry=off\n")}, func(string) string { return "" })
	if err != nil || len(files) != 4 || files[1].Name != "quorum-keyring" || !files[1].Authority || string(files[2].Content) != string(pep.QuorumSettings(2, "mono")) ||
		files[3].Name != pep.ProvisioningPostureName || string(files[3].Content) != "telemetry=off\n" {
		t.Fatalf("fichiers mesurés : %+v, %v", files, err)
	}
}

// proofOn signe EXACTEMENT cette condition (celle que le contrôleur a recalculée) avec n contrôleurs.
func (pf *provFixture) proofOn(t *testing.T, condition string, n int) {
	t.Helper()
	pf.env["TBP_PROVISIONING_TRANSITION_PROOF_FILE"] = pf.signedProofFile(t, condition, n, "recalc-proof.json")
}

// measuredProof : idem pour le démarrage mesuré.
func (pf *provFixture) measuredProof(t *testing.T, condition string) {
	t.Helper()
	pf.env["TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE"] = pf.signedProofFile(t, condition, 2, "recalc-measured-proof.json")
}

func (pf *provFixture) signedProofFile(t *testing.T, condition string, n int, name string) string {
	t.Helper()
	if condition == "" {
		t.Fatal("aucune condition recalculée à signer")
	}
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
	path := filepath.Join(filepath.Dir(pf.witness), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
