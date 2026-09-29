package main

// skill_registry_config_test.go — chargement du registre de skills
// (catalogue de conformité #142-#161, TBP_SKILL_REGISTRY_FILE). Doctrine
// identique à loadAgentRegistry : fail-closed sur toute pièce manquante ou
// mal formée AVANT tout effet de bord, jamais un défaut permissif.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
)

func writeSkillRegistryFile(t *testing.T, dir string, contents string) string {
	t.Helper()
	path := filepath.Join(dir, "skills.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadSkillRegistryValid(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(map[string]skillRegistryEntry{
		"read.doc": {Provenance: "vendor-x", Scope: []string{"doc-1", "doc-2"}, RiskTier: "medium"},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := writeSkillRegistryFile(t, dir, string(body))

	reg, err := loadSkillRegistry(path)
	if err != nil {
		t.Fatalf("loadSkillRegistry: %v", err)
	}
	rec, ok := reg.Resolve("read.doc")
	if !ok || rec.Provenance != "vendor-x" || len(rec.Scope) != 2 || rec.RiskTier != broker.TierMedium {
		t.Fatalf("Resolve(read.doc) = %+v, %v", rec, ok)
	}
	if _, ok := reg.Resolve("unregistered"); ok {
		t.Fatal("action absente du fichier résolue quand même")
	}
}

func TestLoadSkillRegistryRejectsEmptyTable(t *testing.T) {
	dir := t.TempDir()
	path := writeSkillRegistryFile(t, dir, `{}`)
	if _, err := loadSkillRegistry(path); err == nil {
		t.Fatal("table vide acceptée — au moins un skill provisionné requis")
	}
}

func TestLoadSkillRegistryRejectsMissingProvenance(t *testing.T) {
	dir := t.TempDir()
	path := writeSkillRegistryFile(t, dir, `{"read.doc":{"scope":["doc-1"],"risk_tier":"low"}}`)
	if _, err := loadSkillRegistry(path); err == nil {
		t.Fatal("skill sans provenance déclarée accepté — un skill de provenance inconnue n'est pas provisionnable (§1)")
	}
}

func TestLoadSkillRegistryRejectsEmptyAction(t *testing.T) {
	dir := t.TempDir()
	path := writeSkillRegistryFile(t, dir, `{"":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"low"}}`)
	if _, err := loadSkillRegistry(path); err == nil {
		t.Fatal("action vide acceptée")
	}
}

func TestLoadSkillRegistryRejectsMissingFile(t *testing.T) {
	if _, err := loadSkillRegistry(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("fichier absent accepté")
	}
}

func TestLoadSkillRegistryRejectsMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeSkillRegistryFile(t, dir, `{not json`)
	if _, err := loadSkillRegistry(path); err == nil {
		t.Fatal("JSON illisible accepté")
	}
}

func TestLoadSkillRegistryRejectsMissingOrUnknownRiskTier(t *testing.T) {
	for name, body := range map[string]string{
		"absent":     `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"]}}`,
		"vide":       `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":""}}`,
		"inconnu":    `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"extreme"}}`,
		"casse":      `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"Low"}}`,
		"un seul ko": `{"a":{"provenance":"v","scope":["x"],"risk_tier":"low"},"b":{"provenance":"v","scope":["x"]}}`,
	} {
		path := writeSkillRegistryFile(t, t.TempDir(), body)
		if _, err := loadSkillRegistry(path); err == nil {
			t.Errorf("%s : risk_tier manquant ou inconnu accepté — un skill sans niveau n'est pas provisionnable", name)
		}
	}
}

func TestLoadSkillRegistryRejectsScopeWiderThanTier(t *testing.T) {
	scope := make([]string, 9)
	for i := range scope {
		scope[i] = fmt.Sprintf("doc-%d", i)
	}
	body, _ := json.Marshal(map[string]skillRegistryEntry{"read.doc": {Provenance: "v", Scope: scope, RiskTier: "low"}})
	if _, err := loadSkillRegistry(writeSkillRegistryFile(t, t.TempDir(), string(body))); err == nil {
		t.Fatal("9 ressources déclarées « low » acceptées — incohérence niveau/périmètre")
	}
	body, _ = json.Marshal(map[string]skillRegistryEntry{"read.doc": {Provenance: "v", Scope: scope, RiskTier: "medium"}})
	if _, err := loadSkillRegistry(writeSkillRegistryFile(t, t.TempDir(), string(body))); err != nil {
		t.Fatalf("le même périmètre en « medium » doit passer : %v", err)
	}
}
