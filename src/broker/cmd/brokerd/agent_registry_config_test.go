package main

// agent_registry_config_test.go — chargement du registre d'agents (#125, #241).
// Un registre de provisionnement est un fichier de confiance écrit à la main : une
// faute de frappe ne doit jamais être lue comme la valeur zéro du champ.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func writeAgentRegistryFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agents.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// Le fichier de la revue : sans « class » et avec « clas » étaient chargés SANS erreur, les
// deux agents résolus en classe 0 (F), sans alarme.
func TestLoadAgentRegistryRefusesMissingOrMisspelledClass(t *testing.T) {
	for name, body := range map[string]string{
		"entrée vide":                           `{"agent-sans-classe":{}}`,
		"champ mal orthographié":                `{"agent-typo":{"clas":2}}`,
		"les deux du fichier de revue":          `{"agent-sans-classe":{},"agent-typo":{"clas":2}}`,
		"class sans valeur (null)":              `{"a":{"class":null}}`,
		"un bon agent ne couvre pas un mauvais": `{"ok":{"class":2},"agent-typo":{"clas":2}}`,
	} {
		_, err := loadAgentRegistry(writeAgentRegistryFile(t, body))
		if err == nil {
			t.Fatalf("%s : chargé sans erreur (#241)", name)
		}
		if !strings.Contains(err.Error(), "class") && !strings.Contains(err.Error(), "clas") {
			t.Fatalf("%s : l'erreur ne nomme pas le champ : %v", name, err)
		}
	}
}

func TestLoadAgentRegistryRefusesUnknownFieldsAndTrailingContent(t *testing.T) {
	for name, body := range map[string]string{
		"champ inconnu à côté d'une classe valide": `{"a":{"class":2,"quotta":{"max_volume":1,"max_window_s":1}}}`,
		"champ inconnu dans le quota":              `{"a":{"class":2,"quota":{"max_volum":1,"max_window_s":1}}}`,
		"transport_identity mal orthographié":      `{"a":{"class":2,"transport_identty":"cn"}}`,
		"classe hors bornes":                       `{"a":{"class":4}}`,
		"classe négative":                          `{"a":{"class":-1}}`,
		"classe en chaîne":                         `{"a":{"class":"2"}}`,
		"contenu après le document":                `{"a":{"class":2}} {"b":{"class":0}}`,
		"table vide":                               `{}`,
	} {
		if _, err := loadAgentRegistry(writeAgentRegistryFile(t, body)); err == nil {
			t.Fatalf("%s : chargé sans erreur", name)
		}
	}
}

// Voisins autorisés : la classe 0 EXPLICITE (F) reste une classe valide, distincte de l'absence ;
// un fichier complet est chargé tel quel.
func TestLoadAgentRegistryAcceptsExplicitClasses(t *testing.T) {
	reg, err := loadAgentRegistry(writeAgentRegistryFile(t, `{
		"f":    {"class": 0},
		"w":    {"class": 2},
		"net":  {"class": 3, "transport_identity": "agent-net", "quota": {"max_volume": 10, "max_window_s": 60}}
	}`))
	if err != nil {
		t.Fatalf("fichier valide refusé : %v", err)
	}
	for subject, want := range map[string]pep.Class{"f": 0, "w": 2, "net": 3} {
		rec, ok := reg.Resolve(subject)
		if !ok || rec.Class != want {
			t.Fatalf("%s : classe %v (ok=%v), veut %v", subject, rec.Class, ok, want)
		}
	}
	if rec, _ := reg.Resolve("net"); rec.TransportIdentity != "agent-net" || rec.Quota == nil || rec.Quota.MaxVolume != 10 {
		t.Fatalf("champs optionnels perdus : %+v", rec)
	}
}

// Le registre de skills suit la même doctrine : un champ inconnu (« scop » pour « scope »)
// n'est pas ignoré en silence.
func TestLoadSkillRegistryRefusesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"scope mal orthographié": `{"read.doc":{"provenance":"vendor-x","scop":["doc-1"],"risk_tier":"medium"}}`,
		"champ inconnu":          `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"medium","owner":"x"}}`,
		"contenu après":          `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"medium"}} []`,
	} {
		if _, err := loadSkillRegistry(writeSkillRegistryFile(t, dir, body)); err == nil {
			t.Fatalf("%s : chargé sans erreur", name)
		}
	}
	// voisin : le même enregistrement bien formé
	if _, err := loadSkillRegistry(writeSkillRegistryFile(t, dir, `{"read.doc":{"provenance":"vendor-x","scope":["doc-1"],"risk_tier":"medium"}}`)); err != nil {
		t.Fatalf("enregistrement valide refusé : %v", err)
	}
}
