package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// L'unité systemd, la règle polkit et les défauts du programme doivent désigner les MÊMES noms : une dérive se paie en
// production (redémarrage refusé par polkit, silencieusement, au pire moment). Ce test la voit avant.
func TestUnitPolkitAndDefaultsAgree(t *testing.T) {
	unit, err := os.ReadFile("../../tbp-opa-watchdog.service")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := os.ReadFile("../../tbp-opa-watchdog.rules")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(envMap(baseEnv(nil)))
	if err != nil {
		t.Fatal(err)
	}
	u := regexp.MustCompile(`(?m)^User=(\S+)$`).FindSubmatch(unit)
	if u == nil {
		t.Fatal("User= absent de l'unité")
	}
	if !strings.Contains(string(rules), `action.lookup("unit") == "`+cfg.set.Unit+`"`) {
		t.Fatalf("la règle polkit ne vise pas l'unité par défaut %q", cfg.set.Unit)
	}
	if !strings.Contains(string(rules), `subject.user == "`+string(u[1])+`"`) {
		t.Fatalf("la règle polkit ne vise pas l'utilisateur de l'unité %q", u[1])
	}
	if !strings.Contains(string(rules), `action.lookup("verb") == "restart"`) {
		t.Fatal("la règle polkit doit être limitée au verbe restart")
	}
	// les variables de la chaîne propre du chien de garde sont documentées dans l'unité (celles que loadConfig exige)
	for _, v := range []string{"TBP_OPAWD_CELL_ID", "TBP_OPAWD_LOG_ID", "TBP_OPAWD_REGISTRY_DIR", "TBP_OPAWD_AUDIT_RECORDS=", "TBP_OPAWD_AUDIT_RECORDS_KEY_FILE", "TBP_OPAWD_SOURCES"} {
		if !strings.Contains(string(unit), v) {
			t.Errorf("unité : variable %s non documentée", v)
		}
	}
	for _, must := range []string{"CapabilityBoundingSet=\n", "NoNewPrivileges=yes", "RestrictAddressFamilies=AF_UNIX", "ProtectSystem=strict", "ExecStart=/usr/local/bin/opawatchdog", "StateDirectory=tbp/opa-watchdog", "ReadWritePaths=/var/lib/tbp/opa-watchdog"} {
		if !strings.Contains(string(unit), must) {
			t.Errorf("unité : %q attendu", must)
		}
	}
}
