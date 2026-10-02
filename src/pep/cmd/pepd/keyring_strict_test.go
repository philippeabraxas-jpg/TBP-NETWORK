package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Revue tierce du 2 octobre, 4.4 : le trousseau chargé par pepd (émetteurs, contrôleurs) passe par le décodeur strict.
func TestPepdKeyringLoadRefusesAmbiguousFiles(t *testing.T) {
	kid := "000102030405060708090a0b0c0d0e0f"
	pub1 := strings.Repeat("01", 32)
	pub2 := strings.Repeat("02", 32)
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if kr, err := loadKeyring(write("ok.json", `{"`+kid+`":"`+pub1+`"}`)); err != nil || len(kr) != 1 {
		t.Fatalf("trousseau valide refusé : %v", err)
	}
	for name, body := range map[string]string{
		"casse différente":                `{"` + kid + `":"` + pub1 + `","` + strings.ToUpper(kid) + `":"` + pub2 + `"}`,
		"clé dupliquée":                   `{"` + kid + `":"` + pub1 + `","` + kid + `":"` + pub2 + `"}`,
		"même clé publique sous deux kid": `{"` + kid + `":"` + pub1 + `","ffeeddccbbaa99887766554433221100":"` + pub1 + `"}`,
	} {
		for i := 0; i < 40; i++ { // l'ancien décodeur retenait une clé au hasard : le refus doit être constant
			if _, err := loadKeyring(write("ko.json", body)); err == nil {
				t.Fatalf("%s : trousseau ambigu accepté (itération %d)", name, i)
			}
		}
	}
	// et le provisionnement relit le trousseau ATTESTÉ avec le même décodeur
	if _, err := parseKeyring([]byte(`{"` + kid + `":"` + pub1 + `","` + strings.ToUpper(kid) + `":"` + pub2 + `"}`)); err == nil {
		t.Fatal("parseKeyring (trousseau attesté) accepte un trousseau ambigu")
	}
}
