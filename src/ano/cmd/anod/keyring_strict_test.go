package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Revue tierce du 2 octobre, 4.4 : anod charge ses trousseaux avec le même décodeur strict que pepd.
func TestAnodKeyringLoadRefusesAmbiguousFiles(t *testing.T) {
	kid := "000102030405060708090a0b0c0d0e0f"
	pub1, pub2 := strings.Repeat("01", 32), strings.Repeat("02", 32)
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "k.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if kr, err := loadKeyring(write(`{"` + kid + `":"` + pub1 + `"}`)); err != nil || len(kr) != 1 {
		t.Fatalf("trousseau valide refusé : %v", err)
	}
	for name, body := range map[string]string{
		"casse différente": `{"` + kid + `":"` + pub1 + `","` + strings.ToUpper(kid) + `":"` + pub2 + `"}`,
		"clé dupliquée":    `{"` + kid + `":"` + pub1 + `","` + kid + `":"` + pub2 + `"}`,
		"vide":             `{}`,
	} {
		if _, err := loadKeyring(write(body)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
