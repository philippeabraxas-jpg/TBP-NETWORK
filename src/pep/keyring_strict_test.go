package pep

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

func keyHex(b byte) string { return hex.EncodeToString(append(make([]byte, 31), b)) }

const (
	kidA = "000102030405060708090a0b0c0d0e0f"
	kidB = "ffeeddccbbaa99887766554433221100"
)

func TestParseKeyringAcceptsAWellFormedKeyring(t *testing.T) {
	data := `{"` + kidA + `":"` + keyHex(1) + `","` + kidB + `":"` + keyHex(2) + `"}`
	kr, err := ParseKeyring([]byte(data))
	if err != nil || len(kr) != 2 {
		t.Fatalf("keyring valide refusé : %v (%d)", err, len(kr))
	}
	var k [16]byte
	copy(k[:], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	if got := kr[k]; len(got) != ed25519.PublicKeySize || got[31] != 1 {
		t.Fatalf("clé lue de travers : %x", got)
	}
}

// Revue tierce du 2 octobre, 4.4 : deux entrées de même identifiant, l'une en minuscules, l'autre en majuscules, étaient
// chargées sans erreur et la clé retenue dépendait de l'ordre d'itération d'une carte Go (3 fois sur 40 la première, 37 la
// seconde). Refusé, et de façon déterministe.
func TestParseKeyringRefusesTheSameKidInTwoCases(t *testing.T) {
	data := `{"` + kidA + `":"` + keyHex(1) + `","` + strings.ToUpper(kidA) + `":"` + keyHex(2) + `"}`
	for i := 0; i < 200; i++ { // l'ordre des cartes Go est aléatoire : le refus ne doit jamais l'être
		if _, err := ParseKeyring([]byte(data)); err == nil || !strings.Contains(err.Error(), "en double") {
			t.Fatalf("itération %d : erreur attendue « en double », got %v", i, err)
		}
	}
}

func TestParseKeyringRefusesAStrictlyDuplicatedKey(t *testing.T) {
	data := `{"` + kidA + `":"` + keyHex(1) + `","` + kidA + `":"` + keyHex(2) + `"}`
	if _, err := ParseKeyring([]byte(data)); err == nil {
		t.Fatal("identifiant strictement dupliqué accepté (la dernière clé gagnait)")
	}
}

// Une clé publique sous deux identifiants : une signature compterait deux fois dans un quorum k-sur-n.
func TestParseKeyringRefusesOnePublicKeyUnderTwoKids(t *testing.T) {
	data := `{"` + kidA + `":"` + keyHex(7) + `","` + kidB + `":"` + strings.ToUpper(keyHex(7)) + `"}`
	if _, err := ParseKeyring([]byte(data)); err == nil || !strings.Contains(err.Error(), "deux identifiants") {
		t.Fatalf("même clé sous deux kid acceptée : %v", err)
	}
}

func TestParseKeyringIsStrictOnShapeAndContent(t *testing.T) {
	ok := `"` + kidA + `":"` + keyHex(1) + `"`
	for name, data := range map[string]string{
		"vide":                 `{}`,
		"null":                 `null`,
		"tableau":              `[]`,
		"valeur non texte":     `{"` + kidA + `":1}`,
		"contenu final":        `{` + ok + `} {}`,
		"json cassé":           `{` + ok,
		"kid trop court":       `{"abcd":"` + keyHex(1) + `"}`,
		"kid non hexadécimal":  `{"` + strings.Repeat("zz", 16) + `":"` + keyHex(1) + `"}`,
		"clé trop courte":      `{"` + kidA + `":"abcd"}`,
		"clé non hexadécimale": `{"` + kidA + `":"` + strings.Repeat("zz", 32) + `"}`,
		"utf-8 invalide":       "{\"" + kidA + "\":\"\xff\"}",
	} {
		if _, err := ParseKeyring([]byte(data)); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
