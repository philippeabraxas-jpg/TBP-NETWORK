package main

import (
	"strings"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// envOf construit un getenv à partir d'une table.
func envOf(table map[string]string) func(string) string {
	return func(k string) string { return table[k] }
}

func TestDurabilityFromEnvDefaults(t *testing.T) {
	async, window, err := durabilityFromEnv(envOf(nil))
	if err != nil {
		t.Fatalf("défaut: erreur inattendue: %v", err)
	}
	if !async {
		t.Fatal("défaut: async attendu (async borné = défaut #71)")
	}
	if window != registry.DefaultOpposabilityWindow {
		t.Fatalf("défaut: fenêtre %v, attendu %v", window, registry.DefaultOpposabilityWindow)
	}
}

func TestDurabilityFromEnvModes(t *testing.T) {
	cases := []struct {
		name      string
		value     string
		wantAsync bool
		wantErr   bool
	}{
		{"async explicite", "async-bounded", true, false},
		{"sync", "sync", false, false},
		{"mode invalide", "fire-and-forget", false, true},
		{"casse non normalisée", "ASYNC-BOUNDED", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			async, window, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY": tc.value}))
			if tc.wantErr {
				if err == nil {
					t.Fatal("erreur attendue, obtenu nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("erreur inattendue: %v", err)
			}
			if async != tc.wantAsync {
				t.Fatalf("async=%v, attendu %v", async, tc.wantAsync)
			}
			if window != registry.DefaultOpposabilityWindow {
				t.Fatalf("fenêtre %v, attendu défaut %v", window, registry.DefaultOpposabilityWindow)
			}
		})
	}
}

func TestDurabilityFromEnvWindow(t *testing.T) {
	async, window, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY_WINDOW_MS": "250"}))
	if err != nil {
		t.Fatalf("fenêtre 250: erreur inattendue: %v", err)
	}
	if !async {
		t.Fatal("fenêtre 250: async attendu")
	}
	if window != 250*time.Millisecond {
		t.Fatalf("fenêtre %v, attendu 250ms", window)
	}
}

func TestDurabilityFromEnvWindowInvalid(t *testing.T) {
	for _, value := range []string{"0", "-5", "abc", "1.5"} {
		if _, _, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY_WINDOW_MS": value})); err == nil {
			t.Fatalf("fenêtre %q: erreur attendue, obtenu nil", value)
		}
	}
}

func TestDurabilityFromEnvErrorMentionsVariable(t *testing.T) {
	_, _, err := durabilityFromEnv(envOf(map[string]string{"TBP_DURABILITY": "nope"}))
	if err == nil || !strings.Contains(err.Error(), "TBP_DURABILITY") {
		t.Fatalf("erreur doit nommer la variable: %v", err)
	}
}
