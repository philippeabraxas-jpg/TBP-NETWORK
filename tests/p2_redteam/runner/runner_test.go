// runner_test.go — T28 (issue #28) : tests du runner red-team (D95).
//
// Deux familles :
//  1. nominal : la campagne complète passe, tous les mécanismes tiennent,
//     la corrélation feuilles ↔ scénarios est exacte, les trous déclarés
//     sont listés ;
//  2. mutations : chaque mutation M-* doit faire BASCULER son scénario —
//     un scénario qui passe mécanisme cassé ne protège rien.
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testConfig est un profil de campagne réduit mais non trivial (la
// submersion doit rester assez large pour être une submersion).
func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.OutDir = t.TempDir()
	cfg.FloodUp = 40
	cfg.FloodDown = 10
	return cfg
}

// runCampaign exécute la campagne et rend le rapport relu depuis le
// fichier écrit (pas l'objet en mémoire — la preuve est le fichier).
func runCampaign(t *testing.T, cfg Config) *RunReport {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(cfg.OutDir, "run_report.json"))
	if err != nil {
		t.Fatalf("run_report.json: %v", err)
	}
	var r RunReport
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("rapport illisible: %v", err)
	}
	return &r
}

// scenario retrouve la ligne d'un scénario dans le rapport.
func (r *RunReport) scenario(t *testing.T, id string) ScenarioResult {
	t.Helper()
	for _, s := range r.Scenarios {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("scénario %s absent du rapport", id)
	return ScenarioResult{}
}

// TestNominalCampaign : les six scénarios exécutés tiennent, chacun avec
// ses feuilles ; S1/S2 marqués lab-netns ; S3 trou déclaré.
func TestNominalCampaign(t *testing.T) {
	r := runCampaign(t, testConfig(t))

	executed := 0
	for _, s := range r.Scenarios {
		if s.Status == "executed" {
			executed++
			if s.Held == nil || !*s.Held {
				t.Errorf("%s (%s) non tenu en nominal : %s", s.ID, s.Name, s.Detail)
			}
			if len(s.Leaves) == 0 {
				t.Errorf("%s tenu sans aucune feuille — un test qui ne laisse pas de trace n'a rien prouvé", s.ID)
			}
		}
	}
	if executed != 6 {
		t.Errorf("%d scénarios exécutés ≠ 6 (S4–S9)", executed)
	}
	if r.scenario(t, "S1").Status != "lab-netns" || r.scenario(t, "S2").Status != "lab-netns" {
		t.Errorf("S1/S2 doivent être marqués lab-netns, pas faussement exécutés")
	}
	if r.scenario(t, "S3").Status != "declared-hole" {
		t.Errorf("S3 doit être un trou déclaré")
	}
	if len(r.DeclaredHoles) < 4 {
		t.Errorf("%d trous déclarés < 4 (USB, hotspot-prévention, physique, S1/S2-lab)", len(r.DeclaredHoles))
	}
	for _, h := range r.DeclaredHoles {
		if h.Description == "" {
			t.Errorf("trou %s sans description — un trou déclaré sans motif est un trou ignoré", h.ID)
		}
	}
}

// TestLeafCorrelationExact : la couverture du registre est sans trou et
// les comptes par kind recoupent le scan vérifié.
func TestLeafCorrelationExact(t *testing.T) {
	cfg := testConfig(t)
	r := runCampaign(t, cfg)

	b, err := os.ReadFile(filepath.Join(cfg.OutDir, "leaves_export.json"))
	if err != nil {
		t.Fatalf("leaves_export.json: %v", err)
	}
	var leaves []leafRecord
	if err := json.Unmarshal(b, &leaves); err != nil {
		t.Fatalf("export illisible: %v", err)
	}
	if got := correlate(r, leaves); got != "" {
		t.Fatalf("corrélation: %s", got)
	}
	for _, s := range r.Scenarios {
		if s.Status == "executed" && correlationFails(s, leaves) {
			t.Errorf("%s : comptes sink ≠ scan", s.ID)
		}
	}
}

// TestMutationsLethal : chaque mutation bascule SON scénario — et ne fait
// pas échouer la campagne pour une faute de harnais (err != nil).
func TestMutationsLethal(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string // scénario qui doit basculer
	}{
		{"M-S4 détecteur sourd", func(c *Config) { c.MutDetectorDeaf = true }, "S4"},
		{"M-S5 feuilles perdues", func(c *Config) { c.MutSilentFlood = true }, "S5"},
		{"M-S6 déviation avalée", func(c *Config) { c.MutAcceptDeviation = true }, "S6"},
		{"M-S7 canari auto-mesuré", func(c *Config) { c.MutCanarySelfMeasured = true }, "S7"},
		{"M-S8 anti-rejeu neutralisé", func(c *Config) { c.MutReplayAccept = true }, "S8"},
		{"M-S9 quorum d'office", func(c *Config) { c.MutSkipQuorum = true }, "S9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t)
			tc.mut(&cfg)
			r := runCampaign(t, cfg)
			s := r.scenario(t, tc.want)
			if s.Held == nil || *s.Held {
				t.Errorf("%s tenu sous %s — la mutation n'est pas létale, le scénario ne protège rien", tc.want, tc.name)
			}
			// Les autres scénarios doivent rester tenus : une mutation
			// cible un mécanisme, pas la campagne entière.
			for _, o := range r.Scenarios {
				if o.Status == "executed" && o.ID != tc.want && (o.Held == nil || !*o.Held) {
					t.Errorf("%s a basculé sous %s — mutation non ciblée : %s", o.ID, tc.name, o.Detail)
				}
			}
		})
	}
}

// TestConfigFailClosed : toute configuration incomplète est rejetée.
func TestConfigFailClosed(t *testing.T) {
	good := DefaultConfig()
	good.OutDir = t.TempDir()
	if err := good.Validate(); err != nil {
		t.Fatalf("config nominale rejetée: %v", err)
	}
	bads := []Config{
		{CellID: "c", FloodUp: 8, FloodDown: 2},              // OutDir vide
		{OutDir: "o", FloodUp: 8, FloodDown: 2},              // CellID vide
		{OutDir: "o", CellID: "c", FloodUp: 0, FloodDown: 2}, // submersion nulle
		{OutDir: "o", CellID: "c", FloodUp: 8, FloodDown: 1}, // phase B anecdotique
	}
	for i, c := range bads {
		if err := c.Validate(); err == nil {
			t.Errorf("config invalide %d acceptée", i)
		}
	}
}

// TestEvidenceLeafRoundTrip : leaf-evidence inscrit une feuille KindTelemetry
// retrouvée au scan, à l'index consigné dans evidence_log.jsonl — le
// mécanisme de preuve des scénarios réseau n'est pas du théâtre.
func TestEvidenceLeafRoundTrip(t *testing.T) {
	out := t.TempDir()
	cell := "tbp-cell-redteam-test"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	evidence := []byte(`{"scenario":"S1","compteur_mur":3,"journal_nac":"pvid=66"}`)
	idx, err := AppendEvidence(ctx, out, cell, "S1", evidence)
	if err != nil {
		t.Fatalf("AppendEvidence: %v", err)
	}

	leaves, err := exportLeaves(ctx, cell, filepath.Join(out, "registry"))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if int(idx) >= len(leaves) {
		t.Fatalf("index %d hors scan (%d feuilles)", idx, len(leaves))
	}
	if leaves[idx].Kind != 2 { // KindTelemetry
		t.Errorf("feuille %d kind %d ≠ KindTelemetry(2)", idx, leaves[idx].Kind)
	}

	// Le journal sidecar consigne la correspondance.
	b, err := os.ReadFile(filepath.Join(out, "evidence_log.jsonl"))
	if err != nil {
		t.Fatalf("evidence_log.jsonl: %v", err)
	}
	var entry evidenceEntry
	if err := json.Unmarshal(b[:len(b)-1], &entry); err != nil {
		t.Fatalf("entrée illisible: %v", err)
	}
	if entry.Scenario != "S1" || entry.LeafIdx != idx {
		t.Errorf("entrée %+v ≠ (S1, %d)", entry, idx)
	}

	// Le sel reste local, ≥ 16 octets, permissions strictes.
	fi, err := os.Stat(filepath.Join(out, "evidence_salt.hex"))
	if err != nil {
		t.Fatalf("sel absent: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("sel en %o ≠ 0600", fi.Mode().Perm())
	}

	// Fail-closed : scénario vide ou évidence vide refusés.
	if _, err := AppendEvidence(ctx, out, cell, "", evidence); err == nil {
		t.Errorf("évidence sans scénario acceptée")
	}
	if _, err := AppendEvidence(ctx, out, cell, "S1", nil); err == nil {
		t.Errorf("évidence vide acceptée")
	}
}
