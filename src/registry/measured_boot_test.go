// measured_boot_test.go — tests du measured boot (T31, §6.3 — issue #32).
//
// Critère 2 de l'issue mappé : un boot avec hash de conteneur IA modifié
// est DÉTECTÉ, refusé, alarmé — jamais un passage silencieux. Le
// RootMeasurer de test est un stub pilotable ; FileRootMeasurer (dev) est
// testé à part, y compris ses entrées mal formées.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// errRootMeasurer est un RootMeasurer pilotable : mesure fixe ou faute.
type errRootMeasurer struct {
	root [32]byte
	err  error
}

func (e errRootMeasurer) MeasureRoot(context.Context) ([32]byte, error) {
	return e.root, e.err
}

// bootFixture prépare quatre fichiers « artefacts » aux contenus connus, un
// Manifester genèse avec les hashes correspondants, et la racine attendue.
type bootFixture struct {
	m        *Manifester
	sink     *stubMaster
	trips    *manifestTripLog
	paths    ComponentPaths
	root     [32]byte
	contents map[string]string // chemin → contenu initial
}

// newBootFixture crée la cellule « démarrée une première fois » : genèse du
// manifeste à partir des artefacts posés sur disque, horloge fixe.
func newBootFixture(t *testing.T) bootFixture {
	t.Helper()
	dir := t.TempDir()
	contents := map[string]string{
		"policy": "bundle-de-regles-signe-v1",
		"opa":    "config-opa-v1",
		"broker": "binaire-broker-v1",
		"ai":     "image-conteneur-ia-v1",
	}
	f := bootFixture{
		sink:     &stubMaster{},
		trips:    &manifestTripLog{},
		root:     sha256.Sum256([]byte("racine-mesuree-tpm")),
		contents: map[string]string{},
	}
	write := func(name, content string) string {
		p := filepath.Join(dir, name+".bin")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", name, err)
		}
		f.contents[p] = content
		return p
	}
	f.paths = ComponentPaths{
		PolicyBundle: write("policy", contents["policy"]),
		OPAConfig:    write("opa", contents["opa"]),
		BrokerBinary: write("broker", contents["broker"]),
		AIContainer:  write("ai", contents["ai"]),
	}

	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	m, _, _ := newTestManifester(t, f.sink, clock, f.trips)
	st, err := MeasureComponents(f.paths)
	if err != nil {
		t.Fatalf("MeasureComponents: %v", err)
	}
	if _, err := m.Genesis(context.Background(), 7, st); err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	f.m = m
	return f
}

// rewrite remplace le contenu d'un artefact déployé (composant modifié).
func (f bootFixture) rewrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
}

// lastRefusalLeaf rend la dernière feuille et vérifie qu'elle est le refus
// attendu (event=refuse, verdict 0, reason exacte).
func (f bootFixture) lastRefusalLeaf(t *testing.T, reason string) Leaf {
	t.Helper()
	leaves := f.sink.taken()
	if len(leaves) == 0 {
		t.Fatal("aucune feuille — le refus de boot doit être tracé (§4.1)")
	}
	leaf := leaves[len(leaves)-1]
	manifestHash := HashManifest(f.m.lastSigned.Record)
	want := manifestLeafHash(t, manifestEventRefuse, manifestHash, 0, reason)
	if leaf.Kind != KindManifest || leaf.PayloadHash != want {
		t.Fatalf("feuille de refus inattendue (kind %d, reason %q)", leaf.Kind, reason)
	}
	return leaf
}

// ---------------------------------------------------------------------------
// Boot conforme et divergences (critère 2 de #32)
// ---------------------------------------------------------------------------

// TestCheckBootConformant : racine et composants conformes au manifeste
// attendu ⇒ démarrage accepté, tracé par une feuille event=boot « ok ».
func TestCheckBootConformant(t *testing.T) {
	f := newBootFixture(t)
	rm := errRootMeasurer{root: f.root}

	if err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths); err != nil {
		t.Fatalf("CheckBoot conforme : %v", err)
	}
	leaves := f.sink.taken()
	if len(leaves) != 2 { // genèse + boot
		t.Fatalf("%d feuilles, attendu 2", len(leaves))
	}
	manifestHash := HashManifest(f.m.lastSigned.Record)
	want := manifestLeafHash(t, manifestEventBoot, manifestHash, 1, "ok")
	if leaves[1].PayloadHash != want {
		t.Fatal("feuille de boot conforme ≠ event=boot verdict=1 « ok »")
	}
	if len(f.trips.taken()) != 0 {
		t.Fatalf("alarmes inattendues : %v", f.trips.taken())
	}
}

// TestCheckBootDivergentComponents — CRITÈRE 2 de #32 : chaque composant
// modifié (dont LE conteneur IA, cas nommé de l'issue) est détecté au boot ⇒
// refus + feuille event=refuse + alarme « manifest-boot-divergence ». Aucun
// passage silencieux.
func TestCheckBootDivergentComponents(t *testing.T) {
	cases := map[string]func(bootFixture, *testing.T) string{
		"policy_id modifié": func(f bootFixture, t *testing.T) string {
			f.rewrite(t, f.paths.PolicyBundle, "bundle-de-regles-signe-v2-tampered")
			return f.paths.PolicyBundle
		},
		"config OPA modifiée": func(f bootFixture, t *testing.T) string {
			f.rewrite(t, f.paths.OPAConfig, "config-opa-tampered")
			return f.paths.OPAConfig
		},
		"broker modifié": func(f bootFixture, t *testing.T) string {
			f.rewrite(t, f.paths.BrokerBinary, "binaire-broker-tampered")
			return f.paths.BrokerBinary
		},
		// CAS NOMMÉ du critère 2 : le conteneur IA local modifié.
		"conteneur IA modifié": func(f bootFixture, t *testing.T) string {
			f.rewrite(t, f.paths.AIContainer, "image-conteneur-ia-tampered")
			return f.paths.AIContainer
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBootFixture(t)
			tamper(f, t)
			rm := errRootMeasurer{root: f.root}

			err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths)
			if !errors.Is(err, ErrBootDivergence) {
				t.Fatalf("%v, attendu ErrBootDivergence", err)
			}
			f.lastRefusalLeaf(t, "boot-divergence")
			alarms := f.trips.taken()
			if len(alarms) != 1 || alarms[0] != "manifest-boot-divergence" {
				t.Fatalf("alarmes %v, attendu [manifest-boot-divergence]", alarms)
			}
			// L'état attesté n'a pas bougé : le boot divergent ne commit rien.
			st, ok := f.m.State()
			if !ok || st.AIContainerHash != sha256.Sum256([]byte("image-conteneur-ia-v1")) {
				t.Fatal("l'état du manifeste a changé malgré le refus de boot")
			}
		})
	}
}

// TestCheckBootRootDivergence : la racine mesurée ≠ la référence
// provisionnée ⇒ refus + alarme divergence.
func TestCheckBootRootDivergence(t *testing.T) {
	f := newBootFixture(t)
	rm := errRootMeasurer{root: sha256.Sum256([]byte("racine-inattendue"))}

	err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths)
	if !errors.Is(err, ErrBootDivergence) {
		t.Fatalf("%v, attendu ErrBootDivergence", err)
	}
	f.lastRefusalLeaf(t, "boot-divergence")
	if got := f.trips.taken(); len(got) != 1 || got[0] != "manifest-boot-divergence" {
		t.Fatalf("alarmes %v, attendu [manifest-boot-divergence]", got)
	}
}

// TestCheckBootMeasurementFault : mesure impossible (racine ou composant) ⇒
// refus + alarme faute — jamais une valeur de repli.
func TestCheckBootMeasurementFault(t *testing.T) {
	t.Run("mesure de racine en faute", func(t *testing.T) {
		f := newBootFixture(t)
		rm := errRootMeasurer{err: errors.New("tpm injoignable")}
		err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths)
		if !errors.Is(err, ErrBootMeasurement) {
			t.Fatalf("%v, attendu ErrBootMeasurement", err)
		}
		f.lastRefusalLeaf(t, "boot-measurement-fault")
		if got := f.trips.taken(); len(got) != 1 || got[0] != "manifest-boot-fault" {
			t.Fatalf("alarmes %v, attendu [manifest-boot-fault]", got)
		}
	})

	t.Run("artefact de composant illisible", func(t *testing.T) {
		f := newBootFixture(t)
		if err := os.Remove(f.paths.AIContainer); err != nil {
			t.Fatalf("Remove: %v", err)
		}
		rm := errRootMeasurer{root: f.root}
		err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths)
		if !errors.Is(err, ErrBootMeasurement) {
			t.Fatalf("%v, attendu ErrBootMeasurement", err)
		}
		f.lastRefusalLeaf(t, "boot-measurement-fault")
	})
}

// TestCheckBootWithoutGenesis : boot sans manifeste committed ⇒ refus
// fail-closed (rien à quoi confronter la mesure).
func TestCheckBootWithoutGenesis(t *testing.T) {
	sink := &stubMaster{}
	trips := &manifestTripLog{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	m, _, _ := newTestManifester(t, sink, clock, trips)

	f := newBootFixture(t) // pour les chemins d'artefacts
	rm := errRootMeasurer{root: f.root}
	err := CheckBoot(context.Background(), m, rm, f.root, f.paths)
	if !errors.Is(err, ErrBootNoManifest) {
		t.Fatalf("%v, attendu ErrBootNoManifest", err)
	}
	leaves := sink.taken()
	if len(leaves) != 1 {
		t.Fatalf("%d feuilles, attendu 1 (refus)", len(leaves))
	}
	want := manifestLeafHash(t, manifestEventRefuse, [32]byte{}, 0, "boot-no-manifest")
	if leaves[0].PayloadHash != want {
		t.Fatal("feuille de refus ≠ event=refuse hash nul « boot-no-manifest »")
	}
}

// TestCheckBootZeroExpectedRoot : référence de racine nulle = cellule non
// provisionnée ⇒ refus fail-closed (la configuration elle-même est §1).
func TestCheckBootZeroExpectedRoot(t *testing.T) {
	f := newBootFixture(t)
	rm := errRootMeasurer{root: f.root}
	err := CheckBoot(context.Background(), f.m, rm, [32]byte{}, f.paths)
	if !errors.Is(err, ErrBootMisconfiguration) {
		t.Fatalf("%v, attendu ErrBootMisconfiguration", err)
	}
	f.lastRefusalLeaf(t, "boot-misconfiguration")
}

// TestCheckBootNilArgs : CheckBoot refuse les dépendances absentes.
func TestCheckBootNilArgs(t *testing.T) {
	f := newBootFixture(t)
	if err := CheckBoot(context.Background(), nil, errRootMeasurer{root: f.root}, f.root, f.paths); err == nil {
		t.Fatal("Manifester nil accepté")
	}
	if err := CheckBoot(context.Background(), f.m, nil, f.root, f.paths); err == nil {
		t.Fatal("RootMeasurer nil accepté")
	}
}

// TestCheckBootLeafFaultFailsClosed : boot conforme mais feuille impossible
// ⇒ démarrage REFUSÉ (pas de preuve, pas d'état attesté), alarme.
func TestCheckBootLeafFaultFailsClosed(t *testing.T) {
	f := newBootFixture(t)
	f.sink.failing.Store(true)
	rm := errRootMeasurer{root: f.root}

	err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths)
	if !errors.Is(err, ErrManifestLeafFault) {
		t.Fatalf("%v, attendu ErrManifestLeafFault", err)
	}
	if got := f.trips.taken(); len(got) != 1 || got[0] != "manifest-leaf-fault" {
		t.Fatalf("alarmes %v, attendu [manifest-leaf-fault]", got)
	}
	// Guérison : le même boot conforme passe.
	f.sink.failing.Store(false)
	if err := CheckBoot(context.Background(), f.m, rm, f.root, f.paths); err != nil {
		t.Fatalf("CheckBoot après guérison : %v", err)
	}
}

// ---------------------------------------------------------------------------
// RootMeasurer dev et mesure des composants
// ---------------------------------------------------------------------------

// TestFileRootMeasurer : lecture nominale hex 64, et rejet de toute entrée
// mal formée (dev/test uniquement — jamais une preuve de machine).
func TestFileRootMeasurer(t *testing.T) {
	dir := t.TempDir()
	root := sha256.Sum256([]byte("racine-de-test"))

	good := filepath.Join(dir, "root.hex")
	if err := os.WriteFile(good, []byte(hex.EncodeToString(root[:])+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := FileRootMeasurer{Path: good}.MeasureRoot(context.Background())
	if err != nil {
		t.Fatalf("MeasureRoot: %v", err)
	}
	if got != root {
		t.Fatal("hash de racine lu ≠ hash écrit")
	}

	cases := map[string]string{
		"hex invalide":    "zzzz",
		"longueur fausse": hex.EncodeToString([]byte("trop-court")),
		"fichier vide":    "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "bad.hex")
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			if _, err := (FileRootMeasurer{Path: p}).MeasureRoot(context.Background()); err == nil {
				t.Fatal("mesure mal formée acceptée")
			}
		})
	}
	t.Run("fichier absent", func(t *testing.T) {
		if _, err := (FileRootMeasurer{Path: filepath.Join(dir, "absent.hex")}).MeasureRoot(context.Background()); err == nil {
			t.Fatal("mesure sur fichier absent acceptée")
		}
	})
}

// TestMeasureComponents : les hashes mesurés sont exactement les SHA-256 des
// contenus (doré inline), ChainHead est nul par construction, et un chemin
// vide est une faute (fail-closed).
func TestMeasureComponents(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return p
	}
	paths := ComponentPaths{
		PolicyBundle: write("p", "bundle-v1"),
		OPAConfig:    write("o", "opa-v1"),
		BrokerBinary: write("b", "broker-v1"),
		AIContainer:  write("a", "ai-v1"),
	}
	st, err := MeasureComponents(paths)
	if err != nil {
		t.Fatalf("MeasureComponents: %v", err)
	}
	if st.PolicyID != sha256.Sum256([]byte("bundle-v1")) ||
		st.OPAConfigHash != sha256.Sum256([]byte("opa-v1")) ||
		st.BrokerHash != sha256.Sum256([]byte("broker-v1")) ||
		st.AIContainerHash != sha256.Sum256([]byte("ai-v1")) {
		t.Fatal("hash mesuré ≠ SHA-256 du contenu")
	}
	if st.ChainHead != ([32]byte{}) {
		t.Fatal("ChainHead doit être nulle — non mesurée au boot (ancre d'audit)")
	}

	incomplete := paths
	incomplete.AIContainer = ""
	if _, err := MeasureComponents(incomplete); err == nil {
		t.Fatal("ComponentPaths incomplet accepté")
	}
	incomplete2 := paths
	incomplete2.BrokerBinary = filepath.Join(dir, "absent")
	if _, err := MeasureComponents(incomplete2); err == nil {
		t.Fatal("artefact absent accepté")
	}
}
