// provisioning_test.go — mesure des fichiers de provisionnement (issue #192).
//
// Chaque test de refus a son cas voisin accepté : un garde qui refuserait tout
// passerait les tests de refus sans rien prouver.
package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fixtures ---------------------------------------------------------------

type provLeaves struct {
	mu   sync.Mutex
	fail bool
	got  []Leaf
}

func (l *provLeaves) Append(_ context.Context, leaf Leaf) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return 0, errors.New("journal en panne")
	}
	l.got = append(l.got, leaf)
	return uint64(len(l.got)), nil
}

func (l *provLeaves) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.got)
}

type provLog struct{ size uint64 }

func (p *provLog) Head(context.Context) ([32]byte, uint64, error) { return [32]byte{}, p.size, nil }

type provEnv struct {
	t      *testing.T
	dir    string
	files  []ProvisioningFile
	leaves *provLeaves
	log    *provLog
	trips  *manifestTripLog
	opts   ProvisioningGuardOptions
	// firstWitness : témoin de la genèse, pris par le test qui en a besoin
	firstWitness ProvisioningWitness
}

func newProvEnv(t *testing.T, mut func(*ProvisioningGuardOptions)) *provEnv {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) ProvisioningFile {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return ProvisioningFile{Name: name, Path: p}
	}
	files := []ProvisioningFile{
		write("agents.json", `{"agent-1":{"class":2}}`),
		write("operators.json", `["aa"]`),
	}
	signer, verifier := manifestTestKey(t)
	e := &provEnv{t: t, dir: dir, files: files, leaves: &provLeaves{}, log: &provLog{}, trips: &manifestTripLog{}}
	e.opts = ProvisioningGuardOptions{
		CellID: "cell-a", Component: "brokerd", Files: files,
		WitnessFile: filepath.Join(dir, "witness", "prov.json"),
		RegistryDir: filepath.Join(dir, "registry"),
		Signer:      signer, Verifier: verifier,
		Leaves: e.leaves, Log: e.log, Salt: manifestSalt,
		OnTrip: e.trips.add,
		Now:    func() time.Time { return time.Unix(1_800_000_000, 0) },
	}
	if err := os.MkdirAll(filepath.Dir(e.opts.WitnessFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if mut != nil {
		mut(&e.opts)
	}
	return e
}

func (e *provEnv) guard() *ProvisioningGuard {
	e.t.Helper()
	g, err := NewProvisioningGuard(e.opts)
	if err != nil {
		e.t.Fatalf("NewProvisioningGuard: %v", err)
	}
	return g
}

func (e *provEnv) readWitness() ProvisioningWitness {
	e.t.Helper()
	w, err := e.guard().loadWitness()
	if err != nil || w == nil {
		e.t.Fatalf("témoin illisible : %v", err)
	}
	return *w
}

// readWitnessAt rend le témoin en cache pris avant la transition (voir
// TestAuthorizedTransitionReEngagesTheReference : seq 0).
func (e *provEnv) readWitnessAt(int) ProvisioningWitness { return e.firstWitness }

func (e *provEnv) edit(name, content string) {
	e.t.Helper()
	for _, f := range e.files {
		if f.Name == name {
			if err := os.WriteFile(f.Path, []byte(content), 0o600); err != nil {
				e.t.Fatal(err)
			}
			return
		}
	}
	e.t.Fatalf("fichier %q inconnu", name)
}

// --- mesure -------------------------------------------------------------------

func TestMeasureProvisioningIsOrderIndependentAndContentSensitive(t *testing.T) {
	e := newProvEnv(t, nil)
	d1, _, err := MeasureProvisioning(e.files)
	if err != nil {
		t.Fatal(err)
	}
	rev := []ProvisioningFile{e.files[1], e.files[0]}
	d2, _, err := MeasureProvisioning(rev)
	if err != nil || d1 != d2 {
		t.Fatalf("le condensé dépend de l'ordre de la liste (err=%v)", err)
	}
	e.edit("agents.json", `{"agent-1":{"class":0}}`)
	d3, _, _ := MeasureProvisioning(e.files)
	if d3 == d1 {
		t.Fatal("un changement de classe (2 → 0) ne change pas le condensé")
	}
}

func TestMeasureProvisioningBindsTheLogicalName(t *testing.T) {
	e := newProvEnv(t, nil)
	d1, _, _ := MeasureProvisioning(e.files)
	renamed := []ProvisioningFile{{Name: "agents.jsox", Path: e.files[0].Path}, e.files[1]} // même longueur : seul le nom change
	d2, _, _ := MeasureProvisioning(renamed)
	if d1 == d2 {
		t.Fatal("le nom logique n'entre pas dans le condensé : deux rôles échangeables")
	}
}

func TestMeasureProvisioningRefusesBadInput(t *testing.T) {
	e := newProvEnv(t, nil)
	cases := map[string][]ProvisioningFile{
		"liste vide":     nil,
		"nom vide":       {{Name: "", Path: e.files[0].Path}},
		"nom en double":  {e.files[0], {Name: e.files[0].Name, Path: e.files[1].Path}},
		"fichier absent": {{Name: "x", Path: filepath.Join(e.dir, "absent.json")}},
		"répertoire":     {{Name: "d", Path: e.dir}},
		"nom trop long":  {{Name: strings.Repeat("n", 256), Path: e.files[0].Path}},
	}
	for name, files := range cases {
		if _, _, err := MeasureProvisioning(files); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

// --- cycle de vie ---------------------------------------------------------------

func TestGenesisThenConformantBoot(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("genèse: %v", err)
	}
	if _, err := os.Stat(e.opts.WitnessFile); err != nil {
		t.Fatalf("témoin non persisté: %v", err)
	}
	if e.leaves.count() != 1 {
		t.Fatalf("%d feuilles après la genèse, attendu 1", e.leaves.count())
	}
	e.log.size = 1 // le journal a vécu
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("démarrage conforme refusé: %v", err)
	}
	if e.leaves.count() != 2 {
		t.Fatalf("%d feuilles, attendu 2 (genèse + boot)", e.leaves.count())
	}
	if got := e.trips.taken(); len(got) != 0 {
		t.Fatalf("alarmes inattendues : %v", got)
	}
}

func TestModifiedFileRefusesBootAndNamesIt(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.log.size = 1
	before := e.leaves.count()
	secret := `{"agent-1":{"class":0}}` // classe W → F : la modification de l'issue #192
	e.edit("agents.json", secret)

	err := e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningDivergence) {
		t.Fatalf("modification acceptée ou mauvaise erreur : %v", err)
	}
	if !strings.Contains(err.Error(), "agents.json") {
		t.Fatalf("l'erreur ne nomme pas le fichier modifié : %v", err)
	}
	if strings.Contains(err.Error(), "class") || strings.Contains(err.Error(), "agent-1") {
		t.Fatalf("l'erreur fuit du CONTENU : %v", err)
	}
	if strings.Contains(err.Error(), "operators.json") {
		t.Fatalf("l'erreur accuse un fichier inchangé : %v", err)
	}
	if e.leaves.count() != before+1 {
		t.Fatal("pas de feuille de refus")
	}
	if got := e.trips.taken(); len(got) != 1 || got[0] != "provisioning-divergence" {
		t.Fatalf("alarme = %v", got)
	}
	// le refus ne réécrit pas le témoin : retour à l'état d'origine ⇒ ça repart
	e.edit("agents.json", `{"agent-1":{"class":2}}`)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("état d'origine restauré mais démarrage refusé : %v", err)
	}
}

func TestAddedAndRemovedFilesAreDivergences(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.log.size = 1
	// un fichier de plus
	extra := filepath.Join(e.dir, "skills.json")
	if err := os.WriteFile(extra, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	e.opts.Files = append(append([]ProvisioningFile{}, e.files...), ProvisioningFile{Name: "skills.json", Path: extra})
	err := e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningDivergence) || !strings.Contains(err.Error(), "ajouté(s) : skills.json") {
		t.Fatalf("ajout non signalé : %v", err)
	}
	// un fichier de moins
	e.opts.Files = e.files[:1]
	err = e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningDivergence) || !strings.Contains(err.Error(), "retiré(s) : operators.json") {
		t.Fatalf("retrait non signalé : %v", err)
	}
}

func TestAuthorizedTransitionReEngagesTheReference(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.log.size = 1
	e.firstWitness = e.readWitness()
	e.edit("agents.json", `{"agent-1":{"class":2},"agent-2":{"class":3}}`) // ajout légitime d'un agent

	var asked int
	e.opts.AuthorizeTransition = func() error { asked++; return nil }
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("transition autorisée refusée : %v", err)
	}
	if asked != 1 {
		t.Fatalf("autorisation demandée %d fois", asked)
	}
	// le témoin est CHAÎNÉ : seq + 1, prev = sceau du témoin précédent
	first := e.readWitnessAt(0)
	second := e.readWitness()
	if second.Seq != first.Seq+1 || second.Prev != HashManifest(marshalWitnessRecord(first)) {
		t.Fatalf("chaînage rompu : seq=%d prev=%x", second.Seq, second.Prev[:4])
	}
	// la nouvelle référence tient sans autorisation…
	e.opts.AuthorizeTransition = nil
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("nouvelle référence non retenue : %v", err)
	}
	// …et l'ancien contenu est maintenant une divergence
	e.edit("agents.json", `{"agent-1":{"class":2}}`)
	if err := e.guard().Check(context.Background()); !errors.Is(err, ErrProvisioningDivergence) {
		t.Fatalf("l'ancien état est encore accepté : %v", err)
	}
}

func TestRefusedAuthorizationKeepsTheBootRefused(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.log.size = 1
	e.edit("agents.json", `{"agent-1":{"class":0}}`)
	e.opts.AuthorizeTransition = func() error { return errors.New("quorum insuffisant") }
	err := e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningDivergence) || !strings.Contains(err.Error(), "quorum insuffisant") {
		t.Fatalf("transition non autorisée acceptée ou raison perdue : %v", err)
	}
}

func TestErasedWitnessOnUsedLogIsRefused(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.opts.WitnessFile); err != nil {
		t.Fatal(err)
	}
	e.log.size = 5 // ce n'est PAS un premier démarrage
	err := e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningWitnessMissing) {
		t.Fatalf("témoin effacé sur journal non vide : %v", err)
	}
	// cas voisin : journal vide ⇒ vrai premier démarrage
	if err := os.Remove(e.opts.WitnessFile); err == nil || !os.IsNotExist(err) {
		t.Fatalf("le refus a réécrit un témoin : %v", err)
	}
	e.log.size = 0
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("vrai premier démarrage refusé : %v", err)
	}
	// et avec une autorisation, le témoin effacé peut être ré-engagé
	if err := os.Remove(e.opts.WitnessFile); err != nil {
		t.Fatal(err)
	}
	e.log.size = 5
	e.opts.AuthorizeTransition = func() error { return nil }
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatalf("ré-engagement autorisé refusé : %v", err)
	}
}

// --- témoin falsifié -------------------------------------------------------------

func TestForgedOrForeignWitnessIsRefused(t *testing.T) {
	base := newProvEnv(t, nil)
	if err := base.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(base.opts.WitnessFile)
	if err != nil {
		t.Fatal(err)
	}
	base.log.size = 1

	// signé par une AUTRE clé
	otherSigner, _ := manifestOtherKey(t)
	e2 := newProvEnv(t, func(o *ProvisioningGuardOptions) { o.Signer = otherSigner })
	if err := e2.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreign, _ := os.ReadFile(e2.opts.WitnessFile)

	cases := map[string][]byte{
		"signé par une autre clé": foreign,
		"JSON illisible":          []byte(`{not json`),
		"hex illisible":           []byte(`{"record":"zz","signature":"zz"}`),
		"record altéré":           []byte(strings.Replace(string(good), `"record":"5442`, `"record":"5443`, 1)),
	}
	for name, content := range cases {
		if err := os.WriteFile(base.opts.WitnessFile, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := base.guard().Check(context.Background()); !errors.Is(err, ErrProvisioningWitnessBad) {
			t.Errorf("%s : accepté ou mauvaise erreur : %v", name, err)
		}
	}
	// cas voisin : le bon témoin repasse
	if err := os.WriteFile(base.opts.WitnessFile, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := base.guard().Check(context.Background()); err != nil {
		t.Fatalf("bon témoin refusé : %v", err)
	}
}

func TestWitnessOfAnotherComponentOrCellIsRefused(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.log.size = 1
	e.opts.Component = "pepd" // le témoin de brokerd présenté à pepd
	if err := e.guard().Check(context.Background()); !errors.Is(err, ErrProvisioningWitnessBad) {
		t.Fatalf("témoin d'un autre composant accepté : %v", err)
	}
	e.opts.Component = "brokerd"
	e.opts.CellID = "cell-b"
	if err := e.guard().Check(context.Background()); !errors.Is(err, ErrProvisioningWitnessBad) {
		t.Fatalf("témoin d'une autre cellule accepté : %v", err)
	}
}

// --- configuration ---------------------------------------------------------------

func TestWitnessMustLiveOutsideTheRegistryDir(t *testing.T) {
	e := newProvEnv(t, nil)
	e.opts.WitnessFile = filepath.Join(e.opts.RegistryDir, "prov.json")
	if _, err := NewProvisioningGuard(e.opts); !errors.Is(err, ErrProvisioningConfig) {
		t.Fatalf("témoin sous le registre accepté : %v", err)
	}
	// cas voisin : un dossier au préfixe ressemblant n'est pas « sous »
	e.opts.WitnessFile = e.opts.RegistryDir + "-witness/prov.json"
	if _, err := NewProvisioningGuard(e.opts); err != nil {
		t.Fatalf("chemin voisin refusé à tort : %v", err)
	}
}

func TestGuardConfigFailClosed(t *testing.T) {
	mutations := map[string]func(*ProvisioningGuardOptions){
		"cellID":     func(o *ProvisioningGuardOptions) { o.CellID = "" },
		"composant":  func(o *ProvisioningGuardOptions) { o.Component = "" },
		"témoin":     func(o *ProvisioningGuardOptions) { o.WitnessFile = "" },
		"signer":     func(o *ProvisioningGuardOptions) { o.Signer = nil },
		"feuilles":   func(o *ProvisioningGuardOptions) { o.Leaves = nil },
		"journal":    func(o *ProvisioningGuardOptions) { o.Log = nil },
		"sel court":  func(o *ProvisioningGuardOptions) { o.Salt = []byte("court") },
		"liste vide": func(o *ProvisioningGuardOptions) { o.Files = nil },
	}
	for name, mut := range mutations {
		e := newProvEnv(t, mut)
		if _, err := NewProvisioningGuard(e.opts); err == nil {
			t.Errorf("%s : configuration invalide acceptée", name)
		}
	}
}

// --- journal en panne --------------------------------------------------------------

func TestLeafFaultRefusesAndPersistsNothing(t *testing.T) {
	e := newProvEnv(t, nil)
	e.leaves.fail = true
	err := e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningLeafFault) {
		t.Fatalf("panne de journal à la genèse : %v", err)
	}
	if _, serr := os.Stat(e.opts.WitnessFile); !os.IsNotExist(serr) {
		t.Fatal("un témoin a été persisté sans feuille : pas de preuve, pas d'état attesté")
	}
	if got := e.trips.taken(); len(got) == 0 || got[0] != "provisioning-leaf-fault" {
		t.Fatalf("alarme = %v", got)
	}
}

func TestMissingFileAtBootIsAMeasureFault(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.log.size = 1
	if err := os.Remove(e.files[1].Path); err != nil {
		t.Fatal(err)
	}
	err := e.guard().Check(context.Background())
	if !errors.Is(err, ErrProvisioningMeasure) {
		t.Fatalf("fichier supprimé : %v", err)
	}
	if got := e.trips.taken(); len(got) != 1 || got[0] != "provisioning-measure-fault" {
		t.Fatalf("alarme = %v", got)
	}
}

// --- attribut hash-only ------------------------------------------------------------

func TestLeavesAreHashOnlyAndSalted(t *testing.T) {
	e := newProvEnv(t, nil)
	if err := e.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	other := newProvEnv(t, func(o *ProvisioningGuardOptions) { o.Salt = []byte("un-autre-sel-16+++") })
	if err := other.guard().Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.leaves.got[0].PayloadHash == other.leaves.got[0].PayloadHash {
		t.Fatal("la feuille ne dépend pas du sel : hash-only sans sel (§6.2)")
	}
	if e.leaves.got[0].Kind != KindManifest {
		t.Fatalf("kind = %d", e.leaves.got[0].Kind)
	}
}

// --- intégration avec un vrai CellLog ------------------------------------------------

func TestGuardOnARealCellLog(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	log, verifier := openTestLog(t, ctx, filepath.Join(dir, "registry"), nil)
	defer func() { _ = log.Close(ctx) }()
	signer, _ := manifestTestKey(t)

	agents := filepath.Join(dir, "agents.json")
	if err := os.WriteFile(agents, []byte(`{"a":{"class":2}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = verifier
	sig, ver := manifestTestKey(t)
	_ = signer
	opts := ProvisioningGuardOptions{
		CellID: "cell-a", Component: "brokerd",
		Files:       []ProvisioningFile{{Name: "agents.json", Path: agents}},
		WitnessFile: filepath.Join(dir, "prov.json"), RegistryDir: filepath.Join(dir, "registry"),
		Signer: sig, Verifier: ver, Leaves: log, Log: log, Salt: manifestSalt,
	}
	g, err := NewProvisioningGuard(opts)
	if err != nil {
		t.Fatal(err)
	}
	// journal réellement vide ⇒ genèse (Head d'un journal vide fonctionne)
	if err := g.Check(ctx); err != nil {
		t.Fatalf("genèse sur un vrai journal vide : %v", err)
	}
	// on attend la publication du checkpoint : le journal contient maintenant la feuille
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, size, herr := log.Head(ctx)
		if herr == nil && size >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("la feuille de genèse n'a pas atteint le journal (size=%d, err=%v)", size, herr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := g.Check(ctx); err != nil {
		t.Fatalf("redémarrage conforme : %v", err)
	}
	if err := os.WriteFile(agents, []byte(`{"a":{"class":0}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(ctx); !errors.Is(err, ErrProvisioningDivergence) {
		t.Fatalf("modification non détectée sur un vrai journal : %v", err)
	}
}
