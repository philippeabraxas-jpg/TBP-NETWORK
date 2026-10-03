package registry

// testdir_test.go — répertoires temporaires des tests qui hébergent un VRAI log POSIX Tessera (#266).
//
// Pourquoi pas t.TempDir() : CellLog.Close() fait shutdown(ctx) puis bgCancel(), mais ne PEUT PAS attendre la fin
// des goroutines d'arrière-plan de Tessera (suiveurs, publication de checkpoint : tessera.NewAppender les lance sans
// rendre de point de jonction). Elles s'arrêtent peu après l'annulation — pas avant. Le RemoveAll de t.TempDir(), lui,
// ne réessaie jamais : sous charge il tombe sur un fichier créé entre la lecture et le rmdir, et le test échoue sur
// « TempDir RemoveAll cleanup: unlinkat …: directory not empty » alors que ce qu'il vérifie est juste.

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// settleBudget borne l'attente de l'arrêt des goroutines Tessera : très au-delà de ce qu'elles mettent (quelques
// ms), pour qu'une machine saturée ne produise jamais de faux échec ; un répertoire qui résiste plus longtemps est
// un vrai défaut (un writer jamais arrêté) et fait ÉCHOUER le test, il n'est pas ignoré.
const settleBudget = 15 * time.Second

// logTempDir remplace t.TempDir() pour un répertoire de log : même emplacement, même nettoyage automatique, mais
// le nettoyage réessaie tant qu'un writer d'arrière-plan finit de s'arrêter.
func logTempDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tbp-registry-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { removeAllSettled(t, dir, settleBudget) })
	return dir
}

// removeAllSettled supprime dir, en réessayant jusqu'à budget si un writer y crée encore des fichiers.
func removeAllSettled(t testing.TB, dir string, budget time.Duration) {
	t.Helper()
	removeAllSettledWith(t, dir, budget, os.RemoveAll)
}

// removeAllSettledWith : la boucle de réessai, avec la suppression injectée (les tests la rendent déterministe —
// reproduire la course réelle au système de fichiers n'est pas répétable).
func removeAllSettledWith(t testing.TB, dir string, budget time.Duration, remove func(string) error) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		err := remove(dir)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("RemoveAll(%s) : %v — un writer d'arrière-plan n'est jamais arrêté (budget %s)", filepath.Base(dir), err, budget)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRemoveAllSettledRetriesWhileAWriterIsStopping : le cas de #266 — « directory not empty » tant que le writer
// finit de s'arrêter — ne fait pas échouer le nettoyage s'il cesse dans le budget. Mutant : une seule tentative.
func TestRemoveAllSettledRetriesWhileAWriterIsStopping(t *testing.T) {
	var calls atomic.Int32
	remove := func(string) error {
		if calls.Add(1) < 4 {
			return &os.PathError{Op: "unlinkat", Path: "/tmp/x/002", Err: syscall.ENOTEMPTY}
		}
		return nil
	}
	rec := &recordingTB{TB: t}
	removeAllSettledWith(rec, "/tmp/x", 5*time.Second, remove)
	if rec.failed.Load() {
		t.Fatal("un writer qui s'arrête dans le budget ne doit pas faire échouer le nettoyage")
	}
	if calls.Load() != 4 {
		t.Fatalf("tentatives = %d, attendu 4 (3 échecs puis le succès)", calls.Load())
	}
}

// TestRemoveAllSettledReportsAWriterThatNeverStops : un répertoire qui ne se vide jamais est un vrai défaut — le
// nettoyage le DIT (échec), il ne l'avale pas. Mutant : retourner sans Errorf au budget.
func TestRemoveAllSettledReportsAWriterThatNeverStops(t *testing.T) {
	remove := func(string) error {
		return &os.PathError{Op: "unlinkat", Path: "/tmp/x/002", Err: syscall.ENOTEMPTY}
	}
	rec := &recordingTB{TB: t}
	start := time.Now()
	removeAllSettledWith(rec, "/tmp/x", 200*time.Millisecond, remove)
	if !rec.failed.Load() {
		t.Fatal("un writer jamais arrêté doit faire ÉCHOUER le nettoyage, pas être ignoré")
	}
	if d := time.Since(start); d < 200*time.Millisecond || d > 5*time.Second {
		t.Fatalf("le nettoyage doit attendre le budget (200 ms) puis rendre la main, a pris %s", d)
	}
}

// recordingTB capte Errorf pour que le test puisse vérifier l'échec sans échouer lui-même.
type recordingTB struct {
	testing.TB
	failed atomic.Bool
}

func (r *recordingTB) Errorf(string, ...any) { r.failed.Store(true) }
