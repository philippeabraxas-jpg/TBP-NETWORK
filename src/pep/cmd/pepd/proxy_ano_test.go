package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ano "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano"
	svc "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano/svc"
	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

type leafRecorder struct {
	leaves []registry.Leaf
	err    error
}

func (l *leafRecorder) Append(_ context.Context, leaf registry.Leaf) (uint64, error) {
	if l.err != nil {
		return 0, l.err
	}
	l.leaves = append(l.leaves, leaf)
	return uint64(len(l.leaves)), nil
}

// testAuditStore ouvre un journal d'enregistrements neuf (#271) ; renvoie aussi
// son chemin et sa clé pour le relire.
func testAuditStore(t *testing.T) (*registry.RecordStore, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "records.jsonl")
	key := bytes.Repeat([]byte{5}, registry.RecordKeyLen)
	st, err := registry.OpenRecordStore(path, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path, key
}

func anoEnv(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// startAno lance un vrai serveur ano sur un socket Unix.
func startAno(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pepano")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	signer, _ := broker.NewDevSigner(bytes.Repeat([]byte{7}, 32))
	issuer, _ := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: signer})
	ver, err := pep.NewPossessionVerifier(map[[16]byte]ed25519.PublicKey{issuer.KeyID(): signer.Public()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := ano.NewRules(ano.RulesConfig{})
	engine, err := ano.New(ano.Options{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := svc.NewServer(svc.ServerOptions{Ano: engine, Verifier: ver})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(l) }()
	t.Cleanup(func() { _ = hs.Close() })
	return sock
}

func TestApplyAnoDisabledByDefault(t *testing.T) {
	var opts pep.ProxyOptions
	if err := applyAno(context.Background(), anoEnv(nil), &opts, &leafRecorder{}, nil, "cell-a", bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if opts.Rewriter != nil || opts.OnRewrite != nil {
		t.Fatal("sans TBP_PROXY_ANO_SOCKET le proxy doit rester inchangé (destination dans la cellule)")
	}
}

func TestApplyAnoConfigFailClosed(t *testing.T) {
	old := anoProbeWindow
	anoProbeWindow = 300 * time.Millisecond
	defer func() { anoProbeWindow = old }()
	salt := bytes.Repeat([]byte{1}, 32)
	sock := startAno(t)
	store, _, _ := testAuditStore(t)
	for name, env := range map[string]map[string]string{
		"délai sans socket": {"TBP_PROXY_ANO_TIMEOUT_MS": "500"},
		"délai trop court":  {"TBP_PROXY_ANO_SOCKET": sock, "TBP_PROXY_ANO_TIMEOUT_MS": "10"},
		"délai non entier":  {"TBP_PROXY_ANO_SOCKET": sock, "TBP_PROXY_ANO_TIMEOUT_MS": "vite"},
		"ano injoignable":   {"TBP_PROXY_ANO_SOCKET": "/nonexistent/ano.sock"},
	} {
		var opts pep.ProxyOptions
		if err := applyAno(context.Background(), anoEnv(env), &opts, &leafRecorder{}, store, "cell-a", salt); err == nil {
			t.Errorf("%s: doit refuser de démarrer", name)
		}
		if opts.Rewriter != nil {
			t.Errorf("%s: aucun Rewriter ne doit être posé sur une configuration refusée", name)
		}
	}
}

func TestApplyAnoWiresRewriterAndAuditLeaf(t *testing.T) {
	sock := startAno(t)
	salt := bytes.Repeat([]byte{2}, 32)
	rec := &leafRecorder{}
	store, journal, jkey := testAuditStore(t)
	var opts pep.ProxyOptions
	if err := applyAno(context.Background(), anoEnv(map[string]string{"TBP_PROXY_ANO_SOCKET": sock}), &opts, rec, store, "cell-a", salt); err != nil {
		t.Fatal(err)
	}
	if opts.Rewriter == nil || opts.OnRewrite == nil {
		t.Fatal("Rewriter/OnRewrite non posés")
	}
	ev := pep.RewriteEvent{Op: pep.RewriteOpMask, JTI: [16]byte{9}, Report: pep.RewriteReport{Leaves: 3, MaskedPath: 1}}
	if err := opts.OnRewrite(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if len(rec.leaves) != 1 || rec.leaves[0].Kind != registry.KindTelemetry || rec.leaves[0].CellID != "cell-a" ||
		rec.leaves[0].PayloadHash != registry.HashPayload(salt, svc.AuditRecord(ev)) {
		t.Fatalf("feuille d'audit inattendue: %+v", rec.leaves)
	}
	// le clair de la feuille est dans le journal et redonne son hash (#271)
	recs, err := registry.ReadRecords(journal, jkey)
	if err != nil || len(recs) != 1 {
		t.Fatalf("journal: %d enregistrements, err=%v", len(recs), err)
	}
	if recs[0].Leaf != rec.leaves[0] || recs[0].VerifyHash() != nil || !bytes.Equal(recs[0].Record, svc.AuditRecord(ev)) {
		t.Fatalf("enregistrement journalisé inattendu: %+v", recs[0])
	}
	// le registre ne peut pas écrire ⇒ l'audit échoue (le proxy refusera)
	rec.err = errors.New("registre indisponible")
	if err := opts.OnRewrite(context.Background(), ev); err == nil {
		t.Fatal("une feuille non écrite doit faire échouer l'audit (donc refuser la sortie)")
	}
	// le journal ne peut pas écrire ⇒ l'audit échoue ET aucune feuille n'est inscrite
	rec.err = nil
	before := len(rec.leaves)
	_ = store.Close()
	if err := opts.OnRewrite(context.Background(), ev); err == nil {
		t.Fatal("un clair non journalisé doit faire échouer l'audit (donc refuser la sortie)")
	}
	if len(rec.leaves) != before {
		t.Fatalf("une feuille a été inscrite sans clair journalisé (%d → %d)", before, len(rec.leaves))
	}
}

func TestApplyAnoRequiresAuditStore(t *testing.T) {
	sock := startAno(t)
	var opts pep.ProxyOptions
	err := applyAno(context.Background(), anoEnv(map[string]string{"TBP_PROXY_ANO_SOCKET": sock}), &opts, &leafRecorder{}, nil, "cell-a", bytes.Repeat([]byte{1}, 32))
	if err == nil || !strings.Contains(err.Error(), "TBP_AUDIT_RECORDS") {
		t.Fatalf("ano sans journal d'audit : %v, doit refuser de démarrer", err)
	}
	if opts.Rewriter != nil || opts.OnRewrite != nil {
		t.Fatal("aucun hook ne doit être posé sans journal d'audit")
	}
}

func TestOpenAuditStoreConfig(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "records.key")
	if err := registry.GenerateRecordKey(keyFile); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(dir, "records.jsonl")
	if st, err := openAuditStore(anoEnv(nil)); err == nil {
		_ = st.Close()
		t.Fatal("pepd sans journal d'audit accepté : il est requis (#275)")
	}
	for name, env := range map[string]map[string]string{
		"journal sans clé": {"TBP_AUDIT_RECORDS": journal},
		"clé sans journal": {"TBP_AUDIT_RECORDS_KEY_FILE": keyFile},
		"clé absente":      {"TBP_AUDIT_RECORDS": journal, "TBP_AUDIT_RECORDS_KEY_FILE": filepath.Join(dir, "absent")},
	} {
		if st, err := openAuditStore(anoEnv(env)); err == nil {
			_ = st.Close()
			t.Errorf("%s: doit être refusé", name)
		}
	}
	// les deux ensemble ou aucun : message explicite, pas une erreur d'ouverture de hasard
	for _, env := range []map[string]string{{"TBP_AUDIT_RECORDS": journal}, {"TBP_AUDIT_RECORDS_KEY_FILE": keyFile}} {
		if _, err := openAuditStore(anoEnv(env)); err == nil || !strings.Contains(err.Error(), "requis ensemble") {
			t.Errorf("déclaration à moitié : %v, attendu l'erreur « requis ensemble »", err)
		}
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if st, err := openAuditStore(anoEnv(map[string]string{"TBP_AUDIT_RECORDS": journal, "TBP_AUDIT_RECORDS_KEY_FILE": keyFile})); err == nil {
		_ = st.Close()
		t.Error("clé lisible par tous acceptée")
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := openAuditStore(anoEnv(map[string]string{"TBP_AUDIT_RECORDS": journal, "TBP_AUDIT_RECORDS_KEY_FILE": keyFile}))
	if err != nil || st == nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	_ = st.Close()
}
