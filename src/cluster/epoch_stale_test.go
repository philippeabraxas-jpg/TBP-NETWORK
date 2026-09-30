package cluster

// Issue #207 (red team R-14) : un jeton d'époque dont le bail est DÉJÀ
// échu à la réception ne doit jamais remplacer une époque vivante. Le jeton
// est authentique (signé par le quorum), mais l'appliquer tue le service
// (l'époque installée est morte à l'instant même), grille le numéro N (un
// jeton frais au même N devient une « équivoque ») et, en mode auto,
// consomme le budget de bascule. Chaque test provoque cette faute précise.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

func staleFixture(t *testing.T) (*Tracker, *manualClock, *leafRecorder, *alarmRecorder, func(n int, auth string, issued time.Time, ttl int, mode string) []byte) {
	t.Helper()
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves, alarms := &leafRecorder{}, &alarmRecorder{}
	tr := newTracker(t, "cell-a", []string{"cell-a", "cell-b"}, clk, leaves, alarms)
	mk := func(n int, auth string, issued time.Time, ttl int, mode string) []byte {
		return mintEpochToken(t, privs, EpochPayload{N: n, Authority: auth, IssuedAt: issued.Format(time.RFC3339), TTLSeconds: ttl, Mode: mode})
	}
	return tr, clk, leaves, alarms, mk
}

// Un jeton échu à la réception est refusé et ne change RIEN : l'époque
// vivante continue de servir.
func TestExpiredTokenCannotReplaceALiveEpoch(t *testing.T) {
	tr, clk, leaves, _, mk := staleFixture(t)
	ctx := context.Background()
	if err := tr.Accept(ctx, mk(1, "cell-a", t0, 60, ModeManual)); err != nil {
		t.Fatal(err)
	}
	clk.set(t0.Add(30 * time.Second)) // l'époque 1 est vivante jusqu'à t0+60

	// N=2 authentique, émis il y a 10 min, TTL 60 : échu depuis longtemps.
	stale := mk(2, "cell-b", t0.Add(-10*time.Minute), 60, ModeManual)
	err := tr.Accept(ctx, stale)
	if err == nil || !strings.Contains(err.Error(), "epoch-token-expired") {
		t.Fatalf("jeton échu accepté ou refusé pour une autre raison : %v", err)
	}
	if n, err := tr.CurrentEpoch(); err != nil || n != 1 {
		t.Fatalf("après refus : CurrentEpoch=(%d,%v) — l'époque vivante a été remplacée par une époque morte", n, err)
	}
	want := registry.HashPayload(testSalt, epochRecord(epochEventRefuse, 2, "cell-b", "epoch-token-expired"))
	found := false
	for _, l := range leaves.all() {
		if l.PayloadHash == want {
			found = true
		}
	}
	if !found {
		t.Fatal("refus non tracé (feuille KindEpoch epoch-token-expired absente)")
	}
}

// Le numéro N n'est pas grillé : un jeton FRAIS au même N est accepté, pas
// traité en équivoque.
func TestStaleTokenDoesNotBurnItsNumber(t *testing.T) {
	tr, clk, _, alarms, mk := staleFixture(t)
	ctx := context.Background()
	if err := tr.Accept(ctx, mk(1, "cell-a", t0, 60, ModeManual)); err != nil {
		t.Fatal(err)
	}
	// Le jeton N=2 prévu n'a jamais été livré à temps ; quelqu'un le
	// présente après son expiration.
	held := mk(2, "cell-a", t0.Add(30*time.Second), 10, ModeManual)
	clk.set(t0.Add(50 * time.Second))
	if err := tr.Accept(ctx, held); err == nil {
		t.Fatal("jeton échu (émis t0+30 s, TTL 10 s, présenté à t0+50 s) accepté")
	}
	// L'opérateur en signe un frais au même N.
	fresh := mk(2, "cell-a", t0.Add(50*time.Second), 60, ModeManual)
	if err := tr.Accept(ctx, fresh); err != nil {
		t.Fatalf("jeton frais au même N refusé (%v) — le jeton échu a grillé N=2", err)
	}
	for _, a := range alarms.all() {
		if a == "epoch-equivocation" {
			t.Fatal("fausse alarme d'équivoque causée par un jeton échu")
		}
	}
}

// Le budget de bascule automatique n'est pas consommé par un jeton refusé.
func TestStaleAutoTokenDoesNotConsumeTheFailoverBudget(t *testing.T) {
	tr, clk, _, _, mk := staleFixture(t)
	ctx := context.Background()
	if err := tr.Accept(ctx, mk(1, "cell-a", t0, 60, ModeManual)); err != nil {
		t.Fatal(err)
	}
	clk.set(t0.Add(30 * time.Second))
	for n := 2; n <= 6; n++ { // 5 jetons échus > budget de 3 par heure
		_ = tr.Accept(ctx, mk(n, "cell-b", t0.Add(-time.Hour), 60, ModeAuto))
	}
	if got := statusOf(t, tr).AutoFailoversHour; got != 0 {
		t.Fatalf("AutoFailoversHour=%d — des jetons refusés ont épuisé le budget de bascule", got)
	}
	// Une vraie bascule auto est toujours possible.
	if err := tr.Accept(ctx, mk(2, "cell-b", t0.Add(30*time.Second), 60, ModeAuto)); err != nil {
		t.Fatalf("bascule auto légitime refusée : %v", err)
	}
}

// Bord exact : accepté une seconde avant l'échéance, refusé à l'échéance.
func TestTokenLeaseBoundary(t *testing.T) {
	tr, clk, _, _, mk := staleFixture(t)
	ctx := context.Background()
	if err := tr.Accept(ctx, mk(1, "cell-a", t0, 300, ModeManual)); err != nil {
		t.Fatal(err)
	}
	issued := t0.Add(10 * time.Second)
	clk.set(issued.Add(59 * time.Second)) // bail de 60 s : reste 1 s
	if err := tr.Accept(ctx, mk(2, "cell-a", issued, 60, ModeManual)); err != nil {
		t.Fatalf("jeton à 1 s de son échéance refusé : %v — un bail court est légitime", err)
	}
	clk.set(issued.Add(120 * time.Second))
	err := tr.Accept(ctx, mk(3, "cell-a", issued.Add(60*time.Second), 60, ModeManual)) // expire exactement à issued+120
	if err == nil || !strings.Contains(err.Error(), "epoch-token-expired") {
		t.Fatalf("jeton expirant exactement à l'instant de réception : %v", err)
	}
}

// Amorçage documenté : sans époque en cours, l'epoch 0 de la genèse est
// importé même si son bail est échu (brokerd démarre des jours après la
// cérémonie, puis le bail est renouvelé par POST /v1/epoch/renew). La
// cellule ne sert pas tant qu'aucun bail vivant n'est installé.
func TestGenesisImportStillAcceptedWhenNoEpochYet(t *testing.T) {
	tr, clk, _, _, mk := staleFixture(t)
	ctx := context.Background()
	clk.set(t0.Add(72 * time.Hour))
	if err := tr.Accept(ctx, mk(0, "cell-a", t0, 60, "")); err != nil {
		t.Fatalf("epoch 0 échu refusé à l'amorçage : %v — brokerd ne démarrerait plus après la cérémonie", err)
	}
	if _, err := tr.CurrentEpoch(); !errors.Is(err, ErrEpochExpired) {
		t.Fatalf("CurrentEpoch=%v, veut ErrEpochExpired (fail-closed)", err)
	}
	// Puis un bail frais renouvelle.
	if err := tr.Accept(ctx, mk(1, "cell-a", t0.Add(72*time.Hour), 60, ModeManual)); err != nil {
		t.Fatalf("renouvellement après amorçage : %v", err)
	}
	if n, err := tr.CurrentEpoch(); err != nil || n != 1 {
		t.Fatalf("CurrentEpoch=(%d,%v)", n, err)
	}
}
