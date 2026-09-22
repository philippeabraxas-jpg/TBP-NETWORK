package cluster

// Tests du fencing T29 (§7.2–§7.5). Doctrine : tests NON-VACUOLES — les
// horloges sont injectées (manuelles), chaque critère d'acceptation de
// l'issue #30 est exercé en positif ET en mutation (le refus attendu est
// provoqué par une faute précise), et les feuilles sont prouvées par
// re-hash avec le sel révélé (§6.2 : preuve à révélation).

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ---------------------------------------------------------------------------
// Seams de test
// ---------------------------------------------------------------------------

var testSalt = []byte("t29-cluster-salt-0123456789abcdef")

// Seeds Ed25519 fixes de test (aucune valeur de production).
var ctrlSeeds = []string{
	"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
	"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
	"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
}

func testControllers(t *testing.T) (pubs map[int]ed25519.PublicKey, privs map[int]ed25519.PrivateKey) {
	t.Helper()
	pubs, privs = map[int]ed25519.PublicKey{}, map[int]ed25519.PrivateKey{}
	for i, s := range ctrlSeeds {
		seed, err := hex.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("seed %d illisible", i+1)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		privs[i+1], pubs[i+1] = priv, priv.Public().(ed25519.PublicKey)
	}
	return pubs, privs
}

// leafRecorder enregistre les feuilles — la preuve observable.
type leafRecorder struct {
	mu     sync.Mutex
	leaves []registry.Leaf
	err    error
}

func (r *leafRecorder) Append(_ context.Context, l registry.Leaf) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return 0, r.err
	}
	r.leaves = append(r.leaves, l)
	return uint64(len(r.leaves)), nil
}

func (r *leafRecorder) all() []registry.Leaf {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]registry.Leaf(nil), r.leaves...)
}

func (r *leafRecorder) countKind(kind byte) int {
	n := 0
	for _, l := range r.all() {
		if l.Kind == kind {
			n++
		}
	}
	return n
}

// manualClock est l'horloge NTS injectée (§6.2) — déterministe.
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t0 time.Time) *manualClock { return &manualClock{t: t0} }

func (c *manualClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// alarmRecorder capte les alarmes (couture T14).
type alarmRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (a *alarmRecorder) fire(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reasons = append(a.reasons, reason)
}

func (a *alarmRecorder) all() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.reasons...)
}

var t0 = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)

// mintEpochToken frappe un jeton d'époque signé par les contrôleurs donnés
// (défaut : quorum 1,2). La forme canonique signée est le payload seul —
// exactement comme scripts/genesis (T3).
func mintEpochToken(t *testing.T, privs map[int]ed25519.PrivateKey, p EpochPayload, signers ...int) []byte {
	t.Helper()
	if len(signers) == 0 {
		signers = []int{1, 2}
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("payload : %v", err)
	}
	tok := EpochToken{Payload: p, Quorum: "2-of-3"}
	for _, id := range signers {
		sig := ed25519.Sign(privs[id], canonical)
		tok.Signatures = append(tok.Signatures, ControllerSignature{KeyID: id, Sig: hex.EncodeToString(sig)})
	}
	data, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("token : %v", err)
	}
	return data
}

// mintRawEpochToken signe un payload canonique BRUT (pour les formes que
// la struct ne peut pas émettre — p.ex. "roster":[], que omitempty élude
// au marshal mais qu'un attaquant peut écrire à la main).
func mintRawEpochToken(t *testing.T, privs map[int]ed25519.PrivateKey, canonical string, signers ...int) []byte {
	t.Helper()
	if len(signers) == 0 {
		signers = []int{1, 2}
	}
	var sigs []string
	for _, id := range signers {
		sig := ed25519.Sign(privs[id], []byte(canonical))
		sigs = append(sigs, fmt.Sprintf(`{"key_id":%d,"sig":%q}`, id, hex.EncodeToString(sig)))
	}
	return []byte(fmt.Sprintf(`{"payload":%s,"quorum":"2-of-3","signatures":[%s]}`, canonical, strings.Join(sigs, ",")))
}

// newTracker assemble un tracker de test 2-of-3 sur les membres donnés.
func newTracker(t *testing.T, cellID string, members []string, clk *manualClock, leaves *leafRecorder, alarms *alarmRecorder, opts ...func(*TrackerConfig)) *Tracker {
	t.Helper()
	pubs, _ := testControllers(t)
	cfg := TrackerConfig{
		CellID: cellID, Salt: testSalt, Leaves: leaves,
		Controllers: pubs, Quorum: 2, Members: members,
		Now: clk.now, OnAlarm: alarms.fire,
	}
	for _, f := range opts {
		f(&cfg)
	}
	tr, err := NewTracker(cfg)
	if err != nil {
		t.Fatalf("NewTracker(%s): %v", cellID, err)
	}
	return tr
}

// epochRecord reconstruit le record « TBPE1 » attendu pour une feuille
// KindEpoch — la preuve à révélation du sel (§6.2).
func epochRecord(event byte, n uint64, authority, reason string) []byte {
	rec := append([]byte("TBPE1"), event)
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], n)
	rec = append(rec, nb[:]...)
	rec = append(rec, byte(len(authority)))
	rec = append(rec, authority...)
	rec = append(rec, byte(len(reason)))
	rec = append(rec, reason...)
	return rec
}

// ---------------------------------------------------------------------------
// Configuration fail-closed
// ---------------------------------------------------------------------------

// statusOf lit l'état du tracker pour assertion — la lecture locale
// est infaillible (D110 élargi, T37) ; toute erreur est une faute de test.
func statusOf(t *testing.T, tr *Tracker) TrackerStatus {
	t.Helper()
	st, err := tr.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st
}

func TestTrackerConfigFailClosed(t *testing.T) {
	pubs, _ := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	full := TrackerConfig{
		CellID: "cell-a", Salt: testSalt, Leaves: leaves,
		Controllers: pubs, Quorum: 2, Members: []string{"cell-a", "cell-b"},
		Now: clk.now,
	}
	if _, err := NewTracker(full); err != nil {
		t.Fatalf("config complète refusée : %v", err)
	}
	cases := map[string]func(*TrackerConfig){
		"cellID vide":         func(c *TrackerConfig) { c.CellID = "" },
		"sel court":           func(c *TrackerConfig) { c.Salt = []byte("court") },
		"feuilles absentes":   func(c *TrackerConfig) { c.Leaves = nil },
		"sans contrôleurs":    func(c *TrackerConfig) { c.Controllers = nil },
		"quorum 0":            func(c *TrackerConfig) { c.Quorum = 0 },
		"quorum > n":          func(c *TrackerConfig) { c.Quorum = 4 },
		"sans membres":        func(c *TrackerConfig) { c.Members = nil },
		"cellID hors membres": func(c *TrackerConfig) { c.CellID = "cell-z" },
		"TTL incohérents":     func(c *TrackerConfig) { c.MinTTLSeconds, c.MaxTTLSeconds = 100, 10 },
		"budget négatif":      func(c *TrackerConfig) { c.MaxAutoFailoversPerHour = -1 },
	}
	for name, mutate := range cases {
		cfg := full
		mutate(&cfg)
		if _, err := NewTracker(cfg); err == nil {
			t.Fatalf("%s : config acceptée", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Époques (§7.2)
// ---------------------------------------------------------------------------

// TestGenesisEpochZeroImport : le jeton d'époque 0 produit par
// scripts/genesis (T3) s'importe TEL QUEL — le test frappe le JSON à la
// main, dans le layout exact de genesis.go (4 champs, sans mode ni
// roster), pour verrouiller la continuité de format.
func TestGenesisEpochZeroImport(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves, alarms := &leafRecorder{}, &alarmRecorder{}

	// Canonique EXACT de genesis.go : {"n":0,"authority":"cell-a","issued_at":"...","ttl_s":60}
	canonical := fmt.Sprintf(`{"n":0,"authority":"cell-a","issued_at":%q,"ttl_s":60}`, t0.Format(time.RFC3339))
	var sigs []string
	for _, id := range []int{1, 2} {
		sig := ed25519.Sign(privs[id], []byte(canonical))
		sigs = append(sigs, fmt.Sprintf(`{"key_id":%d,"sig":%q}`, id, hex.EncodeToString(sig)))
	}
	tokenJSON := []byte(fmt.Sprintf(`{"payload":%s,"quorum":"2-of-3","signatures":[%s],"warning":"DEV"}`,
		canonical, strings.Join(sigs, ",")))

	trA := newTracker(t, "cell-a", []string{"cell-a", "cell-b"}, clk, leaves, alarms)
	if err := trA.Accept(context.Background(), tokenJSON); err != nil {
		t.Fatalf("epoch 0 de la genèse refusé : %v", err)
	}
	epoch, err := trA.CurrentEpoch()
	if err != nil || epoch != 0 {
		t.Fatalf("CurrentEpoch=(%d,%v), veut (0,nil) — cell-a est l'autorité", epoch, err)
	}

	// La même importation côté cell-b : elle OBSERVE l'époque mais ne
	// sert pas (§7.2 : seul le détenteur sert).
	trB := newTracker(t, "cell-b", []string{"cell-a", "cell-b"}, clk, &leafRecorder{}, &alarmRecorder{})
	if err := trB.Accept(context.Background(), tokenJSON); err != nil {
		t.Fatalf("epoch 0 refusé côté cell-b : %v", err)
	}
	if _, err := trB.CurrentEpoch(); !errors.Is(err, ErrNotAuthority) {
		t.Fatalf("cell-b CurrentEpoch err=%v, veut ErrNotAuthority", err)
	}
	if n, ok := trB.ObservedEpoch(); !ok || n != 0 {
		t.Fatalf("ObservedEpoch=(%d,%v), veut (0,true)", n, ok)
	}

	// Feuille KindEpoch d'acceptation, prouvée par re-hash avec le sel
	// révélé (§6.2) : le mode absent du jeton genèse ⇒ manual, jamais
	// compté dans le budget de bascule.
	ls := leaves.all()
	if len(ls) != 1 || ls[0].Kind != registry.KindEpoch {
		t.Fatalf("feuilles=%+v, veut 1 KindEpoch", ls)
	}
	want := registry.HashPayload(testSalt, epochRecord(epochEventAccept, 0, "cell-a", "ok"))
	if ls[0].PayloadHash != want {
		t.Fatal("feuille d'acceptation non prouvable par re-hash (sel révélé)")
	}
	if ls[0].CellID != "cell-a" {
		t.Fatalf("feuille attribuée à %q, veut cell-a", ls[0].CellID)
	}
	if got := statusOf(t, trA).AutoFailoversHour; got != 0 {
		t.Fatalf("AutoFailoversHour=%d — l'epoch 0 (mode absent ⇒ manual) ne consomme pas le budget", got)
	}
}

// TestFailoverNoDoubleAuthority : bascule cell-a → cell-b à 2 cellules —
// à AUCUN instant deux autorités ne servent (§7.2), au prix d'un trou de
// service borné entre l'acceptation et l'expiration de l'ancienne.
func TestFailoverNoDoubleAuthority(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	members := []string{"cell-a", "cell-b"}
	trA := newTracker(t, "cell-a", members, clk, &leafRecorder{}, &alarmRecorder{})
	trB := newTracker(t, "cell-b", members, clk, &leafRecorder{}, &alarmRecorder{})

	// Époque 1 : cell-a autorité, TTL 60 s (manuelle — bascule initiale).
	tok1 := mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60})
	if err := trA.Accept(context.Background(), tok1); err != nil {
		t.Fatalf("epoch 1 : %v", err)
	}
	if err := trB.Accept(context.Background(), tok1); err != nil {
		t.Fatalf("epoch 1 côté b : %v", err)
	}

	serving := func(tr *Tracker) bool {
		_, err := tr.CurrentEpoch()
		return err == nil
	}
	if !serving(trA) || serving(trB) {
		t.Fatal("à l'époque 1 : cell-a sert, cell-b non")
	}

	// Bascule AUTOMATIQUE à t0+30 (l'ancienne époque est encore valide) :
	// cell-b accepte l'époque 2 mais n'entre en fonction qu'à t0+60.
	clk.set(t0.Add(30 * time.Second))
	tok2 := mintEpochToken(t, privs, EpochPayload{
		N: 2, Authority: "cell-b", IssuedAt: t0.Add(30 * time.Second).Format(time.RFC3339), TTLSeconds: 60, Mode: ModeAuto,
	})
	if err := trB.Accept(context.Background(), tok2); err != nil {
		t.Fatalf("epoch 2 : %v", err)
	}
	if _, err := trB.CurrentEpoch(); !errors.Is(err, ErrEpochNotYetEffective) {
		t.Fatalf("cell-b à t0+30 : err=%v, veut ErrEpochNotYetEffective (jamais de chevauchement)", err)
	}

	// Balayage fin de t0 à t0+120 : jamais deux autorités simultanées.
	overlap := false
	for ts := t0; ts.Before(t0.Add(120 * time.Second)); ts = ts.Add(time.Second) {
		clk.set(ts)
		if serving(trA) && serving(trB) {
			overlap = true
			t.Fatalf("DOUBLE AUTORITÉ à %s — §7.2 violé", ts)
		}
	}
	if overlap {
		t.Fatal("fenêtre de double autorité détectée")
	}

	// cell-a apprend l'époque 2 à t0+35 : elle cesse IMMÉDIATEMENT de
	// servir (seul le détenteur du plus haut N sert) — le trou de service
	// jusqu'à t0+60 est fail-closed, pas une faute.
	clk.set(t0.Add(35 * time.Second))
	if err := trA.Accept(context.Background(), tok2); err != nil {
		t.Fatalf("epoch 2 côté a : %v", err)
	}
	if _, err := trA.CurrentEpoch(); !errors.Is(err, ErrNotAuthority) {
		t.Fatalf("cell-a après bascule : err=%v, veut ErrNotAuthority", err)
	}
	clk.set(t0.Add(45 * time.Second))
	if serving(trA) || serving(trB) {
		t.Fatal("trou de service attendu entre t0+35 et t0+60 (fail-closed)")
	}

	// Après expiration de l'ancienne : cell-b sert, seule.
	clk.set(t0.Add(61 * time.Second))
	if !serving(trB) {
		st := statusOf(t, trB)
		t.Fatalf("cell-b devrait servir à t0+61 (notBefore=%s exp=%s)", st.NotBefore, st.ExpiresAt)
	}

	// Le VIEUX jeton re-présenté après bascule est refusé (monotonie).
	err := trB.Accept(context.Background(), tok1)
	if err == nil || !strings.Contains(err.Error(), "epoch-regression") {
		t.Fatalf("rejeu du vieux jeton : %v, veut epoch-regression", err)
	}
}

// TestNoAuthorityMeansNoService : sans époque, ou époque expirée sans
// successeur, la cellule ne sert pas — fail-closed (D48 + revue #30 :
// l'interface doit pouvoir DIRE « pas d'autorité »).
func TestNoAuthorityMeansNoService(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	tr := newTracker(t, "cell-a", []string{"cell-a"}, clk, &leafRecorder{}, &alarmRecorder{})

	if _, err := tr.CurrentEpoch(); !errors.Is(err, ErrNoEpoch) {
		t.Fatalf("sans genèse : err=%v, veut ErrNoEpoch", err)
	}
	tok := mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 10})
	if err := tr.Accept(context.Background(), tok); err != nil {
		t.Fatalf("epoch 1 : %v", err)
	}
	clk.set(t0.Add(11 * time.Second)) // l'ancien expire seul (§7.2)
	if _, err := tr.CurrentEpoch(); !errors.Is(err, ErrEpochExpired) {
		t.Fatalf("après expiration : err=%v, veut ErrEpochExpired", err)
	}
}

// TestEquivocationDetected : deux jetons valides au même N avec des
// payloads différents = faute byzantine ⇒ refus + alarme + feuille
// d'équivoque. La re-livraison du MÊME jeton est idempotente.
func TestEquivocationDetected(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves, alarms := &leafRecorder{}, &alarmRecorder{}
	tr := newTracker(t, "cell-a", []string{"cell-a", "cell-b"}, clk, leaves, alarms)

	tokA := mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60})
	tokB := mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-b", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60})
	if err := tr.Accept(context.Background(), tokA); err != nil {
		t.Fatalf("epoch 1 : %v", err)
	}
	if err := tr.Accept(context.Background(), tokA); err != nil {
		t.Fatalf("re-livraison du même jeton : %v — doit être idempotente", err)
	}
	err := tr.Accept(context.Background(), tokB)
	if err == nil || !strings.Contains(err.Error(), "epoch-equivocation") {
		t.Fatalf("équivoque : %v, veut epoch-equivocation", err)
	}
	if got := alarms.all(); len(got) != 1 || got[0] != "epoch-equivocation" {
		t.Fatalf("alarmes %v, veut [epoch-equivocation]", got)
	}
	// Feuille d'équivoque prouvée par re-hash.
	ls := leaves.all()
	if len(ls) != 2 {
		t.Fatalf("%d feuilles, veut 2 (accept + équivoque)", len(ls))
	}
	want := registry.HashPayload(testSalt, epochRecord(epochEventEquivocate, 1, "cell-b", "epoch-equivocation"))
	if ls[1].PayloadHash != want {
		t.Fatal("feuille d'équivoque non prouvable par re-hash")
	}
}

// TestEpochRefusals : forme, TTL hors bornes, futur, autorité inconnue,
// quorum insuffisant, signataire en double — tout est refusé et tracé.
func TestEpochRefusals(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	tr := newTracker(t, "cell-a", []string{"cell-a", "cell-b"}, clk, leaves, &alarmRecorder{})
	base := EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60}

	cases := map[string][]byte{
		"json cassé":        []byte(`{pas json`),
		"TTL trop court":    mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 5}),
		"TTL trop long":     mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 600}),
		"futur lointain":    mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Add(time.Minute).Format(time.RFC3339), TTLSeconds: 60}),
		"autorité inconnue": mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-z", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60}),
		"mode inconnu":      mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60, Mode: "turbo"}),
		"quorum 1-of-3":     mintEpochToken(t, privs, base, 1),
		"signataire double": mintEpochToken(t, privs, base, 1, 1),
		"key_id hors manifest": func() []byte {
			// Signé valide par (1,2) puis key_id 2 → 9 : le manifest ne
			// connaît pas 9 — le refus doit précéder toute vérification.
			tok := mintEpochToken(t, privs, base, 1, 2)
			return []byte(strings.Replace(string(tok), `"key_id":2`, `"key_id":9`, 1))
		}(),
	}
	for name, tok := range cases {
		if err := tr.Accept(context.Background(), tok); err == nil {
			t.Fatalf("%s : jeton accepté", name)
		}
	}
	if got := leaves.countKind(registry.KindEpoch); got != len(cases) {
		t.Fatalf("%d feuilles KindEpoch, veut %d (chaque refus est tracé)", got, len(cases))
	}
	// Aucune époque acceptée au passage : la cellule ne sert toujours pas.
	if _, err := tr.CurrentEpoch(); !errors.Is(err, ErrNoEpoch) {
		t.Fatalf("après refus : err=%v, veut ErrNoEpoch", err)
	}
	// key_id 9 n'est pas dans le manifest — vérifié contre le trousseau
	// (garde contre une map de contrôleurs mutée ailleurs).
	pubs, _ := testControllers(t)
	if _, ok := pubs[9]; ok {
		t.Fatal("pubs[9] existe — le test est cassé")
	}
}

// TestFailoverBudgetThenHuman : §7.2 « max N bascules/heure, ensuite
// humain » — le budget auto épuisé refuse les bascules automatiques mais
// accepte l'époque MANUELLE (canal séparé pré-autorisé) ; la fenêtre
// glissante se rouvre après une heure.
func TestFailoverBudgetThenHuman(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leaves, alarms := &leafRecorder{}, &alarmRecorder{}
	members := []string{"cell-a", "cell-b"}
	tr := newTracker(t, "cell-a", members, clk, leaves, alarms,
		func(c *TrackerConfig) { c.MaxAutoFailoversPerHour = 2 })

	mk := func(n int, auth string, at time.Time, mode string) []byte {
		return mintEpochToken(t, privs, EpochPayload{N: n, Authority: auth, IssuedAt: at.Format(time.RFC3339), TTLSeconds: 10, Mode: mode})
	}
	// Genèse manuelle (ne consomme pas le budget).
	if err := tr.Accept(context.Background(), mk(1, "cell-a", t0, ModeManual)); err != nil {
		t.Fatalf("genèse : %v", err)
	}
	// Deux bascules auto dans l'heure : admises.
	clk.set(t0.Add(11 * time.Second))
	if err := tr.Accept(context.Background(), mk(2, "cell-b", t0.Add(11*time.Second), ModeAuto)); err != nil {
		t.Fatalf("bascule auto 1 : %v", err)
	}
	clk.set(t0.Add(22 * time.Second))
	if err := tr.Accept(context.Background(), mk(3, "cell-a", t0.Add(22*time.Second), ModeAuto)); err != nil {
		t.Fatalf("bascule auto 2 : %v", err)
	}
	// Troisième dans l'heure : refusée — ensuite humain.
	clk.set(t0.Add(33 * time.Second))
	err := tr.Accept(context.Background(), mk(4, "cell-b", t0.Add(33*time.Second), ModeAuto))
	if err == nil || !strings.Contains(err.Error(), "failover-budget-exhausted") {
		t.Fatalf("3e bascule auto : %v, veut failover-budget-exhausted", err)
	}
	if got := alarms.all(); len(got) != 1 || got[0] != "failover-budget-exhausted" {
		t.Fatalf("alarmes %v, veut [failover-budget-exhausted]", got)
	}
	// L'époque MANUELLE (canal séparé) passe malgré le budget épuisé.
	clk.set(t0.Add(34 * time.Second))
	if err := tr.Accept(context.Background(), mk(4, "cell-b", t0.Add(34*time.Second), ModeManual)); err != nil {
		t.Fatalf("bascule manuelle après épuisement : %v — « ensuite humain » (§7.2)", err)
	}
	// La fenêtre glissante se rouvre : une heure après la 1re bascule auto,
	// le budget est à nouveau disponible.
	clk.set(t0.Add(11*time.Second + time.Hour + time.Second))
	if err := tr.Accept(context.Background(), mk(5, "cell-a", t0.Add(11*time.Second+time.Hour+time.Second), ModeAuto)); err != nil {
		t.Fatalf("bascule auto après fenêtre glissante : %v", err)
	}
	// Feuille du budget épuisé prouvée par re-hash (event 5).
	want := registry.HashPayload(testSalt, epochRecord(epochEventBudget, 4, "cell-b", "failover-budget-exhausted"))
	found := false
	for _, l := range leaves.all() {
		if l.PayloadHash == want {
			found = true
		}
	}
	if !found {
		t.Fatal("feuille budget-épuisé absente ou non prouvable par re-hash")
	}
}

// TestRevocationQuarantine : révocation = nouvelle époque à roster réduit
// (§7.3). La cellule révoquée est en QUARANTAINE — inspectable, pas
// purgée — et ses jetons pré-émis sont refusés post-bascule (test croisé
// avec le validateur T9 : epoch-mismatch).
func TestRevocationQuarantine(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	leavesA, leavesC := &leafRecorder{}, &leafRecorder{}
	members := []string{"cell-a", "cell-b", "cell-c"}
	trA := newTracker(t, "cell-a", members, clk, leavesA, &alarmRecorder{})
	trC := newTracker(t, "cell-c", members, clk, leavesC, &alarmRecorder{})

	// Époque 1 : cell-a autorité.
	tok1 := mintEpochToken(t, privs, EpochPayload{N: 1, Authority: "cell-a", IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 10})
	for _, tr := range []*Tracker{trA, trC} {
		if err := tr.Accept(context.Background(), tok1); err != nil {
			t.Fatalf("epoch 1 : %v", err)
		}
	}

	// Un jeton d'action est ÉMIS à l'époque 1 (broker réel, signataire
	// dev RFC 8032) et validé par le PEP T9 : allow à son époque.
	token := issueActionToken(t, 1)
	v := newActionValidator(t, leavesA, 1)
	d := v.Validate(context.Background(), token, pep.Request{Action: "a", Resource: "r"})
	if !d.Allow {
		t.Fatalf("jeton époque 1 refusé à son époque : %q", d.Reason)
	}

	// RÉVOCATION de cell-c : époque 2 à roster réduit [cell-a, cell-b],
	// cell-b autorité (§7.3). Émise après expiration de l'époque 1.
	clk.set(t0.Add(11 * time.Second))
	tok2 := mintEpochToken(t, privs, EpochPayload{
		N: 2, Authority: "cell-b", IssuedAt: t0.Add(11 * time.Second).Format(time.RFC3339), TTLSeconds: 60,
		Mode: ModeManual, Roster: []string{"cell-a", "cell-b"},
	})
	for _, tr := range []*Tracker{trA, trC} {
		if err := tr.Accept(context.Background(), tok2); err != nil {
			t.Fatalf("epoch 2 (révocation) : %v", err)
		}
	}

	// Quarantaine, pas meurtre : cell-c est listée, son état reste
	// INSPECTABLE (Status complet), elle ne sert plus jamais.
	if q := trA.Quarantined(); len(q) != 1 || q[0] != "cell-c" {
		t.Fatalf("quarantaine côté a : %v, veut [cell-c]", q)
	}
	if _, err := trC.CurrentEpoch(); !errors.Is(err, ErrCellQuarantined) {
		t.Fatalf("cell-c CurrentEpoch : err=%v, veut ErrCellQuarantined", err)
	}
	st := statusOf(t, trC)
	if st.Epoch != 2 || st.Authority != "cell-b" || len(st.Quarantined) != 1 || st.Quarantined[0] != "cell-c" {
		t.Fatalf("Status cell-c = %+v — la quarantaine doit rester inspectable (§7.3)", st)
	}

	// Les jetons pré-émis sont refusés post-bascule : même jeton, époque
	// observée 2 ⇒ epoch-mismatch au PEP (avant tout autre contrôle).
	ar2, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 16})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	signer, _ := broker.NewDevSigner(actionSeed)
	v2, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:     "cell-a",
		Keyring:    map[[16]byte]ed25519.PublicKey{actionIssuerKeyID(t): signer.Public()},
		PolicyID:   actionPolicyID,
		Salt:       testSalt,
		Leaves:     leavesA,
		AntiReplay: ar2,
		Epochs:     pep.FixedEpoch(2),
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	d2 := v2.Validate(context.Background(), token, pep.Request{Action: "a", Resource: "r"})
	if d2.Allow || d2.Reason != pep.ReasonEpochMismatch {
		t.Fatalf("jeton pré-émis post-bascule : allow=%v reason=%q, veut deny/%q — §7.3 violé", d2.Allow, d2.Reason, pep.ReasonEpochMismatch)
	}

	// La révocation a laissé SA feuille (event 4), prouvée par re-hash.
	want := registry.HashPayload(testSalt, epochRecord(epochEventRevoke, 2, "cell-b", "ok"))
	found := false
	for _, l := range leavesA.all() {
		if l.Kind == registry.KindEpoch && l.PayloadHash == want {
			found = true
		}
	}
	if !found {
		t.Fatal("feuille de révocation absente ou non prouvable (§4.1)")
	}
}

// TestRevocationRefusals : un roster vide, un roster avec une inconnue ou
// une autorité hors roster sont refusés — la mise en quarantaine est une
// décision du quorum, jamais du tracker.
func TestRevocationRefusals(t *testing.T) {
	_, privs := testControllers(t)
	clk := newClock(t0)
	tr := newTracker(t, "cell-a", []string{"cell-a", "cell-b"}, clk, &leafRecorder{}, &alarmRecorder{})
	mk := func(roster []string, auth string) []byte {
		return mintEpochToken(t, privs, EpochPayload{N: 1, Authority: auth, IssuedAt: t0.Format(time.RFC3339), TTLSeconds: 60, Roster: roster})
	}
	// "roster":[] ne peut pas être ÉMIS via la struct (omitempty) mais peut
	// être écrit à la main — le canonique signé le porte explicitement.
	emptyRoster := mintRawEpochToken(t, privs,
		fmt.Sprintf(`{"n":1,"authority":"cell-a","issued_at":%q,"ttl_s":60,"roster":[]}`, t0.Format(time.RFC3339)))
	for name, tok := range map[string][]byte{
		"roster vide":             emptyRoster,
		"roster cellule inconnue": mk([]string{"cell-a", "cell-z"}, "cell-a"),
		"autorité hors roster":    mk([]string{"cell-b"}, "cell-a"),
	} {
		if err := tr.Accept(context.Background(), tok); err == nil {
			t.Fatalf("%s : accepté", name)
		}
	}
	if got := tr.Quarantined(); len(got) != 0 {
		t.Fatalf("quarantaine après refus : %v — un jeton refusé ne met personne en quarantaine", got)
	}
}

// ---------------------------------------------------------------------------
// Coutures du test croisé PEP (révocation ⇒ epoch-mismatch)
// ---------------------------------------------------------------------------

var actionPolicyID [32]byte // zéros — comme le vecteur de schema.md §9

var actionSeed, _ = hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

// actionIssuerKeyID force la création de l'émetteur pour connaître son KID.
func actionIssuerKeyID(t *testing.T) [16]byte {
	t.Helper()
	signer, err := broker.NewDevSigner(actionSeed)
	if err != nil {
		t.Fatalf("NewDevSigner: %v", err)
	}
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: signer, PolicyID: actionPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer.KeyID()
}

// issueActionToken émet un jeton d'action réel (broker.Issuer) à l'époque
// donnée — le jeton pré-émis que la bascule doit invalider.
func issueActionToken(t *testing.T, epoch uint64) []byte {
	t.Helper()
	signer, err := broker.NewDevSigner(actionSeed)
	if err != nil {
		t.Fatalf("NewDevSigner: %v", err)
	}
	issuer, err := broker.NewIssuer(broker.IssuerOptions{CellID: "cell-a", Signer: signer, PolicyID: actionPolicyID})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	var jti [16]byte
	copy(jti[:], []byte("t29-jti-00000001"))
	wire, err := issuer.Issue(broker.IssueParams{
		Subject: "agent-1", Action: "a", Resource: "r",
		JTI: jti, Epoch: epoch, Iat: time.Now().Unix(), // fraîcheur réelle : le validateur T9 borne iat/exp sur son horloge
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return wire
}

// newActionValidator assemble le validateur T9 du même trousseau, à
// l'époque courante donnée. Depuis la revue de sécurité #90 (point 2),
// l'époque n'est plus lue sur la requête : elle vient d'une source
// autoritaire (ici, une valeur fixe simulant l'observation du tracker).
func newActionValidator(t *testing.T, leaves *leafRecorder, epoch uint64) *pep.Validator {
	t.Helper()
	ar, err := pep.NewAntiReplay(pep.AntiReplayOptions{Capacity: 16})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	signer, _ := broker.NewDevSigner(actionSeed)
	v, err := pep.NewValidator(pep.ValidatorOptions{
		CellID:     "cell-a",
		Keyring:    map[[16]byte]ed25519.PublicKey{actionIssuerKeyID(t): signer.Public()},
		PolicyID:   actionPolicyID,
		Salt:       testSalt,
		Leaves:     leaves,
		AntiReplay: ar,
		Epochs:     pep.FixedEpoch(epoch),
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}
