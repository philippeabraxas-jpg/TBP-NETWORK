package cluster

// Tests du PromotionController (§7.4) : la promotion est la preuve de
// réception du bundle ANCRÉ — la fenêtre saine est lue dans le master,
// jamais mesurée par le canari. Le test de partition est le cœur du
// critère d'acceptation : « le canari ne peut pas s'auto-promouvoir ».

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Seeds Ed25519 fixes des cellules candidates (aucune valeur de production).
var cellSeeds = map[string]string{
	"cell-b": "307a8389f688fe3784b5c46b3ffa1c24d0cf6ad15fc1e1e8f3a2be1d39f1e3f0",
	"cell-c": "f725b16e3b638d2a9dd1cd9c04fe2ec62f0b416ea8b72fb5ab4f88d24e773b25",
}

func testCellKeys(t *testing.T) (pubs map[string]ed25519.PublicKey, privs map[string]ed25519.PrivateKey) {
	t.Helper()
	pubs, privs = map[string]ed25519.PublicKey{}, map[string]ed25519.PrivateKey{}
	for id, s := range cellSeeds {
		seed, err := hex.DecodeString(s)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("seed cellule %s illisible", id)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		privs[id], pubs[id] = priv, priv.Public().(ed25519.PublicKey)
	}
	return pubs, privs
}

// fakeAnchors simule la master chain (T6) : ancres par époque + fenêtres
// saines ancrées. down=true = PARTITION — le master est injoignable et le
// contrôleur ne peut rien vérifier (fail-closed).
type fakeAnchors struct {
	bundles map[uint64][32]byte
	windows map[uint64][2]time.Time
	down    bool
}

func (f *fakeAnchors) BundleAnchor(epoch uint64) ([32]byte, bool) {
	if f.down {
		return [32]byte{}, false
	}
	h, ok := f.bundles[epoch]
	return h, ok
}

func (f *fakeAnchors) HealthyWindow(epoch uint64) (time.Time, time.Time, bool) {
	if f.down {
		return time.Time{}, time.Time{}, false
	}
	w, ok := f.windows[epoch]
	return w[0], w[1], ok
}

// mintReceipt frappe une réception signée par la clé de la cellule.
func mintReceipt(t *testing.T, privs map[string]ed25519.PrivateKey, cellID string, epoch uint64, bundle [32]byte, at time.Time) []byte {
	t.Helper()
	r := Receipt{
		CellID:     cellID,
		Epoch:      epoch,
		BundleHash: hex.EncodeToString(bundle[:]),
		ReceivedAt: at.UTC().Format(time.RFC3339),
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("receipt : %v", err)
	}
	priv, ok := privs[cellID]
	if !ok {
		t.Fatalf("pas de clé pour %s", cellID)
	}
	sig := ed25519.Sign(priv, canonical)
	data, err := json.Marshal(SignedReceipt{Receipt: r, Sig: hex.EncodeToString(sig)})
	if err != nil {
		t.Fatalf("signed receipt : %v", err)
	}
	return data
}

func newPromotion(t *testing.T, clk *manualClock, leaves *leafRecorder, src MasterAnchorSource, opts ...func(*PromotionConfig)) *PromotionController {
	t.Helper()
	pubs, _ := testCellKeys(t)
	cfg := PromotionConfig{
		CellID: "cell-a", Salt: testSalt, Leaves: leaves,
		Source: src, CellKeys: pubs, Now: clk.now,
	}
	for _, f := range opts {
		f(&cfg)
	}
	c, err := NewPromotionController(cfg)
	if err != nil {
		t.Fatalf("NewPromotionController: %v", err)
	}
	return c
}

// promotionRecord reconstruit le record « TBPP1 » attendu (§6.2).
func promotionRecord(verdict byte, cell string, epoch uint64, bundle [32]byte, reason string) []byte {
	rec := append([]byte("TBPP1"), verdict, byte(len(cell)))
	rec = append(rec, cell...)
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	rec = append(rec, eb[:]...)
	rec = append(rec, bundle[:]...)
	rec = append(rec, byte(len(reason)))
	rec = append(rec, reason...)
	return rec
}

func TestPromotionConfigFailClosed(t *testing.T) {
	pubs, _ := testCellKeys(t)
	full := PromotionConfig{
		CellID: "cell-a", Salt: testSalt, Leaves: &leafRecorder{},
		Source: &fakeAnchors{}, CellKeys: pubs,
	}
	if _, err := NewPromotionController(full); err != nil {
		t.Fatalf("config complète refusée : %v", err)
	}
	cases := map[string]func(*PromotionConfig){
		"cellID vide":       func(c *PromotionConfig) { c.CellID = "" },
		"sel court":         func(c *PromotionConfig) { c.Salt = []byte("court") },
		"feuilles absentes": func(c *PromotionConfig) { c.Leaves = nil },
		"source absente":    func(c *PromotionConfig) { c.Source = nil },
		"sans clés":         func(c *PromotionConfig) { c.CellKeys = nil },
	}
	for name, mutate := range cases {
		cfg := full
		mutate(&cfg)
		if _, err := NewPromotionController(cfg); err == nil {
			t.Fatalf("%s : config acceptée", name)
		}
	}
}

// TestCanaryCannotSelfPromoteUnderPartition : le critère d'acceptation
// central de §7.4. Sous partition (master injoignable), le canari a beau
// présenter une réception PARFAITEMENT signée pour le BON bundle — sans
// ancre lisible, rien ne peut être vérifié : refus. Un canari sain en
// apparence ne se promeut jamais lui-même.
func TestCanaryCannotSelfPromoteUnderPartition(t *testing.T) {
	_, privs := testCellKeys(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	bundle := [32]byte{0x42}
	src := &fakeAnchors{
		bundles: map[uint64][32]byte{2: bundle},
		windows: map[uint64][2]time.Time{2: {t0.Add(-time.Hour), t0.Add(time.Hour)}},
		down:    true, // PARTITION : le master est injoignable
	}
	c := newPromotion(t, clk, leaves, src)

	// Le canari présente une réception valide — signée, bien liée, dans la
	// fenêtre — que le contrôleur ne peut PAS vérifier contre le master.
	receipt := mintReceipt(t, privs, "cell-b", 2, bundle, t0.Add(-time.Minute))
	err := c.Promote(context.Background(), receipt)
	if !errors.Is(err, ErrPromotionAnchorUnavailable) {
		t.Fatalf("partition : err=%v, veut ErrPromotionAnchorUnavailable (§7.4)", err)
	}
	if got := leaves.countKind(registry.KindPromotion); got != 1 {
		t.Fatalf("%d feuilles KindPromotion, veut 1 (le refus est tracé)", got)
	}
	want := registry.HashPayload(testSalt, promotionRecord(0x00, "cell-b", 2, bundle, "promotion-anchor-unavailable"))
	if leaves.all()[0].PayloadHash != want {
		t.Fatal("feuille de refus (partition) non prouvable par re-hash")
	}
}

// TestPromotionRefusals : chaque faute précise ⇒ refus tracé.
func TestPromotionRefusals(t *testing.T) {
	_, privs := testCellKeys(t)
	clk := newClock(t0)
	bundle := [32]byte{0x42}
	var wrongBundle [32]byte
	wrongBundle[0] = 0xff

	mk := func(down bool, b map[uint64][32]byte, w map[uint64][2]time.Time) *fakeAnchors {
		return &fakeAnchors{bundles: b, windows: w, down: down}
	}
	goodWindow := map[uint64][2]time.Time{2: {t0.Add(-time.Hour), t0.Add(time.Hour)}}
	goodBundles := map[uint64][32]byte{2: bundle}

	cases := map[string]struct {
		src     *fakeAnchors
		receipt []byte
		want    error
	}{
		"partition": {
			mk(true, goodBundles, goodWindow),
			mintReceipt(t, privs, "cell-b", 2, bundle, t0),
			ErrPromotionAnchorUnavailable,
		},
		"bundle ≠ ancré": {
			mk(false, goodBundles, goodWindow),
			mintReceipt(t, privs, "cell-b", 2, wrongBundle, t0),
			ErrPromotionBundleMismatch,
		},
		"fenêtre non ancrée": {
			mk(false, goodBundles, nil),
			mintReceipt(t, privs, "cell-b", 2, bundle, t0),
			ErrPromotionWindowUnavailable,
		},
		"fenêtre expirée": {
			mk(false, goodBundles, map[uint64][2]time.Time{2: {t0.Add(-2 * time.Hour), t0.Add(-time.Hour)}}),
			mintReceipt(t, privs, "cell-b", 2, bundle, t0),
			ErrPromotionWindowExpired,
		},
		"fenêtre pas commencée": {
			mk(false, goodBundles, map[uint64][2]time.Time{2: {t0.Add(time.Hour), t0.Add(2 * time.Hour)}}),
			mintReceipt(t, privs, "cell-b", 2, bundle, t0),
			ErrPromotionWindowExpired,
		},
		"cellule inconnue": {
			mk(false, goodBundles, goodWindow),
			// Réception au nom de cell-z (inconnue) signée par cell-c.
			func() []byte {
				r := Receipt{CellID: "cell-z", Epoch: 2, BundleHash: hex.EncodeToString(bundle[:]), ReceivedAt: t0.Format(time.RFC3339)}
				canonical, _ := json.Marshal(r)
				sig := ed25519.Sign(privs["cell-c"], canonical)
				data, _ := json.Marshal(SignedReceipt{Receipt: r, Sig: hex.EncodeToString(sig)})
				return data
			}(),
			ErrPromotionUnknownCell,
		},
		"signature d'une autre cellule": {
			mk(false, goodBundles, goodWindow),
			// Réception de cell-b signée par la clé de cell-c.
			func() []byte {
				r := Receipt{CellID: "cell-b", Epoch: 2, BundleHash: hex.EncodeToString(bundle[:]), ReceivedAt: t0.Format(time.RFC3339)}
				canonical, _ := json.Marshal(r)
				sig := ed25519.Sign(privs["cell-c"], canonical)
				data, _ := json.Marshal(SignedReceipt{Receipt: r, Sig: hex.EncodeToString(sig)})
				return data
			}(),
			ErrPromotionBadReceipt,
		},
		"réception malformée": {
			mk(false, goodBundles, goodWindow),
			[]byte(`{pas json`),
			ErrPromotionBadReceipt,
		},
	}
	for name, tc := range cases {
		leaves := &leafRecorder{}
		c := newPromotion(t, clk, leaves, tc.src)
		err := c.Promote(context.Background(), tc.receipt)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s : err=%v, veut %v", name, err, tc.want)
		}
		if got := leaves.countKind(registry.KindPromotion); got != 1 {
			t.Fatalf("%s : %d feuilles KindPromotion, veut 1 (le refus est tracé)", name, got)
		}
	}
	_ = fmt.Sprintf
}

// TestPromotionAllow : fenêtre saine ancrée + réception du bundle ancré ⇒
// promotion tracée — le positif qui rend les mutations non-vacuoles.
func TestPromotionAllow(t *testing.T) {
	_, privs := testCellKeys(t)
	clk := newClock(t0)
	leaves := &leafRecorder{}
	bundle := [32]byte{0x42}
	src := &fakeAnchors{
		bundles: map[uint64][32]byte{2: bundle},
		windows: map[uint64][2]time.Time{2: {t0.Add(-time.Hour), t0.Add(time.Hour)}},
	}
	c := newPromotion(t, clk, leaves, src)

	receipt := mintReceipt(t, privs, "cell-b", 2, bundle, t0.Add(-time.Minute))
	if err := c.Promote(context.Background(), receipt); err != nil {
		t.Fatalf("promotion valide refusée : %v", err)
	}
	ls := leaves.all()
	if len(ls) != 1 || ls[0].Kind != registry.KindPromotion {
		t.Fatalf("feuilles=%+v, veut 1 KindPromotion", ls)
	}
	want := registry.HashPayload(testSalt, promotionRecord(0x01, "cell-b", 2, bundle, "ok"))
	if ls[0].PayloadHash != want {
		t.Fatal("feuille de promotion non prouvable par re-hash (§6.2)")
	}
	if ls[0].CellID != "cell-a" {
		t.Fatalf("feuille attribuée à %q — c'est l'autorité qui tranche qui émet", ls[0].CellID)
	}
}

// TestPromotionAllowWithoutLeafFailsClosed : une promotion non tracée
// redevient un refus (pas de preuve, pas de bascule — §4.1).
func TestPromotionAllowWithoutLeafFailsClosed(t *testing.T) {
	_, privs := testCellKeys(t)
	clk := newClock(t0)
	bundle := [32]byte{0x42}
	src := &fakeAnchors{
		bundles: map[uint64][2]time.Time{2: {t0.Add(-time.Hour), t0.Add(time.Hour)}},
	}
	c := newPromotion(t, clk, &leafRecorder{err: errors.New("disque plein simulé")}, src)
	receipt := mintReceipt(t, privs, "cell-b", 2, bundle, t0)
	if err := c.Promote(context.Background(), receipt); err == nil {
		t.Fatal("promotion admise sans feuille — fail-closed violé (§4.1)")
	}
}
