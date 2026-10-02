package cluster

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func anchorKeys(t *testing.T, n int) (map[int]ed25519.PublicKey, map[int]ed25519.PrivateKey) {
	t.Helper()
	pubs := map[int]ed25519.PublicKey{}
	privs := map[int]ed25519.PrivateKey{}
	for i := 1; i <= n; i++ {
		seed := sha256.Sum256([]byte{byte(i), 'a', 'n', 'c'})
		priv := ed25519.NewKeyFromSeed(seed[:])
		privs[i] = priv
		pubs[i] = priv.Public().(ed25519.PublicKey)
	}
	return pubs, privs
}

func anchorPayload(epoch uint64, bundle [32]byte, start, end time.Time) AnchorPayload {
	return AnchorPayload{Anchors: []AnchorEntry{{
		Epoch: epoch, BundleHash: hex.EncodeToString(bundle[:]),
		WindowStart: start.UTC().Format(time.RFC3339), WindowEnd: end.UTC().Format(time.RFC3339),
	}}}
}

func writeAnchors(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "anchors.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFileAnchorSourceHappyPath(t *testing.T) {
	pubs, privs := anchorKeys(t, 3)
	bundle := sha256.Sum256([]byte("bundle-7"))
	start := time.Now().Add(-time.Hour)
	end := time.Now().Add(time.Hour)
	data, err := SignAnchors(anchorPayload(7, bundle, start, end), map[int]ed25519.PrivateKey{1: privs[1], 2: privs[2]})
	if err != nil {
		t.Fatal(err)
	}
	src, err := NewFileAnchorSource(writeAnchors(t, data), pubs, 2)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := src.BundleAnchor(7)
	if !ok || got != bundle {
		t.Fatalf("ancre = %x ok=%v, attendu %x", got, ok, bundle)
	}
	s, e, ok := src.HealthyWindow(7)
	if !ok || s.Unix() != start.Unix() || e.Unix() != end.Unix() {
		t.Fatalf("fenêtre = [%v, %v] ok=%v", s, e, ok)
	}
	if _, ok := src.BundleAnchor(8); ok {
		t.Fatal("ancre d'une époque non ancrée rendue")
	}
	if _, _, ok := src.HealthyWindow(8); ok {
		t.Fatal("fenêtre d'une époque non ancrée rendue")
	}
}

func TestFileAnchorSourceFailsClosed(t *testing.T) {
	pubs, privs := anchorKeys(t, 3)
	bundle := sha256.Sum256([]byte("b"))
	now := time.Now()
	good := anchorPayload(1, bundle, now.Add(-time.Hour), now.Add(time.Hour))
	sign := func(p AnchorPayload, ids ...int) []byte {
		m := map[int]ed25519.PrivateKey{}
		for _, id := range ids {
			m[id] = privs[id]
		}
		d, err := SignAnchors(p, m)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	tamper := func(d []byte, f func(map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(d, &m)
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	// signature valide d'une AUTRE clé (hors manifeste)
	outsider := sha256.Sum256([]byte("intrus"))
	outPriv := ed25519.NewKeyFromSeed(outsider[:])
	canon, _ := json.Marshal(AnchorPayload{Kind: anchorsKind, Anchors: good.Anchors})
	forged, _ := json.Marshal(AnchorFile{Payload: AnchorPayload{Kind: anchorsKind, Anchors: good.Anchors},
		Signatures: []ControllerSignature{{KeyID: 1, Sig: hex.EncodeToString(ed25519.Sign(outPriv, canon))}, {KeyID: 2, Sig: hex.EncodeToString(ed25519.Sign(outPriv, canon))}}})
	dupSig := tamper(sign(good, 1, 2), func(m map[string]any) {
		s := m["signatures"].([]any)
		m["signatures"] = []any{s[0], s[0]}
	})
	long := anchorPayload(1, bundle, now.Add(-time.Hour), now.Add(MaxAnchorWindow+time.Hour))
	inverted := anchorPayload(1, bundle, now.Add(time.Hour), now.Add(-time.Hour))
	dupEpoch := AnchorPayload{Anchors: append(append([]AnchorEntry{}, good.Anchors...), good.Anchors...)}
	badHash := good
	badHash.Anchors = []AnchorEntry{{Epoch: 1, BundleHash: "zz", WindowStart: good.Anchors[0].WindowStart, WindowEnd: good.Anchors[0].WindowEnd}}
	empty := AnchorPayload{}
	// kind étranger SIGNÉ à bon droit par le quorum : la séparation de domaine doit le refuser
	foreign := AnchorPayload{Kind: "tbp-epoch", Anchors: good.Anchors}
	fcanon, _ := json.Marshal(foreign)
	foreignFile, _ := json.Marshal(AnchorFile{Payload: foreign, Signatures: []ControllerSignature{
		{KeyID: 1, Sig: hex.EncodeToString(ed25519.Sign(privs[1], fcanon))},
		{KeyID: 2, Sig: hex.EncodeToString(ed25519.Sign(privs[2], fcanon))}}})

	cases := []struct {
		name string
		data []byte
	}{
		{"quorum_insuffisant", sign(good, 1)},
		{"signature_falsifiee", forged},
		{"signataire_en_double", dupSig},
		{"payload_modifie_apres_signature", tamper(sign(good, 1, 2), func(m map[string]any) {
			m["payload"].(map[string]any)["anchors"].([]any)[0].(map[string]any)["bundle_hash"] = strings.Repeat("ab", 32)
		})},
		{"kind_modifie", tamper(sign(good, 1, 2), func(m map[string]any) { m["payload"].(map[string]any)["kind"] = "tbp-epoch" })},
		{"champ_inconnu", tamper(sign(good, 1, 2), func(m map[string]any) { m["extra"] = 1 })},
		{"fenetre_demesuree", sign(long, 1, 2)},
		{"fenetre_inversee", sign(inverted, 1, 2)},
		{"epoque_en_double", sign(dupEpoch, 1, 2)},
		{"hash_illisible", sign(badHash, 1, 2)},
		{"vide", sign(empty, 1, 2)},
		{"kind_etranger_signe", foreignFile},
		{"pas_du_json", []byte("nope")},
		{"json_cle_en_double", []byte(strings.Replace(string(sign(good, 1, 2)), `"signatures"`, `"signatures":[],"signatures"`, 1))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, err := NewFileAnchorSource(writeAnchors(t, c.data), pubs, 2)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := src.BundleAnchor(1); ok {
				t.Fatal("ancre rendue pour un fichier invalide")
			}
			if _, _, ok := src.HealthyWindow(1); ok {
				t.Fatal("fenêtre rendue pour un fichier invalide")
			}
		})
	}
	// fichier absent, trop gros
	src, _ := NewFileAnchorSource(filepath.Join(t.TempDir(), "absent.json"), pubs, 2)
	if _, ok := src.BundleAnchor(1); ok {
		t.Fatal("fichier absent : ancre rendue")
	}
	big := writeAnchors(t, []byte(strings.Repeat(" ", MaxAnchorFileBytes+10)))
	src, _ = NewFileAnchorSource(big, pubs, 2)
	if _, ok := src.BundleAnchor(1); ok {
		t.Fatal("fichier démesuré : ancre rendue")
	}
}

// Le fichier est relu à chaque lecture : un fichier REMPLACÉ (par un fichier invalide) retire l'ancre aussitôt.
func TestFileAnchorSourceRereadsEveryCall(t *testing.T) {
	pubs, privs := anchorKeys(t, 3)
	bundle := sha256.Sum256([]byte("b"))
	now := time.Now()
	data, _ := SignAnchors(anchorPayload(1, bundle, now.Add(-time.Hour), now.Add(time.Hour)), map[int]ed25519.PrivateKey{1: privs[1], 2: privs[2]})
	p := writeAnchors(t, data)
	src, _ := NewFileAnchorSource(p, pubs, 2)
	if _, ok := src.BundleAnchor(1); !ok {
		t.Fatal("ancre valide non lue")
	}
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := src.BundleAnchor(1); ok {
		t.Fatal("fichier remplacé par un invalide : l'ancre aurait dû disparaître (pas de cache)")
	}
}

func TestNewFileAnchorSourceFailClosed(t *testing.T) {
	pubs, _ := anchorKeys(t, 3)
	for name, f := range map[string]func() error{
		"chemin_vide":       func() error { _, e := NewFileAnchorSource("", pubs, 2); return e },
		"sans_controleurs":  func() error { _, e := NewFileAnchorSource("x", nil, 1); return e },
		"quorum_zero":       func() error { _, e := NewFileAnchorSource("x", pubs, 0); return e },
		"quorum_trop_grand": func() error { _, e := NewFileAnchorSource("x", pubs, 4); return e },
	} {
		if f() == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}

// Une promotion s'appuie sur la source fichier de bout en bout : bundle ancré, fenêtre saine, réception signée.
func TestPromotionWithFileAnchorSource(t *testing.T) {
	pubs, privs := anchorKeys(t, 3)
	bundle := sha256.Sum256([]byte("bundle-3"))
	now := time.Now()
	data, _ := SignAnchors(anchorPayload(3, bundle, now.Add(-time.Minute), now.Add(time.Hour)), map[int]ed25519.PrivateKey{1: privs[1], 2: privs[2]})
	src, _ := NewFileAnchorSource(writeAnchors(t, data), pubs, 2)
	cellPriv := ed25519.NewKeyFromSeed(sha256.New().Sum([]byte("cell-b-seed"))[:32])
	leaves := &leafRecorder{}
	pc, err := NewPromotionController(PromotionConfig{
		CellID: "cell-a", Salt: make([]byte, 16), Leaves: leaves, Source: src,
		CellKeys: map[string]ed25519.PublicKey{"cell-b": cellPriv.Public().(ed25519.PublicKey)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := Receipt{CellID: "cell-b", Epoch: 3, BundleHash: hex.EncodeToString(bundle[:]), ReceivedAt: now.UTC().Format(time.RFC3339)}
	canon, _ := json.Marshal(rc)
	body, _ := json.Marshal(SignedReceipt{Receipt: rc, Sig: hex.EncodeToString(ed25519.Sign(cellPriv, canon))})
	if err := pc.Promote(t.Context(), body); err != nil {
		t.Fatalf("promotion valide refusée : %v", err)
	}
	// époque non ancrée : refus
	rc.Epoch = 4
	canon, _ = json.Marshal(rc)
	body, _ = json.Marshal(SignedReceipt{Receipt: rc, Sig: hex.EncodeToString(ed25519.Sign(cellPriv, canon))})
	if err := pc.Promote(t.Context(), body); err == nil {
		t.Fatal("promotion d'une époque non ancrée acceptée")
	}
	// décodage strict de la réception : clé en double ⇒ refus
	dup := strings.Replace(string(body), `"sig"`, `"sig":"00","sig"`, 1)
	if err := pc.Promote(t.Context(), []byte(dup)); err == nil {
		t.Fatal("réception à clé en double acceptée")
	}
}
