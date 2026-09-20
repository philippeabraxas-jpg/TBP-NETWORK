// manifest_test.go — tests du manifeste attesté (T31, §6.3 — issue #32).
//
// Doctrine : critères d'acceptation de l'issue mappés un à un, tests NON
// vacuoles (les mutations M6–M9 du plan D74 ont été vérifiées échouer contre
// ces tests — preuve dans le commentaire d'évidence de #32), vecteur doré
// figé pour la vérification par un tiers (D70), aucune clé de production
// (clé note dérivée d'un lecteur fixe).
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// manifestCellID est l'identité de cellule des tests (origine de la clé note).
const manifestCellID = "tbp/registry/cell-test-01"

// manifestSalt est le sel de feuilles des tests (§6.2 : ≥ 16 octets).
var manifestSalt = []byte("sel-manifeste-t31")

// manifestTestKey dérive une paire de clés note DÉTERMINISTE (lecteur fixe
// de 32 octets — ed25519.GenerateKey lit exactement une graine de 32 octets)
// — valeur de test uniquement, jamais de production. Le vecteur doré en
// dépend : toute modification de ce lecteur invalide le vecteur.
func manifestTestKey(t *testing.T) (note.Signer, note.Verifier) {
	t.Helper()
	return manifestKeyFromSeed(t, bytes.Repeat([]byte{0xC1}, 32), manifestCellID)
}

// manifestOtherKey est une SECONDE clé déterministe — pour prouver qu'une
// signature d'une autre clé est rejetée (elle partage le même nom, seule la
// graine change).
func manifestOtherKey(t *testing.T) (note.Signer, note.Verifier) {
	t.Helper()
	return manifestKeyFromSeed(t, bytes.Repeat([]byte{0xD2}, 32), manifestCellID)
}

func manifestKeyFromSeed(t *testing.T, seed []byte, name string) (note.Signer, note.Verifier) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(bytes.NewReader(seed), name)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	verifier, err := NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return signer, verifier
}

// manifestTripLog capture les alarmes OnTrip (couture T14).
type manifestTripLog struct {
	mu      sync.Mutex
	reasons []string
}

func (l *manifestTripLog) add(reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reasons = append(l.reasons, reason)
}

func (l *manifestTripLog) taken() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.reasons...)
}

// manifestStateFixture rend un vecteur d'état déterministe à partir de
// contenus symboliques — les hashes sont ceux des « paquets signés » (§1).
func manifestStateFixture(policy, opa, broker, ai string, chainHead [32]byte) ManifestState {
	return ManifestState{
		PolicyID:        sha256.Sum256([]byte(policy)),
		OPAConfigHash:   sha256.Sum256([]byte(opa)),
		BrokerHash:      sha256.Sum256([]byte(broker)),
		AIContainerHash: sha256.Sum256([]byte(ai)),
		ChainHead:       chainHead,
	}
}

// newTestManifester construit un Manifester sur stubMaster (feuilles en
// mémoire, échec pilotable) et fakeClock — heure fixe sauf avancée explicite.
func newTestManifester(t *testing.T, sink *stubMaster, clock *fakeClock, trips *manifestTripLog) (*Manifester, note.Signer, note.Verifier) {
	t.Helper()
	signer, verifier := manifestTestKey(t)
	m, err := NewManifester(ManifestOptions{
		CellID:   manifestCellID,
		Signer:   signer,
		Verifier: verifier,
		Leaves:   sink,
		Salt:     manifestSalt,
		OnTrip:   trips.add,
		Now:      clock.now,
	})
	if err != nil {
		t.Fatalf("NewManifester: %v", err)
	}
	return m, signer, verifier
}

// manifestLeafHash reconstruit le hash de payload attendu d'une feuille
// KindManifest (record « TBPL2 », D69) — l'assertion porte sur le contenu
// EXACT de la feuille, pas seulement sa présence.
func manifestLeafHash(t *testing.T, event byte, manifestHash [32]byte, verdict byte, reason string) [32]byte {
	t.Helper()
	payload := append([]byte("TBPL2"), event)
	payload = append(payload, manifestHash[:]...)
	payload = append(payload, verdict, byte(len(reason)))
	payload = append(payload, reason...)
	return HashPayload(manifestSalt, payload)
}

// ---------------------------------------------------------------------------
// Genèse et transitions (critère 1 de #32)
// ---------------------------------------------------------------------------

// TestGenesisSealsManifestZero : la genèse est le manifeste seq 0, prev nul,
// signé, feuillé event=boot « genesis » — et une seconde genèse est refusée.
func TestGenesisSealsManifestZero(t *testing.T) {
	ctx := context.Background()
	sink := &stubMaster{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, verifier := newTestManifester(t, sink, clock, trips)

	st := manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	sm, err := m.Genesis(ctx, 7, st)
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}

	rec, err := ParseManifestRecord(sm.Record)
	if err != nil {
		t.Fatalf("ParseManifestRecord: %v", err)
	}
	if rec.Seq != 0 {
		t.Fatalf("seq %d, attendu 0 (genèse)", rec.Seq)
	}
	if rec.Prev != ([32]byte{}) {
		t.Fatal("prev de genèse non nul — l'amorce de chaîne doit être 0×32 (D73)")
	}
	if rec.Epoch != 7 || rec.CellID != manifestCellID {
		t.Fatalf("record (epoch %d, cellID %q), attendu (7, %q)", rec.Epoch, rec.CellID, manifestCellID)
	}
	if rec.State != st {
		t.Fatal("l'état du record ne reproduit pas le vecteur commité")
	}
	if !rec.IssuedAt.Equal(time.Unix(1_780_000_000, 0).UTC()) {
		t.Fatalf("issuedAt %v, attendu l'heure de l'horloge contrôlée", rec.IssuedAt)
	}
	// REVUE #32 : la signature se vérifie DIRECTEMENT sur le record.
	if !verifier.Verify(sm.Record, sm.Signature) {
		t.Fatal("signature du manifeste de genèse invalide")
	}

	leaves := sink.taken()
	if len(leaves) != 1 {
		t.Fatalf("%d feuilles, attendu 1", len(leaves))
	}
	leaf := leaves[0]
	if leaf.Kind != KindManifest || leaf.CellID != manifestCellID {
		t.Fatalf("feuille (kind %d, cellID %q), attendu (KindManifest, %q)", leaf.Kind, leaf.CellID, manifestCellID)
	}
	want := manifestLeafHash(t, manifestEventBoot, HashManifest(sm.Record), 1, "genesis")
	if leaf.PayloadHash != want {
		t.Fatal("payload de la feuille de genèse ≠ « TBPL2 » event=boot verdict=1 « genesis »")
	}

	if _, err := m.Genesis(ctx, 8, st); !errors.Is(err, ErrManifestAlreadyGenesis) {
		t.Fatalf("seconde genèse : %v, attendu ErrManifestAlreadyGenesis", err)
	}
	if len(sink.taken()) != 1 {
		t.Fatal("la genèse refusée n'aurait pas dû laisser de feuille")
	}
}

// TestTransitionChainsSignedContinuous — CRITÈRE 1 de #32 : tout changement
// de composant (ici policy_id) est une transition VISIBLE (feuille
// event=transition), SIGNÉE (signature vérifiable sur le record), CONTINûMENT
// chaînée (seq + 1, prev = sceau du manifeste précédent). Le saut silencieux
// est structurellement impossible : sans transition, rien ne bouge.
func TestTransitionChainsSignedContinuous(t *testing.T) {
	ctx := context.Background()
	sink := &stubMaster{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, verifier := newTestManifester(t, sink, clock, trips)

	// Transition avant genèse : refusée, pas de feuille.
	st0 := manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	if _, err := m.Transition(ctx, 7, st0); !errors.Is(err, ErrManifestNotInitialized) {
		t.Fatalf("Transition sans genèse : %v, attendu ErrManifestNotInitialized", err)
	}
	if len(sink.taken()) != 0 {
		t.Fatal("la transition refusée n'aurait pas dû laisser de feuille")
	}

	g0, err := m.Genesis(ctx, 7, st0)
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}

	// Changement de policy_id : transition signée et chaînée.
	clock.advance(time.Minute)
	st1 := manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	g1, err := m.Transition(ctx, 7, st1)
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	rec0, _ := ParseManifestRecord(g0.Record)
	rec1, err := ParseManifestRecord(g1.Record)
	if err != nil {
		t.Fatalf("ParseManifestRecord: %v", err)
	}
	if rec1.Seq != 1 {
		t.Fatalf("seq %d, attendu 1", rec1.Seq)
	}
	if rec1.Prev != HashManifest(g0.Record) {
		t.Fatal("prev du manifeste 1 ≠ sceau du manifeste 0 — chaînage rompu")
	}
	if rec1.State.PolicyID == rec0.State.PolicyID {
		t.Fatal("le changement de policy_id n'est pas attesté dans le record")
	}
	if !verifier.Verify(g1.Record, g1.Signature) {
		t.Fatal("signature de la transition invalide")
	}
	leaves := sink.taken()
	if len(leaves) != 2 {
		t.Fatalf("%d feuilles, attendu 2", len(leaves))
	}
	want := manifestLeafHash(t, manifestEventTransition, HashManifest(g1.Record), 1, "ok")
	if leaves[1].PayloadHash != want {
		t.Fatal("payload de la feuille de transition ≠ « TBPL2 » event=transition verdict=1 « ok »")
	}

	// Vecteur inchangé : une transition atteste un CHANGEMENT (§6.3).
	if _, err := m.Transition(ctx, 7, st1); !errors.Is(err, ErrManifestUnchanged) {
		t.Fatalf("Transition sans changement : %v, attendu ErrManifestUnchanged", err)
	}
	// Époque en régression : refusée (§7.2).
	st2 := manifestStateFixture("policy-v3", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	if _, err := m.Transition(ctx, 6, st2); !errors.Is(err, ErrManifestEpochRegression) {
		t.Fatalf("Transition époque 6 après 7 : %v, attendu ErrManifestEpochRegression", err)
	}
	if len(sink.taken()) != 2 {
		t.Fatal("les transitions refusées n'auraient pas dû laisser de feuille")
	}
	// La chaîne publiée à ce stade doit déjà être vérifiable par un tiers.
	if err := VerifyManifestChain([]SignedManifest{g0, g1}, verifier); err != nil {
		t.Fatalf("VerifyManifestChain: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Vérification par un tiers (critère 3 de #32)
// ---------------------------------------------------------------------------

// manifestChainFixture produit une chaîne de 3 manifestes signés : genèse
// (epoch 7), changement de policy_id (epoch 7), changement de conteneur IA
// (epoch 8) — heures fixes, chaînage exact.
func manifestChainFixture(t *testing.T) ([]SignedManifest, note.Verifier) {
	t.Helper()
	sink := &stubMaster{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, verifier := newTestManifester(t, sink, clock, trips)
	ctx := context.Background()

	g0, err := m.Genesis(ctx, 7, manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{}))
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	clock.advance(time.Minute)
	g1, err := m.Transition(ctx, 7, manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v1", [32]byte{}))
	if err != nil {
		t.Fatalf("Transition 1: %v", err)
	}
	clock.advance(time.Minute)
	g2, err := m.Transition(ctx, 8, manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v2", [32]byte{}))
	if err != nil {
		t.Fatalf("Transition 2: %v", err)
	}
	return []SignedManifest{g0, g1, g2}, verifier
}

// TestVerifyManifestChainThirdParty — CRITÈRE 3 de #32 : avec la SEULE clé
// publique de la cellule, un tiers vérifie la chaîne d'artefacts publiés
// sans relire le code de la cellule. Chaque altération est rejetée avec la
// bonne erreur — la vérification n'est pas un always-true.
func TestVerifyManifestChainThirdParty(t *testing.T) {
	chain, verifier := manifestChainFixture(t)
	signer, _ := manifestTestKey(t)

	if err := VerifyManifestChain(chain, verifier); err != nil {
		t.Fatalf("chaîne nominale : %v", err)
	}

	// forgeRecord construit un manifeste altéré RE-SIGNÉ par la vraie clé :
	// seul le contrôle de chaînage peut le rejeter (cible de la mutation M6).
	forgeRecord := func(epoch, seq uint64, prev [32]byte, cellID string) SignedManifest {
		st := manifestStateFixture("policy-forge", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
		rec := marshalRecord(cellID, epoch, seq, prev, st, time.Unix(1_780_000_100, 0))
		sig, err := signer.Sign(rec)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return SignedManifest{Record: rec, Signature: sig}
	}

	t.Run("chaîne vide", func(t *testing.T) {
		if err := VerifyManifestChain(nil, verifier); !errors.Is(err, ErrManifestContinuity) {
			t.Fatalf("%v, attendu ErrManifestContinuity", err)
		}
	})

	t.Run("prev falsifié mais re-signé", func(t *testing.T) {
		forged := forgeRecord(7, 1, sha256.Sum256([]byte("autre")), manifestCellID)
		err := VerifyManifestChain([]SignedManifest{chain[0], forged, chain[2]}, verifier)
		if !errors.Is(err, ErrManifestContinuity) {
			t.Fatalf("%v, attendu ErrManifestContinuity", err)
		}
	})

	t.Run("saut de seq re-signé", func(t *testing.T) {
		forged := forgeRecord(7, 2, HashManifest(chain[0].Record), manifestCellID)
		err := VerifyManifestChain([]SignedManifest{chain[0], forged}, verifier)
		if !errors.Is(err, ErrManifestContinuity) {
			t.Fatalf("%v, attendu ErrManifestContinuity", err)
		}
	})

	t.Run("genèse avec prev non nul", func(t *testing.T) {
		forged := forgeRecord(7, 0, sha256.Sum256([]byte("amorce")), manifestCellID)
		err := VerifyManifestChain([]SignedManifest{forged}, verifier)
		if !errors.Is(err, ErrManifestContinuity) {
			t.Fatalf("%v, attendu ErrManifestContinuity", err)
		}
	})

	t.Run("cellID change en cours de chaîne", func(t *testing.T) {
		forged := forgeRecord(7, 1, HashManifest(chain[0].Record), "tbp/registry/cell-autre")
		err := VerifyManifestChain([]SignedManifest{chain[0], forged}, verifier)
		if !errors.Is(err, ErrManifestContinuity) {
			t.Fatalf("%v, attendu ErrManifestContinuity", err)
		}
	})

	t.Run("époque en régression", func(t *testing.T) {
		forged := forgeRecord(6, 1, HashManifest(chain[0].Record), manifestCellID)
		err := VerifyManifestChain([]SignedManifest{chain[0], forged}, verifier)
		if !errors.Is(err, ErrManifestContinuity) {
			t.Fatalf("%v, attendu ErrManifestContinuity", err)
		}
	})

	t.Run("signature d'une autre clé", func(t *testing.T) {
		otherSigner, _ := manifestOtherKey(t)
		sig, err := otherSigner.Sign(chain[1].Record)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		tampered := SignedManifest{Record: chain[1].Record, Signature: sig}
		err = VerifyManifestChain([]SignedManifest{chain[0], tampered}, verifier)
		if !errors.Is(err, ErrManifestSignature) {
			t.Fatalf("%v, attendu ErrManifestSignature (cible de la mutation M7)", err)
		}
	})

	t.Run("octet de record retourné", func(t *testing.T) {
		rec := append([]byte(nil), chain[1].Record...)
		rec[len(rec)-20] ^= 0xFF // dans la zone des hashes d'état
		tampered := SignedManifest{Record: rec, Signature: chain[1].Signature}
		if err := VerifyManifestChain([]SignedManifest{chain[0], tampered}, verifier); err == nil {
			t.Fatal("record altéré accepté")
		}
	})

	t.Run("record tronqué", func(t *testing.T) {
		tampered := SignedManifest{Record: chain[1].Record[:len(chain[1].Record)-8], Signature: chain[1].Signature}
		if err := VerifyManifestChain([]SignedManifest{chain[0], tampered}, verifier); !errors.Is(err, ErrManifestRecordMalformed) {
			t.Fatalf("%v, attendu ErrManifestRecordMalformed", err)
		}
	})

	t.Run("artefacts JSON publiés vérifiables", func(t *testing.T) {
		// Le chemin réel d'un tiers : fichiers JSON → ParseSignedManifest → chaîne.
		var published []SignedManifest
		for _, sm := range chain {
			data, err := MarshalSignedManifest(sm)
			if err != nil {
				t.Fatalf("MarshalSignedManifest: %v", err)
			}
			back, err := ParseSignedManifest(data)
			if err != nil {
				t.Fatalf("ParseSignedManifest: %v", err)
			}
			published = append(published, back)
		}
		if err := VerifyManifestChain(published, verifier); err != nil {
			t.Fatalf("chaîne via artefacts JSON : %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Vecteur doré (D70) — format « TBP-M1 » + artefacts figés
// ---------------------------------------------------------------------------

// TestGoldenManifestChain fige le format fil : trois artefacts JSON publiés
// et la clé publique, générés UNE FOIS depuis le code (fixtures
// déterministes ci-dessus), puis embarqués. Le test n'utilise QUE le chemin
// du tiers (ParseSignedManifest + VerifyManifestChain) : toute dérive du
// format — layout du record, sérialisation JSON, chaînage — casse ce test.
func TestGoldenManifestChain(t *testing.T) {
	// Clé publique de cellule et artefacts publiés, figés (générés depuis les
	// fixtures déterministes, puis embarqués — ne JAMAIS régénérer en silence :
	// une valeur différente signale une dérive du format « TBP-M1 »).
	const goldenVKey = "tbp/registry/cell-test-01+c5a03021+AazcyElNRY9Ep6qsHWqE7GJNruiENtsq4m5numRaEGIo"

	goldenArtifacts := []string{
		`{"record":"5442502d4d3101197462702f72656769737472792f63656c6c2d746573742d303100000000000000070000000000000000000000000000000000000000000000000000000000000000000000000000000072993b6cb83904d39a8c73bd0651aa6251288ede5dbc2c7bcbdc54cc5bbf5d773cf6ecd03475cc9bb00ee397db65cbfda1546ead533b69f3c969d43e8bccc43e5e7a87719b5220bb69f4a36681cefd830181c4f1406209be5c263f4d422b6b09ecbfc0abb018d13725f26809801dfb8df9403f8aab3dfd3d8d4b35e75d9cd94e0000000000000000000000000000000000000000000000000000000000000000000000006a18a500","signature":"66fbc51fb7f3c56bfe852bc282ef3be5c26eaa2939510220a4b7c739dc60138162e45b37e0589e1785ea975b0a23b89e1e0245c7fc3551cbc2b38d02a7844d09"}`,
		`{"record":"5442502d4d3101197462702f72656769737472792f63656c6c2d746573742d303100000000000000070000000000000001aa630eeed4fad965e7dc19433f89b30ddea69940c12563965c4ae7e9042e01e005d35c3cff576032c2ec020b80090de59407c157e924b1e1140f9d29a48331133cf6ecd03475cc9bb00ee397db65cbfda1546ead533b69f3c969d43e8bccc43e5e7a87719b5220bb69f4a36681cefd830181c4f1406209be5c263f4d422b6b09ecbfc0abb018d13725f26809801dfb8df9403f8aab3dfd3d8d4b35e75d9cd94e0000000000000000000000000000000000000000000000000000000000000000000000006a18a53c","signature":"28099bea9bd971c88d05c070ab75ca430685390fb0e1b4be271f13438361f6fd4401c120fdb5865ad138a54b66c65e8bd7ed9e832e7ab1e0e0bc74c47cf6730d"}`,
		`{"record":"5442502d4d3101197462702f72656769737472792f63656c6c2d746573742d303100000000000000080000000000000002a660e49145c740e20b3176a68a037727e5a5fafaaaa5c45fe4ade10d36e712da05d35c3cff576032c2ec020b80090de59407c157e924b1e1140f9d29a48331133cf6ecd03475cc9bb00ee397db65cbfda1546ead533b69f3c969d43e8bccc43e5e7a87719b5220bb69f4a36681cefd830181c4f1406209be5c263f4d422b6b092612cdbf509c5dec0bea5c279dd1e06ad1af70974d4bf5c7c3a02b9e843239e40000000000000000000000000000000000000000000000000000000000000000000000006a18a578","signature":"213966a55114b4ebff85bd34da413ba7472298043ea87336085ea98c1eb047e3c926ed35b6623ed65dcc8cf2d05f1e4b82f773eee3428bbf6f6311533194aa01"}`,
	}

	verifier, err := NewVerifier(goldenVKey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	var chain []SignedManifest
	for i, raw := range goldenArtifacts {
		sm, err := ParseSignedManifest([]byte(raw))
		if err != nil {
			t.Fatalf("artefact %d : %v", i, err)
		}
		chain = append(chain, sm)
	}
	if err := VerifyManifestChain(chain, verifier); err != nil {
		t.Fatalf("chaîne dorée : %v", err)
	}
	// Contenu figé — le vecteur atteste le scénario du critère 1.
	rec0, _ := ParseManifestRecord(chain[0].Record)
	rec1, _ := ParseManifestRecord(chain[1].Record)
	rec2, _ := ParseManifestRecord(chain[2].Record)
	if rec0.Seq != 0 || rec1.Seq != 1 || rec2.Seq != 2 {
		t.Fatalf("seqs %d/%d/%d, attendu 0/1/2", rec0.Seq, rec1.Seq, rec2.Seq)
	}
	if rec0.Epoch != 7 || rec1.Epoch != 7 || rec2.Epoch != 8 {
		t.Fatalf("époques %d/%d/%d, attendu 7/7/8", rec0.Epoch, rec1.Epoch, rec2.Epoch)
	}
	if rec0.CellID != manifestCellID {
		t.Fatalf("cellID %q, attendu %q", rec0.CellID, manifestCellID)
	}
	if rec0.State.PolicyID == rec1.State.PolicyID {
		t.Fatal("le changement de policy_id n'est pas visible dans le vecteur doré")
	}
	if rec1.State.AIContainerHash == rec2.State.AIContainerHash {
		t.Fatal("le changement de conteneur IA n'est pas visible dans le vecteur doré")
	}
}

// ---------------------------------------------------------------------------
// Fail-closed : fautes de feuille, reprise, configuration
// ---------------------------------------------------------------------------

// TestManifestLeafFaultFailsClosed — cible de la mutation M9 : feuille de
// transition impossible ⇒ la transition N'A PAS LIEU (erreur, alarme, état
// et seq non avancés) ; une fois le puits guéri, la même transition réussit
// en seq 1 — preuve qu'aucun état n'a été commité « en silence ».
func TestManifestLeafFaultFailsClosed(t *testing.T) {
	ctx := context.Background()
	sink := &stubMaster{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, _ := newTestManifester(t, sink, clock, trips)

	st0 := manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	if _, err := m.Genesis(ctx, 7, st0); err != nil {
		t.Fatalf("Genesis: %v", err)
	}

	sink.failing.Store(true)
	st1 := manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	if _, err := m.Transition(ctx, 7, st1); !errors.Is(err, ErrManifestLeafFault) {
		t.Fatalf("Transition sans feuille : %v, attendu ErrManifestLeafFault", err)
	}
	if got := trips.taken(); len(got) != 1 || got[0] != "manifest-leaf-fault" {
		t.Fatalf("alarmes %v, attendu [manifest-leaf-fault]", got)
	}
	st, ok := m.State()
	if !ok || st != st0 {
		t.Fatal("l'état a avancé malgré la faute de feuille — saut silencieux")
	}
	last, _ := m.LastSigned()
	lastRec, _ := ParseManifestRecord(last.Record)
	if lastRec.Seq != 0 {
		t.Fatalf("seq avancée à %d malgré la faute", lastRec.Seq)
	}

	sink.failing.Store(false)
	if _, err := m.Transition(ctx, 7, st1); err != nil {
		t.Fatalf("Transition après guérison : %v", err)
	}
	last, _ = m.LastSigned()
	lastRec, _ = ParseManifestRecord(last.Record)
	if lastRec.Seq != 1 {
		t.Fatalf("seq %d après guérison, attendu 1 (aucune seq perdue)", lastRec.Seq)
	}
}

// TestManifestGenesisLeafFault : la genèse elle-même exige sa feuille — pas
// de preuve, pas d'état attesté, même pour le manifeste 0.
func TestManifestGenesisLeafFault(t *testing.T) {
	ctx := context.Background()
	sink := &stubMaster{}
	sink.failing.Store(true)
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, _ := newTestManifester(t, sink, clock, trips)

	st0 := manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	if _, err := m.Genesis(ctx, 7, st0); !errors.Is(err, ErrManifestLeafFault) {
		t.Fatalf("Genesis sans feuille : %v, attendu ErrManifestLeafFault", err)
	}
	if _, ok := m.State(); ok {
		t.Fatal("cellule initialisée malgré la faute de feuille de genèse")
	}
	sink.failing.Store(false)
	if _, err := m.Genesis(ctx, 7, st0); err != nil {
		t.Fatalf("Genesis après guérison : %v", err)
	}
}

// TestManifesterRestoreFromArtifact : la chaîne se restaure depuis l'artefact
// publié (D70) et continue en seq + 1 ; un artefact falsifié ou d'une autre
// cellule est rejeté À LA CONSTRUCTION — jamais un état silencieux.
func TestManifesterRestoreFromArtifact(t *testing.T) {
	ctx := context.Background()
	sink := &stubMaster{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, verifier := newTestManifester(t, sink, clock, trips)

	if _, err := m.Genesis(ctx, 7, manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{})); err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	g1, err := m.Transition(ctx, 7, manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v1", [32]byte{}))
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}

	// Reprise : le nouveau Manifester continue la chaîne (seq 2).
	signer, _ := manifestTestKey(t)
	sink2 := &stubMaster{}
	m2, err := NewManifester(ManifestOptions{
		CellID:   manifestCellID,
		Signer:   signer,
		Verifier: verifier,
		Leaves:   sink2,
		Salt:     manifestSalt,
		Last:     &g1,
		Now:      clock.now,
	})
	if err != nil {
		t.Fatalf("NewManifester avec Last: %v", err)
	}
	g2, err := m2.Transition(ctx, 8, manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v2", [32]byte{}))
	if err != nil {
		t.Fatalf("Transition après reprise : %v", err)
	}
	rec2, _ := ParseManifestRecord(g2.Record)
	if rec2.Seq != 2 || rec2.Prev != HashManifest(g1.Record) {
		t.Fatalf("reprise : seq %d / chaînage rompu", rec2.Seq)
	}

	// Artefact à signature falsifiée : construction refusée.
	bad := SignedManifest{Record: g1.Record, Signature: append([]byte(nil), g1.Signature...)}
	bad.Signature[0] ^= 0xFF
	if _, err := NewManifester(ManifestOptions{
		CellID: manifestCellID, Signer: signer, Verifier: verifier,
		Leaves: sink2, Salt: manifestSalt, Last: &bad,
	}); !errors.Is(err, ErrManifestSignature) {
		t.Fatalf("reprise sur artefact falsifié : %v, attendu ErrManifestSignature", err)
	}

	// Artefact d'une autre cellule : construction refusée.
	otherRecord := marshalRecord("tbp/registry/cell-autre", 7, 0, [32]byte{}, manifestStateFixture("p", "o", "b", "a", [32]byte{}), clock.now())
	otherSig, _ := signer.Sign(otherRecord)
	foreign := SignedManifest{Record: otherRecord, Signature: otherSig}
	if _, err := NewManifester(ManifestOptions{
		CellID: manifestCellID, Signer: signer, Verifier: verifier,
		Leaves: sink2, Salt: manifestSalt, Last: &foreign,
	}); !errors.Is(err, ErrManifestContinuity) {
		t.Fatalf("reprise sur artefact étranger : %v, attendu ErrManifestContinuity", err)
	}
}

// TestManifesterConfigFailClosed : la construction refuse toute configuration
// incomplète — pas de manifester « à moitié armé ».
func TestManifesterConfigFailClosed(t *testing.T) {
	signer, verifier := manifestTestKey(t)
	sink := &stubMaster{}
	base := ManifestOptions{
		CellID:   manifestCellID,
		Signer:   signer,
		Verifier: verifier,
		Leaves:   sink,
		Salt:     manifestSalt,
	}
	cases := map[string]func(o *ManifestOptions){
		"cellID vide":      func(o *ManifestOptions) { o.CellID = "" },
		"cellID trop long": func(o *ManifestOptions) { o.CellID = strings.Repeat("x", maxCellIDLen+1) },
		"signer nil":       func(o *ManifestOptions) { o.Signer = nil },
		"verifier nil":     func(o *ManifestOptions) { o.Verifier = nil },
		"feuilles nil":     func(o *ManifestOptions) { o.Leaves = nil },
		"sel trop court":   func(o *ManifestOptions) { o.Salt = []byte("court") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := base
			mutate(&o)
			if _, err := NewManifester(o); err == nil {
				t.Fatal("configuration incomplète acceptée — fail-closed rompu")
			}
		})
	}
}

// TestSignedManifestArtifactRoundTrip : sérialisation JSON hex exacte, et
// rejet des artefacts mal formés dès le parsing.
func TestSignedManifestArtifactRoundTrip(t *testing.T) {
	ctx := context.Background()
	sink := &stubMaster{}
	clock := newFakeClock(time.Unix(1_780_000_000, 0))
	trips := &manifestTripLog{}
	m, _, _ := newTestManifester(t, sink, clock, trips)

	sm, err := m.Genesis(ctx, 7, manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{}))
	if err != nil {
		t.Fatalf("Genesis: %v", err)
	}
	data, err := MarshalSignedManifest(sm)
	if err != nil {
		t.Fatalf("MarshalSignedManifest: %v", err)
	}
	back, err := ParseSignedManifest(data)
	if err != nil {
		t.Fatalf("ParseSignedManifest: %v", err)
	}
	if !bytes.Equal(back.Record, sm.Record) || !bytes.Equal(back.Signature, sm.Signature) {
		t.Fatal("round-trip artefact non exact")
	}
	if _, err := MarshalSignedManifest(SignedManifest{}); err == nil {
		t.Fatal("artefact incomplet marshalisé sans erreur")
	}
	if _, err := ParseSignedManifest([]byte(`{"record":"zz","signature":"00"}`)); err == nil {
		t.Fatal("record non hexadécimal accepté")
	}
	if _, err := ParseSignedManifest([]byte(`{"record":"00","signature":"zz"}`)); err == nil {
		t.Fatal("signature non hexadécimale acceptée")
	}
	if _, err := ParseSignedManifest([]byte(`{"record":"00","signature":"00"}`)); !errors.Is(err, ErrManifestRecordMalformed) {
		t.Fatalf("record mal formé : %v, attendu ErrManifestRecordMalformed", err)
	}
}

// TestManifestRealCellLog : les feuilles KindManifest traversent le VRAI log
// Tessera (T7) — la whitelist kind 11 est effective des deux côtés
// (marshal/unmarshal, leçon #65) et la tête avance.
func TestManifestRealCellLog(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log, _ := openTestLog(t, ctx, t.TempDir(), nil)
	defer log.Close(ctx)

	signer, verifier := manifestTestKey(t)
	m, err := NewManifester(ManifestOptions{
		CellID:   manifestCellID,
		Signer:   signer,
		Verifier: verifier,
		Leaves:   log,
		Salt:     manifestSalt,
	})
	if err != nil {
		t.Fatalf("NewManifester: %v", err)
	}
	st0 := manifestStateFixture("policy-v1", "opa-v1", "broker-v1", "ai-v1", [32]byte{})
	if _, err := m.Genesis(ctx, 7, st0); err != nil {
		t.Fatalf("Genesis sur vrai log: %v", err)
	}
	if _, err := m.Transition(ctx, 7, manifestStateFixture("policy-v2", "opa-v1", "broker-v1", "ai-v1", [32]byte{})); err != nil {
		t.Fatalf("Transition sur vrai log: %v", err)
	}
	root, size, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if size != 2 {
		t.Fatalf("taille %d, attendu 2 (genèse + transition)", size)
	}
	if root == ([32]byte{}) {
		t.Fatal("racine Merkle nulle après feuilles KindManifest")
	}
}
