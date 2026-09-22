package pep

// Revue de sécurité #89 : l'ancien vérifieur de pepd comptait des identités
// DÉCLARÉES ("signers": ["x","y"]), jamais une signature — n'importe quel
// appelant joignant le port de données pouvait donc couper l'application
// des règles. Ces tests couvrent le remplacement cryptographique
// (NewSignatureQuorumVerifier) de bout en bout, y compris via l'endpoint
// HTTP réel (revue #90 : « à confirmer en exécution », même discipline que
// pour la revue #89 elle-même).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mustGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func signQuorum(priv ed25519.PrivateKey, kid [16]byte, condition string, expiry time.Time) QuorumSignature {
	return QuorumSignature{KeyID: kid, Signature: ed25519.Sign(priv, QuorumMessage(condition, expiry))}
}

// TestSignatureQuorumVerifierRequiresDistinctValidSignatures : k=2, 3
// contrôleurs — le quorum n'est atteint qu'avec 2 signatures DISTINCTES et
// valides ; une seule, une invalide, ou la même répétée ne suffisent pas.
func TestSignatureQuorumVerifierRequiresDistinctValidSignatures(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	pub3, _ := mustGenKey(t)
	kid1, kid2, kid3 := [16]byte{1}, [16]byte{2}, [16]byte{3}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2, kid3: pub3}

	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time { return now }
	verify, err := NewSignatureQuorumVerifier(keyring, 2, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	expiry := now.Add(1 * time.Minute)
	condition := "mode-closed"

	// Une seule signature valide : insuffisant.
	if verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, condition, expiry),
	}}) {
		t.Fatal("k=2 admis avec une seule signature")
	}

	// Même signataire répété deux fois : toujours une seule identité distincte.
	sig1 := signQuorum(priv1, kid1, condition, expiry)
	if verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{sig1, sig1}}) {
		t.Fatal("k=2 admis avec le même signataire compté deux fois")
	}

	// Une valide + une forgée (mauvaise clé prétendant être kid2) : insuffisant.
	forged := QuorumSignature{KeyID: kid2, Signature: ed25519.Sign(priv1, QuorumMessage(condition, expiry))}
	if verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{sig1, forged}}) {
		t.Fatal("signature forgée (mauvaise clé) admise")
	}

	// 2 signatures distinctes et valides : quorum atteint.
	if !verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, condition, expiry),
		signQuorum(priv2, kid2, condition, expiry),
	}}) {
		t.Fatal("k=2 refusé avec 2 signatures distinctes et valides")
	}
}

// TestSignatureQuorumVerifierBindsCondition : une preuve signée pour une
// AUTRE condition (ex. « mode-monitor ») ne vaut rien pour celle-ci — le
// message signé lie la condition (revue #89 : lier le contenu, pas
// seulement compter des noms).
func TestSignatureQuorumVerifierBindsCondition(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	kid1, kid2 := [16]byte{1}, [16]byte{2}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2}
	now := time.Unix(1_700_000_000, 0)
	verify, err := NewSignatureQuorumVerifier(keyring, 2, 5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	expiry := now.Add(1 * time.Minute)

	proof := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-monitor", expiry), // signé pour l'AUTRE bascule
		signQuorum(priv2, kid2, "mode-monitor", expiry),
	}}
	if verify("mode-closed", proof) {
		t.Fatal("preuve liée à mode-monitor acceptée pour mode-closed")
	}
	if !verify("mode-monitor", proof) {
		t.Fatal("preuve correctement liée refusée")
	}
}

// TestSignatureQuorumVerifierFreshness : une preuve déjà expirée est
// refusée (fail-closed) ; une preuve à une fraîcheur invraisemblable
// (au-delà du TTL max) l'est aussi — ni blanc-seing, ni rejeu tardif.
func TestSignatureQuorumVerifierFreshness(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	kid1, kid2 := [16]byte{1}, [16]byte{2}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2}
	now := time.Unix(1_700_000_000, 0)
	verify, err := NewSignatureQuorumVerifier(keyring, 2, 5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	condition := "mode-closed"

	sign := func(expiry time.Time) QuorumProof {
		return QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
			signQuorum(priv1, kid1, condition, expiry),
			signQuorum(priv2, kid2, condition, expiry),
		}}
	}

	if verify(condition, sign(now.Add(-1*time.Second))) {
		t.Fatal("preuve déjà expirée acceptée")
	}
	if verify(condition, sign(now)) {
		t.Fatal("preuve expirant exactement maintenant acceptée")
	}
	if verify(condition, sign(now.Add(10*time.Minute))) {
		t.Fatal("preuve au-delà du TTL max acceptée")
	}
	if !verify(condition, sign(now.Add(1*time.Minute))) {
		t.Fatal("preuve fraîche et correctement signée refusée")
	}
}

// TestNewSignatureQuorumVerifierFailClosedConfig : trousseau vide ou k
// incohérent refusent DÈS la construction (§1).
func TestNewSignatureQuorumVerifierFailClosedConfig(t *testing.T) {
	pub, _ := mustGenKey(t)
	if _, err := NewSignatureQuorumVerifier(nil, 1, 0, nil); err == nil {
		t.Fatal("trousseau vide accepté")
	}
	keyring := map[[16]byte]ed25519.PublicKey{{1}: pub}
	if _, err := NewSignatureQuorumVerifier(keyring, 0, 0, nil); err == nil {
		t.Fatal("k=0 accepté")
	}
	if _, err := NewSignatureQuorumVerifier(keyring, 2, 0, nil); err == nil {
		t.Fatal("k > nombre de contrôleurs accepté")
	}
	if _, err := NewSignatureQuorumVerifier(keyring, 1, 0, nil); err != nil {
		t.Fatalf("config nominale refusée: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Bout en bout via le VRAI endpoint HTTP /v1/mode (revue #89 : « je l'ai
// établi en lisant le code, pas en l'exécutant » — ce test l'exécute).
// ---------------------------------------------------------------------------

// TestModeEndpointRejectsForgedProofRealCrypto : le endpoint réel refuse une
// bascule dont la preuve invente des identités (kid inconnu du trousseau,
// ou vide) — exactement le format que l'ancien /v1/mode acceptait
// aveuglément ({"mode":"monitor","signers":["x","x"]}) — puis l'accepte
// avec de vraies signatures Ed25519 d'un quorum de contrôleurs.
func TestModeEndpointRejectsForgedProofRealCrypto(t *testing.T) {
	sink := &stubSink{}
	now := func() time.Time { return time.Unix(testIAT+30, 0) }

	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	kid1, kid2 := [16]byte{0xaa}, [16]byte{0xbb}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2}
	verify, err := NewSignatureQuorumVerifier(keyring, 2, 5*time.Minute, now)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}

	mc, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: sink, VerifyQuorum: verify, Now: now,
	})
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}
	ar, err := NewAntiReplay(AntiReplayOptions{Capacity: 256, Now: now})
	if err != nil {
		t.Fatalf("NewAntiReplay: %v", err)
	}
	v, err := NewValidator(ValidatorOptions{
		CellID: opaTestCellID,
		Keyring: map[[16]byte]ed25519.PublicKey{
			testKID: ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey),
		},
		PolicyID: arr32(policyV1), Salt: testSalt, Leaves: sink, AntiReplay: ar, Now: now,
	})
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	l, err := NewListener(ListenerOptions{Validator: v, Mode: mc})
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	srv := httptest.NewServer(l.Handler())
	defer srv.Close()

	post := func(body []byte) (int, []byte) {
		resp, err := http.Post(srv.URL+"/v1/mode", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/mode: %v", err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}

	// L'ancienne attaque exacte de la revue #89 : des identités déclarées,
	// aucune signature — refusée (le champ n'existe même plus sur le fil).
	legacy, _ := json.Marshal(map[string]any{"mode": "closed", "signers": []string{"x", "x"}})
	if status, _ := post(legacy); status != http.StatusForbidden {
		t.Fatalf("attaque #89 (signers déclarés, sans signature) : status=%d, veut 403", status)
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("mode basculé par l'attaque #89")
	}

	// Format actuel, mais sans aucune signature : refusé.
	expiry := now().Add(1 * time.Minute)
	empty, _ := json.Marshal(ModeChangeRequest{Mode: "closed", Expiry: expiry.Unix()})
	if status, _ := post(empty); status != http.StatusForbidden {
		t.Fatalf("preuve vide : status=%d, veut 403", status)
	}

	// Une seule signature valide (k=2 exigé) : refusé.
	one, _ := json.Marshal(ModeChangeRequest{
		Mode: "closed", Expiry: expiry.Unix(),
		Signatures: []QuorumSignatureWire{wireSig(signQuorum(priv1, kid1, "mode-closed", expiry))},
	})
	if status, _ := post(one); status != http.StatusForbidden {
		t.Fatalf("une seule signature (k=2) : status=%d, veut 403", status)
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("mode basculé avec une seule signature")
	}

	// Même contrôleur compté deux fois (kid1 répété) : toujours k=1 en
	// réalité, refusé — un simple comptage de longueur s'y laisserait
	// prendre (revue #89 : compter n'est pas vérifier).
	dup := signQuorum(priv1, kid1, "mode-closed", expiry)
	dupBody, _ := json.Marshal(ModeChangeRequest{
		Mode: "closed", Expiry: expiry.Unix(),
		Signatures: []QuorumSignatureWire{wireSig(dup), wireSig(dup)},
	})
	if status, _ := post(dupBody); status != http.StatusForbidden {
		t.Fatalf("même signataire répété (kid1, kid1) : status=%d, veut 403", status)
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("mode basculé avec un signataire répété")
	}

	// k=2 signatures valides et distinctes : la bascule est acceptée.
	two, _ := json.Marshal(ModeChangeRequest{
		Mode: "closed", Expiry: expiry.Unix(),
		Signatures: []QuorumSignatureWire{
			wireSig(signQuorum(priv1, kid1, "mode-closed", expiry)),
			wireSig(signQuorum(priv2, kid2, "mode-closed", expiry)),
		},
	})
	status, data := post(two)
	if status != http.StatusOK {
		t.Fatalf("quorum réel k=2 : status=%d body=%s, veut 200", status, data)
	}
	var mr ModeResponse
	if err := json.Unmarshal(data, &mr); err != nil || mr.Mode != "closed" {
		t.Fatalf("mode=%q err=%v, veut closed", mr.Mode, err)
	}
	if mc.Mode() != ModeClosed {
		t.Fatal("ModeController pas en closed malgré 200")
	}
}

func wireSig(s QuorumSignature) QuorumSignatureWire {
	return QuorumSignatureWire{KeyID: hex.EncodeToString(s.KeyID[:]), Signature: hex.EncodeToString(s.Signature)}
}
