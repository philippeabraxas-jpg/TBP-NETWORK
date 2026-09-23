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
	"path/filepath"
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

func signQuorum(priv ed25519.PrivateKey, kid [16]byte, condition, cellID string, expiry time.Time) QuorumSignature {
	return QuorumSignature{KeyID: kid, Signature: ed25519.Sign(priv, QuorumMessage(condition, cellID, expiry))}
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
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	expiry := now.Add(1 * time.Minute)
	condition := "mode-closed"

	// Une seule signature valide : insuffisant.
	if verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, condition, opaTestCellID, expiry),
	}}) {
		t.Fatal("k=2 admis avec une seule signature")
	}

	// Même signataire répété deux fois : toujours une seule identité distincte.
	sig1 := signQuorum(priv1, kid1, condition, opaTestCellID, expiry)
	if verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{sig1, sig1}}) {
		t.Fatal("k=2 admis avec le même signataire compté deux fois")
	}

	// Une valide + une forgée (mauvaise clé prétendant être kid2) : insuffisant.
	forged := QuorumSignature{KeyID: kid2, Signature: ed25519.Sign(priv1, QuorumMessage(condition, opaTestCellID, expiry))}
	if verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{sig1, forged}}) {
		t.Fatal("signature forgée (mauvaise clé) admise")
	}

	// 2 signatures distinctes et valides : quorum atteint.
	if !verify(condition, QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, condition, opaTestCellID, expiry),
		signQuorum(priv2, kid2, condition, opaTestCellID, expiry),
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
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	expiry := now.Add(1 * time.Minute)

	proof := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-monitor", opaTestCellID, expiry), // signé pour l'AUTRE bascule
		signQuorum(priv2, kid2, "mode-monitor", opaTestCellID, expiry),
	}}
	if verify("mode-closed", proof) {
		t.Fatal("preuve liée à mode-monitor acceptée pour mode-closed")
	}
	if !verify("mode-monitor", proof) {
		t.Fatal("preuve correctement liée refusée")
	}
}

// TestSignatureQuorumVerifierBindsCellID : une preuve signée pour une
// AUTRE cellule ne vaut rien ici — même trousseau, même signatures,
// même condition (revue de sécurité #105 : sans cette liaison, une
// preuve « monitor » capturée sur une cellule restait valide sur
// N'IMPORTE QUELLE autre cellule du même trousseau).
func TestSignatureQuorumVerifierBindsCellID(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	kid1, kid2 := [16]byte{1}, [16]byte{2}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2}
	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time { return now }
	verifyA, err := NewSignatureQuorumVerifier("cell-a", keyring, 2, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier(cell-a): %v", err)
	}
	verifyB, err := NewSignatureQuorumVerifier("cell-b", keyring, 2, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier(cell-b): %v", err)
	}
	expiry := now.Add(1 * time.Minute)
	condition := "mode-monitor"

	proofForA := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, condition, "cell-a", expiry),
		signQuorum(priv2, kid2, condition, "cell-a", expiry),
	}}
	if !verifyA(condition, proofForA) {
		t.Fatal("preuve correctement liée à cell-a refusée par le vérifieur de cell-a")
	}
	if verifyB(condition, proofForA) {
		t.Fatal("preuve signée pour cell-a acceptée par le vérifieur de cell-b — rejeu inter-cellule (#105)")
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
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	condition := "mode-closed"

	sign := func(expiry time.Time) QuorumProof {
		return QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
			signQuorum(priv1, kid1, condition, opaTestCellID, expiry),
			signQuorum(priv2, kid2, condition, opaTestCellID, expiry),
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

// TestNewSignatureQuorumVerifierFailClosedConfig : cellID vide, trousseau
// vide ou k incohérent refusent DÈS la construction (§1).
func TestNewSignatureQuorumVerifierFailClosedConfig(t *testing.T) {
	pub, _ := mustGenKey(t)
	if _, err := NewSignatureQuorumVerifier("", map[[16]byte]ed25519.PublicKey{{1}: pub}, 1, 0, nil); err == nil {
		t.Fatal("cellID vide accepté")
	}
	if _, err := NewSignatureQuorumVerifier(opaTestCellID, nil, 1, 0, nil); err == nil {
		t.Fatal("trousseau vide accepté")
	}
	keyring := map[[16]byte]ed25519.PublicKey{{1}: pub}
	if _, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 0, 0, nil); err == nil {
		t.Fatal("k=0 accepté")
	}
	if _, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 0, nil); err == nil {
		t.Fatal("k > nombre de contrôleurs accepté")
	}
	if _, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 1, 0, nil); err != nil {
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
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, now)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	state := NewFileQuorumStateStore(filepath.Join(t.TempDir(), "quorum_state.json"))

	mc, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: sink, VerifyQuorum: verify, QuorumState: state, Now: now,
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
	srv := httptest.NewServer(l.AdminHandler())
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
		Signatures: []QuorumSignatureWire{wireSig(signQuorum(priv1, kid1, "mode-closed", opaTestCellID, expiry))},
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
	dup := signQuorum(priv1, kid1, "mode-closed", opaTestCellID, expiry)
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
			wireSig(signQuorum(priv1, kid1, "mode-closed", opaTestCellID, expiry)),
			wireSig(signQuorum(priv2, kid2, "mode-closed", opaTestCellID, expiry)),
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

// ---------------------------------------------------------------------------
// Revue de sécurité #105 : rejeu de la preuve de quorum, MÊME cellule.
// ---------------------------------------------------------------------------

// TestModeControllerRejectsReplayedProof : preuve NON-VACUE directe — la
// MÊME preuve (même signatures, même expiry, toujours valide et non
// expirée) rejouée une seconde fois pour la MÊME bascule est refusée. Sans
// QuorumStateStore, le crypto seul (#89) l'aurait acceptée deux fois tant
// qu'elle reste fraîche (jusqu'à 5 min, DefaultQuorumProofTTL).
func TestModeControllerRejectsReplayedProof(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	kid1, kid2 := [16]byte{1}, [16]byte{2}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2}
	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time { return now }
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	state := NewFileQuorumStateStore(filepath.Join(t.TempDir(), "quorum_state.json"))
	mc, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: &stubSink{}, VerifyQuorum: verify, QuorumState: state, Now: nowFn,
	})
	if err != nil {
		t.Fatalf("NewModeController: %v", err)
	}

	expiry := now.Add(1 * time.Minute)
	proof := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-closed", opaTestCellID, expiry),
		signQuorum(priv2, kid2, "mode-closed", opaTestCellID, expiry),
	}}

	if err := mc.SetMode(ModeClosed, proof); err != nil {
		t.Fatalf("première bascule (preuve fraîche, jamais consommée): %v", err)
	}
	if mc.Mode() != ModeClosed {
		t.Fatal("bascule non appliquée malgré succès")
	}

	// Retour à monitor pour pouvoir soumettre EXACTEMENT la même preuve
	// closed une seconde fois (SetMode est un no-op si le mode demandé
	// est déjà courant — il faut quitter closed d'abord, avec une preuve
	// DIFFÉRENTE, pour isoler le rejeu de la preuve closed elle-même).
	backProof := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-monitor", opaTestCellID, expiry),
		signQuorum(priv2, kid2, "mode-monitor", opaTestCellID, expiry),
	}}
	if err := mc.SetMode(ModeMonitor, backProof); err != nil {
		t.Fatalf("retour à monitor: %v", err)
	}

	// Rejeu de l'EXACTE preuve closed déjà consommée plus haut — toujours
	// cryptographiquement valide et dans sa fenêtre de fraîcheur (5 min,
	// l'horloge de test n'a pas avancé) : doit être refusé.
	if err := mc.SetMode(ModeClosed, proof); err == nil {
		t.Fatal("preuve de quorum REJOUÉE acceptée (#105)")
	}
	if mc.Mode() != ModeMonitor {
		t.Fatal("mode basculé par une preuve rejouée")
	}
}

// TestModeControllerRejectsReplayAfterRestart : le second axe de l'issue
// #105 — une preuve « monitor » capturée une fois reste rejouable APRÈS
// un redémarrage de pepd si l'antirejeu n'est qu'en mémoire, ce qui
// annule le fail-closed du redémarrage (#93). Ce test simule un
// redémarrage en reconstruisant un ModeController FRAIS (comme au
// process suivant), adossé au MÊME fichier d'état persistant — la preuve
// consommée par « l'ancien processus » doit rester refusée par le
// « nouveau ».
func TestModeControllerRejectsReplayAfterRestart(t *testing.T) {
	pub1, priv1 := mustGenKey(t)
	pub2, priv2 := mustGenKey(t)
	kid1, kid2 := [16]byte{1}, [16]byte{2}
	keyring := map[[16]byte]ed25519.PublicKey{kid1: pub1, kid2: pub2}
	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time { return now }
	verify, err := NewSignatureQuorumVerifier(opaTestCellID, keyring, 2, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("NewSignatureQuorumVerifier: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "quorum_state.json")

	expiry := now.Add(1 * time.Minute)
	proof := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-monitor", opaTestCellID, expiry),
		signQuorum(priv2, kid2, "mode-monitor", opaTestCellID, expiry),
	}}

	// « Ancien processus » : consomme la preuve (mode déjà monitor par
	// défaut, donc bascule d'abord vers closed avec une AUTRE preuve pour
	// pouvoir ensuite consommer la preuve monitor ci-dessus en retour).
	closedProof := QuorumProof{Expiry: expiry, Signatures: []QuorumSignature{
		signQuorum(priv1, kid1, "mode-closed", opaTestCellID, expiry),
		signQuorum(priv2, kid2, "mode-closed", opaTestCellID, expiry),
	}}
	old, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: &stubSink{}, VerifyQuorum: verify,
		QuorumState: NewFileQuorumStateStore(statePath), Now: nowFn,
	})
	if err != nil {
		t.Fatalf("NewModeController (ancien processus): %v", err)
	}
	if err := old.SetMode(ModeClosed, closedProof); err != nil {
		t.Fatalf("ancien processus: bascule closed: %v", err)
	}
	if err := old.SetMode(ModeMonitor, proof); err != nil {
		t.Fatalf("ancien processus: consommation de la preuve monitor: %v", err)
	}

	// « Redémarrage » : nouveau ModeController, même fichier d'état sur
	// disque (même registre) — StartRefused comme le ferait pepd/main.go
	// au vu de #93, mais peu importe ici : ce qui compte est que le
	// magasin d'état ait survécu.
	restarted, err := NewModeController(ModeOptions{
		CellID: opaTestCellID, Salt: testSalt, Leaves: &stubSink{}, VerifyQuorum: verify,
		QuorumState: NewFileQuorumStateStore(statePath), Now: nowFn, StartRefused: true,
	})
	if err != nil {
		t.Fatalf("NewModeController (redémarrage): %v", err)
	}

	// L'attaque #105 exacte : rejouer la MÊME preuve « monitor » déjà
	// consommée par l'ancien processus, maintenant que le nouveau
	// processus démarre en ModeRefused (§93) — le rejeu ne doit PAS
	// pouvoir en sortir.
	if err := restarted.SetMode(ModeMonitor, proof); err == nil {
		t.Fatal("preuve monitor REJOUÉE après redémarrage acceptée — annule #93 (#105)")
	}
	if restarted.Mode() != ModeRefused {
		t.Fatal("mode sorti de refused par une preuve rejouée après redémarrage")
	}
}
