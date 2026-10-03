// mono.go — T35 (issue #61) : phase mono-cellule RÉELLE du selftest.
//
// Exécute la séquence documentée dans deploy/cellule.md contre les vrais
// binaires : build de pepd, capabilities OPA générées puis restreintes
// (helpers partagés de opa.go — même recette que
// policies/gen_capabilities.sh, jq remplacé par Go), OPA lancé avec ces
// capabilities, pepd en monitor, jetons valides et
// témoins, bascule gouvernée monitor→closed (§5.3), scan vérifié du
// registre tessera. Chaque témoin est une faute précise qui DOIT être
// prise — un contrôle qui passerait sans la faute est non-vacuole.
//
// Substitution DEV (documentée dans deploy/cellule.md) : la clé d'émetteur
// est dérivée d'une seed fixe en pure Go, faute de HSM ici. Ce n'est PAS
// une genèse — la vraie cérémonie est scripts/genesis (§12).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/client"

	devmode "github.com/philippeabraxas-jpg/TBP-NETWORK/src/devmode"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
	supervision "github.com/philippeabraxas-jpg/TBP-NETWORK/src/supervision"
)

const (
	phaseMono    = "mono"
	phaseScale1  = "scale1"
	monoOPAAddr  = "127.0.0.1:18181"
	monoPEPDAddr = "127.0.0.1:18443"
	monoCellID   = "cell-a"
	// kid de l'émetteur DEV du selftest : 16 octets (32 car. hex) — le
	// keyring pepd rejette toute autre longueur (fail-closed au chargement).
	monoDevKIDHex = "7433352d73656c66746573742d646576" // "t35-selftest-dev"
)

// evalResponse est la vue locale du verdict du listener.
type evalResponse struct {
	Allow     bool   `json:"allow"`
	Reason    string `json:"reason"`
	Mode      string `json:"mode"`
	Forwarded bool   `json:"forwarded"`
}

// runCmd exécute une commande et capture stdout/stderr séparément.
func runCmd(dir string, env []string, name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	var out, errB strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errB
	err := cmd.Run()
	return out.String(), errB.String(), err
}

// waitHTTP200 attend qu'un endpoint réponde 200 (sonde de démarrage).
func waitHTTP200(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:noctx — sonde locale à timeout borné
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s toujours injoignable après %s", url, timeout)
}

// postJSON POSTe un corps JSON et rend (status, corps).
func postJSON(url string, body any) (int, []byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// evaluate frappe POST /v1/evaluate et décode le verdict.
//
// PAS de champ epoch dans le corps (retiré — revue de sécurité #90, point
// 2) : l'époque n'est plus une entrée de la requête, elle vient
// exclusivement d'EpochSource côté pepd (TBP_BROKER_SOCKET, ou FixedEpoch(0)
// par défaut) — l'envoyer aurait été un paramètre malhonnête, sans effet.
func evaluate(pepdURL string, token []byte, action, resource string) (int, evalResponse, error) {
	status, raw, err := postJSON(pepdURL+"/v1/evaluate", map[string]any{
		"token":    base64.StdEncoding.EncodeToString(token),
		"action":   action,
		"resource": resource,
	})
	var er evalResponse
	if err != nil {
		return status, er, err
	}
	if err := json.Unmarshal(raw, &er); err != nil {
		return status, er, fmt.Errorf("verdict illisible: %w", err)
	}
	return status, er, nil
}

// devKey dérive une clé Ed25519 de test depuis une seed labelisée.
// SUBSTITUTION DEV — jamais une clé de gouvernance (§12).
func devKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("tbp-t35-selftest-dev:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// cellProfile est un profil de sécurité d'échelle (issue #86) : les MÊMES
// binaires, seules les briques réglables changent. La phase mono garde le
// quorum 2/2 historique ; scale1 exerce le quorum k=1 (l'admin seul signe).
type cellProfile struct {
	phase     string // étiquette des contrôles dans le rapport
	dir       string // sous-répertoire de sortie (registre, logs, socket)
	quorumMin int    // TBP_QUORUM_MIN, = nombre de clés du trousseau
	// drillSlowBody joue l'exercice du corps calé (≈ 10 s : le ReadTimeout de
	// pepd) — une seule fois par exécution du selftest, dans scale1.
	drillSlowBody bool
}

// runMono exécute la phase mono-cellule. Les échecs sont enregistrés dans
// la suite ; la fonction ne rend d'erreur que sur faute d'orchestration.
func runMono(s *suite, cfg config) {
	runCell(s, cfg, cellProfile{phase: phaseMono, dir: ".", quorumMin: 2})
}

func runScale1(s *suite, cfg config) {
	runCell(s, cfg, cellProfile{phase: phaseScale1, dir: "scale1", quorumMin: 1, drillSlowBody: true})
}

// runCell exécute la séquence cellule unique sous un profil donné. Les échecs
// sont enregistrés dans la suite ; la fonction ne rend pas d'erreur.
func runCell(s *suite, cfg config, prof cellProfile) {
	ph := prof.phase
	cfg.out = filepath.Join(cfg.out, prof.dir)

	ctx := context.Background()
	pepdURL := "http://" + monoPEPDAddr
	opaURL := "http://" + monoOPAAddr

	// --- Prérequis : binaires go et opa ------------------------------------
	if _, err := exec.LookPath(cfg.goBin); err != nil {
		s.fail(ph, "prérequis: binaire go", fmt.Errorf("go introuvable (%s) : %w", cfg.goBin, err))
		return
	}
	s.add(ph, "prérequis: binaire go", true, cfg.goBin)
	if _, err := exec.LookPath(cfg.opaBin); err != nil {
		s.fail(ph, "prérequis: binaire opa", fmt.Errorf("opa introuvable (%s) : %w", cfg.opaBin, err))
		return
	}
	s.add(ph, "prérequis: binaire opa", true, cfg.opaBin)

	binDir := filepath.Join(cfg.out, "bin")
	opaDir := filepath.Join(cfg.out, "opa")
	regDir := filepath.Join(cfg.out, "registry", monoCellID)
	adminSock := filepath.Join(cfg.out, "pepd-admin.sock")
	// Le selftest rejoue un premier démarrage : un registre ou un témoin
	// laissé par une exécution précédente (out/ persiste hors CI) ferait
	// repartir pepd en « refused » (#93) — ce serait un faux échec.
	_ = os.RemoveAll(regDir)
	_ = os.Remove(filepath.Join(cfg.out, "pepd-provisioning-witness.json"))
	for _, d := range []string{binDir, opaDir, regDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			s.fail(ph, "préparation des répertoires", err)
			return
		}
	}

	// --- Étape : build de pepd ---------------------------------------------
	pepdBin := filepath.Join(binDir, "pepd")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", pepdBin, "./src/pep/cmd/pepd"); err != nil {
		s.fail(ph, "build pepd", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(ph, "build pepd (deploy/cellule.md §binaire)", true, pepdBin)

	// --- Témoin : démarrage sans TBP_SALT = refus fail-closed ---------------
	hermetic := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "TBP_CELL_ID=" + monoCellID}
	_, errB, err := runCmd(cfg.repo, hermetic, pepdBin)
	if err == nil {
		s.fail(ph, "témoin: pepd sans TBP_SALT refuse de démarrer", fmt.Errorf("pepd a démarré SANS sel — fail-open"))
		return
	}
	s.add(ph, "témoin: pepd sans TBP_SALT refuse de démarrer", true,
		strings.TrimSpace(strings.SplitN(errB, "\n", 2)[0]))

	// --- Étape : capabilities OPA (recette gen_capabilities.sh) -------------
	// Contrôles détaillés dans opa.go (partagés avec la phase daemons, T37).
	strippedPath, ok := prepareCapabilities(s, ph, cfg, opaDir)
	if !ok {
		return
	}

	// --- Étape : OPA serveur sur le bundle compilé avec capabilities --------
	// policyID est calculé AVANT le build (hash des sources rego, pas de
	// l'artefact compilé) : c'est ce qui permet de l'épingler comme
	// révision du bundle SANS circularité (revue de sécurité #92, A5).
	regoPath := filepath.Join(cfg.repo, "policies", "rego", "action_example.rego")
	regoRaw, err := os.ReadFile(regoPath)
	if err != nil {
		s.fail(ph, "policyID (hash du bundle rego)", err)
		return
	}
	policyID := sha256.Sum256(regoRaw)
	bundlePath := filepath.Join(opaDir, "tbp-example.tar.gz")
	// Signature de bundle (revue de sécurité #106) : la révision seule
	// (juste au-dessus) est une étiquette auto-déclarée — seule une
	// signature vérifiée par OPA au chargement prouve que le contenu n'a
	// pas été altéré après coup.
	signingKeyPath, verificationKeyPath, ok := generateSigningKeypair(s, ph, opaDir)
	if !ok {
		return
	}
	if !buildBundle(s, ph, cfg, strippedPath, regoPath, bundlePath, hex.EncodeToString(policyID[:]), signingKeyPath) {
		return
	}
	// Témoin NON-VACUE de #106 : un bundle produit avec la MÊME révision
	// et les MÊMES capabilities mais signé par une AUTRE clé (tout ce
	// qu'un simple accès en écriture au fichier bundle permettrait de
	// reproduire) doit être refusé par un OPA qui vérifie contre la clé
	// pinglée de la cellule.
	if !verifyForgedBundleRefused(s, ph, cfg, strippedPath, regoPath, hex.EncodeToString(policyID[:]), verificationKeyPath, opaDir) {
		return
	}
	opa, ok := startOPA(s, ph, cfg, monoOPAAddr, bundlePath, verificationKeyPath, filepath.Join(opaDir, "opa.log"))
	if !ok {
		return
	}
	defer func() { opa.stop() }() // opa est remplacé par l'exercice de redémarrage (#205)

	// --- Étape : environnement pepd (SUBSTITUTION DEV documentée) -----------
	issuer := devKey("issuer")
	issuerPub := issuer.Public().(ed25519.PublicKey)
	keyringPath := filepath.Join(cfg.out, "keyring.dev.json")
	keyring, _ := json.Marshal(map[string]string{monoDevKIDHex: hex.EncodeToString(issuerPub)})
	if err := os.WriteFile(keyringPath, keyring, 0o600); err != nil {
		s.fail(ph, "keyring dev", err)
		return
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		s.fail(ph, "sel registre", err)
		return
	}

	// Trousseau de contrôleurs pour la preuve de quorum de /v1/mode (§5.3,
	// revue de sécurité #89) : k=2 signatures Ed25519 DISTINCTES, jamais
	// une liste d'identités déclarées.
	ctrl1, ctrl2 := devKey("quorum-ctrl-1"), devKey("quorum-ctrl-2")
	ctrl1KID, ctrl2KID := [16]byte{0x11}, [16]byte{0x22}
	keys := map[string]string{
		hex.EncodeToString(ctrl1KID[:]): hex.EncodeToString(ctrl1.Public().(ed25519.PublicKey)),
	}
	if prof.quorumMin >= 2 {
		keys[hex.EncodeToString(ctrl2KID[:])] = hex.EncodeToString(ctrl2.Public().(ed25519.PublicKey))
	}
	quorumKeyring, _ := json.Marshal(keys)
	// signAll rend les signatures du quorum COMPLET du profil : une seule
	// (l'admin) à l'échelle 1, les deux contrôleurs sinon.
	signAll := func(sign func(ed25519.PrivateKey, [16]byte) map[string]string) []map[string]string {
		sigs := []map[string]string{sign(ctrl1, ctrl1KID)}
		if prof.quorumMin >= 2 {
			sigs = append(sigs, sign(ctrl2, ctrl2KID))
		}
		return sigs
	}
	quorumKeyringPath := filepath.Join(cfg.out, "quorum-keyring.dev.json")
	if err := os.WriteFile(quorumKeyringPath, quorumKeyring, 0o600); err != nil {
		s.fail(ph, "trousseau de quorum dev", err)
		return
	}

	// Journal des enregistrements d'audit de pepd (#275) : REQUIS. Clé et journal
	// neufs à chaque exécution (GenerateRecordKey n'écrase jamais).
	auditKeyPath := filepath.Join(cfg.out, "pepd-audit.key")
	auditJournalPath := filepath.Join(cfg.out, "pepd-audit-records.jsonl")
	_ = os.Remove(auditKeyPath)
	_ = os.Remove(auditJournalPath)
	if err := registry.GenerateRecordKey(auditKeyPath); err != nil {
		s.fail(ph, "clé du journal d'audit de pepd", err)
		return
	}

	pepdEnv := append(os.Environ(),
		"TBP_AUDIT_RECORDS="+auditJournalPath,
		"TBP_AUDIT_RECORDS_KEY_FILE="+auditKeyPath,
		"TBP_CELL_ID="+monoCellID,
		"TBP_SALT="+hex.EncodeToString(salt),
		"TBP_KEYRING_FILE="+keyringPath,
		"TBP_POLICY_ID="+hex.EncodeToString(policyID[:]),
		"TBP_REGISTRY_DIR="+regDir,
		// mono : aucun TBP_CELL_BROKER_SOCKET (scale 1, cellule unique) —
		// TBP_TOPOLOGY=mono le déclare EXPLICITEMENT (issue #128), fail-closed
		// depuis la revue post-#86 si les deux venaient à diverger.
		"TBP_TOPOLOGY=mono",
		"TBP_LISTEN_ADDR="+monoPEPDAddr,
		// Plan d'ADMINISTRATION dédié (revue de sécurité #95, finding A10) :
		// /healthz et /v1/mode ne sont plus servis sur le plan de données
		// (TBP_LISTEN_ADDR) — un test qui les sonderait encore là échouerait
		// désormais systématiquement (revue #86 : le selftest doit rester
		// exécutable, pas seulement le code).
		"TBP_ADMIN_SOCKET="+adminSock,
		"TBP_OPA_ENDPOINT="+opaURL+"/v1/data/tbp/example/action",
		// OPA reste en TCP loopback ici (selftest local, pas de socket
		// Unix propre à cette machine partagée) — dev/lab EXPLICITE,
		// revue de sécurité #92, finding A3.
		"TBP_OPA_INSECURE_TCP_DEV=1",
		"TBP_QUORUM_KEYRING_FILE="+quorumKeyringPath,
		fmt.Sprintf("TBP_QUORUM_MIN=%d", prof.quorumMin),
		// Reprise après faute OPA (issue #205) : seuil par défaut (3 fautes
		// consécutives), sonde rapprochée pour que l'exercice de fin de
		// phase ne dure que quelques secondes.
		"TBP_OPA_AUTOCLEAR_PROBES=2",
		"TBP_OPA_AUTOCLEAR_INTERVAL_MS=300",
		"TBP_OPA_REVISION_CHECK_INTERVAL_MS=500",
		// Télémétrie anti-dribble (§4.1-bis, #275) : exercée de bout en bout (fenêtres d'une seconde).
		"TBP_TELEMETRY=1",
		"TBP_TELEMETRY_INTERVAL_MS=1000",
		"TBP_TELEMETRY_WINDOW_S=1",
		// T38/#71 : explicite même si async-bounded est le défaut — le
		// selftest éping le modèle de durabilité qu'il exerce.
		"TBP_DURABILITY=async-bounded",
		"TBP_DURABILITY_WINDOW_MS=1000",
		// Measured boot est désormais actif PAR DÉFAUT (revue #112) ; le
		// câblage réel (genèse, CheckBoot, transition sous preuve de
		// quorum) est déjà couvert par measured_boot_test.go en isolation.
		// Le désactiver ici EXPLICITEMENT est dev/lab uniquement, jamais en
		// production — même doctrine que TBP_OPA_INSECURE_TCP_DEV ci-dessus.
		"TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1",
		// Mesure des trousseaux épinglés (issue #192) : le témoin vit hors de
		// TBP_REGISTRY_DIR. L'édition d'un fichier de confiance entre deux
		// démarrages est exercée de bout en bout par la phase daemons (brokerd).
		"TBP_PROVISIONING_WITNESS_FILE="+filepath.Join(cfg.out, "pepd-provisioning-witness.json"),
	)

	// --- Étape : démarrage pepd — TOUJOURS monitor au boot (§5.3) -----------
	pepdLog, err := os.Create(filepath.Join(cfg.out, "pepd.log"))
	if err != nil {
		s.fail(ph, "pepd démarrage", err)
		return
	}
	defer func() { _ = pepdLog.Close() }()
	pepdCmd := exec.Command(pepdBin)
	pepdCmd.Env = pepdEnv
	pepdCmd.Stdout, pepdCmd.Stderr = pepdLog, pepdLog
	if err := pepdCmd.Start(); err != nil {
		s.fail(ph, "pepd démarrage", err)
		return
	}
	defer func() { _ = pepdCmd.Process.Kill(); _, _ = pepdCmd.Process.Wait() }()
	adminHC := unixClient(adminSock)
	if err := waitUnix200(adminHC, "http://pepd-admin/healthz", 15*time.Second); err != nil {
		s.fail(ph, "pepd démarrage (sonde /healthz, plan d'administration)", err)
		return
	}
	s.add(ph, "pepd démarré (OPA branché, registre réel)", true, pepdURL)

	// Avertissement de quorum fragile (issue #199) : k = 1 (scale1) ou 2-sur-2 sans clé de
	// rechange (mono) — dit au démarrage, dans le journal du démon.
	wantNotice := "sans clé de rechange"
	if prof.quorumMin == 1 {
		wantNotice = "quorum k=1"
	}
	logBytes, _ := os.ReadFile(filepath.Join(cfg.out, "pepd.log"))
	s.add(ph, "#199 : pepd avertit au démarrage d'un quorum fragile ("+wantNotice+")",
		strings.Contains(string(logBytes), "AVERTISSEMENT") && strings.Contains(string(logBytes), wantNotice),
		fmt.Sprintf("k=%d", prof.quorumMin))

	// Posture au démarrage : monitor, jamais closed (§5.3).
	var modeView struct {
		Mode string `json:"mode"`
	}
	_, raw, err := getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err != nil {
		s.fail(ph, "posture initiale = monitor", err)
		return
	}
	_ = json.Unmarshal(raw, &modeView)
	s.add(ph, "posture initiale = monitor (§5.3)", modeView.Mode == "monitor", "mode="+modeView.Mode)

	// --- Étape : jeton valide (action « read » → allow OPA) -----------------
	kid, _ := hex.DecodeString(monoDevKIDHex)
	mintOK := func(action string) ([]byte, error) {
		jti := make([]byte, 16)
		_, _ = rand.Read(jti)
		now := time.Now().Unix()
		// TTL du jeton borné à [30, 60] s par le validateur
		// (src/pep/validator.go) : 45 s — hors de cette fenêtre, le refus
		// serait ttl-out-of-range et les témoins ne prouveraient rien.
		return mintToken(issuer, mintClaims{
			iss: "selftest-dev", sub: "agent-1",
			exp: now + 45, iat: now,
			jti: jti, policyID: policyID[:],
			action: action, resource: "doc-1",
			class: 1, epoch: 0, version: 1, kid: kid,
		})
	}
	tokRead, err := mintOK("read")
	if err != nil {
		s.fail(ph, "menthe jeton read", err)
		return
	}
	_, er, err := evaluate(pepdURL, tokRead, "read", "doc-1")
	s.add(ph, "monitor: jeton valide (read) → allow, forwardé (log only)",
		err == nil && er.Allow && er.Forwarded && er.Mode == "monitor",
		fmt.Sprintf("allow=%v forwarded=%v reason=%s", er.Allow, er.Forwarded, er.Reason))

	// --- Témoin : action hors politique (write → deny OPA), monitor ---------
	tokWrite, _ := mintOK("write")
	_, er, err = evaluate(pepdURL, tokWrite, "write", "doc-1")
	// La raison DOIT être le veto OPA (opa_*) : un deny pour une autre cause
	// (signature, TTL…) rendrait ce témoin non-vacuole.
	s.add(ph, "monitor: témoin write → deny OPA, forwardé quand même (§5.3)",
		err == nil && !er.Allow && er.Forwarded && strings.HasPrefix(er.Reason, "opa"),
		fmt.Sprintf("allow=%v forwarded=%v reason=%s", er.Allow, er.Forwarded, er.Reason))

	// --- Témoin : clé inconnue (rogue) → refus validateur -------------------
	rogue := devKey("rogue")
	rogueKID, _ := hex.DecodeString("726f6775652d73656c66746573742d6431") // "rogue-selftest-d1" — absent du keyring
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := time.Now().Unix()
	tokRogue, _ := mintToken(rogue, mintClaims{
		iss: "selftest-dev", sub: "agent-2",
		exp: now + 45, iat: now, // TTL conforme : le refus vient de la CLÉ, rien d'autre
		jti: jti, policyID: policyID[:],
		action: "read", resource: "doc-1",
		class: 1, epoch: 0, version: 1, kid: rogueKID,
	})
	_, er, err = evaluate(pepdURL, tokRogue, "read", "doc-1")
	s.add(ph, "témoin: jeton signé par une clé inconnue → refus",
		err == nil && !er.Allow,
		fmt.Sprintf("allow=%v reason=%s", er.Allow, er.Reason))

	// --- #275 : le clair des décisions est vérifiable (tbp-audit verify) ----
	// Chaque décision rendue ci-dessus a laissé sa feuille ET son clair dans le
	// journal : le clair redonne le hash de la feuille, et la feuille est dans
	// le log sous un checkpoint signé (preuve d'inclusion RFC 6962).
	verifyAuditJournal(s, ph, "pepd", regDir, auditJournalPath, auditKeyPath, 3)

	// --- Étape : bascule gouvernée monitor→closed (§5.3) --------------------
	// Preuve de quorum RÉELLE (revue de sécurité #89) : k signatures Ed25519
	// distinctes sur pep.QuorumMessage("mode-closed", cellID, expiry) — un
	// ancien appelant qui se contenterait de déclarer des noms ("signers")
	// est witnessé séparément juste après (attaque #89 exacte, refusée).
	// cellID lié dans le message signé (revue #105) — jamais un champ de
	// la requête.
	expiry := time.Now().Add(1 * time.Minute)
	signCtrl := func(priv ed25519.PrivateKey, kid [16]byte) map[string]string {
		sig := ed25519.Sign(priv, pep.QuorumMessage("mode-closed", monoCellID, expiry))
		return map[string]string{"key_id": hex.EncodeToString(kid[:]), "signature": hex.EncodeToString(sig)}
	}

	// Depuis #289 le corps est décodé strictement : le champ « signers » n'existe plus sur le fil, il est
	// refusé dès la lecture (400, unknown-field) — la posture ne bouge pas ; le corps de la BONNE forme
	// mais sans aucune signature est, lui, refusé par le vérificateur de quorum (403).
	legacy, legacyBody, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{"mode": "closed", "signers": []string{"op-1", "op-1"}})
	s.add(ph, "témoin #89: attaque historique (signers déclarés, sans signature) → refusée",
		legacy == http.StatusBadRequest && strings.Contains(string(legacyBody), `"unknown-field"`) && strings.Contains(string(legacyBody), `"signers"`),
		fmt.Sprintf("status=%d body=%s", legacy, strings.TrimSpace(string(legacyBody))))
	unsigned, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{"mode": "closed", "expiry": expiry.Unix(), "signatures": []map[string]string{}})
	s.add(ph, "témoin #89: bonne forme, aucune signature → 403 (le vérificateur de quorum, pas le décodeur)",
		unsigned == http.StatusForbidden, fmt.Sprintf("status=%d", unsigned))

	if prof.quorumMin >= 2 {
		status, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
			"mode": "closed", "expiry": expiry.Unix(),
			"signatures": []map[string]string{signCtrl(ctrl1, ctrl1KID)},
		})
		s.add(ph, "bascule closed: 1 signature valide < quorum 2 → 403", status == http.StatusForbidden,
			fmt.Sprintf("status=%d", status))
	} else {
		// Échelle 1 : l'admin est le quorum (k=1) — mais « k=1 » ne veut
		// PAS dire « sans signature » : zéro signature, ou une signature
		// d'une clé hors trousseau, reste refusée.
		status, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
			"mode": "closed", "expiry": expiry.Unix(), "signatures": []map[string]string{},
		})
		s.add(ph, "échelle 1: bascule closed sans aucune signature → 403", status == http.StatusForbidden,
			fmt.Sprintf("status=%d", status))
		stranger := devKey("not-in-keyring")
		status, _, _ = postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
			"mode": "closed", "expiry": expiry.Unix(),
			"signatures": []map[string]string{signCtrl(stranger, ctrl1KID), signCtrl(stranger, [16]byte{0x99})},
		})
		s.add(ph, "échelle 1: bascule closed signée par une clé hors trousseau → 403", status == http.StatusForbidden,
			fmt.Sprintf("status=%d", status))
	}
	status, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
		"mode": "closed", "expiry": expiry.Unix(),
		"signatures": signAll(signCtrl),
	})
	s.add(ph, fmt.Sprintf("bascule closed: quorum %d/%d signatures valides → 200", prof.quorumMin, prof.quorumMin), status == http.StatusOK,
		fmt.Sprintf("status=%d", status))
	_, raw, err = getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err == nil {
		_ = json.Unmarshal(raw, &modeView)
	}
	s.add(ph, "posture effective = closed après quorum", modeView.Mode == "closed", "mode="+modeView.Mode)

	// --- Post-closed : le verdict s'APPLIQUE --------------------------------
	tokWrite2, _ := mintOK("write")
	_, er, err = evaluate(pepdURL, tokWrite2, "write", "doc-1")
	s.add(ph, "closed: write → deny BLOQUÉ (forwarded=false)",
		err == nil && !er.Allow && !er.Forwarded,
		fmt.Sprintf("allow=%v forwarded=%v", er.Allow, er.Forwarded))
	tokRead2, _ := mintOK("read")
	_, er, err = evaluate(pepdURL, tokRead2, "read", "doc-1")
	s.add(ph, "closed: read → allow forwardé",
		err == nil && er.Allow && er.Forwarded,
		fmt.Sprintf("allow=%v forwarded=%v", er.Allow, er.Forwarded))

	// --- Étape #93 : redémarrage = refus total jusqu'à reconfirmation ------
	// Vérification prioritaire suggérée par l'issue elle-même : pepd en
	// closed (bascule quorée ci-dessus), puis kill + redémarrage — la
	// posture ne doit JAMAIS repartir en monitor SANS signature (attaque
	// par rétrogradation, revue de sécurité #93, option la plus stricte
	// actée par le mainteneur).
	_ = pepdCmd.Process.Kill()
	_, _ = pepdCmd.Process.Wait()

	pepdLog2, err := os.Create(filepath.Join(cfg.out, "pepd-restart.log"))
	if err != nil {
		s.fail(ph, "pepd redémarrage (§93)", err)
		return
	}
	pepdCmd = exec.Command(pepdBin)
	pepdCmd.Env = pepdEnv // MÊME registre : cell_log.key existe déjà
	pepdCmd.Stdout, pepdCmd.Stderr = pepdLog2, pepdLog2
	if err := pepdCmd.Start(); err != nil {
		_ = pepdLog2.Close()
		s.fail(ph, "pepd redémarrage (§93)", err)
		return
	}
	if err := waitUnix200(adminHC, "http://pepd-admin/healthz", 15*time.Second); err != nil {
		s.fail(ph, "pepd redémarrage (§93, sonde /healthz)", err)
		return
	}

	_, raw, err = getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err == nil {
		_ = json.Unmarshal(raw, &modeView)
	}
	s.add(ph, "témoin #93: redémarrage → posture refused (PAS monitor silencieux)",
		modeView.Mode == "refused", "mode="+modeView.Mode)

	// Refus TOTAL : même un jeton par ailleurs valide (allow) est bloqué.
	tokReadRestart, _ := mintOK("read")
	_, er, err = evaluate(pepdURL, tokReadRestart, "read", "doc-1")
	s.add(ph, "témoin #93: refused bloque même un allow",
		err == nil && !er.Forwarded && er.Mode == "refused",
		fmt.Sprintf("allow=%v forwarded=%v mode=%s", er.Allow, er.Forwarded, er.Mode))

	// Seule sortie : quorum reconfirmant EXPLICITEMENT une posture — ici
	// monitor, comme tout acte gouverné (aller ou retour).
	expiry93 := time.Now().Add(1 * time.Minute)
	signCtrlMonitor := func(priv ed25519.PrivateKey, kid [16]byte) map[string]string {
		sig := ed25519.Sign(priv, pep.QuorumMessage("mode-monitor", monoCellID, expiry93))
		return map[string]string{"key_id": hex.EncodeToString(kid[:]), "signature": hex.EncodeToString(sig)}
	}
	status93, _, _ := postUnixJSON(adminHC, "http://pepd-admin/v1/mode", map[string]any{
		"mode": "monitor", "expiry": expiry93.Unix(),
		"signatures": signAll(signCtrlMonitor),
	})
	s.add(ph, "témoin #93: reconfirmation quorée de monitor après redémarrage → 200",
		status93 == http.StatusOK, fmt.Sprintf("status=%d", status93))
	_, raw, err = getUnix(adminHC, "http://pepd-admin/v1/mode")
	if err == nil {
		_ = json.Unmarshal(raw, &modeView)
	}
	s.add(ph, "témoin #93: posture = monitor après reconfirmation", modeView.Mode == "monitor", "mode="+modeView.Mode)

	// --- Étape : registre — chaque décision laisse une feuille (§4.1) -------
	// Non-vacuité par DELTA. Une évaluation ALLOW écrit exactement DEUX
	// feuilles KindDecision : le verdict du validateur ET l'ouverture du
	// passeport de quota (§4.1-bis — src/pep/validator.go + src/pep/quota.go).
	before, err := countKinds(ctx, monoCellID, regDir)
	if err != nil {
		s.fail(ph, "registre: scan vérifié", err)
		return
	}
	tokDelta, _ := mintOK("read")
	if _, _, err := evaluate(pepdURL, tokDelta, "read", "doc-1"); err != nil {
		s.fail(ph, "registre: évaluation delta", err)
		return
	}
	// tessera intègre de façon asynchrone : borne courte de repli.
	var after map[byte]int
	for i := 0; i < 20; i++ {
		time.Sleep(150 * time.Millisecond)
		after, err = countKinds(ctx, monoCellID, regDir)
		if err == nil && after[registry.KindDecision] > before[registry.KindDecision] {
			break
		}
	}
	if err != nil {
		s.fail(ph, "registre: re-scan", err)
		return
	}
	s.add(ph, "registre: une évaluation allow = verdict + passeport (delta KindDecision +2, §4.1-bis)",
		after[registry.KindDecision] == before[registry.KindDecision]+2,
		fmt.Sprintf("avant=%d après=%d", before[registry.KindDecision], after[registry.KindDecision]))
	s.add(ph, "registre: ≥6 décisions tracées (valides + témoins)",
		after[registry.KindDecision] >= 6, fmt.Sprintf("KindDecision=%d", after[registry.KindDecision]))
	s.add(ph, "registre: bascule de posture tracée (KindTelemetry ≥ 1)",
		after[registry.KindTelemetry] >= 1, fmt.Sprintf("KindTelemetry=%d", after[registry.KindTelemetry]))

	// --- Télémétrie anti-dribble (§4.1-bis, #275) : un passeport consommé laisse, une fenêtre plus tard,
	// une feuille d'agrégat « TBAG1 » dont le clair est dans le journal — des MÉTADONNÉES (compteurs), pas
	// le contenu d'un flux. Le décompte se fait par /v1/passport/consume (le service qui exécute l'action).
	{
		now := time.Now().Unix()
		jti := make([]byte, 16)
		_, _ = rand.Read(jti)
		tokPass, perr := mintToken(issuer, mintClaims{
			iss: "selftest-dev", sub: "agent-1", exp: now + 45, iat: now, jti: jti, policyID: policyID[:],
			action: "read", resource: "doc-1", class: 1, epoch: 0, version: 1, kid: kid,
			quota: map[int]any{1: "10.99.99.7", 2: "send", 3: 1 << 20, 4: 3600},
		})
		if perr != nil {
			s.fail(ph, "télémétrie: menthe d'un jeton à passeport", perr)
			return
		}
		_, pe, perr := evaluate(pepdURL, tokPass, "read", "doc-1")
		s.add(ph, "télémétrie: un jeton à passeport est admis (allow + passeport ouvert)",
			perr == nil && pe.Allow, fmt.Sprintf("allow=%v reason=%s", pe.Allow, pe.Reason))
		tel, telKey := 0, ""
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) && tel == 0 {
			_, _, _ = postJSON(pepdURL+"/v1/passport/consume", map[string]any{"token": base64.StdEncoding.EncodeToString(tokPass), "n": 100})
			time.Sleep(500 * time.Millisecond)
			if k, kerr := registry.LoadRecordKey(auditKeyPath); kerr == nil {
				telKey = "clé lue"
				if recs, rerr := registry.ReadRecords(auditJournalPath, k); rerr == nil {
					for _, r := range recs {
						if bytes.HasPrefix(r.Record, []byte("TBAG1")) && r.VerifyHash() == nil {
							tel++
						}
					}
				}
			}
		}
		s.add(ph, "télémétrie: un passeport consommé laisse une feuille d'agrégat TBAG1 dont le clair est journalisé",
			tel > 0, fmt.Sprintf("%d agrégat(s) journalisé(s) %s", tel, telKey))
	}

	// --- Issue #208 (R-13) : les échappatoires dev actives laissent une feuille ---
	// Ce pepd tourne avec TBP_OPA_INSECURE_TCP_DEV et
	// TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE (déclarés par le sentinel du
	// selftest) : l'alarme n'est plus qu'un log, le registre en porte la preuve.
	devLeaf := registry.HashPayload(salt, devmode.ActiveRecord([]string{"TBP_OPA_INSECURE_TCP_DEV", "TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE"}))
	foundDev, derr := waitPayloadHash(ctx, monoCellID, regDir, devLeaf, 5*time.Second)
	s.add(ph, "#208 : les échappatoires dev actives de pepd sont consignées en feuille KindTelemetry (recalculable par re-hash)",
		derr == nil && foundDev, fmt.Sprintf("trouvée=%v err=%v", foundDev, derr))

	// --- Issue #209 (R-16) : corps bornés et lecture à délai sur le vrai pepd ---
	bigBody := `{"action":"read","resource":"doc-1","token":"` + strings.Repeat("A", 1<<20) + `"}`
	bigStatus, _, bigErr := postJSONRaw(pepdURL+"/v1/evaluate", bigBody)
	s.add(ph, "#209 : un corps de 1 Mio sur /v1/evaluate est refusé en 413 sans être traité (plan de données)",
		bigErr == nil && bigStatus == http.StatusRequestEntityTooLarge, fmt.Sprintf("status=%d err=%v", bigStatus, bigErr))
	bigMode := `{"mode":"closed","expiry":1,"signatures":[],"x":"` + strings.Repeat("A", 1<<20) + `"}`
	modeStatus, _, modeErr := postUnixRaw(adminHC, "http://pepd-admin/v1/mode", bigMode)
	s.add(ph, "#209 : un corps de 1 Mio sur /v1/mode est refusé en 413 (plan d'administration)",
		modeErr == nil && modeStatus == http.StatusRequestEntityTooLarge, fmt.Sprintf("status=%d err=%v", modeStatus, modeErr))
	if prof.drillSlowBody {
		// Les en-têtes, puis un seul octet de corps, puis le silence : pepd doit couper
		// la connexion au ReadTimeout (10 s) au lieu de la tenir indéfiniment.
		conn, derr := net.Dial("tcp", monoPEPDAddr)
		cut, took := false, time.Duration(0)
		if derr == nil {
			_, _ = fmt.Fprintf(conn, "POST /v1/evaluate HTTP/1.1\r\nHost: t\r\nContent-Length: 1000\r\n\r\nX")
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			start := time.Now()
			_, rerr := io.ReadAll(conn)
			took = time.Since(start)
			nerr, isNet := rerr.(net.Error)
			cut = !(isNet && nerr.Timeout()) && took < 15*time.Second
			_ = conn.Close()
		}
		s.add(ph, "#209 : un client dont le corps est calé est coupé par pepd (ReadTimeout), pas tenu indéfiniment",
			derr == nil && cut, fmt.Sprintf("coupé après %s", took.Round(100*time.Millisecond)))
	}

	// --- Issue #205 (R-18) : un redémarrage d'OPA ne doit PAS immobiliser la
	// cellule. OPA est tué, pepd refuse (fail-closed, par requête puis par
	// verrou global), OPA revient sur le MÊME bundle signé : pepd reprend
	// SANS redémarrage ni quorum. Avant #205, le verrou ne se levait jamais.
	opa.stop()
	for i := 0; i < 4; i++ {
		tokDown, _ := mintOK("read")
		if _, er, err := evaluate(pepdURL, tokDown, "read", "doc-1"); err == nil && er.Allow {
			s.add(ph, "#205: OPA arrêté → aucune évaluation ne peut être allow", false, "allow=true")
			return
		}
	}
	s.add(ph, "#205: OPA arrêté → chaque évaluation est refusée (fail-closed par requête)", true, "4 refus")
	latched := false
	for i := 0; i < 30 && !latched; i++ {
		_, raw, err := getUnix(adminHC, "http://pepd-admin/v1/failclosed")
		latched = err == nil && strings.Contains(string(raw), `"name"`)
		if !latched {
			time.Sleep(200 * time.Millisecond)
		}
	}
	s.add(ph, "#205: la faute persistante bascule le verrou global, visible sur le plan d'administration", latched, "GET /v1/failclosed")

	restarted, ok := startOPA(s, ph, cfg, monoOPAAddr, bundlePath, verificationKeyPath, filepath.Join(opaDir, "opa-restart.log"))
	if !ok {
		return
	}
	opa = restarted
	recovered := false
	for i := 0; i < 100 && !recovered; i++ {
		_, raw, err := getUnix(adminHC, "http://pepd-admin/v1/failclosed")
		recovered = err == nil && !strings.Contains(string(raw), `"name"`)
		if !recovered {
			time.Sleep(200 * time.Millisecond)
		}
	}
	s.add(ph, "#205: OPA revenu sur le bundle épinglé → le verrou se lève SEUL (sonde + révision conforme)", recovered, "GET /v1/failclosed vide")
	tokUp, _ := mintOK("read")
	_, erUp, errUp := evaluate(pepdURL, tokUp, "read", "doc-1")
	s.add(ph, "#205: la cellule redécide après la reprise, sans redémarrage de pepd ni quorum",
		errUp == nil && erUp.Allow, fmt.Sprintf("allow=%v reason=%s", erUp.Allow, erUp.Reason))

	// --- #218 : le trousseau de quorum édité avec les clés de l'attaquant (dernière étape : il réécrit l'autorité) ---
	_ = pepdCmd.Process.Kill()
	_, _ = pepdCmd.Process.Wait()
	honest := []proofKey{{kid: ctrl1KID, priv: ctrl1}}
	if prof.quorumMin >= 2 {
		honest = append(honest, proofKey{kid: ctrl2KID, priv: ctrl2})
	}
	runPepdTransitionStage(s, ph, pepdBin, pepdEnv, cfg.out, monoCellID, quorumKeyringPath, keys, honest, prof.quorumMin,
		func() bool {
			st, _, err := getUnix(adminHC, "http://pepd-admin/healthz")
			return err == nil && st == http.StatusOK
		})
}

// postJSONRaw POSTe un corps déjà sérialisé (postJSON re-marshale).
func postJSONRaw(url, body string) (int, []byte, error) {
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// postUnixRaw est postUnixJSON pour un corps déjà sérialisé.
func postUnixRaw(hc *http.Client, url, body string) (int, []byte, error) {
	resp, err := hc.Post(url, "application/json", strings.NewReader(body)) //nolint:noctx
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// verifyAuditJournal relit le journal d'audit de pepd et vérifie chaque
// enregistrement contre le log de la cellule — ce que fait `tbp-audit verify
// -log … -vkey-file …` pour un auditeur externe (#275, #271).
func verifyAuditJournal(s *suite, ph, who, regDir, journalPath, keyPath string, minDecisions int) {
	key, err := registry.LoadRecordKey(keyPath)
	if err != nil {
		s.add(ph, "#275 : "+who+" — clé du journal d'audit lisible", false, err.Error())
		return
	}
	recs, err := registry.ReadRecords(journalPath, key)
	if err != nil {
		s.add(ph, "#275 : journal d'audit de "+who+" lisible et déchiffrable", false, err.Error())
		return
	}
	vkeyRaw, err := os.ReadFile(filepath.Join(regDir, "cell_log.vkey"))
	if err != nil {
		s.add(ph, "#275 : "+who+" — clé publique du log", false, err.Error())
		return
	}
	verifier, err := registry.NewVerifier(string(vkeyRaw))
	if err != nil {
		s.add(ph, "#275 : "+who+" — clé publique du log valide", false, err.Error())
		return
	}
	fetch := client.FileFetcher{Root: regDir}
	decisions, bad := 0, ""
	for i, r := range recs {
		// L'écriture de pepd est asynchrone bornée : le checkpoint signé peut
		// ne pas couvrir encore la toute dernière feuille. On laisse quelques
		// secondes au log avant de conclure à un orphelin.
		var err error
		for try := 0; try < 50; try++ {
			if _, err = r.VerifyInLog(context.Background(), fetch, verifier); !errors.Is(err, registry.ErrRecordNotInLog) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			bad = fmt.Sprintf("enregistrement %d : %v", i+1, err)
			break
		}
		if r.Leaf.Kind == registry.KindDecision {
			decisions++
		}
	}
	s.add(ph, "#275 : "+who+" — le clair de chaque feuille est vérifiable (hash + inclusion dans le log signé)",
		bad == "" && decisions >= minDecisions,
		fmt.Sprintf("%d enregistrements, %d décisions %s", len(recs), decisions, bad))

	// Vérification INVERSE (`tbp-audit verify -coverage`) : toute feuille du log a son clair dans le journal.
	// Le clair est journalisé AVANT la feuille : une feuille sans entrée n'est pas un retard, c'est un
	// producteur non câblé (ou la dérogation « journal refusé » de la feuille d'arrêt).
	leaves, _, werr := supervision.NewChainWatcher(context.Background(), who, regDir, verifier.Name(), verifier, 0)
	if werr != nil {
		s.add(ph, "#275 : "+who+" — couverture : le log se relit sous checkpoint signé", false, werr.Error())
		return
	}
	journaled := make(map[registry.Leaf]int, len(recs))
	for _, r := range recs {
		journaled[r.Leaf]++
	}
	var uncovered []string
	for i, l := range leaves {
		if journaled[l] > 0 {
			journaled[l]--
			continue
		}
		uncovered = append(uncovered, fmt.Sprintf("index=%d kind=%d", i, l.Kind))
	}
	s.add(ph, "#275 : "+who+" — couverture : toute feuille du log a une entrée de journal (aucune feuille sans clair)",
		len(uncovered) == 0, fmt.Sprintf("%d feuilles dans le log, %d sans entrée %s", len(leaves), len(uncovered), strings.Join(uncovered, ", ")))
}
