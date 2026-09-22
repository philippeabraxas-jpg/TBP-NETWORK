// Tests du démon brokerd (T37, issue #74).
//
// Doctrine : le démon est de l'ASSEMBLAGE — ses tests vérifient donc les
// deux seules choses qui peuvent y être fausses : la validation de
// configuration (fail-closed §1) et le câblage de bout en bout (une
// action traverse TOUTE la pile assemblée et ressort avec un jeton, les
// lectures de supervision rendent l'état réel des briques).
//
// Non-vacuité (mutations qui DOIVENT faire échouer un test nommé) :
//   - accepter une config sans TBP_SALT/TBP_OPA_ENDPOINT/… →
//     TestLoadConfig* (chaque ligne de la table) ;
//   - accepter une seed émetteur en 0644 → TestBrokerdStartupFailClosed/
//     seed_lisible_par_d_autres ;
//   - accepter TBP_QUORUM_MIN > N contrôleurs → …/quorum_impossible ;
//   - démarrer sans epoch0 valide → …/epoch0_* ;
//   - servir sans qu'une action émise remonte dans les stats →
//     TestBrokerdEndToEnd (compteurs exacts 3/1/2/1) ;
//   - répondre autre chose que 405 à POST /v1/supervision/stats →
//     TestBrokerdEndToEnd (témoin méthode).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
)

// mapGetenv adapte une table à la couture getenv du démon.
func mapGetenv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// validConfigEnv rend une configuration d'environnement complète et
// cohérente (loadConfig ne touche à aucun fichier — les chemins peuvent
// être symboliques ici).
func validConfigEnv() map[string]string {
	return map[string]string{
		"TBP_CELL_ID":            "cell-a",
		"TBP_SALT":               strings.Repeat("01", 16),
		"TBP_POLICY_ID":          strings.Repeat("02", 32),
		"TBP_REGISTRY_DIR":       "/srv/tbp/registry",
		"TBP_OPA_ENDPOINT":       "http://127.0.0.1:8181/v1/data/tbp/allow",
		"TBP_TRANSLATOR":         "structured",
		"TBP_ISSUER_SEED_FILE":   "/etc/tbp/issuer.seed",
		"TBP_GENESIS_DIR":        "/etc/tbp/genesis",
		"TBP_CLUSTER_MEMBERS":    "cell-a,cell-b",
		"TBP_OPERATOR_KEYS_FILE": "/etc/tbp/operators.json",
	}
}

func TestLoadConfigOK(t *testing.T) {
	cfg, err := loadConfig(mapGetenv(validConfigEnv()))
	if err != nil {
		t.Fatalf("config valide refusée: %v", err)
	}
	if cfg.cellID != "cell-a" || len(cfg.salt) != 16 {
		t.Fatalf("identité/sel mal lus: %+v", cfg)
	}
	if cfg.quorumMin != 2 {
		t.Fatalf("quorum par défaut = %d, attendu 2 (même défaut que pepd)", cfg.quorumMin)
	}
	if cfg.socketPath != defaultBrokerSocket {
		t.Fatalf("socket par défaut = %q, attendu %q", cfg.socketPath, defaultBrokerSocket)
	}
	if cfg.envelopeEndpoint != "" {
		t.Fatalf("enveloppe absente attendue, got %q", cfg.envelopeEndpoint)
	}
	env := validConfigEnv()
	env["TBP_QUORUM_MIN"] = "3"
	env["TBP_BROKER_SOCKET"] = "/tmp/x.sock"
	env["TBP_ENVELOPE_ENDPOINT"] = "http://127.0.0.1:8181/v1/data/tbp/envelope"
	cfg, err = loadConfig(mapGetenv(env))
	if err != nil {
		t.Fatalf("config explicite refusée: %v", err)
	}
	if cfg.quorumMin != 3 || cfg.socketPath != "/tmp/x.sock" || cfg.envelopeEndpoint == "" {
		t.Fatalf("valeurs explicites mal lues: %+v", cfg)
	}
}

// TestLoadConfigPKCS11 : la custody HSM (revue de sécurité #90, point 5)
// est acceptée à la place de la seed de dev, et REND les quatre champs.
func TestLoadConfigPKCS11(t *testing.T) {
	env := validConfigEnv()
	delete(env, "TBP_ISSUER_SEED_FILE")
	env["TBP_ISSUER_PKCS11_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
	env["TBP_ISSUER_PKCS11_TOKEN_LABEL"] = "cell-a"
	env["TBP_ISSUER_PKCS11_KEY_LABEL"] = "issuer-key-1"
	env["TBP_ISSUER_PKCS11_PIN_FILE"] = "/etc/tbp/issuer.pin"
	cfg, err := loadConfig(mapGetenv(env))
	if err != nil {
		t.Fatalf("config PKCS#11 valide refusée: %v", err)
	}
	if cfg.issuerSeedFile != "" {
		t.Fatalf("issuerSeedFile = %q, veut vide (custody HSM)", cfg.issuerSeedFile)
	}
	if cfg.issuerPKCS11Module != env["TBP_ISSUER_PKCS11_MODULE"] ||
		cfg.issuerPKCS11Token != env["TBP_ISSUER_PKCS11_TOKEN_LABEL"] ||
		cfg.issuerPKCS11KeyLabel != env["TBP_ISSUER_PKCS11_KEY_LABEL"] ||
		cfg.issuerPKCS11PINFile != env["TBP_ISSUER_PKCS11_PIN_FILE"] {
		t.Fatalf("champs PKCS#11 mal lus: %+v", cfg)
	}
}

// TestLoadConfigFailClosed : chaque pièce manquante ou invalide est une
// erreur — un broker à moitié configuré émettrait des décisions à moitié
// contrôlées (§1).
func TestLoadConfigFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(env map[string]string)
		want   string
	}{
		{"cell_id_absent", func(e map[string]string) { delete(e, "TBP_CELL_ID") }, "TBP_CELL_ID requis"},
		{"salt_absent", func(e map[string]string) { delete(e, "TBP_SALT") }, "TBP_SALT requis"},
		{"salt_trop_court", func(e map[string]string) { e["TBP_SALT"] = "aabb" }, "hex ≥ 16 octets"},
		{"policy_invalide", func(e map[string]string) { e["TBP_POLICY_ID"] = "zz" }, "hex ≥ 32 octets"},
		{"registry_absent", func(e map[string]string) { delete(e, "TBP_REGISTRY_DIR") }, "TBP_REGISTRY_DIR requis"},
		{"opa_absent", func(e map[string]string) { delete(e, "TBP_OPA_ENDPOINT") }, "TBP_OPA_ENDPOINT requis"},
		{"traducteur_refuse", func(e map[string]string) { e["TBP_TRANSLATOR"] = "natural" }, "structured"},
		{"traducteur_vide_refuse", func(e map[string]string) { delete(e, "TBP_TRANSLATOR") }, "structured"},
		{"seed_absente", func(e map[string]string) { delete(e, "TBP_ISSUER_SEED_FILE") }, "custody de l'émetteur requise"},
		{"custody_double", func(e map[string]string) {
			e["TBP_ISSUER_PKCS11_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
		}, "mutuellement exclusifs"},
		{"pkcs11_incomplet", func(e map[string]string) {
			delete(e, "TBP_ISSUER_SEED_FILE")
			e["TBP_ISSUER_PKCS11_MODULE"] = "/usr/lib/softhsm/libsofthsm2.so"
			e["TBP_ISSUER_PKCS11_TOKEN_LABEL"] = "cell-a"
			// KEY_LABEL et PIN_FILE manquants.
		}, "requis ensemble"},
		{"genesis_absente", func(e map[string]string) { delete(e, "TBP_GENESIS_DIR") }, "TBP_GENESIS_DIR requis"},
		{"quorum_zero", func(e map[string]string) { e["TBP_QUORUM_MIN"] = "0" }, "TBP_QUORUM_MIN invalide"},
		{"quorum_non_numerique", func(e map[string]string) { e["TBP_QUORUM_MIN"] = "deux" }, "TBP_QUORUM_MIN invalide"},
		{"membres_absents", func(e map[string]string) { delete(e, "TBP_CLUSTER_MEMBERS") }, "TBP_CLUSTER_MEMBERS requis"},
		{"cellule_hors_roster", func(e map[string]string) {
			e["TBP_CLUSTER_MEMBERS"] = "cell-b,cell-c"
		}, "absent de TBP_CLUSTER_MEMBERS"},
		{"membre_en_double", func(e map[string]string) {
			e["TBP_CLUSTER_MEMBERS"] = "cell-a,cell-b,cell-a"
		}, "en double"},
		{"membre_vide", func(e map[string]string) {
			e["TBP_CLUSTER_MEMBERS"] = "cell-a,,cell-b"
		}, "membre vide ou en double"},
		{"operateurs_absents", func(e map[string]string) { delete(e, "TBP_OPERATOR_KEYS_FILE") }, "TBP_OPERATOR_KEYS_FILE requis"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := validConfigEnv()
			tc.mutate(env)
			cfg, err := loadConfig(mapGetenv(env))
			if err == nil {
				t.Fatalf("config invalide acceptée: %+v", cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("erreur %q ne contient pas %q", err, tc.want)
			}
		})
	}
}

// — Fixture d'assemblage (fichiers réels : genèse signée, seed 0600,
// clés d'opérateurs) —

type runFixture struct {
	env      map[string]string
	genDir   string
	seedFile string
	opsFile  string
}

// mintManifest écrit le manifest de genèse (nKeys contrôleurs, key_id
// 1-basé) et rend les clés privées correspondantes — la part du format
// scripts/genesis que le quorum classe W (§7.5) exige TOUJOURS, avec ou
// sans fencing d'époque (issue #97 : mode mono-cellule).
func mintManifest(t *testing.T, dir string, nKeys int) []ed25519.PrivateKey {
	t.Helper()
	privs := make([]ed25519.PrivateKey, nKeys)
	pubs := make([]string, nKeys)
	for i := range privs {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		privs[i] = priv
		pubs[i] = hex.EncodeToString(pub)
	}
	manifest, err := json.Marshal(struct {
		PubKeys []string `json:"pubkeys"`
	}{PubKeys: pubs})
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	return privs
}

// mintGenesis écrit un manifest (nKeys contrôleurs, key_id 1-basé) et un
// epoch0 signé par nSigs clés — exactement le format de scripts/genesis
// (payload JSON à champs fixes, signature Ed25519 du payload seul).
func mintGenesis(t *testing.T, dir, authority string, nKeys, quorum, nSigs, ttl int) {
	t.Helper()
	privs := mintManifest(t, dir, nKeys)
	payload := cluster.EpochPayload{
		N:          0,
		Authority:  authority,
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		TTLSeconds: ttl,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	sigs := make([]cluster.ControllerSignature, 0, nSigs)
	for i := 0; i < nSigs; i++ {
		sigs = append(sigs, cluster.ControllerSignature{
			KeyID: i + 1,
			Sig:   hex.EncodeToString(ed25519.Sign(privs[i], canonical)),
		})
	}
	token := cluster.EpochToken{
		Payload:    payload,
		Quorum:     fmt.Sprintf("%d-of-%d", quorum, nKeys),
		Signatures: sigs,
	}
	tok, err := json.Marshal(token)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "epoch0.json"), tok, 0o600); err != nil {
		t.Fatalf("epoch0: %v", err)
	}
}

// newRunFixture prépare tous les fichiers d'une configuration runnable
// (genèse 2-of-3 valide, epoch0 TTL 60 s, seed 0600, 1 opérateur).
func newRunFixture(t *testing.T, sock string) *runFixture {
	t.Helper()
	dir := t.TempDir()
	genDir := filepath.Join(dir, "genesis")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("genesis dir: %v", err)
	}
	mintGenesis(t, genDir, "cell-a", 3, 2, 2, 60)

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seedFile := filepath.Join(dir, "issuer.seed")
	if err := os.WriteFile(seedFile, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	opPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("operateur: %v", err)
	}
	opsFile := filepath.Join(dir, "operators.json")
	ops, err := json.Marshal([]string{hex.EncodeToString(opPub)})
	if err != nil {
		t.Fatalf("operateurs: %v", err)
	}
	if err := os.WriteFile(opsFile, ops, 0o600); err != nil {
		t.Fatalf("operateurs: %v", err)
	}

	policy := make([]byte, 32)
	salt := make([]byte, 16)
	if _, err := rand.Read(policy); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("salt: %v", err)
	}
	return &runFixture{
		genDir:   genDir,
		seedFile: seedFile,
		opsFile:  opsFile,
		env: map[string]string{
			"TBP_CELL_ID":            "cell-a",
			"TBP_SALT":               hex.EncodeToString(salt),
			"TBP_POLICY_ID":          hex.EncodeToString(policy),
			"TBP_REGISTRY_DIR":       filepath.Join(dir, "registry"),
			"TBP_OPA_ENDPOINT":       "http://127.0.0.1:1/opa", // pas de connexion à la construction
			"TBP_TRANSLATOR":         "structured",
			"TBP_ISSUER_SEED_FILE":   seedFile,
			"TBP_GENESIS_DIR":        genDir,
			"TBP_CLUSTER_MEMBERS":    "cell-a,cell-b",
			"TBP_OPERATOR_KEYS_FILE": opsFile,
			"TBP_BROKER_SOCKET":      sock,
		},
	}
}

// TestBrokerdStartupFailClosed : chaque pièce d'assemblage fautive est
// fatale AVANT le service — jamais un broker à moitié contrôlé.
func TestBrokerdStartupFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, fx *runFixture)
		want   string
	}{
		{"seed_lisible_par_d_autres", func(t *testing.T, fx *runFixture) {
			if err := os.Chmod(fx.seedFile, 0o644); err != nil {
				t.Fatalf("chmod: %v", err)
			}
		}, "0600"},
		{"quorum_impossible", func(t *testing.T, fx *runFixture) {
			fx.env["TBP_QUORUM_MIN"] = "9"
		}, "contrôleurs du manifest"},
		{"epoch0_ttl_hors_bornes", func(t *testing.T, fx *runFixture) {
			mintGenesis(t, fx.genDir, "cell-a", 3, 2, 2, 5) // < MinTTL 10 s
		}, "epoch0 refusé"},
		{"epoch0_quorum_insuffisant", func(t *testing.T, fx *runFixture) {
			mintGenesis(t, fx.genDir, "cell-a", 3, 2, 1, 60) // 1 signature pour M=2
		}, "epoch0 refusé"},
		{"epoch0_absent", func(t *testing.T, fx *runFixture) {
			if err := os.Remove(filepath.Join(fx.genDir, "epoch0.json")); err != nil {
				t.Fatalf("remove: %v", err)
			}
		}, "epoch0"},
		{"manifest_sans_cle", func(t *testing.T, fx *runFixture) {
			if err := os.WriteFile(filepath.Join(fx.genDir, "manifest.json"), []byte(`{"pubkeys":[]}`), 0o600); err != nil {
				t.Fatalf("manifest: %v", err)
			}
		}, "sans clé"},
		{"operateurs_en_double", func(t *testing.T, fx *runFixture) {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("operateur: %v", err)
			}
			k := hex.EncodeToString(pub)
			ops, err := json.Marshal([]string{k, k})
			if err != nil {
				t.Fatalf("operateurs: %v", err)
			}
			if err := os.WriteFile(fx.opsFile, ops, 0o600); err != nil {
				t.Fatalf("operateurs: %v", err)
			}
		}, "en double"},
		{"operateurs_vides", func(t *testing.T, fx *runFixture) {
			if err := os.WriteFile(fx.opsFile, []byte(`[]`), 0o600); err != nil {
				t.Fatalf("operateurs: %v", err)
			}
		}, "liste vide"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "broker.sock")
			fx := newRunFixture(t, sock)
			tc.mutate(t, fx)
			err := run(context.Background(), mapGetenv(fx.env))
			if err == nil {
				t.Fatal("assemblage fautif accepté — le démon sert")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("erreur %q ne contient pas %q", err, tc.want)
			}
		})
	}
}

// — End-to-end : la pile assemblée sert de vraies décisions —

func unixClient(t *testing.T, sock string) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 10 * time.Second,
	}
}

func waitSocket(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("unix", sock, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("socket %s jamais en écoute", sock)
}

type actionResp struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Token  string `json:"token"`
	JTI    string `json:"jti"`
}

func postAction(t *testing.T, hc *http.Client, subject, intent string) actionResp {
	t.Helper()
	body, err := json.Marshal(map[string]string{"subject": subject, "intent": intent})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := hc.Post("http://brokerd/v1/actions", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /v1/actions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /v1/actions: statut %d", resp.StatusCode)
	}
	var ar actionResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		t.Fatalf("décodage réponse: %v", err)
	}
	return ar
}

func getJSON(t *testing.T, hc *http.Client, url string, dst any) {
	t.Helper()
	resp, err := hc.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: statut %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("GET %s: décodage: %v", url, err)
	}
}

// TestBrokerdEndToEnd : une action traverse TOUTE la pile assemblée
// (OPA stub → traducteur structuré → époque → émetteur) et les trois
// lectures de supervision rendent l'état RÉEL des briques — y compris
// les refus, qui sont des faits autant que les émissions.
func TestBrokerdEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)

	var allow atomic.Bool
	allow.Store(true)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"result":{"allow":%t}}`, allow.Load())
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env)) }()
	waitSocket(t, sock)
	hc := unixClient(t, sock)

	// 1. Action autorisée de bout en bout : jeton émis, jti posé.
	res := postAction(t, hc, "agent-1", `{"action":"read","resource":"doc-1","class":0}`)
	if !res.Allow {
		t.Fatalf("action autorisée refusée: %+v", res)
	}
	if res.Token == "" || res.JTI == "" {
		t.Fatalf("émission incomplète: %+v", res)
	}

	// 2. Refus OPA : la décision remonte avec sa raison.
	allow.Store(false)
	res = postAction(t, hc, "agent-1", `{"action":"write","resource":"doc-2","class":0}`)
	if res.Allow || res.Reason != "opa-deny" {
		t.Fatalf("refus OPA attendu, got %+v", res)
	}

	// 3. Intention intraduisible : « je ne sais pas » est un refus sain.
	res = postAction(t, hc, "agent-1", "pas du json")
	if res.Allow || res.Reason != "translation-failed" {
		t.Fatalf("refus traduction attendu, got %+v", res)
	}

	// 4. Stats : les trois passages sont comptés — exactement.
	var stats struct {
		Requests            uint64 `json:"requests"`
		Allows              uint64 `json:"allows"`
		Denies              uint64 `json:"denies"`
		TranslationFailures uint64 `json:"translation_failures"`
	}
	getJSON(t, hc, "http://brokerd/v1/supervision/stats", &stats)
	// Denies = 2 : le refus OPA (compté à l'étape 5) ET le refus de
	// traduction (compté dans deny()) — tout refus est un deny, quelle
	// que soit l'étape qui le prononce.
	if stats.Requests != 3 || stats.Allows != 1 || stats.Denies != 2 || stats.TranslationFailures != 1 {
		t.Fatalf("compteurs = %+v, attendu 3 requêtes / 1 allow / 2 denies / 1 traduction", stats)
	}

	// 5. Époque : celle de la genèse, autorité = la cellule elle-même.
	var epoch struct {
		Epoch       int       `json:"epoch"`
		Authority   string    `json:"authority"`
		NotBefore   time.Time `json:"not_before"`
		ExpiresAt   time.Time `json:"expires_at"`
		Quarantined []string  `json:"quarantined"`
	}
	getJSON(t, hc, "http://brokerd/v1/supervision/epoch", &epoch)
	if epoch.Epoch != 0 || epoch.Authority != "cell-a" {
		t.Fatalf("époque = %+v, attendu epoch 0 autorité cell-a", epoch)
	}
	if !epoch.ExpiresAt.After(epoch.NotBefore) {
		t.Fatalf("fenêtre d'époque incohérente: %+v", epoch)
	}

	// 6. Arbitrage : policy épinglée, file vide (rien de soumis).
	var arb struct {
		PolicyID string `json:"policy_id"`
		Pending  []struct {
			Hash string `json:"hash"`
		} `json:"pending"`
	}
	getJSON(t, hc, "http://brokerd/v1/supervision/arbitration", &arb)
	if arb.PolicyID != fx.env["TBP_POLICY_ID"] {
		t.Fatalf("policy_id = %q, attendu %q", arb.PolicyID, fx.env["TBP_POLICY_ID"])
	}
	if len(arb.Pending) != 0 {
		t.Fatalf("file d'arbitrage non vide: %+v", arb.Pending)
	}

	// 7. Les lectures de supervision sont GET-only : 405 aux autres
	// méthodes (patterns Go 1.22 — même doctrine que la console T34c).
	req, err := http.NewRequest(http.MethodPost, "http://brokerd/v1/supervision/stats", nil)
	if err != nil {
		t.Fatalf("requête: %v", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("POST supervision/stats: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /v1/supervision/stats: statut %d, attendu 405", resp.StatusCode)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// TestBrokerdMonoCelluleNoEpochLease : revue de sécurité #97 (confirmée en
// exécution contre le vrai binaire avant ce correctif : une cellule
// s'arrêtait de servir au plus tard TTLSeconds après sa genèse, sans
// aucun renouvellement). Avec UNE seule cellule dans TBP_CLUSTER_MEMBERS,
// brokerd démarre SANS epoch0.json (absent du répertoire de genèse ici,
// exprès) et sert indéfiniment — la vue de supervision reflète
// honnêtement l'absence de bail plutôt que de simuler un epochView vide.
func TestBrokerdMonoCelluleNoEpochLease(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	dir := t.TempDir()
	genDir := filepath.Join(dir, "genesis")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("genesis dir: %v", err)
	}
	// SEULEMENT le manifest (requis par le quorum classe W, §7.5) — PAS
	// d'epoch0.json : le point même de ce test est qu'il n'en faut plus
	// en mode mono-cellule.
	mintManifest(t, genDir, 1)
	if _, err := os.Stat(filepath.Join(genDir, "epoch0.json")); err == nil {
		t.Fatal("epoch0.json existe alors que ce test doit prouver qu'il n'est pas nécessaire")
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	seedFile := filepath.Join(dir, "issuer.seed")
	if err := os.WriteFile(seedFile, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	opPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("operateur: %v", err)
	}
	opsFile := filepath.Join(dir, "operators.json")
	ops, _ := json.Marshal([]string{hex.EncodeToString(opPub)})
	if err := os.WriteFile(opsFile, ops, 0o600); err != nil {
		t.Fatalf("operateurs: %v", err)
	}
	policy, salt := make([]byte, 32), make([]byte, 16)
	if _, err := rand.Read(policy); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("salt: %v", err)
	}

	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"allow":true}}`)
	}))
	defer opa.Close()

	env := map[string]string{
		"TBP_CELL_ID":            "cell-a",
		"TBP_SALT":               hex.EncodeToString(salt),
		"TBP_POLICY_ID":          hex.EncodeToString(policy),
		"TBP_REGISTRY_DIR":       filepath.Join(dir, "registry"),
		"TBP_OPA_ENDPOINT":       opa.URL,
		"TBP_TRANSLATOR":         "structured",
		"TBP_ISSUER_SEED_FILE":   seedFile,
		"TBP_GENESIS_DIR":        genDir,
		"TBP_QUORUM_MIN":         "1",
		"TBP_CLUSTER_MEMBERS":    "cell-a", // UNE seule cellule ⇒ mono-cellule (#97)
		"TBP_OPERATOR_KEYS_FILE": opsFile,
		"TBP_BROKER_SOCKET":      sock,
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(env)) }()
	waitSocket(t, sock)
	hc := unixClient(t, sock)

	// Démarre SANS epoch0.json — c'est déjà la preuve principale : avant
	// ce correctif, l'absence d'epoch0.json faisait échouer run() avec
	// « epoch0: … no such file ».
	res := postAction(t, hc, "agent-1", `{"action":"read","resource":"doc-1","class":0}`)
	if !res.Allow {
		t.Fatalf("action refusée en mode mono-cellule: %+v", res)
	}

	// La vue de supervision est honnête sur l'absence de fencing — pas un
	// epochView à moitié rempli (not_before/expires_at seraient à la
	// valeur zéro, lisibles comme « bail déjà expiré »).
	var raw map[string]any
	getJSON(t, hc, "http://brokerd/v1/supervision/epoch", &raw)
	if raw["mode"] != "mono-cellule" {
		t.Fatalf("vue d'époque = %+v, attendu mode=mono-cellule", raw)
	}
	if _, has := raw["not_before"]; has {
		t.Fatalf("vue d'époque = %+v, ne doit PAS porter not_before (aucun bail à ce sujet)", raw)
	}
	if _, has := raw["expires_at"]; has {
		t.Fatalf("vue d'époque = %+v, ne doit PAS porter expires_at (aucun bail à ce sujet)", raw)
	}

	// Aucune expiration possible : une seconde action, un peu plus tard,
	// doit encore passer (contrairement au comportement pré-#97, où une
	// genèse à TTL 10 s aurait déjà basculé en epoch-unavailable ici).
	time.Sleep(200 * time.Millisecond)
	res = postAction(t, hc, "agent-1", `{"action":"read","resource":"doc-2","class":0}`)
	if !res.Allow || res.Reason == "epoch-unavailable" {
		t.Fatalf("action refusée après délai en mode mono-cellule: %+v", res)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}
