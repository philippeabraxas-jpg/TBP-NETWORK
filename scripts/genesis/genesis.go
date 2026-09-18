// scripts/genesis/genesis.go — T3 (issue #2)
//
// Outillage de genèse DEV/TEST : génération des clés contrôleurs (m-of-n),
// signature du jeton d'epoch 0, ancrage hors-bande simulé, vérification.
//
// ⚠ SoftHSM = dev/test UNIQUEMENT — jamais en gouvernance réelle (spec §12).
// La cérémonie de genèse réelle est procédurale, pas du code : quorum de
// contrôleurs humains, HSM véritables, canal hors-bande authentifié (§3.2,
// §7.2). Ce programme existe pour que les phases suivantes (registre, PEP,
// NAC) disposent de clés et d'un epoch 0 signés sans attendre la cérémonie.
//
// Commandes :
//
//	genesis keygen  -n 3                     génère n paires Ed25519 (PKCS#11)
//	genesis sign    -m 2 -authority cell-a   signe le jeton d'epoch 0 (m-of-n)
//	genesis anchor                           ancrage hors-bande simulé (dev)
//	genesis verify  -m 2                     vérifie quorum + ancrage
//
// Ed25519 partout (§12) : CKM_EDDSA côté HSM, crypto/ed25519 côté vérifier
// — la vérification est publique et ne requiert pas l'accès au HSM.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/pkcs11"
)

// Constantes PKCS#11 v3.0 (absentes de miekg/pkcs11 v1.1.1).
const (
	ckmEDDSA     = 0x00001057 // CKM_EDDSA
	ckkEcEdwards = 0x00000040 // CKK_EC_EDWARDS
	ckoPublicKey = 0x00000002 // CKO_PUBLIC_KEY
	ckaValue     = 0x00000011 // CKA_VALUE
	ckaKeyType   = 0x00000100 // CKA_KEY_TYPE
)

// ed25519OID est le CKA_EC_PARAMS d'une clé Ed25519 : OID 1.3.101.112
// encodé DER (06 03 2B 65 70).
var ed25519OID = []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

const (
	keyLabelPrefix = "tbp-controller-" // label PKCS#11 : tbp-controller-<i>
	tokenLabel     = "tbp-genesis-dev" // label du token SoftHSM (dev)
)

// EpochPayload est le jeton d'epoch (§7.2) : (N, authority, TTL ~60 s).
// Struct à champs fixes → sérialisation JSON déterministe (profil §11.3).
type EpochPayload struct {
	N          int    `json:"n"`
	Authority  string `json:"authority"`
	IssuedAt   string `json:"issued_at"` // RFC3339 UTC
	TTLSeconds int    `json:"ttl_s"`
}

// EpochToken = payload + signatures du quorum + paramètre m-of-n.
// Le champ Warning est hors payload signé : il marque l'artefact dev sans
// toucher à la surface signée.
type EpochToken struct {
	Payload    EpochPayload `json:"payload"`
	Quorum     string       `json:"quorum"` // ex. "2-of-3"
	Signatures []Signature  `json:"signatures"`
	Warning    string       `json:"warning"`
}

type Signature struct {
	KeyID int    `json:"key_id"`
	Sig   string `json:"sig"` // hex Ed25519
}

// Manifest des clés publiques : le hash engage l'ensemble des clés du
// quorum — un entrant tardif vérifie la chaîne de clés hors-bande (§3.2).
type Manifest struct {
	TokenLabel   string   `json:"token_label"`
	Mechanism    string   `json:"mechanism"` // "Ed25519 (CKM_EDDSA)"
	GeneratedAt  string   `json:"generated_at"`
	PubKeys      []string `json:"pubkeys"` // hex, ordre = key_id
	ManifestHash string   `json:"manifest_hash"`
	Warning      string   `json:"warning"`
}

const softHSMWarning = "DEV/TEST UNIQUEMENT — SoftHSM n'est jamais une racine de confiance de gouvernance (spec §12)"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "anchor":
		err = cmdAnchor(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: genesis <commande> [flags]

  keygen  -n 3 -module <libsofthsm2.so> -pin <pin> -out <dir>
  sign    -m 2 -n 3 -authority <cellule> -module ... -pin ... -out <dir>
  anchor  -out <dir>
  verify  -m 2 -out <dir>

`+softHSMWarning)
}

// newFlagSet : flags communs (module PKCS#11, PIN, sortie). Le Parse est
// fait par chaque commande APRÈS avoir défini ses propres flags — parser
// avant échouerait sur les flags spécifiques (-n, -m, -authority).
func newFlagSet() (fs *flag.FlagSet, module, pin, out *string) {
	fs = flag.NewFlagSet("", flag.ExitOnError)
	module = fs.String("module", envOr("SOFTHSM2_MODULE", ""), "bibliothèque PKCS#11 (libsofthsm2.so)")
	pin = fs.String("pin", envOr("TBP_DEV_PIN", ""), "PIN utilisateur du token (dev)")
	out = fs.String("out", "out", "répertoire de sortie")
	return fs, module, pin, out
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// Contexte HSM
// ---------------------------------------------------------------------------

type hsm struct {
	p       *pkcs11.Ctx
	session pkcs11.SessionHandle
}

func openHSM(module, pin string) (*hsm, error) {
	if module == "" {
		return nil, fmt.Errorf("-module requis (ou SOFTHSM2_MODULE) : chemin de libsofthsm2.so")
	}
	p := pkcs11.New(module)
	if p == nil {
		return nil, fmt.Errorf("impossible de charger le module PKCS#11 %s", module)
	}
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("C_Initialize: %w", err)
	}

	// Retrouver le slot par label de token — pas par index : SoftHSM
	// réassigne les numéros de slot à l'initialisation.
	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("GetSlotList: %w", err)
	}
	slot := -1
	for _, s := range slots {
		info, err := p.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if strings.TrimSpace(info.Label) == tokenLabel {
			slot = int(s)
			break
		}
	}
	if slot < 0 {
		return nil, fmt.Errorf("token %q introuvable — lancer genesis_dev.sh (initialisation) d'abord", tokenLabel)
	}

	session, err := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("OpenSession: %w", err)
	}
	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, fmt.Errorf("Login (PIN incorrect ?): %w", err)
	}
	return &hsm{p: p, session: session}, nil
}

func (h *hsm) Close() {
	h.p.Logout(h.session)
	h.p.CloseSession(h.session)
	h.p.Finalize()
	h.p.Destroy()
}

// generateController crée la paire Ed25519 d'un contrôleur dans le token.
//
// SoftHSM 2.6 ne supporte PAS C_GenerateKeyPair pour CKM_EDDSA (les flags
// du mécanisme sont SIGN|VERIFY, sans GENERATE_KEY_PAIR — vérifié par
// GetMechanismInfo). En dev, la paire est donc générée par crypto/ed25519
// puis IMPORTÉE dans le token via C_CreateObject (CKA_VALUE = seed). La
// clé transite par la mémoire du processus — acceptable pour un HSM
// logiciel de dev (§12 : SoftHSM jamais en gouvernance) ; la cérémonie
// réelle génère les clés DANS le HSM véritable, sans extraction possible,
// et ce code n'est pas fait pour ça.
func (h *hsm) generateController(id int) (pub ed25519.PublicKey, err error) {
	label := fmt.Sprintf("%s%d", keyLabelPrefix, id)

	// Idempotence : détruire toute clé existante sous ce label avant de
	// régénérer — sinon les doublons s'accumulent et findKey peut
	// retourner l'ancienne clé (signature invalide au verify).
	if err := h.destroyByLabel(label); err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("génération Ed25519: %w", err)
	}
	idBytes := []byte{byte(id)}

	pubTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckoPublicKey),
		pkcs11.NewAttribute(ckaKeyType, ckkEcEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, []byte(pub)),
	}
	privTpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(ckaKeyType, ckkEcEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519OID),
		pkcs11.NewAttribute(ckaValue, priv.Seed()),
	}
	if _, err := h.p.CreateObject(h.session, pubTpl); err != nil {
		return nil, fmt.Errorf("CreateObject(pub %s): %w", label, err)
	}
	if _, err := h.p.CreateObject(h.session, privTpl); err != nil {
		return nil, fmt.Errorf("CreateObject(priv %s): %w", label, err)
	}
	return pub, nil
}

// findAll retourne tous les handles d'objets d'une classe donnée portant
// un label donné (recherche exhaustive, par lots de 16).
func (h *hsm) findAll(class uint, label string) ([]pkcs11.ObjectHandle, error) {
	tpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := h.p.FindObjectsInit(h.session, tpl); err != nil {
		return nil, err
	}
	defer h.p.FindObjectsFinal(h.session)
	var all []pkcs11.ObjectHandle
	for {
		handles, more, err := h.p.FindObjects(h.session, 16)
		if err != nil {
			return nil, err
		}
		all = append(all, handles...)
		if !more {
			return all, nil
		}
	}
}

// destroyByLabel supprime les clés publiques et privées portant le label.
func (h *hsm) destroyByLabel(label string) error {
	for _, class := range []uint{ckoPublicKey, pkcs11.CKO_PRIVATE_KEY} {
		handles, err := h.findAll(class, label)
		if err != nil {
			return err
		}
		for _, oh := range handles {
			if err := h.p.DestroyObject(h.session, oh); err != nil {
				return fmt.Errorf("DestroyObject(%s): %w", label, err)
			}
		}
	}
	return nil
}

// findKey retrouve le handle de la clé privée d'un contrôleur. Une clé en
// double est une anomalie (le keygen est censé être idempotent) : refus.
func (h *hsm) findKey(id int) (pkcs11.ObjectHandle, error) {
	label := fmt.Sprintf("%s%d", keyLabelPrefix, id)
	handles, err := h.findAll(pkcs11.CKO_PRIVATE_KEY, label)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("clé privée %s introuvable dans le token", label)
	}
	if len(handles) > 1 {
		return 0, fmt.Errorf("%d clés privées portent le label %s — token incohérent, relancer keygen", len(handles), label)
	}
	return handles[0], nil
}

// sign signe avec la clé privée d'un contrôleur (la clé ne quitte pas le HSM).
func (h *hsm) sign(id int, msg []byte) ([]byte, error) {
	priv, err := h.findKey(id)
	if err != nil {
		return nil, err
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEDDSA, nil)}
	if err := h.p.SignInit(h.session, mech, priv); err != nil {
		return nil, fmt.Errorf("SignInit: %w", err)
	}
	return h.p.Sign(h.session, msg)
}

// ---------------------------------------------------------------------------
// Commandes
// ---------------------------------------------------------------------------

func cmdKeygen(args []string) error {
	fs, module, pin, out := newFlagSet()
	n := fs.Int("n", 3, "nombre de contrôleurs (n de m-of-n)")
	fs.Parse(args)
	if *n < 1 {
		return fmt.Errorf("-n doit être ≥ 1")
	}

	h, err := openHSM(*module, *pin)
	if err != nil {
		return err
	}
	defer h.Close()

	pubDir := filepath.Join(*out, "pubkeys")
	if err := os.MkdirAll(pubDir, 0o755); err != nil {
		return err
	}

	mf := Manifest{
		TokenLabel:  tokenLabel,
		Mechanism:   "Ed25519 (CKM_EDDSA)",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Warning:     softHSMWarning,
	}
	for i := 1; i <= *n; i++ {
		pub, err := h.generateController(i)
		if err != nil {
			return err
		}
		hexKey := hex.EncodeToString(pub)
		mf.PubKeys = append(mf.PubKeys, hexKey)
		if err := os.WriteFile(filepath.Join(pubDir, fmt.Sprintf("controller-%d.hex", i)),
			[]byte(hexKey+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("contrôleur %d : clé Ed25519 générée dans le HSM, pubkey exportée\n", i)
	}
	mf.ManifestHash = hashPubKeys(mf.PubKeys)

	data, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "manifest.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("manifest écrit (%d clés, hash %s…)\n", *n, mf.ManifestHash[:16])
	fmt.Println("⚠ " + softHSMWarning)
	return nil
}

// hashPubKeys : sha256 de la concaténation des clés publiques triées —
// déterministe, indépendant de l'ordre de génération (profil §11.3).
func hashPubKeys(pubs []string) string {
	sorted := append([]string{}, pubs...)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "")))
	return hex.EncodeToString(h[:])
}

func cmdSign(args []string) error {
	fs, module, pin, out := newFlagSet()
	m := fs.Int("m", 2, "quorum (m de m-of-n)")
	n := fs.Int("n", 3, "nombre total de contrôleurs")
	authority := fs.String("authority", "cell-a", "cellule autorité de l'epoch 0")
	fs.Parse(args)
	if *m < 1 || *m > *n {
		return fmt.Errorf("quorum invalide : m=%d, n=%d", *m, *n)
	}

	payload := EpochPayload{
		N:          0,
		Authority:  *authority,
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		TTLSeconds: 60, // §7.2 : TTL ~60 s
	}
	canonical, err := json.Marshal(payload) // struct → ordre de champs fixe
	if err != nil {
		return err
	}

	h, err := openHSM(*module, *pin)
	if err != nil {
		return err
	}
	defer h.Close()

	token := EpochToken{
		Payload: payload,
		Quorum:  fmt.Sprintf("%d-of-%d", *m, *n),
		Warning: softHSMWarning,
	}
	for i := 1; i <= *m; i++ {
		sig, err := h.sign(i, canonical)
		if err != nil {
			return err
		}
		token.Signatures = append(token.Signatures, Signature{KeyID: i, Sig: hex.EncodeToString(sig)})
		fmt.Printf("signature %d/%d : contrôleur %d (clé restée dans le HSM)\n", i, *m, i)
	}

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "epoch0.json"), append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("epoch 0 signé (%s) → %s\n", token.Quorum, filepath.Join(*out, "epoch0.json"))
	fmt.Println("⚠ " + softHSMWarning)
	return nil
}

// cmdAnchor : ancrage hors-bande SIMULÉ (§3.2). En réel, ce hash part sur
// un canal authentifié indépendant ; en dev, un fichier séparé fait office
// de canal — il matérialise ce que le vérificateur doit connaître par
// ailleurs, pas par le dépôt lui-même.
func cmdAnchor(args []string) error {
	fs, _, _, out := newFlagSet()
	fs.Parse(args)

	tokenBytes, err := os.ReadFile(filepath.Join(*out, "epoch0.json"))
	if err != nil {
		return fmt.Errorf("epoch0.json introuvable — lancer 'sign' d'abord: %w", err)
	}
	h := sha256.Sum256(tokenBytes)
	line := fmt.Sprintf("%s  %s  # ancrage hors-bande simulé (dev) — %s\n",
		hex.EncodeToString(h[:]), time.Now().UTC().Format(time.RFC3339), softHSMWarning)
	if err := os.WriteFile(filepath.Join(*out, "anchor_epoch0.txt"), []byte(line), 0o644); err != nil {
		return err
	}
	fmt.Printf("ancrage écrit → %s\n", filepath.Join(*out, "anchor_epoch0.txt"))
	fmt.Println("⚠ " + softHSMWarning)
	return nil
}

func cmdVerify(args []string) error {
	fs, _, _, out := newFlagSet()
	m := fs.Int("m", 2, "quorum attendu")
	fs.Parse(args)
	if *m < 1 {
		// Sans ce garde, -m 0 rend "valid < *m" toujours faux : un jeton
		// à zéro signature valide "passerait" le contrôle de quorum.
		// cmdSign valide déjà m ≥ 1 côté signature ; même garde ici, pas
		// de passage silencieux (§1 : default-deny).
		return fmt.Errorf("-m doit être ≥ 1 (quorum attendu, reçu %d)", *m)
	}

	// 1. Manifest : intégrité de l'ensemble des clés publiques
	mfData, err := os.ReadFile(filepath.Join(*out, "manifest.json"))
	if err != nil {
		return fmt.Errorf("manifest.json introuvable — lancer 'keygen' d'abord: %w", err)
	}
	var mf Manifest
	if err := json.Unmarshal(mfData, &mf); err != nil {
		return err
	}
	if got := hashPubKeys(mf.PubKeys); got != mf.ManifestHash {
		return fmt.Errorf("manifest altéré : hash recalculé %s ≠ %s", got[:16], mf.ManifestHash[:16])
	}
	fmt.Printf("manifest intègre (%d clés, hash %s…)\n", len(mf.PubKeys), mf.ManifestHash[:16])

	// 2. Jeton : signatures valides, signataires DISTINCTS, quorum atteint
	tokenBytes, err := os.ReadFile(filepath.Join(*out, "epoch0.json"))
	if err != nil {
		return err
	}
	var token EpochToken
	if err := json.Unmarshal(tokenBytes, &token); err != nil {
		return err
	}
	canonical, err := json.Marshal(token.Payload)
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	valid := 0
	for _, s := range token.Signatures {
		if seen[s.KeyID] {
			return fmt.Errorf("signataire %d en double — un quorum se compose de contrôleurs distincts", s.KeyID)
		}
		seen[s.KeyID] = true
		if s.KeyID < 1 || s.KeyID > len(mf.PubKeys) {
			return fmt.Errorf("key_id %d hors manifest", s.KeyID)
		}
		pub, err := hex.DecodeString(mf.PubKeys[s.KeyID-1])
		if err != nil {
			return err
		}
		sig, err := hex.DecodeString(s.Sig)
		if err != nil {
			return err
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), canonical, sig) {
			return fmt.Errorf("signature du contrôleur %d INVALIDE", s.KeyID)
		}
		valid++
	}
	if valid < *m {
		return fmt.Errorf("quorum non atteint : %d signature(s) valide(s), %d requises (%s)", valid, *m, token.Quorum)
	}
	fmt.Printf("quorum vérifié : %d signatures valides de contrôleurs distincts (%s)\n", valid, token.Quorum)

	// 3. Ancrage : le hash du jeton doit correspondre à l'ancre hors-bande
	anchor, err := os.ReadFile(filepath.Join(*out, "anchor_epoch0.txt"))
	if err != nil {
		return fmt.Errorf("anchor_epoch0.txt introuvable — lancer 'anchor' d'abord: %w", err)
	}
	h := sha256.Sum256(tokenBytes)
	if !strings.HasPrefix(string(anchor), hex.EncodeToString(h[:])) {
		return fmt.Errorf("ancrage mismatch : le jeton ne correspond pas à l'ancre hors-bande — discontinuité = refus (§3)")
	}
	fmt.Println("ancrage hors-bande vérifié — non-altération prouvée (§3.2 : la légitimité reste hors protocole)")
	fmt.Println("⚠ " + softHSMWarning)
	return nil
}
