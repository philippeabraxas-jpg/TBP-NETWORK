// quorumproof — fabrique les fichiers de preuve de quorum que lisent pepd et brokerd
// (pep.VerifyQuorumProofFile) : transition du démarrage mesuré, transition du
// provisionnement (issue #192), même forme que le corps de POST /v1/mode.
//
// Une preuve = k signatures Ed25519 DISTINCTES de contrôleurs épinglés, chacune sur
// pep.QuorumMessage(condition, cellID, expiry). L'outil ne décide de rien : il
// construit le message, assemble le fichier, et sait signer avec des clés LOGICIELLES
// (échelle 1 : l'administrateur seul, k = 1 ; dev/labo). Des contrôleurs dont la clé vit
// dans un HSM signent le message avec leur outillage HSM (sous-commande message), puis
// on assemble (sous-commande assemble) — la clé privée ne passe jamais ici.
//
//	quorumproof keygen   -key <fichier> -keyring <trousseau.json>
//	    crée une clé LOGICIELLE d'administrateur (graine hex, 0600, jamais écrasée) et
//	    l'ajoute au trousseau de quorum {kid: clé publique} — échelle 1 (dev/labo)
//	quorumproof message  -condition C -cell ID [-ttl 240]
//	    affiche l'expiration et le message à signer (hex)
//	quorumproof sign     -condition C -cell ID [-ttl 240] -key <fichier> [-key <fichier>…] -out <preuve.json>
//	    signe avec des clés logicielles (fichier : graine 32 octets ou clé 64 octets, en hex)
//	quorumproof assemble -expiry E -sig KID=SIGHEX [-sig …] -out <preuve.json>
//	    assemble des signatures faites ailleurs (KID = SHA-256(pub)[:16], hex)
//
// Conditions : « provisioning-transition-brokerd », « provisioning-transition-pepd »,
// « measured-boot-transition », « mode-closed », « mode-monitor ». La condition est
// liée par la signature : une preuve ne vaut jamais pour une autre.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

type sigWire struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type proofWire struct {
	Expiry     int64     `json:"expiry"`
	Signatures []sigWire `json:"signatures"`
}

// multi est un flag répétable.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = cmdKeygen(os.Args[2:], os.Stdout)
	case "message":
		err = cmdMessage(os.Args[2:], os.Stdout)
	case "sign":
		err = cmdSign(os.Args[2:])
	case "assemble":
		err = cmdAssemble(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "quorumproof: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: quorumproof <keygen|message|sign|assemble> [flags]
  keygen   -key FILE -keyring TROUSSEAU.json
  message  -condition C -cell ID [-ttl 240]
  sign     -condition C -cell ID [-ttl 240] -key FILE [-key FILE …] -out PREUVE.json
  assemble -expiry UNIX -sig KID=SIGHEX [-sig …] -out PREUVE.json`)
}

func expiryFrom(ttl int, now time.Time) (time.Time, error) {
	if ttl < 10 || ttl > int(pep.DefaultQuorumProofTTL/time.Second) {
		return time.Time{}, fmt.Errorf("-ttl hors bornes [10, %d] s (la preuve doit rester fraîche)", int(pep.DefaultQuorumProofTTL/time.Second))
	}
	return now.Add(time.Duration(ttl) * time.Second), nil
}

func cmdMessage(args []string, out *os.File) error {
	fs := flag.NewFlagSet("message", flag.ContinueOnError)
	cond := fs.String("condition", "", "condition liée par la signature")
	cell := fs.String("cell", "", "identité de la cellule")
	ttl := fs.Int("ttl", 240, "durée de validité de la preuve, en secondes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cond == "" || *cell == "" {
		return errors.New("-condition et -cell requis")
	}
	exp, err := expiryFrom(*ttl, time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "expiry=%d\nmessage=%s\n", exp.Unix(), hex.EncodeToString(pep.QuorumMessage(*cond, *cell, exp)))
	return nil
}

// loadKey lit une clé Ed25519 logicielle : graine (32 octets) ou clé complète (64), en hex.
func loadKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("%s : hex illisible", path)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, fmt.Errorf("%s : %d octets (graine de 32 ou clé de 64 attendus)", path, len(raw))
}

// buildProof signe avec les clés données ; refuse deux fois la même clé.
func buildProof(cond, cell string, exp time.Time, keys []ed25519.PrivateKey) (proofWire, error) {
	pf := proofWire{Expiry: exp.Unix()}
	seen := map[string]bool{}
	msg := pep.QuorumMessage(cond, cell, exp)
	for _, k := range keys {
		kid := pep.KeyIDFromPublicKey(k.Public().(ed25519.PublicKey))
		id := hex.EncodeToString(kid[:])
		if seen[id] {
			return pf, fmt.Errorf("clé %s fournie deux fois — un quorum compte des signataires DISTINCTS", id)
		}
		seen[id] = true
		pf.Signatures = append(pf.Signatures, sigWire{KeyID: id, Signature: hex.EncodeToString(ed25519.Sign(k, msg))})
	}
	return pf, nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	cond := fs.String("condition", "", "condition liée par la signature")
	cell := fs.String("cell", "", "identité de la cellule")
	ttl := fs.Int("ttl", 240, "durée de validité, en secondes")
	out := fs.String("out", "", "fichier de preuve à écrire (0600)")
	var keyFiles multi
	fs.Var(&keyFiles, "key", "fichier de clé logicielle (répétable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cond == "" || *cell == "" || *out == "" || len(keyFiles) == 0 {
		return errors.New("-condition, -cell, -out et au moins un -key requis")
	}
	exp, err := expiryFrom(*ttl, time.Now())
	if err != nil {
		return err
	}
	var keys []ed25519.PrivateKey
	for _, f := range keyFiles {
		k, err := loadKey(f)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	pf, err := buildProof(*cond, *cell, exp, keys)
	if err != nil {
		return err
	}
	return writeProof(*out, pf)
}

func cmdAssemble(args []string) error {
	fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
	expiry := fs.String("expiry", "", "expiration (secondes Unix) affichée par « message »")
	out := fs.String("out", "", "fichier de preuve à écrire (0600)")
	var sigs multi
	fs.Var(&sigs, "sig", "KID=SIGHEX (répétable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	exp, err := strconv.ParseInt(*expiry, 10, 64)
	if err != nil || *out == "" || len(sigs) == 0 {
		return errors.New("-expiry (entier), -out et au moins un -sig requis")
	}
	pf := proofWire{Expiry: exp}
	seen := map[string]bool{}
	for _, s := range sigs {
		kid, sig, ok := strings.Cut(s, "=")
		if !ok || len(kid) != 32 || len(sig) != 2*ed25519.SignatureSize {
			return fmt.Errorf("-sig %q : KID (hex 32) = SIGNATURE (hex 128) attendu", s)
		}
		if seen[kid] {
			return fmt.Errorf("signataire %s en double", kid)
		}
		seen[kid] = true
		pf.Signatures = append(pf.Signatures, sigWire{KeyID: kid, Signature: sig})
	}
	return writeProof(*out, pf)
}

func writeProof(path string, pf proofWire) error {
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// cmdKeygen crée une clé d'administrateur logicielle et l'inscrit au trousseau de quorum.
// Refuse d'écraser une clé existante et d'inscrire deux fois la même clé publique :
// une clé perdue ne se « régénère » pas sous le même nom, on en épingle une nouvelle.
func cmdKeygen(args []string, out *os.File) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	keyPath := fs.String("key", "", "fichier de la clé privée à créer (graine hex, 0600)")
	ringPath := fs.String("keyring", "", "trousseau de quorum {kid: clé publique} à créer ou compléter")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *ringPath == "" {
		return errors.New("-key et -keyring requis")
	}
	ring := map[string]string{}
	if data, err := os.ReadFile(*ringPath); err == nil {
		if err := json.Unmarshal(data, &ring); err != nil {
			return fmt.Errorf("%s : trousseau illisible (%v) — pas de réécriture à l'aveugle", *ringPath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	kid := pep.KeyIDFromPublicKey(pub)
	kidHex := hex.EncodeToString(kid[:])
	if _, dup := ring[kidHex]; dup {
		return fmt.Errorf("kid %s déjà dans le trousseau", kidHex)
	}
	f, err := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("%s : %v (une clé existante n'est jamais écrasée)", *keyPath, err)
	}
	if _, err := f.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ring[kidHex] = hex.EncodeToString(pub)
	data, err := json.MarshalIndent(ring, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*ringPath, append(data, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "kid=%s\npublic=%s\nkeyring=%s (%d clé(s))\n", kidHex, hex.EncodeToString(pub), *ringPath, len(ring))
	return nil
}
