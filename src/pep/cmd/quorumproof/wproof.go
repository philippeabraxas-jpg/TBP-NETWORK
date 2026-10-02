package main

// wproof.go — preuves de quorum de CLASSE W pour brokerd (§7.5), distinctes des preuves
// de transition/posture du reste de l'outil.
//
//	quorumproof wproof    -manifest M -action A -resource R -policy HEX64 [-epoch N] [-ttl S] -key FILE [-key FILE…] -out P
//	    signe avec des clés logicielles de contrôleurs ; le key_id de chaque clé est sa POSITION
//	    (base 1) dans le manifeste de genèse M — jamais saisi à la main
//	quorumproof wmessage  -action A -resource R -policy HEX64 [-epoch N] [-ttl S] -out DECLARATION.json
//	    écrit la déclaration à signer et affiche son message (hex) : pour les contrôleurs en HSM
//	quorumproof wassemble -statement DECLARATION.json -sig ID=SIGHEX [-sig …] -quorum K-of-N -out P
//	    assemble des signatures faites ailleurs (ID = position dans le manifeste, base 1)
//
// La preuve est liée à (action, ressource, bundle de règles, époque, expiration) : elle n'autorise
// qu'UNE exécution (#206). Les contrôleurs en signent une NOUVELLE pour chaque exécution.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
)

// wStatement construit la déclaration pour une expiration donnée.
func wStatement(action, resource, policyHex string, epoch uint64, exp time.Time) (cluster.QuorumStatement, error) {
	if action == "" || resource == "" {
		return cluster.QuorumStatement{}, errors.New("-action et -resource requis")
	}
	if raw, err := hex.DecodeString(policyHex); err != nil || len(raw) != 32 {
		return cluster.QuorumStatement{}, errors.New("-policy : 64 caractères hexadécimaux (le TBP_POLICY_ID de la cellule)")
	}
	return cluster.QuorumStatement{
		Action: action, Resource: resource, PolicyID: policyHex, Epoch: epoch,
		Expiry: exp.UTC().Format(time.RFC3339),
	}, nil
}

// manifestIDs rend, pour chaque clé publique du manifeste de genèse, son key_id (position, base 1).
func manifestIDs(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifeste de genèse : %w", err)
	}
	var mf struct {
		PubKeys []string `json:"pubkeys"`
	}
	if err := json.Unmarshal(data, &mf); err != nil || len(mf.PubKeys) == 0 {
		return nil, fmt.Errorf("manifeste de genèse %s illisible ou sans clés", path)
	}
	ids := make(map[string]int, len(mf.PubKeys))
	for i, p := range mf.PubKeys {
		// la même clé deux fois : la dernière écrasait la première en silence, et le key_id rendu dépendait de l'ordre ;
		// brokerd refuse un tel manifeste (revue tierce 4.4) — l'outil ne le contourne pas
		if first, dup := ids[strings.ToLower(p)]; dup {
			return nil, fmt.Errorf("manifeste de genèse %s : la clé du contrôleur %d est déjà le contrôleur %d", path, i+1, first)
		}
		ids[strings.ToLower(p)] = i + 1
	}
	return ids, nil
}

func wFlags(name string) (*flag.FlagSet, *string, *string, *string, *uint64, *int, *string, *multi) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	action := fs.String("action", "", "action liée (celle que brokerd traduit)")
	resource := fs.String("resource", "", "ressource liée")
	policy := fs.String("policy", "", "TBP_POLICY_ID de la cellule (hex 64)")
	epoch := fs.Uint64("epoch", 0, "époque (0 en topologie mono)")
	ttl := fs.Int("ttl", 240, "durée de validité en secondes (≤ 300)")
	out := fs.String("out", "", "fichier à écrire (0600)")
	var keys multi
	fs.Var(&keys, "key", "fichier de clé logicielle de contrôleur (répétable)")
	return fs, action, resource, policy, epoch, ttl, out, &keys
}

func wTTL(ttl int) (time.Time, error) {
	if ttl < 10 || ttl > 300 {
		return time.Time{}, fmt.Errorf("-ttl hors bornes [10, 300] s (la preuve doit rester fraîche)")
	}
	return time.Now().Add(time.Duration(ttl) * time.Second), nil
}

func cmdWProof(args []string) error {
	fs, action, resource, policy, epoch, ttl, out, keys := wFlags("wproof")
	manifest := fs.String("manifest", "", "manifeste de genèse (position des clés = key_id)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *manifest == "" || len(*keys) == 0 {
		return errors.New("-manifest, -out et au moins un -key requis")
	}
	exp, err := wTTL(*ttl)
	if err != nil {
		return err
	}
	st, err := wStatement(*action, *resource, *policy, *epoch, exp)
	if err != nil {
		return err
	}
	ids, err := manifestIDs(*manifest)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(st)
	if err != nil {
		return err
	}
	proof := cluster.QuorumProof{Statement: st, Quorum: fmt.Sprintf("?-of-%d", len(ids))}
	seen := map[int]bool{}
	for _, f := range *keys {
		k, err := loadKey(f)
		if err != nil {
			return err
		}
		id, ok := ids[hex.EncodeToString(k.Public().(ed25519.PublicKey))]
		if !ok {
			return fmt.Errorf("la clé %s n'est PAS dans le manifeste de genèse %s : ce n'est pas un contrôleur de cette cellule", f, *manifest)
		}
		if seen[id] {
			return fmt.Errorf("contrôleur %d fourni deux fois : un quorum se compose de contrôleurs distincts", id)
		}
		seen[id] = true
		proof.Signatures = append(proof.Signatures, cluster.ControllerSignature{KeyID: id, Sig: hex.EncodeToString(ed25519.Sign(k, canonical))})
	}
	return writeJSON0600(*out, proof)
}

func cmdWMessage(args []string) error {
	fs, action, resource, policy, epoch, ttl, out, _ := wFlags("wmessage")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out requis")
	}
	exp, err := wTTL(*ttl)
	if err != nil {
		return err
	}
	st, err := wStatement(*action, *resource, *policy, *epoch, exp)
	if err != nil {
		return err
	}
	canonical, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := writeJSON0600(*out, st); err != nil {
		return err
	}
	fmt.Printf("expiry=%s\nmessage=%s\n", st.Expiry, hex.EncodeToString(canonical))
	return nil
}

func cmdWAssemble(args []string) error {
	fs := flag.NewFlagSet("wassemble", flag.ContinueOnError)
	stmtFile := fs.String("statement", "", "déclaration écrite par « wmessage »")
	quorum := fs.String("quorum", "", "K-of-N (informatif : le gate revérifie)")
	out := fs.String("out", "", "fichier de preuve à écrire (0600)")
	var sigs multi
	fs.Var(&sigs, "sig", "ID=SIGHEX (répétable ; ID = position dans le manifeste, base 1)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *stmtFile == "" || *out == "" || len(sigs) == 0 {
		return errors.New("-statement, -out et au moins un -sig requis")
	}
	data, err := os.ReadFile(*stmtFile)
	if err != nil {
		return err
	}
	var st cluster.QuorumStatement
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("déclaration %s illisible : %w", *stmtFile, err)
	}
	proof := cluster.QuorumProof{Statement: st, Quorum: *quorum}
	seen := map[int]bool{}
	for _, s := range sigs {
		idStr, sig, ok := strings.Cut(s, "=")
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); !ok || err != nil || id < 1 || len(sig) != 2*ed25519.SignatureSize {
			return fmt.Errorf("-sig %q : ID (entier ≥ 1) = SIGNATURE (hex 128) attendu", s)
		}
		if seen[id] {
			return fmt.Errorf("contrôleur %d en double", id)
		}
		seen[id] = true
		proof.Signatures = append(proof.Signatures, cluster.ControllerSignature{KeyID: id, Sig: sig})
	}
	return writeJSON0600(*out, proof)
}

func writeJSON0600(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
