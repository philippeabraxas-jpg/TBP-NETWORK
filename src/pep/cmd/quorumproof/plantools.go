package main

// plantools.go — le geste d'opérateur du contrat de plan (§4.2, #177) pour les actions de classe I/W.
//
//	quorumproof planapprove -plan-hash HEX64 [-ttl S] -key FILE -out APPROBATION.json
//	    signe l'approbation d'un plan avec la clé d'OPÉRATEUR (celle de TBP_OPERATOR_KEYS_FILE) et écrit
//	    le corps à poster sur POST /v1/supervision/plan/approve (socket d'administration de brokerd)
//	quorumproof planbind -plan-hash HEX64 [-params-hex HEX]
//	    affiche le plan_binding (hex) à placer dans l'intention de l'agent
//
// Le hash du plan est celui que rend POST /v1/supervision/plan/submit.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func parsePlanHash(s string) ([32]byte, error) {
	var h [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return h, errors.New("-plan-hash : 64 caractères hexadécimaux (le plan_hash rendu par plan/submit)")
	}
	copy(h[:], raw)
	return h, nil
}

func cmdPlanApprove(args []string) error {
	fs := flag.NewFlagSet("planapprove", flag.ContinueOnError)
	planHash := fs.String("plan-hash", "", "hash du plan (hex 64)")
	ttl := fs.Int("ttl", 300, "durée de validité de l'approbation, en secondes")
	keyFile := fs.String("key", "", "clé d'opérateur (fichier de graine ou de clé, hex)")
	out := fs.String("out", "", "corps JSON à écrire (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planHash == "" || *keyFile == "" || *out == "" {
		return errors.New("-plan-hash, -key et -out requis")
	}
	if *ttl < 10 || *ttl > 3600 {
		return errors.New("-ttl hors bornes [10, 3600] s")
	}
	h, err := parsePlanHash(*planHash)
	if err != nil {
		return err
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	exp := time.Now().Add(time.Duration(*ttl) * time.Second).UTC()
	sig := ed25519.Sign(key, pep.ApprovalMessage(h, exp))
	return writeJSON0600(*out, map[string]string{
		"plan_hash":  *planHash,
		"expires_at": exp.Format(time.RFC3339),
		"signature":  hex.EncodeToString(sig),
	})
}

func cmdPlanBind(args []string) error {
	fs := flag.NewFlagSet("planbind", flag.ContinueOnError)
	planHash := fs.String("plan-hash", "", "hash du plan (hex 64)")
	params := fs.String("params-hex", "", "paramètres opaques de l'étape (hex, vide par défaut)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	h, err := parsePlanHash(*planHash)
	if err != nil {
		return err
	}
	p, err := hex.DecodeString(*params)
	if err != nil {
		return errors.New("-params-hex : hexadécimal attendu")
	}
	b, err := pep.BuildBinding(h, p)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(b))
	return nil
}
