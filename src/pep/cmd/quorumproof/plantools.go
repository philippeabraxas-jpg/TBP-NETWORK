package main

// plantools.go — le geste d'opérateur du contrat de plan (§4.2, #177) pour les actions de classe I/W.
//
//	quorumproof planapprove -plan-hash HEX64 [-ttl S] -key FILE -out APPROBATION.json
//	    signe l'approbation d'un plan avec la clé d'OPÉRATEUR (celle de TBP_OPERATOR_KEYS_FILE) et écrit
//	    le corps à poster sur POST /v1/supervision/plan/approve (socket d'administration de brokerd)
//	quorumproof planrevoke -plan-hash HEX64 [-ttl S] -key FILE -out REVOCATION.json
//	    signe la RÉVOCATION d'un plan (soumis ou approuvé, #244) avec la clé d'opérateur et écrit le corps
//	    à poster sur POST /v1/supervision/plan/revoke (même socket d'administration). Le message signé est
//	    distinct de celui de l'approbation : l'une ne vaut jamais l'autre.
//	quorumproof planhash -cell ID -policy-id HEX64 -submitted-at T -plan PLAN.json [-expect HEX64]
//	    RECALCULE le hash d'un plan (HashPlan, domaine TBPC2) à partir du plan en clair — le même
//	    corps que celui de plan/submit — au lieu de croire le hash que rend le broker (#273). À faire
//	    AVANT planapprove : on signe ce qu'on a recalculé, pas ce qu'on a reçu
//	quorumproof planbind -plan-hash HEX64 [-params-hex HEX]
//	    affiche le plan_binding (hex) à placer dans l'intention de l'agent
//
// Le hash du plan est celui que rend POST /v1/supervision/plan/submit.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
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
	fmt.Fprintf(os.Stderr, "quorumproof: approbation du plan %s signée, expire %s — l'avez-vous recalculé (planhash) ?\n", *planHash, exp.Format(time.RFC3339))
	return writeJSON0600(*out, map[string]string{
		"plan_hash":  *planHash,
		"expires_at": exp.Format(time.RFC3339),
		"signature":  hex.EncodeToString(sig),
	})
}

func cmdPlanRevoke(args []string) error {
	fs := flag.NewFlagSet("planrevoke", flag.ContinueOnError)
	planHash := fs.String("plan-hash", "", "hash du plan (hex 64)")
	ttl := fs.Int("ttl", 300, "durée de validité de la révocation, en secondes")
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
	sig := ed25519.Sign(key, pep.RevocationMessage(h, exp))
	fmt.Fprintf(os.Stderr, "quorumproof: révocation du plan %s signée, expire %s\n", *planHash, exp.Format(time.RFC3339))
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

// planFile est le corps de POST /v1/supervision/plan/submit : le sujet et les étapes que
// l'opérateur a reçus de l'agent (ou soumis lui-même). Même forme, même vocabulaire.
type planFile struct {
	Subject string `json:"subject"`
	Steps   []struct {
		Action    string `json:"action"`
		Resource  string `json:"resource"`
		ParamsHex string `json:"params_hex"` // hex des octets BRUTS ; "" = étape sans paramètres
	} `json:"steps"`
}

// readPlanFile décode STRICTEMENT le plan (champ inconnu, contenu après l'objet : refus) et
// applique les bornes du broker (pep.ValidatePlan).
func readPlanFile(path string) (string, []pep.PlanStep, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var pf planFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pf); err != nil {
		return "", nil, fmt.Errorf("-plan %s : %w", path, err)
	}
	if dec.More() {
		return "", nil, fmt.Errorf("-plan %s : contenu après l'objet JSON", path)
	}
	steps := make([]pep.PlanStep, 0, len(pf.Steps))
	for i, s := range pf.Steps {
		params, err := hex.DecodeString(s.ParamsHex)
		if err != nil {
			return "", nil, fmt.Errorf("-plan : étape %d : params_hex invalide", i+1)
		}
		steps = append(steps, pep.PlanStep{Action: s.Action, Resource: s.Resource, ParamsHash: pep.HashParams(params)})
	}
	if err := pep.ValidatePlan(pf.Subject, steps); err != nil {
		return "", nil, fmt.Errorf("-plan : %w (sujet 1..255 octets, 1..%d étapes, action 1..255, ressource 1..1024)", err, pep.MaxPlanSteps)
	}
	return pf.Subject, steps, nil
}

// parseSubmittedAt accepte un instant RFC3339 (le « submitted_at » de la vue d'arbitrage du
// broker) ou des secondes Unix. Le sceau n'en retient que les SECONDES (HashPlan : Unix()).
func parseSubmittedAt(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
		return time.Unix(n, 0), nil
	}
	return time.Time{}, errors.New("-submitted-at : RFC3339 (le submitted_at de la vue d'arbitrage) ou secondes Unix")
}

func cmdPlanHash(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("planhash", flag.ContinueOnError)
	cell := fs.String("cell", "", "identité de la cellule du broker (TBP_CELL_ID)")
	policy := fs.String("policy-id", "", "hash du bundle de règles de la cellule (TBP_POLICY_ID, hex 64)")
	submittedAt := fs.String("submitted-at", "", "instant de soumission : le submitted_at de la vue d'arbitrage (RFC3339) ou secondes Unix")
	planPath := fs.String("plan", "", "le plan en clair : le corps de plan/submit (subject + steps)")
	expect := fs.String("expect", "", "le plan_hash reçu du broker (hex 64) : exit 1 s'il diffère du hash recalculé")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cell == "" || *policy == "" || *submittedAt == "" || *planPath == "" {
		return errors.New("-cell, -policy-id, -submitted-at et -plan requis")
	}
	if len(*cell) > 255 {
		return errors.New("-cell : 255 octets au plus (u8 dans le sceau)")
	}
	pol, err := parsePlanHash(*policy)
	if err != nil {
		return errors.New("-policy-id : 64 caractères hexadécimaux (TBP_POLICY_ID)")
	}
	at, err := parseSubmittedAt(*submittedAt)
	if err != nil {
		return err
	}
	subject, steps, err := readPlanFile(*planPath)
	if err != nil {
		return err
	}
	h := pep.HashPlan(*cell, subject, at, pol, steps)
	got := hex.EncodeToString(h[:])

	// « ce qu'on voit est ce qu'on signe » : tout ce qui entre dans le sceau, en clair.
	fmt.Fprintf(out, "plan_hash=%s\ncell=%s\nsubject=%s\nsubmitted_at=%d (%s)\npolicy_id=%s\nsteps=%d\n",
		got, *cell, subject, at.Unix(), time.Unix(at.Unix(), 0).UTC().Format(time.RFC3339), *policy, len(steps))
	for i, st := range steps {
		fmt.Fprintf(out, "step %d: action=%s resource=%s params_hash=%s\n", i+1, st.Action, st.Resource, hex.EncodeToString(st.ParamsHash[:]))
	}
	if *expect != "" {
		want, err := parsePlanHash(*expect)
		if err != nil {
			return errors.New("-expect : 64 caractères hexadécimaux")
		}
		if want != h {
			return fmt.Errorf("plan_hash DIFFÉRENT : le broker annonce %s, le plan en clair donne %s — ne signez pas", *expect, got)
		}
		fmt.Fprintln(out, "conforme : le hash annoncé par le broker est celui du plan en clair")
	}
	return nil
}
