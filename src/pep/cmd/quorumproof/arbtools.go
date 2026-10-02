package main

// arbtools.go — le geste d'opérateur de l'arbitrage HUMAIN des demandes dégradées (§4.5, #275 ; src/arbiter).
//
//	quorumproof arbid -subject S (-intent STR | -intent-file F)
//	    RECALCULE l'identifiant d'une demande (SHA-256 du sujet et de l'intention EXACTE) à partir de ce que
//	    l'agent a envoyé — au lieu de croire l'id que rend le broker. À faire AVANT arbdecide : on signe ce qu'on a
//	    recalculé. L'intention doit être octet pour octet celle de la demande (un saut de ligne final en plus, et
//	    c'est une autre demande).
//	quorumproof arbpresence -key FILE -out PRESENCE.json
//	    signe un battement de présence avec la clé d'OPÉRATEUR et écrit le corps à poster sur
//	    POST /v1/supervision/degraded/presence (socket d'administration de brokerd). À répéter plus souvent que
//	    TBP_ARBITRATION_PRESENCE_TTL_S : sans battement frais, aucun arbitre n'est « joignable ».
//	quorumproof arbdecide -id HEX64 -verdict approve|refuse [-ttl S] -key FILE -out DECISION.json
//	    signe la décision et écrit le corps à poster sur POST /v1/supervision/degraded/decide. Le ttl est le temps
//	    laissé à l'agent pour REPRÉSENTER sa demande ; l'approbation est à usage unique.
//
// Les messages signés (« TBAH1 », « TBAV1 ») sont distincts de l'approbation de plan (« TBPA1 ») et de la
// révocation (« TBPR1 ») : une signature ne vaut que pour l'acte pour lequel elle a été donnée.

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
)

func cmdArbID(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("arbid", flag.ContinueOnError)
	subject := fs.String("subject", "", "sujet (agent) de la demande")
	intent := fs.String("intent", "", "intention, telle qu'envoyée par l'agent (octets exacts)")
	intentFile := fs.String("intent-file", "", "fichier contenant l'intention EXACTE (alternative à -intent)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *subject == "" || (*intent == "") == (*intentFile == "") {
		return errors.New("-subject et EXACTEMENT un de -intent / -intent-file requis")
	}
	body := []byte(*intent)
	if *intentFile != "" {
		b, err := os.ReadFile(*intentFile)
		if err != nil {
			return err
		}
		body = b
	}
	id := arbiter.IntentID(*subject, body)
	fmt.Fprintln(stdout, hex.EncodeToString(id[:]))
	return nil
}

func cmdArbPresence(args []string) error {
	fs := flag.NewFlagSet("arbpresence", flag.ContinueOnError)
	keyFile := fs.String("key", "", "clé d'opérateur (fichier de graine ou de clé, hex)")
	out := fs.String("out", "", "corps JSON à écrire (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *out == "" {
		return errors.New("-key et -out requis")
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	at := time.Now().UTC().Truncate(time.Second)
	return writeJSON0600(*out, map[string]string{
		"at":        at.Format(time.RFC3339),
		"signature": hex.EncodeToString(ed25519.Sign(key, arbiter.PresenceMessage(at))),
	})
}

func cmdArbDecide(args []string) error {
	fs := flag.NewFlagSet("arbdecide", flag.ContinueOnError)
	id := fs.String("id", "", "identifiant de la demande (hex 64), RECALCULÉ avec arbid")
	verdict := fs.String("verdict", "", "approve | refuse")
	ttl := fs.Int("ttl", 300, "temps laissé à l'agent pour représenter sa demande, en secondes")
	keyFile := fs.String("key", "", "clé d'opérateur (fichier de graine ou de clé, hex)")
	out := fs.String("out", "", "corps JSON à écrire (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *keyFile == "" || *out == "" {
		return errors.New("-id, -verdict, -key et -out requis")
	}
	var v arbiter.Verdict
	switch *verdict {
	case "approve":
		v = arbiter.VerdictApprove
	case "refuse":
		v = arbiter.VerdictRefuse
	default:
		return errors.New(`-verdict : "approve" ou "refuse"`)
	}
	raw, err := hex.DecodeString(*id)
	if err != nil || len(raw) != 32 {
		return errors.New("-id : 64 caractères hexadécimaux (arbid)")
	}
	var idb [32]byte
	copy(idb[:], raw)
	if *ttl < int(arbiter.MinDecisionTTL/time.Second) || *ttl > int(arbiter.MaxEntryTTL/time.Second) {
		return fmt.Errorf("-ttl hors bornes [%d, %d] s", int(arbiter.MinDecisionTTL/time.Second), int(arbiter.MaxEntryTTL/time.Second))
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	exp := time.Now().Add(time.Duration(*ttl) * time.Second).UTC().Truncate(time.Second)
	sig := ed25519.Sign(key, arbiter.DecisionMessage(idb, v, exp))
	fmt.Fprintf(os.Stderr, "quorumproof: décision %s de la demande %s signée, expire %s — l'avez-vous recalculée (arbid) ?\n", *verdict, *id, exp.Format(time.RFC3339))
	return writeJSON0600(*out, map[string]string{
		"id":         *id,
		"verdict":    *verdict,
		"expires_at": exp.Format(time.RFC3339),
		"signature":  hex.EncodeToString(sig),
	})
}
