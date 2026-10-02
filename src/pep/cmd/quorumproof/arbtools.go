package main

// arbtools.go — le geste d'opérateur de l'arbitrage HUMAIN des demandes dégradées (§4.5, #275 ; src/arbiter).
//
//	quorumproof arbid -subject S (-intent STR | -intent-file F)
//	    RECALCULE l'identifiant d'une demande (SHA-256 du sujet et de l'intention EXACTE) à partir de ce que
//	    l'agent a envoyé — au lieu de croire l'id que rend le broker. À faire AVANT arbdecide : on signe ce qu'on a
//	    recalculé. L'intention doit être octet pour octet celle de la demande (un saut de ligne final en plus, et
//	    c'est une autre demande).
//	quorumproof arbpresence -cell CELLULE -key FILE -out PRESENCE.json
//	    signe un battement de présence POUR CETTE CELLULE avec la clé d'OPÉRATEUR et écrit le corps à poster sur
//	    POST /v1/supervision/degraded/presence (socket d'administration de brokerd). À répéter plus souvent que
//	    TBP_ARBITRATION_PRESENCE_TTL_S : sans battement frais, aucun arbitre n'est « joignable ».
//	quorumproof arbdecide -cell CELLULE -id HEX64 -ticket HEX32 -verdict approve|refuse [-ttl S] -key FILE -out DECISION.json
//	    signe la décision et écrit le corps à poster sur POST /v1/supervision/degraded/decide. Le ttl est le temps
//	    laissé à l'agent pour REPRÉSENTER sa demande ; l'approbation est à usage unique. -ticket est celui de la
//	    mise en file (GET /v1/supervision/degraded, champ « ticket ») : la signature ne vaut que pour CETTE mise en
//	    file de CETTE cellule — une même demande remise en file plus tard exige une nouvelle signature.
//
// Les messages signés (« TBAH2 », « TBAV2 », liés à la cellule) sont distincts de l'approbation de plan (« TBPA1 ») et de la
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
	cell := fs.String("cell", "", "identité de la cellule (TBP_CELL_ID de brokerd) pour laquelle on bat")
	keyFile := fs.String("key", "", "clé d'opérateur (fichier de graine ou de clé, hex)")
	out := fs.String("out", "", "corps JSON à écrire (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cell == "" || *keyFile == "" || *out == "" {
		return errors.New("-cell, -key et -out requis")
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	at := time.Now().UTC().Truncate(time.Second)
	return writeJSON0600(*out, map[string]string{
		"at":        at.Format(time.RFC3339),
		"signature": hex.EncodeToString(ed25519.Sign(key, arbiter.PresenceMessage(*cell, at))),
	})
}

func cmdArbDecide(args []string) error {
	fs := flag.NewFlagSet("arbdecide", flag.ContinueOnError)
	cell := fs.String("cell", "", "identité de la cellule (TBP_CELL_ID de brokerd) pour laquelle on décide")
	ticket := fs.String("ticket", "", "ticket de la mise en file (hex 32), lu dans GET /v1/supervision/degraded")
	id := fs.String("id", "", "identifiant de la demande (hex 64), RECALCULÉ avec arbid")
	verdict := fs.String("verdict", "", "approve | refuse")
	ttl := fs.Int("ttl", 300, "temps laissé à l'agent pour représenter sa demande, en secondes")
	keyFile := fs.String("key", "", "clé d'opérateur (fichier de graine ou de clé, hex)")
	out := fs.String("out", "", "corps JSON à écrire (0600)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cell == "" || *id == "" || *ticket == "" || *keyFile == "" || *out == "" {
		return errors.New("-cell, -id, -ticket, -verdict, -key et -out requis")
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
	traw, err := hex.DecodeString(*ticket)
	if err != nil || len(traw) != 16 {
		return errors.New("-ticket : 32 caractères hexadécimaux (champ « ticket » de GET /v1/supervision/degraded)")
	}
	var tk arbiter.Ticket
	copy(tk[:], traw)
	if *ttl < int(arbiter.MinDecisionTTL/time.Second) || *ttl > int(arbiter.MaxEntryTTL/time.Second) {
		return fmt.Errorf("-ttl hors bornes [%d, %d] s", int(arbiter.MinDecisionTTL/time.Second), int(arbiter.MaxEntryTTL/time.Second))
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	exp := time.Now().Add(time.Duration(*ttl) * time.Second).UTC().Truncate(time.Second)
	sig := ed25519.Sign(key, arbiter.DecisionMessage(*cell, idb, tk, v, exp))
	fmt.Fprintf(os.Stderr, "quorumproof: décision %s de la demande %s signée, expire %s — l'avez-vous recalculée (arbid) ?\n", *verdict, *id, exp.Format(time.RFC3339))
	return writeJSON0600(*out, map[string]string{
		"id":         *id,
		"verdict":    *verdict,
		"expires_at": exp.Format(time.RFC3339),
		"signature":  hex.EncodeToString(sig),
	})
}
