package main

// arbitration.go — l'arbitrage HUMAIN des demandes dégradées (§4.5, #275 suite) : voir src/arbiter.
//
// OPT-IN, et seulement AVEC la garde (TBP_TRANSLATOR_GUARD=1) : sans garde, aucun mode dégradé n'existe.
//
//	TBP_ARBITRATION                  « 1 » active ; absent ou « 0 » : un système standard est refusé en mode dégradé
//	TBP_ARBITRATION_PRESENCE_TTL_S   durée de validité d'un battement d'opérateur, [10, 600], défaut 60
//	TBP_ARBITRATION_ENTRY_TTL_S      durée de vie d'une demande en file ET borne d'une décision, [60, 3600], défaut 600
//	TBP_ARBITRATION_MAX_PENDING      taille de la file, [1, 4096], défaut 256
//
// Le trousseau d'opérateurs est celui du store de contrats (TBP_OPERATOR_KEYS_FILE, déjà MESURÉ par le
// provisionnement). Un TBP_ARBITRATION_* sans TBP_ARBITRATION=1 est une incohérence : refus de démarrer.
//
// Plan d'ADMINISTRATION (socket admin : l'accès EST le contrôle d'accès ; chaque acte est de toute façon signé) :
//
//	POST /v1/supervision/degraded/presence  {"at": RFC3339, "signature": hex}        battement de présence
//	GET  /v1/supervision/degraded                                                    présence + file (jamais l'intention)
//	POST /v1/supervision/degraded/decide    {"id": hex, "verdict": "approve"|"refuse", "expires_at": RFC3339, "signature": hex}

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
)

type arbitrationConfig struct {
	enabled     bool
	presenceTTL time.Duration
	entryTTL    time.Duration
	maxPending  int
}

// arbitrationFromEnv lit et valide TBP_ARBITRATION* — fail-closed.
func arbitrationFromEnv(getenv func(string) string, guardEnabled bool) (arbitrationConfig, error) {
	cfg := arbitrationConfig{presenceTTL: arbiter.DefaultPresenceTTL, entryTTL: arbiter.DefaultEntryTTL, maxPending: arbiter.DefaultMaxEntries}
	knobs := []string{"TBP_ARBITRATION_PRESENCE_TTL_S", "TBP_ARBITRATION_ENTRY_TTL_S", "TBP_ARBITRATION_MAX_PENDING"}
	switch v := getenv("TBP_ARBITRATION"); v {
	case "", "0":
		for _, k := range knobs {
			if getenv(k) != "" {
				return cfg, fmt.Errorf("%s sans TBP_ARBITRATION=1 — configuration incohérente", k)
			}
		}
		return cfg, nil
	case "1":
	default:
		return cfg, fmt.Errorf("TBP_ARBITRATION invalide %q (« 1 » pour activer, « 0 » ou absent sinon)", v)
	}
	if !guardEnabled {
		return cfg, errors.New("TBP_ARBITRATION=1 sans TBP_TRANSLATOR_GUARD=1 — configuration incohérente (l'arbitrage ne sert qu'en mode dégradé)")
	}
	cfg.enabled = true
	intRange := func(name string, lo, hi int) (int, bool, error) {
		s := getenv(name)
		if s == "" {
			return 0, false, nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < lo || n > hi {
			return 0, false, fmt.Errorf("%s invalide %q (entier dans [%d, %d] attendu)", name, s, lo, hi)
		}
		return n, true, nil
	}
	if n, ok, err := intRange("TBP_ARBITRATION_PRESENCE_TTL_S", int(arbiter.MinPresenceTTL/time.Second), int(arbiter.MaxPresenceTTL/time.Second)); err != nil {
		return cfg, err
	} else if ok {
		cfg.presenceTTL = time.Duration(n) * time.Second
	}
	if n, ok, err := intRange("TBP_ARBITRATION_ENTRY_TTL_S", int(arbiter.MinEntryTTL/time.Second), int(arbiter.MaxEntryTTL/time.Second)); err != nil {
		return cfg, err
	} else if ok {
		cfg.entryTTL = time.Duration(n) * time.Second
	}
	if n, ok, err := intRange("TBP_ARBITRATION_MAX_PENDING", 1, arbiter.MaxMaxEntries); err != nil {
		return cfg, err
	} else if ok {
		cfg.maxPending = n
	}
	return cfg, nil
}

// Corps du plan d'administration — décodés STRICTEMENT (decodeStrictJSON, #274).
type arbPresenceRequest struct {
	At        time.Time `json:"at"`
	Signature string    `json:"signature"` // hex Ed25519 sur arbiter.PresenceMessage(cellule, at)
}

type arbDecideRequest struct {
	ID        string    `json:"id"`         // hex, 32 octets — arbiter.IntentID
	Verdict   string    `json:"verdict"`    // "approve" | "refuse"
	ExpiresAt time.Time `json:"expires_at"` // RFC3339 — entre dans DecisionMessage
	Signature string    `json:"signature"`  // hex Ed25519 sur arbiter.DecisionMessage(cellule, id, ticket, verdict, expires_at)
}

type arbEntryView struct {
	ID        string `json:"id"`
	Ticket    string `json:"ticket"` // hex, 16 octets — à signer avec la décision (une mise en file = un ticket)
	Subject   string `json:"subject"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type arbStatusView struct {
	Reachable bool           `json:"reachable"`
	Pending   []arbEntryView `json:"pending"`
}
