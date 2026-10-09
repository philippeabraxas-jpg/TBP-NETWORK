package main

// operators.go — le trousseau d'opérateurs et les rôles de ses clés.
//
// Jusqu'ici, toute clé du trousseau pouvait tout faire : approuver un plan, le révoquer, trancher une demande
// dégradée. Celui qui détient la clé d'une astreinte de nuit pouvait donc approuver un plan critique. Les rôles
// séparent ces gestes, et la séparation suit la règle « restreindre n'est pas élargir » : approuver ÉLARGIT ce que
// la cellule autorise, révoquer et refuser RESTREIGNENT. Une personne peut tenir le droit de couper sans tenir
// celui d'approuver.
//
// Deux formes de fichier (TBP_OPERATOR_KEYS_FILE, mesuré par le témoin de provisionnement) :
//
//   - historique : ["pubkey_ed25519_hex", …] — chaque clé tient TOUS les rôles (aucune séparation) ;
//   - avec rôles : [{"key": "pubkey_ed25519_hex", "roles": ["submit", "approve", "revoke", "arbitrate"]}, …].
//
// Les deux formes ne se mélangent pas dans un même fichier : une chaîne égarée dans un fichier à rôles donnerait
// tous les rôles à une clé, en silence. Un rôle inconnu, une liste de rôles vide ou répétée, un champ inconnu : refus
// au chargement. Dans la forme à rôles, approve, revoke et arbitrate doivent chacun être tenus par au moins une clé : un
// acte que personne ne peut signer est dit à voix haute au démarrage, pas découvert le jour où il faut couper. Le rôle
// submit n'est exigé que quand la cellule sépare les tâches (voir plan_approvals.go : checkSeparatedDuties).
//
// Les règles vivent ici et dans ContractStore et la file d'arbitrage, donc pour tout chemin qui atteint le socket
// d'administration : une variante locale plus faible n'existe pas.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/strictjson"
)

const (
	roleSubmit    = "submit"    // soumettre un plan SIGNÉ (plan/submit)
	roleApprove   = "approve"   // approuver un plan (plan/approve)
	roleRevoke    = "revoke"    // révoquer un plan (plan/revoke)
	roleArbitrate = "arbitrate" // présence et décision sur les demandes dégradées
)

var operatorRoles = []string{roleSubmit, roleApprove, roleRevoke, roleArbitrate}

// operatorKeyring est le trousseau chargé : toutes les clés, et le sous-ensemble qui tient chaque rôle.
type operatorKeyring struct {
	All        []ed25519.PublicKey
	Submitters []ed25519.PublicKey
	Approvers  []ed25519.PublicKey
	Revokers   []ed25519.PublicKey
	Arbiters   []ed25519.PublicKey
}

type operatorEntry struct {
	Key   string   `json:"key"`
	Roles []string `json:"roles"`
}

// loadOperatorKeyring charge le trousseau d'opérateurs (T30) : au moins une clé, sans doublon.
func loadOperatorKeyring(path string) (operatorKeyring, error) {
	var ring operatorKeyring
	data, err := os.ReadFile(path)
	if err != nil {
		return ring, fmt.Errorf("clés d'opérateurs: %w", err)
	}
	var raw []json.RawMessage
	if err := strictjson.Decode(data, &raw); err != nil {
		return ring, fmt.Errorf("clés d'opérateurs JSON: %w", err)
	}
	if len(raw) == 0 {
		return ring, errors.New("clés d'opérateurs : liste vide — le store de contrats exige ≥ 1 opérateur (T30)")
	}
	withRoles := bytes.HasPrefix(bytes.TrimSpace(raw[0]), []byte("{"))
	// le doublon se juge sur la clé DÉCODÉE : « AA… » et « aa… » sont la même clé (revue tierce 4.4) —
	// comparer le texte laissait une clé compter pour deux opérateurs
	seen := map[string]bool{}
	for i, item := range raw {
		var pubHex string
		var roles []string
		trimmed := bytes.TrimSpace(item)
		switch {
		case withRoles && bytes.HasPrefix(trimmed, []byte("{")):
			var e operatorEntry
			if err := strictjson.Decode(item, &e); err != nil {
				return ring, fmt.Errorf("clé d'opérateur %d : %w", i+1, err)
			}
			if e.Key == "" || len(e.Roles) == 0 {
				return ring, fmt.Errorf("clé d'opérateur %d : « key » et « roles » (au moins un rôle) sont requis", i+1)
			}
			pubHex, roles = e.Key, e.Roles
		case !withRoles && bytes.HasPrefix(trimmed, []byte(`"`)):
			if err := json.Unmarshal(item, &pubHex); err != nil {
				return ring, fmt.Errorf("clé d'opérateur %d illisible : %w", i+1, err)
			}
			roles = operatorRoles // forme historique : tous les rôles
		default:
			return ring, errors.New("clés d'opérateurs : ne pas mélanger la liste de clés (chaînes) et la liste à rôles (objets) dans un même fichier")
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return ring, fmt.Errorf("clé d'opérateur %q illisible (Ed25519 hex)", pubHex)
		}
		if seen[string(pub)] {
			return ring, fmt.Errorf("clé d'opérateur %q en double (même clé, casse hexadécimale éventuellement différente)", pubHex)
		}
		seen[string(pub)] = true
		key := ed25519.PublicKey(pub)
		ring.All = append(ring.All, key)
		held := map[string]bool{}
		for _, r := range roles {
			if held[r] {
				return ring, fmt.Errorf("clé d'opérateur %q : le rôle %q est répété", pubHex, r)
			}
			held[r] = true
			switch r {
			case roleSubmit:
				ring.Submitters = append(ring.Submitters, key)
			case roleApprove:
				ring.Approvers = append(ring.Approvers, key)
			case roleRevoke:
				ring.Revokers = append(ring.Revokers, key)
			case roleArbitrate:
				ring.Arbiters = append(ring.Arbiters, key)
			default:
				return ring, fmt.Errorf("clé d'opérateur %q : rôle inconnu %q (attendus : %v)", pubHex, r, operatorRoles)
			}
		}
	}
	for role, keys := range map[string][]ed25519.PublicKey{roleApprove: ring.Approvers, roleRevoke: ring.Revokers, roleArbitrate: ring.Arbiters} {
		if len(keys) == 0 {
			return ring, fmt.Errorf("clés d'opérateurs : aucune clé n'a le rôle %q — cet acte serait impossible", role)
		}
	}
	return ring, nil
}
