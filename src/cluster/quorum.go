// quorum.go — QuorumGate : co-signature k-of-n pour la classe W (§7.5,
// T29).
//
// §7.5 : « a single cell, adversarial or captured, cannot authorize the
// maximal irreversible » — une action classe W (survie) n'est admise que
// si k contrôleurs DISTINCTS l'ont co-signée. Le gate est une vérification
// PUREMENT LOCALE (Ed25519, §12) : aucun appel réseau, rien sur le chemin
// chaud (§9.1) — le demandeur collecte les co-signatures AVANT de se
// présenter (canal contrôleurs, hors du flux de décision).
//
// La preuve lie cryptographiquement (action, resource, policy_id, epoch,
// expiry) : une preuve faite pour une autre action, une autre époque ou
// un autre bundle de règles ne vaut rien. Toute décision — admission
// comme refus — laisse une feuille KindQuorum (§4.1, hash-only §6.2).
package cluster

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// DefaultMaxProofTTLSeconds borne la durée de vie d'une preuve de quorum
// (une co-signature n'est pas un blanc-seing : §7.2 même logique que le
// TTL d'époque).
const DefaultMaxProofTTLSeconds = 300

// Erreurs du quorum — codes machine stables.
var (
	ErrQuorumProofRequired = errors.New("cluster: classe W sans preuve de quorum (§7.5 : une cellule seule ne peut autoriser le maximal irréversible)")
	ErrQuorumBinding       = errors.New("cluster: preuve de quorum liée à une autre action/ressource/époque/policy")
	ErrQuorumProofExpired  = errors.New("cluster: preuve de quorum expirée")
	ErrQuorumProofTTLLong  = errors.New("cluster: preuve de quorum au-delà du TTL maximal")
	ErrQuorumInsufficient  = errors.New("cluster: quorum k-of-n non atteint (signatures distinctes insuffisantes)")
)

// QuorumStatement est le contenu signé par les contrôleurs : il lie
// l'action classée W à son contexte d'exécution exact. Struct à champs
// fixes ⇒ sérialisation canonique déterministe (§11.3) — même patron que
// EpochPayload.
type QuorumStatement struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	PolicyID string `json:"policy_id"` // hex, 32 octets — hash du bundle de règles (claim −1)
	Epoch    uint64 `json:"epoch"`
	Expiry   string `json:"expiry"` // RFC3339 UTC
}

// QuorumProof = statement + co-signatures k-of-n (format identique aux
// jetons d'époque : key_id indexe le manifest des contrôleurs).
type QuorumProof struct {
	Statement  QuorumStatement       `json:"statement"`
	Quorum     string                `json:"quorum"` // informatif — le gate revérifie
	Signatures []ControllerSignature `json:"signatures"`
}

// QuorumGateConfig paramètre le gate. Fail-closed dès la configuration.
type QuorumGateConfig struct {
	// CellID identifie la cellule dans les feuilles KindQuorum. Requis.
	CellID string
	// Salt ≥ 16 octets, reste chez le producteur (§6.2). Requis.
	Salt []byte
	// Leaves : chaque décision de quorum laisse une feuille (§4.1). Requis.
	Leaves LeafSink
	// Controllers : manifest des clés publiques des contrôleurs (T3,
	// hors-bande §3.2). Requis.
	Controllers map[int]ed25519.PublicKey
	// K est le quorum requis (k-of-n, §7.5). Requis, ≥ 1, ≤ n.
	K int
	// PolicyID est le hash du bundle de règles admis (claim −1) : une
	// preuve liée à un autre bundle est refusée. Requis.
	PolicyID [32]byte
	// MaxProofTTLSeconds borne la fraîcheur d'une preuve.
	// 0 ⇒ DefaultMaxProofTTLSeconds.
	MaxProofTTLSeconds int
	// Now : horloge NTS (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// QuorumGate vérifie les preuves k-of-n de la classe W. Sans état mutable
// après construction (la fraîcheur est lue sur l'horloge injectée) —
// sûr pour un usage concurrent. Implémente broker.QuorumGate.
type QuorumGate struct {
	cellID string
	salt   []byte
	leaves LeafSink
	ctrls  map[int]ed25519.PublicKey
	k      int
	policy [32]byte
	maxTTL time.Duration
	now    func() time.Time
	mu     sync.Mutex // sérialise feuilles + lecture d'horloge
}

// NewQuorumGate construit le gate — configuration complète exigée.
func NewQuorumGate(cfg QuorumGateConfig) (*QuorumGate, error) {
	if cfg.CellID == "" {
		return nil, errors.New("cluster: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(cfg.Salt) < 16 {
		return nil, errors.New("cluster: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if cfg.Leaves == nil {
		return nil, errors.New("cluster: couture feuilles requise (§4.1 : chaque décision de quorum laisse une feuille)")
	}
	if len(cfg.Controllers) == 0 {
		return nil, errors.New("cluster: manifest des contrôleurs requis (§7.5 : k-of-n)")
	}
	if cfg.K < 1 || cfg.K > len(cfg.Controllers) {
		return nil, fmt.Errorf("cluster: quorum incohérent : k=%d pour %d contrôleurs", cfg.K, len(cfg.Controllers))
	}
	maxTTL := cfg.MaxProofTTLSeconds
	if maxTTL == 0 {
		maxTTL = DefaultMaxProofTTLSeconds
	}
	if maxTTL < 1 {
		return nil, errors.New("cluster: MaxProofTTLSeconds négatif")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(cfg.Salt))
	copy(salt, cfg.Salt)
	ctrls := make(map[int]ed25519.PublicKey, len(cfg.Controllers))
	for id, pub := range cfg.Controllers {
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("cluster: pubkey contrôleur %d de %d octets", id, len(pub))
		}
		ctrls[id] = append(ed25519.PublicKey(nil), pub...)
	}
	return &QuorumGate{
		cellID: cfg.CellID, salt: salt, leaves: cfg.Leaves,
		ctrls: ctrls, k: cfg.K, policy: cfg.PolicyID,
		maxTTL: time.Duration(maxTTL) * time.Second, now: now,
	}, nil
}

// VerifyClassW vérifie une preuve de quorum pour une action classe W
// candidate (appelé par le broker APRÈS l'allow OPA, avant l'émission).
// Fail-closed : toute faute — preuve absente, mal liée, expirée, quorum
// insuffisant — est un refus TRACÉ (KindQuorum) ; une admission dont la
// feuille ne peut être écrite redevient un refus (pas de preuve, pas
// d'accès — même doctrine que T9/T33).
func (g *QuorumGate) VerifyClassW(ctx context.Context, proofJSON []byte, action, resource string, epoch uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(proofJSON) == 0 {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "quorum-proof-required", ErrQuorumProofRequired)
	}
	var proof QuorumProof
	if err := json.Unmarshal(proofJSON, &proof); err != nil {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "malformed-quorum-proof", ErrQuorumProofRequired)
	}
	st := proof.Statement

	// Liaison : la preuve doit désigner EXACTEMENT l'action traduite, la
	// ressource, l'époque courante et le bundle de règles de la cellule.
	policyHex := hex.EncodeToString(g.policy[:])
	if st.Action != action || st.Resource != resource || st.Epoch != epoch || st.PolicyID != policyHex {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "quorum-binding-mismatch", ErrQuorumBinding)
	}
	expiry, err := time.Parse(time.RFC3339, st.Expiry)
	if err != nil {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "expiry-unparseable", ErrQuorumProofExpired)
	}
	now := g.now()
	if !now.Before(expiry) {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "quorum-proof-expired", ErrQuorumProofExpired)
	}
	if expiry.After(now.Add(g.maxTTL)) {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "quorum-proof-ttl-out-of-range", ErrQuorumProofTTLLong)
	}

	// k signatures valides de contrôleurs DISTINCTS — le champ "quorum"
	// de la preuve n'est jamais cru (§7.5).
	canonical, err := json.Marshal(st)
	if err != nil {
		return g.refuseLocked(ctx, 0, 0, action, epoch, "statement-unserializable", ErrQuorumInsufficient)
	}
	seen := map[int]bool{}
	valid := 0
	for _, s := range proof.Signatures {
		if seen[s.KeyID] {
			return g.refuseLocked(ctx, int8(valid), int8(g.k), action, epoch, "quorum-duplicate-signer", ErrQuorumInsufficient)
		}
		seen[s.KeyID] = true
		pub, ok := g.ctrls[s.KeyID]
		if !ok {
			return g.refuseLocked(ctx, int8(valid), int8(g.k), action, epoch, "quorum-unknown-signer", ErrQuorumInsufficient)
		}
		sig, err := hex.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return g.refuseLocked(ctx, int8(valid), int8(g.k), action, epoch, "quorum-bad-signature", ErrQuorumInsufficient)
		}
		if !ed25519.Verify(pub, canonical, sig) {
			return g.refuseLocked(ctx, int8(valid), int8(g.k), action, epoch, "quorum-bad-signature", ErrQuorumInsufficient)
		}
		valid++
	}
	if valid < g.k {
		return g.refuseLocked(ctx, int8(valid), int8(g.k), action, epoch, "quorum-insufficient", ErrQuorumInsufficient)
	}
	return g.leafLocked(ctx, 0x01, int8(valid), int8(g.k), action, epoch, "ok")
}

// refuseLocked écrit la feuille de refus KindQuorum puis rend l'erreur —
// pas de décision de quorum sans preuve (§4.1).
func (g *QuorumGate) refuseLocked(ctx context.Context, valid, k int8, action string, epoch uint64, reason string, cause error) error {
	if err := g.leafLocked(ctx, 0x00, valid, k, action, epoch, reason); err != nil {
		return fmt.Errorf("cluster: refus quorum %s NON TRACÉ (feuille impossible) : %w", reason, err)
	}
	return fmt.Errorf("%w (%s)", cause, reason)
}

// leafLocked inscrit la feuille KindQuorum — record « TBPQ1 » :
//
//	"TBPQ1" ‖ verdict 1B ‖ valid i8 ‖ k i8 ‖ epoch u64 BE ‖ actionLen u8 ‖ action ‖ reasonLen u8 ‖ reason
//
// L'action est bornée (≤ 255, comme côté émission) ; hash-only (§6.2).
func (g *QuorumGate) leafLocked(ctx context.Context, verdict byte, valid, k int8, action string, epoch uint64, reason string) error {
	if len(action) > 255 {
		action = action[:255]
	}
	if len(reason) > 255 {
		reason = reason[:255]
	}
	rec := make([]byte, 0, 5+1+1+1+8+1+len(action)+1+len(reason))
	rec = append(rec, "TBPQ1"...)
	rec = append(rec, verdict, byte(valid), byte(k))
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], epoch)
	rec = append(rec, eb[:]...)
	rec = append(rec, byte(len(action)))
	rec = append(rec, action...)
	rec = append(rec, byte(len(reason)))
	rec = append(rec, reason...)
	_, err := g.leaves.Append(ctx, registry.Leaf{
		Kind:        registry.KindQuorum,
		CellID:      g.cellID,
		PayloadHash: registry.HashPayload(g.salt, rec),
		Timestamp:   g.now().UnixNano(),
	})
	return err
}
