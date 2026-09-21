// Package cluster implante le fencing du cluster TBP (T29, §7.2–§7.5) :
// époques à autorité unique, quorum k-of-n pour la classe W, promotion
// miroir/canari par preuve de réception.
//
// Doctrine (§7.1) : une cellule est du bétail, jamais une racine de
// confiance. Ce package ne DÉTIENT aucune clé : les jetons d'époque sont
// signés m-of-n par les contrôleurs (HSM, cérémonie hors-bande — la
// genèse epoch 0 vient de scripts/genesis, T3) ; le tracker ne fait que
// VÉRIFIER et appliquer mécaniquement. Fail-closed partout (§1) : pas
// d'époque valide ⇒ la cellule ne sert pas ; équivoque ⇒ refus + alarme ;
// budget de bascule épuisé ⇒ humain (§7.2 « max N bascules/heure, ensuite
// humain »).
//
// Continuité T3 : le format du jeton d'époque reprend exactement le
// layout JSON de scripts/genesis (payload (n, authority, issued_at,
// ttl_s) + signatures key_id/sig). Deux champs OPTIONNELS sont ajoutés
// (omitempty — l'epoch 0 de la genèse, sans eux, s'importe tel quel) :
//
//	mode   "auto" | "manual" — absent ⇒ "manual" (la genèse est une
//	       cérémonie procédurale, pas un failover automatique) ;
//	roster liste des cellules survivantes — présent ⇒ RÉVOCATION (§7.3) :
//	       les cellules membres absentes du roster passent en quarantaine.
//
// Règle d'autorité unique (§7.2) : N strictement monotone ; seule la
// cellule détentrice du plus haut N vérifié sert ; l'ancien jeton expire
// seul (TTL borné) ; si le nouveau jeton arrive AVANT l'expiration de
// l'ancien, la nouvelle autorité n'entre en fonction qu'à l'expiration de
// l'ancienne (notBefore) — jamais de fenêtre de double autorité, au prix
// d'un trou de service borné (fail-closed). Toute décision — acceptation,
// refus, équivoque, révocation, budget épuisé — laisse une feuille
// KindEpoch (§4.1) : hash-only, le sel ≥ 16 octets reste chez le
// producteur (§6.2).
package cluster

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Défauts et bornes du fencing (§7.2 : TTL ~60 s ; « max N bascules/heure »
// est un paramètre nommé de la spec — ici une option, pas une constante).
const (
	// DefaultMaxAutoFailoversPerHour borne les bascules AUTOMATIQUES
	// (mode=auto) par fenêtre glissante d'une heure ; au-delà, seul un
	// epoch mode=manual (canal séparé pré-autorisé, §7.2) est accepté.
	DefaultMaxAutoFailoversPerHour = 3
	// DefaultMinTTLSeconds / DefaultMaxTTLSeconds bornent le TTL déclaré
	// (§7.2 ~60 s) : un TTL trop court rend la bascule instable, un TTL
	// trop long allonge la fenêtre où une autorité compromise sert encore.
	DefaultMinTTLSeconds = 10
	DefaultMaxTTLSeconds = 300
	// maxIssuedAtSkew tolère la dérive d'horloge entre contrôleurs (NTS,
	// §6.2) : un jeton « émis » plus de 5 s dans le futur est refusé.
	maxIssuedAtSkew = 5 * time.Second

	// Modes de bascule (champ optionnel mode du payload).
	ModeAuto   = "auto"   // failover pré-autorisé — compté dans le budget
	ModeManual = "manual" // cérémonie / canal séparé — jamais compté, jamais borné
)

// Événements portés par les feuilles KindEpoch (octet event du record).
const (
	epochEventAccept     byte = 1 // bascule acceptée (nouvelle autorité)
	epochEventRefuse     byte = 2 // jeton refusé (raison dans le record)
	epochEventEquivocate byte = 3 // équivoque : deux jetons valides, même N
	epochEventRevoke     byte = 4 // révocation : roster réduit (§7.3)
	epochEventBudget     byte = 5 // budget de bascules auto épuisé
)

// Erreurs de fencing — codes machine stables (consommés par T34/T14).
var (
	ErrNoEpoch              = errors.New("cluster: aucune époque — genèse non importée, la cellule ne sert pas (fail-closed)")
	ErrEpochNotYetEffective = errors.New("cluster: époque basculée mais pas encore effective — attente d'expiration de l'ancienne autorité")
	ErrEpochExpired         = errors.New("cluster: époque expirée — aucune autorité valide, la cellule ne sert pas (fail-closed)")
	ErrNotAuthority         = errors.New("cluster: cette cellule n'est pas l'autorité de l'époque courante")
	ErrCellQuarantined      = errors.New("cluster: cellule en quarantaine (§7.3) — inspectable, ne sert pas")
)

// LeafSink est la couture vers le registre de la cellule (T7) — même
// signature que pep.LeafSink ; *registry.CellLog l'implémente nativement.
type LeafSink interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// EpochPayload est le contenu signé du jeton d'époque (§7.2 : (N,
// autorité, TTL ~60 s)). Layout identique à scripts/genesis (T3) — struct
// à champs fixes ⇒ sérialisation JSON déterministe (profil §11.3) ; les
// champs ajoutés sont omitempty pour que l'epoch 0 de la genèse (sans
// eux) se vérifie tel quel.
type EpochPayload struct {
	N          int      `json:"n"`
	Authority  string   `json:"authority"`
	IssuedAt   string   `json:"issued_at"` // RFC3339 UTC
	TTLSeconds int      `json:"ttl_s"`
	Mode       string   `json:"mode,omitempty"`   // absent ⇒ ModeManual
	Roster     []string `json:"roster,omitempty"` // présent ⇒ révocation §7.3
}

// ControllerSignature est une signature Ed25519 d'un contrôleur du quorum
// — même format que scripts/genesis (key_id indexe le manifest des clés).
type ControllerSignature struct {
	KeyID int    `json:"key_id"`
	Sig   string `json:"sig"` // hex Ed25519 (64 octets)
}

// EpochToken = payload + signatures du quorum (artefact transporté sur le
// canal de bascule ; sa forme canonique signée est le payload seul).
type EpochToken struct {
	Payload    EpochPayload          `json:"payload"`
	Quorum     string                `json:"quorum"` // ex. "2-of-3" — informatif, le tracker revérifie
	Signatures []ControllerSignature `json:"signatures"`
}

// canonicalPayload sérialise le payload signé — exactement comme
// scripts/genesis (json.Marshal sur struct à ordre de champs fixe).
func canonicalPayload(p EpochPayload) ([]byte, error) {
	return json.Marshal(p)
}

// payloadHash identifie un jeton pour la détection d'équivoque (deux
// jetons au même N avec des payloads différents = faute byzantine).
func payloadHash(p EpochPayload) ([32]byte, error) {
	c, err := canonicalPayload(p)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(c), nil
}

// TrackerConfig paramètre le tracker d'époques d'UNE cellule. Fail-closed
// dès la configuration : toute couture manquante = erreur (même patron
// que broker.BrokerOptions).
type TrackerConfig struct {
	// CellID identifie la cellule qui fait tourner ce tracker ; elle doit
	// être membre du cluster. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre : chaque décision de fencing laisse
	// une feuille KindEpoch (§4.1). Requis.
	Leaves LeafSink
	// Controllers est le manifest des clés publiques Ed25519 des
	// contrôleurs (key_id → pubkey), distribué hors-bande à la genèse
	// (T3) — la légitimité reste hors protocole (§3.2). Requis.
	Controllers map[int]ed25519.PublicKey
	// Quorum est m de m-of-n (§7.2) — le tracker revérifie toujours les
	// signatures, le champ "quorum" du jeton n'est qu'informatif. Requis.
	Quorum int
	// Members est la liste des cellules autorisées à porter l'autorité.
	// Requis.
	Members []string
	// MaxAutoFailoversPerHour borne les bascules mode=auto (§7.2 « max N
	// bascules/heure, ensuite humain »). 0 ⇒ DefaultMaxAutoFailoversPerHour.
	MaxAutoFailoversPerHour int
	// MinTTLSeconds / MaxTTLSeconds bornent le TTL des jetons acceptés.
	// 0 ⇒ DefaultMinTTLSeconds / DefaultMaxTTLSeconds.
	MinTTLSeconds int
	MaxTTLSeconds int
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
	// OnAlarm est la couture d'alarme vers T14 : équivoque, budget épuisé.
	// Nil ⇒ pas d'alarme (le refus reste fail-closed et laisse sa feuille).
	OnAlarm func(reason string)
}

// epochState est l'époque courante vérifiée.
type epochState struct {
	payload   EpochPayload
	hash      [32]byte // hash du payload canonique (équivoque)
	issuedAt  time.Time
	expiresAt time.Time // issuedAt + ttl — l'ancien expire seul (§7.2)
	notBefore time.Time // max(issuedAt, expiration de l'ép. précédente si encore valide à l'acceptation)
}

// Tracker est la machine à états d'époques d'une cellule : il VÉRIFIE les
// jetons m-of-n, applique la monotonie de N, fait expirer l'ancienne
// autorité seule, borne les bascules automatiques et met en quarantaine
// les cellules révoquées. Il implémente broker.EpochProvider
// (CurrentEpoch() (uint64, error)) : sans époque valide dont CETTE
// cellule est l'autorité, il ne rend pas d'époque — la cellule ne sert
// pas (§7.2 « seul le détenteur sert »).
type Tracker struct {
	cellID    string
	salt      []byte
	leaves    LeafSink
	ctrls     map[int]ed25519.PublicKey
	quorum    int
	members   map[string]bool
	maxAutoHr int
	minTTL    int
	maxTTL    int
	now       func() time.Time
	onAlarm   func(string)

	mu          sync.Mutex
	current     *epochState
	quarantined map[string]bool
	autoLog     []time.Time // acceptations mode=auto dans l'heure glissante — borné par maxAutoHr (§4.3)
}

// NewTracker construit le tracker. Fail-closed : configuration complète
// exigée, CellID membre, quorum cohérent avec le manifest.
func NewTracker(cfg TrackerConfig) (*Tracker, error) {
	if cfg.CellID == "" {
		return nil, errors.New("cluster: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(cfg.Salt) < 16 {
		return nil, errors.New("cluster: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if cfg.Leaves == nil {
		return nil, errors.New("cluster: couture feuilles requise (§4.1 : chaque bascule laisse une feuille)")
	}
	if len(cfg.Controllers) == 0 {
		return nil, errors.New("cluster: manifest des contrôleurs requis (§7.2 : m-of-n)")
	}
	if cfg.Quorum < 1 || cfg.Quorum > len(cfg.Controllers) {
		return nil, fmt.Errorf("cluster: quorum incohérent : m=%d pour %d contrôleurs", cfg.Quorum, len(cfg.Controllers))
	}
	if len(cfg.Members) == 0 {
		return nil, errors.New("cluster: liste des cellules membres requise (§7.2)")
	}
	members := make(map[string]bool, len(cfg.Members))
	for _, m := range cfg.Members {
		if m == "" {
			return nil, errors.New("cluster: cellID membre vide")
		}
		members[m] = true
	}
	if !members[cfg.CellID] {
		return nil, fmt.Errorf("cluster: %q n'est pas membre du cluster — un tracker hors roster ne sert jamais", cfg.CellID)
	}
	maxAuto := cfg.MaxAutoFailoversPerHour
	if maxAuto == 0 {
		maxAuto = DefaultMaxAutoFailoversPerHour
	}
	if maxAuto < 0 {
		return nil, errors.New("cluster: MaxAutoFailoversPerHour négatif")
	}
	minTTL, maxTTL := cfg.MinTTLSeconds, cfg.MaxTTLSeconds
	if minTTL == 0 {
		minTTL = DefaultMinTTLSeconds
	}
	if maxTTL == 0 {
		maxTTL = DefaultMaxTTLSeconds
	}
	if minTTL < 1 || maxTTL < minTTL {
		return nil, fmt.Errorf("cluster: bornes TTL incohérentes : min=%d max=%d", minTTL, maxTTL)
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
			return nil, fmt.Errorf("cluster: pubkey contrôleur %d de %d octets — %d attendus", id, len(pub), ed25519.PublicKeySize)
		}
		ctrls[id] = append(ed25519.PublicKey(nil), pub...)
	}
	return &Tracker{
		cellID: cfg.CellID, salt: salt, leaves: cfg.Leaves,
		ctrls: ctrls, quorum: cfg.Quorum, members: members,
		maxAutoHr: maxAuto, minTTL: minTTL, maxTTL: maxTTL,
		now: now, onAlarm: cfg.OnAlarm,
		quarantined: map[string]bool{},
	}, nil
}

// Accept vérifie et applique un jeton d'époque présenté sur le canal de
// bascule. Toute issue — acceptation comme refus — laisse une feuille
// KindEpoch (§4.1) ; un échec d'écriture de feuille bascule l'acceptation
// en refus (pas de preuve, pas de bascule — même doctrine que T9/T33).
//
// Ordre strict : forme → TTL borné → futur borné → autorité membre →
// signatures m-of-n distinctes → monotonie de N → équivoque → budget auto
// → révocation éventuelle → calcul notBefore → bascule.
func (t *Tracker) Accept(ctx context.Context, tokenJSON []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var tok EpochToken
	if err := json.Unmarshal(tokenJSON, &tok); err != nil {
		return t.refuseLocked(ctx, 0, "", "malformed-epoch-token")
	}
	p := tok.Payload
	if p.N < 0 || p.Authority == "" || len(p.Authority) > 255 {
		return t.refuseLocked(ctx, p.N, p.Authority, "schema-violation")
	}
	if p.TTLSeconds < t.minTTL || p.TTLSeconds > t.maxTTL {
		return t.refuseLocked(ctx, p.N, p.Authority, "ttl-out-of-range")
	}
	issuedAt, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil {
		return t.refuseLocked(ctx, p.N, p.Authority, "issued-at-unparseable")
	}
	now := t.now()
	if issuedAt.After(now.Add(maxIssuedAtSkew)) {
		return t.refuseLocked(ctx, p.N, p.Authority, "epoch-from-future")
	}
	if !t.members[p.Authority] {
		return t.refuseLocked(ctx, p.N, p.Authority, "authority-not-member")
	}
	mode := p.Mode
	if mode == "" {
		mode = ModeManual // la genèse est une cérémonie (§7.2)
	}
	if mode != ModeAuto && mode != ModeManual {
		return t.refuseLocked(ctx, p.N, p.Authority, "unknown-mode")
	}
	if err := t.verifyQuorumLocked(p, tok.Signatures); err != nil {
		return t.refuseLocked(ctx, p.N, p.Authority, "epoch-quorum-insufficient")
	}
	hash, err := payloadHash(p)
	if err != nil {
		return t.refuseLocked(ctx, p.N, p.Authority, "payload-unserializable")
	}

	if t.current != nil {
		switch {
		case p.N < t.current.payload.N:
			// Rejeu d'un vieux jeton : N strictement monotone (§7.2).
			return t.refuseLocked(ctx, p.N, p.Authority, "epoch-regression")
		case p.N == t.current.payload.N:
			if hash == t.current.hash {
				return nil // re-livraison du MÊME jeton : idempotent, événement déjà tracé
			}
			// Deux jetons valides au même N : faute byzantine de quorum.
			if t.onAlarm != nil {
				t.onAlarm("epoch-equivocation")
			}
			return t.refuseLocked(ctx, p.N, p.Authority, "epoch-equivocation", epochEventEquivocate)
		}
	}

	if mode == ModeAuto && !t.consumeAutoBudgetLocked(now) {
		// §7.2 : « max N bascules/heure, ensuite humain » — un epoch
		// manuel (canal séparé pré-autorisé) reste accepté.
		if t.onAlarm != nil {
			t.onAlarm("failover-budget-exhausted")
		}
		return t.refuseLocked(ctx, p.N, p.Authority, "failover-budget-exhausted", epochEventBudget)
	}

	// Révocation (§7.3) : le roster réduit est partie intégrante du
	// payload signé — la mise en quarantaine est une décision DU QUORUM,
	// jamais du tracker.
	event := epochEventAccept
	var revoked []string
	if p.Roster != nil {
		if len(p.Roster) == 0 {
			return t.refuseLocked(ctx, p.N, p.Authority, "empty-roster")
		}
		inRoster := make(map[string]bool, len(p.Roster))
		for _, c := range p.Roster {
			if !t.members[c] {
				return t.refuseLocked(ctx, p.N, p.Authority, "roster-unknown-cell")
			}
			inRoster[c] = true
		}
		if !inRoster[p.Authority] {
			// Une cellule qu'on révoque ne peut pas porter la bascule.
			return t.refuseLocked(ctx, p.N, p.Authority, "authority-not-in-roster")
		}
		for m := range t.members {
			if !inRoster[m] && !t.quarantined[m] {
				revoked = append(revoked, m)
			}
		}
		event = epochEventRevoke
	}

	// Jamais de fenêtre de double autorité : si l'ancienne époque est
	// encore valide à l'instant de la bascule, la nouvelle n'entre en
	// fonction qu'à son expiration (trou de service borné, fail-closed).
	notBefore := issuedAt
	if t.current != nil && now.Before(t.current.expiresAt) && t.current.expiresAt.After(notBefore) {
		notBefore = t.current.expiresAt
	}

	t.current = &epochState{
		payload:   p,
		hash:      hash,
		issuedAt:  issuedAt,
		expiresAt: issuedAt.Add(time.Duration(p.TTLSeconds) * time.Second),
		notBefore: notBefore,
	}
	for _, c := range revoked {
		t.quarantined[c] = true // quarantaine, pas meurtre : l'état reste lisible (Status)
	}
	return t.leafLocked(ctx, event, p.N, p.Authority, "ok")
}

// verifyQuorumLocked revérifie m signatures valides de contrôleurs
// DISTINCTS sur le payload canonique — le champ "quorum" du jeton n'est
// jamais cru (§7.2 : la vérification est publique, Ed25519 partout §12).
func (t *Tracker) verifyQuorumLocked(p EpochPayload, sigs []ControllerSignature) error {
	canonical, err := canonicalPayload(p)
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	valid := 0
	for _, s := range sigs {
		if seen[s.KeyID] {
			return fmt.Errorf("cluster: signataire %d en double — un quorum se compose de contrôleurs distincts", s.KeyID)
		}
		seen[s.KeyID] = true
		pub, ok := t.ctrls[s.KeyID]
		if !ok {
			return fmt.Errorf("cluster: key_id %d hors manifest", s.KeyID)
		}
		sig, err := hex.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return fmt.Errorf("cluster: signature du contrôleur %d illisible", s.KeyID)
		}
		if !ed25519.Verify(pub, canonical, sig) {
			return fmt.Errorf("cluster: signature du contrôleur %d invalide", s.KeyID)
		}
		valid++
	}
	if valid < t.quorum {
		return fmt.Errorf("cluster: quorum non atteint : %d signature(s) valide(s), %d requises", valid, t.quorum)
	}
	return nil
}

// consumeAutoBudgetLocked applique la fenêtre glissante d'une heure sur
// les bascules automatiques. autoLog est borné par maxAutoHr (§4.3 : état
// borné) — arrivé à la borne, on refuse au lieu d'empiler.
func (t *Tracker) consumeAutoBudgetLocked(now time.Time) bool {
	cutoff := now.Add(-time.Hour)
	kept := t.autoLog[:0]
	for _, ts := range t.autoLog {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	t.autoLog = kept
	if len(t.autoLog) >= t.maxAutoHr {
		return false
	}
	t.autoLog = append(t.autoLog, now)
	return true
}

// CurrentEpoch implémente broker.EpochProvider (§7.2). Fail-closed : sans
// époque valide dont CETTE cellule est l'autorité — pas d'époque rendue,
// la cellule ne sert pas (le broker refuse alors epoch-unavailable AVANT
// toute traduction, avec feuille et alarme).
func (t *Tracker) CurrentEpoch() (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		return 0, ErrNoEpoch
	}
	now := t.now()
	if t.quarantined[t.cellID] {
		return 0, ErrCellQuarantined
	}
	if t.current.payload.Authority != t.cellID {
		return 0, ErrNotAuthority
	}
	if now.Before(t.current.notBefore) {
		return 0, ErrEpochNotYetEffective
	}
	if !now.Before(t.current.expiresAt) {
		return 0, ErrEpochExpired
	}
	return uint64(t.current.payload.N), nil
}

// ObservedEpoch rapporte l'époque courante OBSERVÉE (plus haut N
// vérifié), quelle qu'en soit l'autorité — couture de supervision (T34)
// et de validation : un présentant dont le jeton porte un N différent
// tombe sur epoch-mismatch au PEP (§7.2/§7.3 : la révocation invalide les
// jetons pré-émis par incrément d'époque).
func (t *Tracker) ObservedEpoch() (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		return 0, false
	}
	return t.current.payload.N, true
}

// Quarantined liste les cellules en quarantaine (§7.3 : quarantaine, pas
// meurtre — la cellule gelée reste INSPECTABLE, son état n'est purgé ni
// ici ni dans son registre).
func (t *Tracker) Quarantined() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.quarantined))
	for c := range t.quarantined {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// TrackerStatus est un instantané lisible de l'état de fencing —
// inspection d'une cellule gelée comprise (§7.3) et supervision (T34).
type TrackerStatus struct {
	Epoch             int       // plus haut N vérifié (-1 si aucun)
	Authority         string    // autorité de l'époque courante
	NotBefore         time.Time // entrée en fonction effective (§7.2)
	ExpiresAt         time.Time // expiration de l'époque courante
	Quarantined       []string  // cellules en quarantaine
	AutoFailoversHour int       // bascules auto consommées dans l'heure glissante
}

// Status rend l'état courant — y compris pour une cellule en quarantaine
// (la quarantaine gèle le service, pas l'inspection). Lecture locale
// infaillible : l'erreur est toujours nil ICI — elle existe dans la
// signature parce que la couture EpochStatusSource de la console (T37,
// D110 élargi après revue) peut être un adaptateur réseau, dont la
// lecture peut échouer ; une zero-value serait une demi-vérité (§1).
func (t *Tracker) Status() (TrackerStatus, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	quar := make([]string, 0, len(t.quarantined))
	for c := range t.quarantined {
		quar = append(quar, c)
	}
	sort.Strings(quar)
	st := TrackerStatus{Epoch: -1, Quarantined: quar, AutoFailoversHour: len(t.autoLog)}
	if t.current != nil {
		st.Epoch = t.current.payload.N
		st.Authority = t.current.payload.Authority
		st.NotBefore = t.current.notBefore
		st.ExpiresAt = t.current.expiresAt
	}
	return st, nil
}

// refuseLocked écrit la feuille de refus (KindEpoch, event donné) puis
// rend l'erreur — pas de décision de fencing sans preuve (§4.1).
func (t *Tracker) refuseLocked(ctx context.Context, n int, authority, reason string, event ...byte) error {
	ev := epochEventRefuse
	if len(event) > 0 {
		ev = event[0]
	}
	if err := t.leafLocked(ctx, ev, n, authority, reason); err != nil {
		return fmt.Errorf("cluster: refus %s NON TRACÉ (feuille impossible) : %w", reason, err)
	}
	return fmt.Errorf("cluster: jeton d'époque refusé : %s", reason)
}

// leafLocked inscrit la feuille KindEpoch — record « TBPE1 » :
//
//	"TBPE1" ‖ event 1B ‖ n u64 BE ‖ authorityLen u8 ‖ authority ‖ reasonLen u8 ‖ reason
//
// hash-only (§6.2 : le sel reste chez le producteur ; un auditeur re-hash
// à révélation du sel).
func (t *Tracker) leafLocked(ctx context.Context, event byte, n int, authority, reason string) error {
	if n < 0 {
		n = 0
	}
	rec := make([]byte, 0, 5+1+8+1+len(authority)+1+len(reason))
	rec = append(rec, "TBPE1"...)
	rec = append(rec, event)
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], uint64(n))
	rec = append(rec, nb[:]...)
	rec = append(rec, byte(len(authority)))
	rec = append(rec, authority...)
	rec = append(rec, byte(len(reason)))
	rec = append(rec, reason...)
	_, err := t.leaves.Append(ctx, registry.Leaf{
		Kind:        registry.KindEpoch,
		CellID:      t.cellID,
		PayloadHash: registry.HashPayload(t.salt, rec),
		Timestamp:   t.now().UnixNano(),
	})
	return err
}
