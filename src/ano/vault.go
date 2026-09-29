package ano

// vault.go — la table de correspondance jeton ↔ valeur réelle d'ano (#178).
//
// Décision de conception : table EN MÉMOIRE, dans le processus ano
// uniquement (jamais partagée, jamais persistée). Un échange = un jeton
// broker (son jti) ; sa durée de vie est l'expiration de ce jeton, bornée.
// Perdre la table (redémarrage d'ano, expiration) est un refus explicite —
// la demande est à refaire — jamais une reconstitution approximative.
//
// État borné (§4.3, même doctrine que ContractStore) : nombre d'échanges et
// entrées par échange plafonnés ; la saturation est un refus + une alarme,
// JAMAIS une éviction (évincer un échange vivant changerait en silence ce
// qu'une réponse reconstituée veut dire).
//
// Les valeurs sont gardées en []byte et effacées à l'expiration / à la
// fermeture (au mieux — Go ne garantit pas l'absence de copies, c'est une
// hygiène, pas une preuve). La déduplication ne garde AUCUNE valeur en clé
// de map : elle passe par un hash salé par échange.

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Erreurs du coffre.
var (
	ErrVaultSaturated  = errors.New("ano: coffre saturé — refus, jamais d'éviction (§4.3)")
	ErrTooManyEntries  = errors.New("ano: trop d'entrées dans cet échange — refus (§4.3)")
	ErrExchangeUnknown = errors.New("ano: échange inconnu ou expiré — la demande est à refaire")
	ErrBadExpiry       = errors.New("ano: expiration d'échange déjà passée")
	ErrBadExchangeID   = errors.New("ano: identifiant d'échange invalide (1–128 octets)")
)

const (
	kindLeaf byte = 1 // valeur entière (JSON brut conservé : le type est restitué)
	kindSpan byte = 2 // plage de texte masquée dans une chaîne

	maxExchangeIDLen = 128
)

type entry struct {
	kind byte
	orig []byte
}

// text rend la forme texte de l'entrée (pour un jeton inséré dans une chaîne
// plus longue). Une valeur JSON chaîne est rendue sans ses guillemets.
func (e *entry) text() string {
	if e.kind == kindLeaf && len(e.orig) > 0 && e.orig[0] == '"' {
		var s string
		if err := unmarshalString(e.orig, &s); err == nil {
			return s
		}
	}
	return string(e.orig)
}

type exchange struct {
	mu      sync.Mutex
	expires time.Time
	dkey    [16]byte
	n       int
	byHash  map[[32]byte]string
	byTok   map[string]*entry
	// lookups compte les résolutions de jetons : un compteur de diagnostic
	// qui rend observable, sans mesurer la mémoire, qu'une reconstitution
	// trop grosse s'arrête AVANT d'avoir tout résolu.
	lookups atomic.Int64
}

func (e *exchange) alive(now time.Time) bool { return now.Before(e.expires) }

// intern rend le jeton de (kind, orig), en créant l'entrée si besoin. La même
// valeur donne toujours le même jeton DANS un échange.
func (e *exchange) intern(kind byte, orig []byte, maxEntries int) (string, error) {
	h := sha256.New()
	h.Write(e.dkey[:])
	h.Write([]byte{kind})
	h.Write(orig)
	var key [32]byte
	copy(key[:], h.Sum(nil))

	e.mu.Lock()
	defer e.mu.Unlock()
	if tok, ok := e.byHash[key]; ok {
		return tok, nil
	}
	if len(e.byTok) >= maxEntries {
		return "", ErrTooManyEntries
	}
	e.n++
	tok := fmt.Sprintf("TBP_VAR_%d", e.n)
	e.byHash[key] = tok
	e.byTok[tok] = &entry{kind: kind, orig: append([]byte(nil), orig...)}
	return tok, nil
}

// lookup rend une COPIE de l'entrée (le coffre peut l'effacer à tout moment).
func (e *exchange) lookup(tok string) (entry, bool) {
	e.lookups.Add(1)
	e.mu.Lock()
	defer e.mu.Unlock()
	ent, ok := e.byTok[tok]
	if !ok {
		return entry{}, false
	}
	return entry{kind: ent.kind, orig: append([]byte(nil), ent.orig...)}, true
}

func (e *exchange) wipe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ent := range e.byTok {
		clear(ent.orig)
	}
	clear(e.dkey[:])
	e.byTok = map[string]*entry{}
	e.byHash = map[[32]byte]string{}
}

type vault struct {
	mu           sync.Mutex
	ex           map[string]*exchange
	maxExchanges int
	maxEntries   int
	maxTTL       time.Duration
	now          func() time.Time
	trip         func(string)
}

func (v *vault) purgeLocked(now time.Time) {
	for id, e := range v.ex {
		if !e.alive(now) {
			e.wipe()
			delete(v.ex, id)
		}
	}
}

// open ouvre (ou retrouve) l'échange id. L'expiration est plafonnée à maxTTL ;
// rouvrir un échange vivant conserve son expiration d'origine.
func (v *vault) open(id string, expiry time.Time) (*exchange, error) {
	if l := len(id); l < 1 || l > maxExchangeIDLen {
		return nil, ErrBadExchangeID
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	v.purgeLocked(now)
	if e, ok := v.ex[id]; ok {
		return e, nil
	}
	if !expiry.After(now) {
		return nil, ErrBadExpiry
	}
	if limit := now.Add(v.maxTTL); expiry.After(limit) {
		expiry = limit
	}
	if len(v.ex) >= v.maxExchanges {
		if v.trip != nil {
			v.trip(TripVaultSaturated)
		}
		return nil, ErrVaultSaturated
	}
	e := &exchange{
		expires: expiry,
		byHash:  map[[32]byte]string{},
		byTok:   map[string]*entry{},
	}
	if _, err := rand.Read(e.dkey[:]); err != nil {
		return nil, fmt.Errorf("ano: aléa indisponible: %w", err)
	}
	v.ex[id] = e
	return e, nil
}

func (v *vault) get(id string) (*exchange, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	v.purgeLocked(now)
	e, ok := v.ex[id]
	if !ok {
		return nil, ErrExchangeUnknown
	}
	return e, nil
}

func (v *vault) close(id string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e, ok := v.ex[id]; ok {
		e.wipe()
		delete(v.ex, id)
	}
}

func (v *vault) size() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.purgeLocked(v.now())
	return len(v.ex)
}
