package pep

// Cache anti-replay borné en mémoire (T10, §4.3).
//
// Doctrine : signature + fraîcheur + portée ne répondent pas à « déjà
// consommé ? ». Chaque PEP tient ce cache LOCAL de jti consommés. La
// structure est bornée EN MÉMOIRE, pas seulement en TTL : un flot de jetons
// distincts individuellement valides épuiserait un cache non borné ou un
// LRU naïf, qui évincerait un jti non expiré et casserait silencieusement
// la garantie anti-replay. Ici : ring buffer à capacité fixe, allouée au
// démarrage, dimensionnée au quota réseau max du passeport — JAMAIS
// d'éviction sous pression. Saturation = fail-closed : refus du nouveau
// jeton + alarme (couture T14, circuit-breaker T11).
//
// Coûts : chemin chaud O(1) amorti (lookup de la table + purge de tête
// paresseuse) ; le scan complet de purge n'a lieu qu'à saturation
// (chemin froid), pour ne jamais tripper sur des slots en réalité expirés.

import (
	"errors"
	"sync"
	"time"
)

// TripReasonJTISaturated est la raison d'alarme passée à OnTrip quand le
// cache est saturé (consommée par T14/T11).
const TripReasonJTISaturated = "jti-cache-saturated"

// replayEntry est un slot du ring : jti consommé + son expiration.
type replayEntry struct {
	jti  [16]byte
	exp  int64 // secondes unix
	live bool
}

// AntiReplayOptions paramètre le cache.
type AntiReplayOptions struct {
	// Capacity est la capacité FIXE du ring — dimensionnée au quota réseau
	// max du passeport (jetons max par fenêtre TTL). Jamais de croissance.
	Capacity int
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
	// OnTrip est la couture d'alarme vers T14 (bascule fail-closed) et le
	// circuit-breaker T11. Appelé une seule fois, à la première saturation.
	// Nil ⇒ pas d'alarme (dev minimal — le refus reste fail-closed).
	OnTrip func(reason string)
}

// AntiReplay est le cache borné de jti consommés. Sûr pour un usage
// concurrent ; sans allocation après construction.
type AntiReplay struct {
	ring  []replayEntry
	head  int // index de la plus ancienne entrée occupée
	count int // entrées occupées (expirées ou non)

	set map[[16]byte]struct{} // appartenance O(1) — bornée par Capacity

	now    func() time.Time
	onTrip func(reason string)

	mu      sync.Mutex
	tripped bool // collant : la première saturation est latched (T14)
}

// NewAntiReplay construit le cache. Fail-closed dès la configuration :
// capacité non positive ⇒ erreur.
func NewAntiReplay(opts AntiReplayOptions) (*AntiReplay, error) {
	if opts.Capacity <= 0 {
		return nil, errors.New("pep: capacité anti-replay > 0 requise (§4.3 : borné en mémoire)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &AntiReplay{
		ring:   make([]replayEntry, opts.Capacity), // alloué au démarrage, fixe
		set:    make(map[[16]byte]struct{}, opts.Capacity),
		now:    now,
		onTrip: opts.OnTrip,
	}, nil
}

// compile-time : *AntiReplay satisfait la couture AntiReplayCache du
// validateur (T9).
var _ AntiReplayCache = (*AntiReplay)(nil)

// CheckAndConsume répond à « déjà consommé ? » et consomme si non.
// Atomique. true = jti inconnu, désormais consommé jusqu'à exp ; false =
// replay détecté OU cache saturé (fail-closed, alarme T14). Jamais
// d'éviction d'un jti non expiré.
func (c *AntiReplay) CheckAndConsume(jti [16]byte, exp time.Time) bool {
	now := c.now().Unix()
	expUnix := exp.Unix()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.purgeHead(now)

	if _, seen := c.set[jti]; seen {
		return false // replay
	}

	if c.count == len(c.ring) {
		// Chemin froid : avant de tripper, purge exhaustive — des expirés
		// peuvent traîner au milieu du ring derrière une tête longue.
		c.purgeAll(now)
		if c.count == len(c.ring) {
			c.trip()
			return false // fail-closed : refus, JAMAIS d'éviction
		}
	}

	slot := (c.head + c.count) % len(c.ring)
	c.ring[slot] = replayEntry{jti: jti, exp: expUnix, live: true}
	c.set[jti] = struct{}{}
	c.count++
	return true
}

// purgeHead dépile les entrées expirées en tête du ring. Coût amorti O(1)
// par opération : chaque slot n'est dépilé qu'une fois.
func (c *AntiReplay) purgeHead(now int64) {
	for c.count > 0 && c.ring[c.head].exp <= now {
		delete(c.set, c.ring[c.head].jti)
		c.ring[c.head] = replayEntry{}
		c.head = (c.head + 1) % len(c.ring)
		c.count--
	}
}

// purgeAll libère tous les expirés, où qu'ils soient. Chemin froid : appelé
// uniquement à saturation, pour ne pas tripper sur des slots morts.
// Compacte le ring en conservant l'ordre d'insertion.
func (c *AntiReplay) purgeAll(now int64) {
	if c.count == 0 {
		return
	}
	n := len(c.ring)
	kept := make([]replayEntry, 0, c.count)
	for i := 0; i < c.count; i++ {
		e := c.ring[(c.head+i)%n]
		if e.exp > now {
			kept = append(kept, e)
		} else {
			delete(c.set, e.jti)
		}
	}
	for i := range c.ring {
		c.ring[i] = replayEntry{}
	}
	copy(c.ring, kept)
	c.head = 0
	c.count = len(kept)
}

// trip enclenche l'alarme de saturation — collante (T14) : une seule fois.
func (c *AntiReplay) trip() {
	if c.tripped {
		return
	}
	c.tripped = true
	if c.onTrip != nil {
		c.onTrip(TripReasonJTISaturated)
	}
}

// Len rapporte le nombre de jti consommés non purgés (expirés ou non).
func (c *AntiReplay) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// Capacity rapporte la capacité fixe du ring (allouée au démarrage).
func (c *AntiReplay) Capacity() int { return len(c.ring) }

// Tripped rapporte si le cache a saturé au moins une fois (couture T11 :
// le circuit-breaker lit ce latch ; il ne se ré-arme pas tout seul).
func (c *AntiReplay) Tripped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tripped
}
