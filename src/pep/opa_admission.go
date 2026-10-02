package pep

// opa_admission.go — la file BORNÉE devant OPA (§9.1, §12).
//
// Sans elle, chaque requête appelle OPA seule, sans borne de concurrence : sous charge (ou attaque) OPA sature, le
// client qui abandonne à 5 ms n'empêche pas OPA d'évaluer la requête abandonnée, et la saturation s'entretient jusqu'à
// l'effondrement (tests/opa_latency : 82-99 % d'opa-timeout à 16 concurrents). La file :
//
//   - borne les requêtes EN VOL vers OPA (MaxInflight) ;
//   - met le surplus en attente FIFO, borné (MaxQueue), l'attente étant COMPTÉE dans le budget de 5 ms ;
//   - n'envoie JAMAIS à OPA une demande dont il reste moins de MinService : travail déjà perdu, il n'atteint pas OPA ;
//   - plafonne la part d'un MÊME sujet (SubjectShare) : un agent qui inonde ne peut pas occuper toute la capacité ni
//     toute la file, les autres passent ;
//   - refuse IMMÉDIATEMENT le reste (opa-overloaded) : fail-closed, explicite, et distinct de opa-timeout (OPA n'a pas
//     été sollicité, ce n'est PAS une faute d'OPA : ni compteur de fautes consécutives, ni verrou T14).

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// Causes de refus de la file (diagnostic ; la raison de décision est toujours opa-overloaded).
const (
	shedQueueFull    = "queue-full"
	shedSubjectShare = "subject-share"
	shedExpired      = "expired-in-queue"
)

// AdmissionOptions paramètre la file. Zéro MaxInflight ⇒ pas de file (comportement historique : concurrence non bornée).
type AdmissionOptions struct {
	// MaxInflight : requêtes simultanées vers OPA. 0 ⇒ file désactivée.
	MaxInflight int
	// MaxQueue : demandes en attente au-delà. 0 ⇒ aucune attente (saturé = refus immédiat).
	MaxQueue int
	// SubjectShare : part maximale, en % de (MaxInflight+MaxQueue), qu'un même sujet peut occuper (en vol + en
	// attente), dans [1, 100]. 0 ⇒ 100 (pas d'équité).
	SubjectShare int
	// MinService : temps minimal restant au budget pour envoyer une demande à OPA. 0 ⇒ 1 ms.
	MinService time.Duration
}

// AdmissionStats est l'instantané de la file (observabilité, supervision).
type AdmissionStats struct {
	Inflight         int    `json:"inflight"`
	Queued           int    `json:"queued"`
	Admitted         uint64 `json:"admitted"`
	ShedQueueFull    uint64 `json:"shed_queue_full"`
	ShedSubjectShare uint64 `json:"shed_subject_share"`
	ShedExpired      uint64 `json:"shed_expired"`
	// SinceLastShedMS : millisecondes depuis le dernier refus de la file (-1 : jamais). Les compteurs sont cumulatifs ;
	// c'est cette valeur qui dit si la surcharge est EN COURS.
	SinceLastShedMS int64 `json:"since_last_shed_ms"`
}

type waiter struct {
	subject  string
	deadline time.Time
	granted  chan bool // true = place accordée ; false = expirée en file
	elem     *list.Element
	done     bool
}

type admission struct {
	maxInflight, maxQueue, subjectCap int
	minService                        time.Duration
	now                               func() time.Time

	mu         sync.Mutex
	inflight   int
	queue      *list.List
	perSubject map[string]int // en vol + en attente, par sujet (plafond d'équité)
	running    map[string]int // en vol seulement, par sujet (ordre de service équitable)
	stats      AdmissionStats
	lastShed   time.Time
}

func newAdmission(o AdmissionOptions, now func() time.Time) *admission {
	if o.MaxInflight <= 0 {
		return nil
	}
	share := o.SubjectShare
	if share <= 0 || share > 100 {
		share = 100
	}
	capacity := o.MaxInflight + o.MaxQueue
	subjectCap := (capacity*share + 99) / 100 // arrondi au-dessus : au moins 1
	if subjectCap < 1 {
		subjectCap = 1
	}
	ms := o.MinService
	if ms <= 0 {
		ms = time.Millisecond
	}
	return &admission{maxInflight: o.MaxInflight, maxQueue: o.MaxQueue, subjectCap: subjectCap, minService: ms,
		now: now, queue: list.New(), perSubject: map[string]int{}, running: map[string]int{}}
}

// acquire rend release != nil quand la place est accordée (à appeler UNE fois), sinon la cause du refus.
func (a *admission) acquire(ctx context.Context, subject string, deadline time.Time) (release func(), shed string) {
	a.mu.Lock()
	if a.perSubject[subject] >= a.subjectCap {
		a.stats.ShedSubjectShare++
		a.lastShed = a.now()
		a.mu.Unlock()
		return nil, shedSubjectShare
	}
	if a.inflight < a.maxInflight && a.queue.Len() == 0 {
		a.inflight++
		a.running[subject]++
		a.perSubject[subject]++
		a.stats.Admitted++
		a.mu.Unlock()
		return a.releaser(subject), ""
	}
	if a.queue.Len() >= a.maxQueue {
		a.stats.ShedQueueFull++
		a.lastShed = a.now()
		a.mu.Unlock()
		return nil, shedQueueFull
	}
	w := &waiter{subject: subject, deadline: deadline, granted: make(chan bool, 1)}
	w.elem = a.queue.PushBack(w)
	a.perSubject[subject]++
	a.mu.Unlock()

	select {
	case ok := <-w.granted:
		if ok {
			return a.releaser(subject), ""
		}
		return nil, shedExpired
	case <-ctx.Done():
		a.mu.Lock()
		if w.done { // la place a été accordée (ou refusée) entre-temps : on la rend
			a.mu.Unlock()
			if ok := <-w.granted; ok { // place accordée mais budget épuisé : on la rend, la demande est abandonnée
				a.releaser(subject)()
				a.mu.Lock()
				a.stats.ShedExpired++
				a.lastShed = a.now()
				a.mu.Unlock()
			} // sinon dispatchLocked l'a déjà comptée
			return nil, shedExpired
		}
		a.queue.Remove(w.elem)
		w.done = true
		a.perSubject[subject]--
		if a.perSubject[subject] == 0 {
			delete(a.perSubject, subject)
		}
		a.stats.ShedExpired++
		a.lastShed = a.now()
		a.mu.Unlock()
		return nil, shedExpired
	}
}

func (a *admission) releaser(subject string) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.inflight--
			if a.running[subject]--; a.running[subject] == 0 {
				delete(a.running, subject)
			}
			a.perSubject[subject]--
			if a.perSubject[subject] == 0 {
				delete(a.perSubject, subject)
			}
			a.dispatchLocked()
		})
	}
}

// dispatchLocked accorde les places libres dans un ordre ÉQUITABLE : parmi les demandes en attente, celle dont le sujet a le
// MOINS de requêtes en vol passe d'abord (à égalité, la plus ancienne). Un sujet qui inonde et occupe déjà les places ne
// passe donc pas devant un sujet qui n'en a aucune. Les demandes dont il reste moins de MinService sont écartées (elles
// ne seront pas envoyées à OPA : travail déjà perdu).
func (a *admission) dispatchLocked() {
	for a.inflight < a.maxInflight {
		var best *list.Element
		for e := a.queue.Front(); e != nil; {
			w := e.Value.(*waiter)
			next := e.Next()
			if w.deadline.Sub(a.now()) < a.minService {
				a.queue.Remove(e)
				w.done = true
				if a.perSubject[w.subject]--; a.perSubject[w.subject] == 0 {
					delete(a.perSubject, w.subject)
				}
				a.stats.ShedExpired++
				a.lastShed = a.now()
				w.granted <- false
			} else if best == nil || a.running[w.subject] < a.running[best.Value.(*waiter).subject] {
				best = e
			}
			e = next
		}
		if best == nil {
			return
		}
		w := best.Value.(*waiter)
		a.queue.Remove(best)
		w.done = true
		a.inflight++
		a.running[w.subject]++
		a.stats.Admitted++
		w.granted <- true
	}
}

func (a *admission) snapshot() AdmissionStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.stats
	s.Inflight, s.Queued = a.inflight, a.queue.Len()
	s.SinceLastShedMS = -1
	if !a.lastShed.IsZero() {
		s.SinceLastShedMS = a.now().Sub(a.lastShed).Milliseconds()
	}
	return s
}
