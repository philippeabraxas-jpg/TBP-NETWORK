package pep

// Point UNIQUE de décision « refuser maintenant » (T14, §4.1 + §9.1).
//
// Toute défaillance doit aboutir à un refus, jamais à un passage
// silencieux : OPA injoignable (T11), horloge au-delà de la borne NTS
// (T13), ancrage en retard (T6, fencing §6.2), cache jti saturé (T10),
// registre de quota saturé (T12), disque registre à 80 % (T5). Le README
// de src/registry l'exige : UN SEUL endroit décide « refuser maintenant »
// — pas deux implémentations qui peuvent dériver.
//
// Ce module est ce point. Les détecteurs y basculent leurs conditions
// (Trip — directement ou via l'adaptateur OnTrip() qui épouse la couture
// func(reason string) de T10/T11/T12/T13) ; le validateur T9 l'interroge
// AVANT chaque décision (Gate, couture ValidatorOptions.Gate, étape 0 de
// la chaîne — avant même le décodage, donc avant toute mutation comme la
// consommation anti-rejeu).
//
// Doctrine :
//   - Trip est tracé (feuille KindTelemetry, hash-only §6.2) et alarmé —
//     une bascule silencieuse est interdite ;
//   - Gate est PUR (aucune écriture) : la feuille du refus est la feuille
//     de décision que le validateur écrit pour toute décision (§4.1) ;
//   - Clear est tracé ; pour les conditions classe W (§5.3), il EXIGE un
//     quorum — sans vérifieur configuré ou preuve rejetée, la condition
//     reste basculée (fail-closed) ;
//   - une condition inconnue basculée par un détecteur futur refuse
//     quand même (fail-closed) et hérite de la classe la plus dure à
//     lever (W, défaut §5.3).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Conditions de défaillance sans constante existante dans leur détecteur
// (T5 et T6 sont des phases ultérieures — le nom est déclaré ici, unique).
const (
	// CondRegistryDiskHigh : disque du registre ≥ 80 % (T5).
	CondRegistryDiskHigh = "registry-disk-high"
	// CondAnchorLag : ancrage en retard au-delà du seuil §6.2 (T6, fencing).
	CondAnchorLag = "anchor-lag"
)

// Erreurs du point fail-closed.
var (
	ErrConditionUnknown      = errors.New("pep: condition inconnue")
	ErrConditionNotTripped   = errors.New("pep: condition non basculée")
	ErrConditionClassChange  = errors.New("pep: condition déjà enregistrée avec une autre classe")
	ErrQuorumVerifierMissing = errors.New("pep: levée classe W sans vérifieur de quorum (fail-closed)")
	ErrQuorumRejected        = errors.New("pep: preuve de quorum rejetée (§5.3)")
)

// Actions tracées dans les feuilles du point fail-closed.
const (
	failClosedActionTrip  byte = 1
	failClosedActionClear byte = 2
)

// Refusal est le refus motivé rendu par Gate(). C'est le SEUL type de
// refus « système » du package : aucun composant ne construit le sien
// (critère « revue + linter » de l'issue — vérifié par test).
type Refusal struct {
	Reason string    // nom de la condition basculée (code machine stable)
	Since  time.Time // instant de la bascule
	Detail string    // diagnostic du détecteur
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("pep: refus fail-closed (%s): %s", r.Reason, r.Detail)
}

// FailClosedGate est la couture lue par le validateur T9 avant chaque
// décision. *FailClosed l'implémente nativement.
type FailClosedGate interface {
	Gate() *Refusal
}

// QuorumProof atteste une décision de gouvernance (§5.3). Opaque pour
// T14 : la vérification est une couture (QuorumVerifier) — les phases
// ultérieures y brancheront la crypto de quorum.
type QuorumProof struct {
	Signers [][]byte // identités des signataires de la levée
}

// QuorumVerifier valide une preuve de quorum pour lever une condition
// classe W. Fail-closed : absent ou rejet ⇒ la condition reste basculée.
type QuorumVerifier func(condition string, proof QuorumProof) bool

// Condition est l'état d'une condition de défaillance enregistrée.
type Condition struct {
	Name    string
	Class   Class // §5.3 — W ⇒ levée gouvernée (quorum)
	Tripped bool
	Since   time.Time // instant de la bascule (zéro si jamais basculée)
	Detail  string    // premier diagnostic (conservé — forensique)
}

// FailClosedOptions paramètre le point unique. Fail-closed dès la
// configuration : cellID, sel ≥ 16 o et couture feuilles requis.
type FailClosedOptions struct {
	// CellID identifie la cellule dans les feuilles. Requis.
	CellID string
	// Salt est le sel de hachage des feuilles (§6.2) : ≥ 16 octets, reste
	// chez le producteur. Requis.
	Salt []byte
	// Leaves est la couture registre (T7) : bascules et levées y sont
	// tracées. Requis (une bascule non tracée est interdite).
	Leaves LeafSink
	// OnAlarm est la couture d'alarme vers le monitor : appelée à chaque
	// bascule (jamais silencieux). Nil ⇒ pas d'alarme externe (la feuille
	// reste obligatoire).
	OnAlarm func(name string)
	// VerifyQuorum valide les levées classe W. Nil ⇒ toute levée W est
	// refusée (fail-closed). Remplaçable via SetQuorumVerifier.
	VerifyQuorum QuorumVerifier
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// FailClosed est le registre central des conditions de refus — le SEUL
// point de décision « refuser maintenant ». Sûr pour un usage concurrent.
type FailClosed struct {
	cellID  string
	salt    []byte
	leaves  LeafSink
	onAlarm func(name string)
	now     func() time.Time

	mu       sync.Mutex
	conds    map[string]*Condition
	verifier QuorumVerifier
}

// NewFailClosed construit le point unique. Fail-closed : cellID, sel et
// couture feuilles requis.
func NewFailClosed(opts FailClosedOptions) (*FailClosed, error) {
	if opts.CellID == "" {
		return nil, errors.New("pep: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: couture feuilles requise (§4.1 : bascule TOUJOURS tracée)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	return &FailClosed{
		cellID:   opts.CellID,
		salt:     salt,
		leaves:   opts.Leaves,
		onAlarm:  opts.OnAlarm,
		now:      now,
		conds:    make(map[string]*Condition),
		verifier: opts.VerifyQuorum,
	}, nil
}

// SetQuorumVerifier (re)branche la couture de vérification de quorum
// (phases ultérieures : crypto de gouvernance §5.3).
func (f *FailClosed) SetQuorumVerifier(v QuorumVerifier) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifier = v
}

// Register déclare une condition et sa classe §5.3 AVANT usage. Ré-enregistrer
// avec la même classe est idempotent ; avec une autre classe ⇒ erreur.
func (f *FailClosed) Register(name string, class Class) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.conds[name]; ok {
		if c.Class != class {
			return fmt.Errorf("%w (%s : %v → %v)", ErrConditionClassChange, name, c.Class, class)
		}
		return nil
	}
	f.conds[name] = &Condition{Name: name, Class: class}
	return nil
}

// Trip bascule une condition : le détecteur l'appelle quand il constate la
// défaillance. La bascule est TRACÉE (feuille hash-only) et ALARMÉE —
// jamais silencieuse. Une condition inconnue est auto-enregistrée en
// classe W (défaut §5.3, la plus dure à lever) : fail-closed, un refus de
// plus ne s'ignore pas. Re-trip sans changement d'état : aucun doublon,
// le premier diagnostic est conservé (forensique).
func (f *FailClosed) Trip(name, detail string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conds[name]
	if !ok {
		c = &Condition{Name: name, Class: ClassW}
		f.conds[name] = c
	}
	if c.Tripped {
		return
	}
	c.Tripped = true
	c.Since = f.now()
	c.Detail = detail
	f.writeLeafLocked(failClosedActionTrip, name, detail)
	if f.onAlarm != nil {
		f.onAlarm(name)
	}
}

// Gate est LE point de décision « refuser maintenant », interrogé par le
// validateur T9 AVANT chaque décision. Pur : n'écrit rien (la feuille du
// refus est la feuille de décision du validateur, §4.1). Déterministe :
// la raison est la première condition basculée par ordre lexicographique.
func (f *FailClosed) Gate() *Refusal {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.conds))
	for name, c := range f.conds {
		if c.Tripped {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	c := f.conds[names[0]]
	return &Refusal{Reason: c.Name, Since: c.Since, Detail: c.Detail}
}

// Clear lève une condition — action TRACÉE. Classes F/I : levée opérateur
// simple. Classe W (§5.3) : quorum EXIGE — vérifieur absent ou preuve
// rejetée ⇒ erreur, la condition reste basculée (fail-closed).
func (f *FailClosed) Clear(name string, proof QuorumProof) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conds[name]
	if !ok {
		return fmt.Errorf("%w (%s)", ErrConditionUnknown, name)
	}
	if !c.Tripped {
		return fmt.Errorf("%w (%s)", ErrConditionNotTripped, name)
	}
	if c.Class == ClassW {
		if f.verifier == nil {
			return fmt.Errorf("%w (%s)", ErrQuorumVerifierMissing, name)
		}
		if !f.verifier(name, proof) {
			return fmt.Errorf("%w (%s)", ErrQuorumRejected, name)
		}
	}
	c.Tripped = false
	c.Since = time.Time{}
	c.Detail = ""
	f.writeLeafLocked(failClosedActionClear, name, "")
	return nil
}

// Condition retourne l'état d'une condition (couture forensique /
// observabilité). Le second retour dit si elle est enregistrée.
func (f *FailClosed) Condition(name string) (Condition, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conds[name]
	if !ok {
		return Condition{}, false
	}
	return *c, true
}

// OnTrip est l'adaptateur qui épouse la couture d'alarme func(reason
// string) des détecteurs existants (T10, T11, T12, T13) : leur alarme
// devient une bascule du point unique. Le détail est laissé au Trip
// direct ; ici la raison suffit (refus motivé par son nom).
func (f *FailClosed) OnTrip() func(reason string) {
	return func(reason string) { f.Trip(reason, "") }
}

// writeLeafLocked inscrit la feuille de bascule/levée (KindTelemetry :
// un événement système, pas une décision). Hash-only : le registre ne
// voit que l'engagement.
func (f *FailClosed) writeLeafLocked(action byte, name, detail string) {
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      f.cellID,
		PayloadHash: registry.HashPayload(f.salt, failClosedRecord(action, name, detail)),
		Timestamp:   f.now().UnixNano(),
	}
	// L'échec d'écriture est signalé sur la couture d'alarme (jamais
	// silencieux) ; il ne DÉFAIT pas la bascule — la direction d'échec
	// reste le déni (§9.1).
	if _, err := f.leaves.Append(context.Background(), leaf); err != nil && f.onAlarm != nil {
		f.onAlarm(ReasonLeafWriteFailed)
	}
}

// failClosedRecord sérialise le record de bascule/levée :
// "TBFF1" ‖ action(1) ‖ u8 len(name) ‖ name ‖ u16be len(detail) ‖ detail.
func failClosedRecord(action byte, name, detail string) []byte {
	record := make([]byte, 0, 5+1+1+len(name)+2+len(detail))
	record = append(record, "TBFF1"...)
	record = append(record, action)
	record = append(record, byte(len(name)))
	record = append(record, name...)
	record = append(record, byte(len(detail)>>8), byte(len(detail)))
	record = append(record, detail...)
	return record
}
