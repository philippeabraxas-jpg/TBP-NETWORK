// dryrun.go — T36 (issue #62) : dry-run avec diff d'état soumis à OPA
// avant commit (§4.4(1), décision D104).
//
// « Pour les classes F/I/W : l'action candidate s'exécute en mode dry-run
// (quand le composant cible le permet), le diff d'état résultant est
// soumis à OPA comme entrée supplémentaire de la décision, avant tout
// commit réel. » Complète le validateur T9, qui ne voit que scope +
// fraîcheur + non-consommation — jamais l'effet.
//
// Orchestration (revue #62) : au PEP, à l'ÉVALUATION — pas à l'émission
// broker (un diff calculé à l'émission serait potentiellement périmé à
// l'exécution) — et AVANT l'ouverture du passeport de quota : un refus
// dry-run n'ouvre jamais de compteur pour une action qui ne se fera pas.
// Sans OPA configuré, pas de dry-run : le diff n'a pas de destinataire,
// le verdict T9 seul s'applique (comme avant cette tâche).
//
// Diff STRUCTUREL, hash-only de bout en bout (§6.2) : le composant cible
// calcule lui-même les hashes avant/après de ses valeurs ; ce qui sort
// de lui est {objet, champ, kind} + hashes — JAMAIS une valeur en clair,
// y compris vis-à-vis d'OPA. La politique juge la structure (quel objet,
// quel champ, quel type de changement) ; le diff_hash lie la décision au
// diff exact observé.
//
// Séparation de domaine (tags vérifiés libres au moment de l'écriture,
// revue #62 — TBPD1/TBPS1 étaient pris) :
//
//   - « TBPF1 » : hash du diff canonique (ci-dessous) ;
//   - « TBPF2 » : record de la feuille télémétrie dry-run — mesure §9.1
//     SÉPARÉE du verdict (la feuille de décision garde les formats
//     « TBPD1 »/« TBPD2 » figés, jamais modifiés).
//
// Latence (§9.1, D105) : mitigation bornée aux classes F/I/W — hors
// classes, le chemin est STRICTEMENT inchangé (aucun appel, aucune
// mesure ajoutée). Pour F/I/W : un dry-run local à timeout borné +
// l'appel OPA existant à entrée étendue (pas de second aller-retour).
package pep

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Raisons de refus du chemin dry-run (fail-closed §4.1).
const (
	// ReasonDryRunFailed : le composant a échoué à produire un diff
	// (erreur, diff mal formé). Jamais de passage sans diff quand le
	// dry-run est configuré.
	ReasonDryRunFailed = "dryrun-failed"
	// ReasonDryRunTimeout : le dry-run a dépassé son budget dédié.
	ReasonDryRunTimeout = "dryrun-timeout"
	// ReasonDryRunCallerCancelled : le contexte de l'APPELANT (pas le
	// budget dédié du dry-run) est déjà annulé/expiré quand le composant
	// observe ctx.Done() — même motif que classifyContextFault côté OPA
	// (opa_client.go) : étiqueter ceci dryrun-failed ou dryrun-timeout
	// accuserait le composant à tort d'une cause qui lui est étrangère.
	ReasonDryRunCallerCancelled = "dryrun-caller-cancelled"
)

// Budget dry-run : distinct du circuit-breaker OPA (§12) — le dry-run
// est un chemin F/I/W « à arbitrer » (§9.1), pas le tier-1.
const (
	DefaultDryRunTimeout = 2 * time.Second
	MaxDryRunTimeout     = 30 * time.Second
)

// MaxDiffEntries borne le diff (§4.3 : état borné). Les bornes
// objet/champ réutilisent celles du contrat de sceau (D102) — mêmes
// ordres de grandeur, un seul endroit à faire évoluer.
const MaxDiffEntries = MaxSealFields

// ErrDiffBounds : diff mal formé ou hors bornes — refus explicite,
// jamais de troncature (un diff tronqué mentirait à la politique).
var ErrDiffBounds = errors.New("pep: diff d'état hors bornes ou mal formé (§4.3)")

// DiffKind est le type de changement d'une entrée de diff.
type DiffKind uint8

const (
	DiffCreate DiffKind = 1
	DiffUpdate DiffKind = 2
	DiffDelete DiffKind = 3
)

// String rend le kind lisible côté Rego ("create"|"update"|"delete").
func (k DiffKind) String() string {
	switch k {
	case DiffCreate:
		return "create"
	case DiffUpdate:
		return "update"
	case DiffDelete:
		return "delete"
	}
	return "unknown"
}

// DiffEntry est un changement sur UN champ d'UN objet. BeforeHash /
// AfterHash sont calculés PAR LE COMPOSANT cible (SHA-256 de la valeur,
// sel métier chez lui) : les valeurs ne sortent jamais du composant.
// Conventions structurelles (vérifiées par CanonicalizeDiff) :
// create ⇒ BeforeHash nul ; delete ⇒ AfterHash nul.
type DiffEntry struct {
	Object     string
	Field      string
	Kind       DiffKind
	BeforeHash [32]byte
	AfterHash  [32]byte
}

// StateDiff est le diff d'état observé en dry-run.
type StateDiff struct {
	Entries []DiffEntry
}

// DryRunner est la couture vers le composant cible « quand il le permet »
// (§4.4(1)) : exécuter l'action candidate en dry-run et rapporter le
// diff d'état. L'implémentation appartient au composant — jamais au PEP.
type DryRunner interface {
	DryRun(ctx context.Context, action, resource string) (StateDiff, error)
}

// CanonicalizeDiff trie (object, field, kind) et valide la structure.
// Aucune mutation de l'entrée : la slice rendue est une copie.
func CanonicalizeDiff(d StateDiff) (StateDiff, error) {
	if len(d.Entries) > MaxDiffEntries {
		return StateDiff{}, fmt.Errorf("%w : %d entrées > %d", ErrDiffBounds, len(d.Entries), MaxDiffEntries)
	}
	out := make([]DiffEntry, len(d.Entries))
	copy(out, d.Entries)
	for _, e := range out {
		if len(e.Object) == 0 || len(e.Object) > MaxSealObjectLen {
			return StateDiff{}, fmt.Errorf("%w : object=%d octets", ErrDiffBounds, len(e.Object))
		}
		if len(e.Field) == 0 || len(e.Field) > MaxSealFieldLen {
			return StateDiff{}, fmt.Errorf("%w : field=%d octets", ErrDiffBounds, len(e.Field))
		}
		switch e.Kind {
		case DiffCreate:
			if e.BeforeHash != ([32]byte{}) {
				return StateDiff{}, fmt.Errorf("%w : create avec BeforeHash non nul", ErrDiffBounds)
			}
		case DiffDelete:
			if e.AfterHash != ([32]byte{}) {
				return StateDiff{}, fmt.Errorf("%w : delete avec AfterHash non nul", ErrDiffBounds)
			}
		case DiffUpdate:
			// BeforeHash == AfterHash toléré : réécriture à l'identique.
		default:
			return StateDiff{}, fmt.Errorf("%w : kind=%d inconnu", ErrDiffBounds, e.Kind)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Object != out[j].Object {
			return out[i].Object < out[j].Object
		}
		if out[i].Field != out[j].Field {
			return out[i].Field < out[j].Field
		}
		return out[i].Kind < out[j].Kind
	})
	return StateDiff{Entries: out}, nil
}

// HashDiff calcule l'engagement du diff (D104) — séparation de domaine
// « TBPF1 » :
//
//	SHA-256("TBPF1" ‖ u8 len(cellID) ‖ cellID ‖ u16 BE n
//	        ‖ par entrée triée : u16 len(object)‖object
//	            ‖ u16 len(field)‖field ‖ kind(1) ‖ before(32) ‖ after(32))
//
// Exporté pour l'audit (§6 : vérifiable par un tiers qui reçoit le diff
// structurel — les valeurs restent chez le producteur, §6.2).
func HashDiff(cellID string, d StateDiff) ([32]byte, error) {
	var zero [32]byte
	if len(cellID) == 0 || len(cellID) > maxSealCellIDLen {
		return zero, fmt.Errorf("%w : cellID=%d octets", ErrDiffBounds, len(cellID))
	}
	c, err := CanonicalizeDiff(d)
	if err != nil {
		return zero, err
	}
	h := sha256.New()
	h.Write([]byte("TBPF1"))
	h.Write([]byte{byte(len(cellID))})
	h.Write([]byte(cellID))
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(c.Entries)))
	h.Write(buf[:2])
	for _, e := range c.Entries {
		binary.BigEndian.PutUint16(buf[:2], uint16(len(e.Object)))
		h.Write(buf[:2])
		h.Write([]byte(e.Object))
		binary.BigEndian.PutUint16(buf[:2], uint16(len(e.Field)))
		h.Write(buf[:2])
		h.Write([]byte(e.Field))
		h.Write([]byte{byte(e.Kind)})
		h.Write(e.BeforeHash[:])
		h.Write(e.AfterHash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// DryRunEntry est la vue OPA d'une entrée : structure SEULE (objet,
// champ, kind lisible) — ni valeur, ni hash de valeur : la politique
// juge QUOI change, le diff_hash lie la décision au diff exact.
type DryRunEntry struct {
	Object string `json:"object"`
	Field  string `json:"field"`
	Kind   string `json:"kind"`
}

// DryRunInput est l'entrée supplémentaire soumise à OPA (§4.4(1)) —
// input.dry_run, omitempty : les politiques écrites avant cette tâche
// sont inchangées (rétro-compat).
type DryRunInput struct {
	Available  bool          `json:"available"`             // false = composant sans dry-run : la politique tranche (résidu §10.5)
	DiffHash   string        `json:"diff_hash,omitempty"`   // hex « TBPF1 » — lie la décision au diff
	EntryCount int           `json:"entry_count"`           // cardinalité jugée sans la liste
	Entries    []DryRunEntry `json:"entries,omitempty"`     // structure hash-only
}

// DryRunGate orchestre le dry-run au PEP (D104) : exécution bornée,
// canonisation, engagement, feuilles. Sûr pour un usage concurrent.
type DryRunGate struct {
	runner  DryRunner
	timeout time.Duration
	cellID  string
	salt    []byte
	leaves  LeafSink
	now     func() time.Time
	onAlarm func(string)
}

// DryRunGateOptions paramètre la porte. Fail-closed dès la configuration.
type DryRunGateOptions struct {
	// Runner est la couture composant. Requis : une porte sans runner ne
	// mesure rien — l'indisponibilité se déclare en NE configurant PAS de
	// porte (le listener soumet alors available=false, cf. handleEvaluate).
	Runner DryRunner
	// Timeout borne le dry-run (défaut DefaultDryRunTimeout, plafond
	// MaxDryRunTimeout) — budget DÉDIÉ, distinct du circuit-breaker OPA.
	Timeout time.Duration
	// CellID, Salt, Leaves : couture registre (T7) — la télémétrie et les
	// refus dry-run laissent des feuilles comme toute décision (§4.1).
	CellID string
	Salt   []byte // ≥ 16 octets, reste chez le producteur (§6.2)
	Leaves LeafSink
	// Now est l'horloge (tests : horloge manuelle). Défaut time.Now.
	Now func() time.Time
	// OnAlarm est la couture T14 (échec d'écriture de feuille).
	OnAlarm func(string)
}

// NewDryRunGate construit la porte. Fail-closed : runner, cellID, sel
// ≥ 16 octets et sink de feuilles requis ; timeout borné.
func NewDryRunGate(opts DryRunGateOptions) (*DryRunGate, error) {
	if opts.Runner == nil {
		return nil, errors.New("pep: dry-run runner requis (une porte sans runner ne mesure rien — déclarer l'indisponibilité en l'absence de porte)")
	}
	if len(opts.CellID) == 0 || len(opts.CellID) > maxSealCellIDLen {
		return nil, errors.New("pep: cellID requis (≤ 255 octets) pour la porte dry-run")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("pep: sel ≥ 16 octets requis (§6.2) pour la porte dry-run")
	}
	if opts.Leaves == nil {
		return nil, errors.New("pep: sink de feuilles requis (§4.1) pour la porte dry-run")
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultDryRunTimeout
	}
	if timeout < 0 || timeout > MaxDryRunTimeout {
		return nil, fmt.Errorf("pep: timeout dry-run hors bornes (0, %ds]", int(MaxDryRunTimeout.Seconds()))
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &DryRunGate{
		runner: opts.Runner, timeout: timeout, cellID: opts.CellID,
		salt: opts.Salt, leaves: opts.Leaves, now: now, onAlarm: opts.OnAlarm,
	}, nil
}

// Execute réalise le dry-run de l'action candidate et rend l'entrée OPA.
// En cas d'échec (erreur composant, diff mal formé, timeout), Execute
// rend une RAISON non vide — refus fail-closed — après avoir tracé la
// feuille de décision correspondante (format « TBPD1 » partagé, via
// decisionLeafRecord) ; la feuille télémétrie « TBPF2 » est écrite dans
// TOUS les cas (la mesure §9.1 existe aussi pour un échec).
func (g *DryRunGate) Execute(ctx context.Context, jti [16]byte, action, resource string) (*DryRunInput, string) {
	start := g.now()

	dctx, cancel := context.WithTimeout(ctx, g.timeout)
	diff, err := g.runner.DryRun(dctx, action, resource)
	cancel()
	elapsed := g.now().Sub(start)

	if err != nil {
		// ctx (l'appelant) est vérifié EN PREMIER, comme
		// classifyContextFault côté OPA (opa_client.go) : quand ctx est
		// déjà terminé, dctx.Err() reporte souvent la même cause
		// apparente (DeadlineExceeded), indiscernable d'un dépassement du
		// budget dédié — étiqueter ça dryrun-timeout ou dryrun-failed
		// accuserait le composant à tort d'une cause qui lui est
		// étrangère (revue #62 : un signal malhonnête, même doctrine).
		reason := ReasonDryRunFailed
		switch {
		case ctx.Err() != nil:
			reason = ReasonDryRunCallerCancelled
		case dctx.Err() == context.DeadlineExceeded:
			reason = ReasonDryRunTimeout
		}
		g.writeTelemetryLeaf(jti, false, [32]byte{}, elapsed)
		g.writeDenyLeaf(jti, reason)
		return nil, reason
	}

	canon, err := CanonicalizeDiff(diff)
	if err != nil {
		g.writeTelemetryLeaf(jti, false, [32]byte{}, elapsed)
		g.writeDenyLeaf(jti, ReasonDryRunFailed)
		return nil, ReasonDryRunFailed
	}
	digest, err := HashDiff(g.cellID, canon)
	if err != nil {
		g.writeTelemetryLeaf(jti, false, [32]byte{}, elapsed)
		g.writeDenyLeaf(jti, ReasonDryRunFailed)
		return nil, ReasonDryRunFailed
	}

	entries := make([]DryRunEntry, len(canon.Entries))
	for i, e := range canon.Entries {
		entries[i] = DryRunEntry{Object: e.Object, Field: e.Field, Kind: e.Kind.String()}
	}
	in := &DryRunInput{
		Available:  true,
		DiffHash:   hex.EncodeToString(digest[:]),
		EntryCount: len(entries),
		Entries:    entries,
	}
	g.writeTelemetryLeaf(jti, true, digest, elapsed)
	return in, ""
}

// writeDenyLeaf inscrit la feuille de REFUS dry-run (KindDecision, format
// « TBPD1 » partagé avec T9/T11 — §4.1 : la décision réellement rendue à
// l'appelant doit avoir sa feuille ; le validateur a déjà tracé SON allow
// avant que le dry-run n'échoue).
func (g *DryRunGate) writeDenyLeaf(jti [16]byte, reason string) {
	leaf := registry.Leaf{
		Kind:        registry.KindDecision,
		CellID:      g.cellID,
		PayloadHash: registry.HashPayload(g.salt, decisionLeafRecord(jti, false, reason)),
		Timestamp:   g.now().UnixNano(),
	}
	if _, err := g.leaves.Append(context.Background(), leaf); err != nil && g.onAlarm != nil {
		g.onAlarm(ReasonLeafWriteFailed)
	}
}

// writeTelemetryLeaf inscrit la mesure dry-run (KindTelemetry — une
// mesure, pas une décision). Record « TBPF2 » :
//
//	"TBPF2" ‖ jti(16) ‖ available(1) ‖ diff_hash(32, zéros si !available)
//	        ‖ elapsed_us(u64 BE)
func (g *DryRunGate) writeTelemetryLeaf(jti [16]byte, available bool, digest [32]byte, elapsed time.Duration) {
	record := make([]byte, 0, 5+16+1+32+8)
	record = append(record, "TBPF2"...)
	record = append(record, jti[:]...)
	if available {
		record = append(record, 0x01)
	} else {
		record = append(record, 0x00)
	}
	record = append(record, digest[:]...)
	record = binary.BigEndian.AppendUint64(record, uint64(elapsed.Microseconds()))
	leaf := registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      g.cellID,
		PayloadHash: registry.HashPayload(g.salt, record),
		Timestamp:   g.now().UnixNano(),
	}
	if _, err := g.leaves.Append(context.Background(), leaf); err != nil && g.onAlarm != nil {
		g.onAlarm(ReasonLeafWriteFailed)
	}
}
