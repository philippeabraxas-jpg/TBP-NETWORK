// metrics.go — T26 (issue #22) : feuille de métriques du traducteur (§4.5).
//
// measure.py produit le rapport d'évaluation (agrégats par classe + hash
// de corpus — JAMAIS de contenu en clair) ; ce module définit le FORMAT du
// record inscrit au registre (versionné « TBTM1 ») et l'append via la
// couture feuilles. Le registre ne voit que l'engagement salé (§6.2,
// hash-only) ; quiconque détient le sel et le rapport peut revérifier
// l'engagement — les comptages sont des AGRÉGATS, jamais des cas.
//
// Les cibles FNR < 0,1 % / FPR < 2 % sont des cibles de conception à
// valider sur le premier corpus natif au pilote (§15) : elles vivent dans
// measure.py (gate CI) et dans la documentation — PAS dans la feuille, qui
// n'inscrit que des faits mesurés (comptages + hash de corpus).
package translator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// Erreurs du module de métriques (fail-closed).
var (
	ErrMetricsVersion      = errors.New("translator: version de rapport de métriques inconnue")
	ErrMetricsCorpusHash   = errors.New("translator: hash de corpus invalide (sha256 hex attendu)")
	ErrMetricsClassName    = errors.New("translator: nom de classe hors bornes (1–8 octets ASCII)")
	ErrMetricsInconsistent = errors.New("translator: comptages incohérents (FN > positifs ou FP > négatifs)")
	ErrMetricsSalt         = errors.New("translator: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	ErrMetricsCellID       = errors.New("translator: cellID requis (§6.2 : feuilles attribuées)")
	// ErrMetricsDuplicateClass : deux entrées portent le même nom de classe.
	// Le tri de MetricsLeafRecord ne les départage pas (il ne compare que
	// Class), donc leur ordre relatif après tri dépend de l'ordre d'ENTRÉE
	// — deux rapports portant les « mêmes » classes produiraient alors des
	// records (et des hash) DIFFÉRENTS selon l'ordre, ce que ce contrat
	// promet justement de ne jamais faire (revue de PR #80 — même doctrine
	// que la revue #62/T36 : jamais d'ordre arbitraire choisi en silence).
	ErrMetricsDuplicateClass = errors.New("translator: classe dupliquée dans le rapport — ordre du record non déterministe")
)

// ClassMetrics porte les AGRÉGATS d'une classe (F / I / W / OUT — §5.3) :
// des comptages, jamais du contenu. Les taux se dérivent des comptages —
// aucun flottant ne transite par le record (déterminisme du hash).
type ClassMetrics struct {
	Class          string `json:"class"`
	Positives      uint32 `json:"positives"`
	Negatives      uint32 `json:"negatives"`
	FalseNegatives uint32 `json:"false_negatives"`
	FalsePositives uint32 `json:"false_positives"`
}

// MetricsReport est le rapport d'évaluation produit par measure.py.
type MetricsReport struct {
	CorpusHash [32]byte       // hash déterministe du corpus rejoué (corpus/README.md)
	Classes    []ClassMetrics // agrégats par classe, triés par nom dans le record
}

// metricsReportJSON est la forme sérialisée du rapport (sortie de
// measure.py --out). Version 1 : champs figés — toute évolution passe par
// une nouvelle version, jamais par un champ ajouté en silence.
type metricsReportJSON struct {
	Version    int            `json:"version"`
	CorpusHash string         `json:"corpus_hash"`
	Classes    []ClassMetrics `json:"classes"`
}

// maxMetricsClassLen borne le nom de classe dans le record.
const maxMetricsClassLen = 8

// MetricsReportFromJSON parse un rapport measure.py. Fail-closed : version
// inconnue, hash mal formé, nom de classe hors bornes ou comptages
// incohérents (FN > positifs, FP > négatifs) refusent le rapport — un
// rapport douteux n'entre pas au registre.
func MetricsReportFromJSON(data []byte) (MetricsReport, error) {
	var raw metricsReportJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return MetricsReport{}, fmt.Errorf("translator: rapport illisible : %w", err)
	}
	if raw.Version != 1 {
		return MetricsReport{}, fmt.Errorf("%w (%d)", ErrMetricsVersion, raw.Version)
	}
	hash, err := hex.DecodeString(raw.CorpusHash)
	if err != nil || len(hash) != 32 {
		return MetricsReport{}, fmt.Errorf("%w (%q)", ErrMetricsCorpusHash, raw.CorpusHash)
	}
	report := MetricsReport{Classes: raw.Classes}
	copy(report.CorpusHash[:], hash)
	for _, c := range report.Classes {
		if err := validateClassMetrics(c); err != nil {
			return MetricsReport{}, err
		}
	}
	return report, nil
}

// validateClassMetrics impose les bornes d'une classe (fail-closed).
func validateClassMetrics(c ClassMetrics) error {
	if c.Class == "" || len(c.Class) > maxMetricsClassLen {
		return fmt.Errorf("%w (%q)", ErrMetricsClassName, c.Class)
	}
	for i := 0; i < len(c.Class); i++ {
		b := c.Class[i]
		if b < 0x21 || b > 0x7e { // ASCII visible — pas de contrôle, pas d'espace
			return fmt.Errorf("%w (%q)", ErrMetricsClassName, c.Class)
		}
	}
	if c.FalseNegatives > c.Positives || c.FalsePositives > c.Negatives {
		return fmt.Errorf("%w (classe %s : pos=%d neg=%d fn=%d fp=%d)",
			ErrMetricsInconsistent, c.Class, c.Positives, c.Negatives, c.FalseNegatives, c.FalsePositives)
	}
	return nil
}

// MetricsLeafRecord sérialise le rapport en record versionné (déterministe
// — les classes sont triées par nom, quiconque reconstruit le record
// retrouve le même hash) :
//
//	"TBTM1" ‖ corpusHash(32) ‖ u8 nClasses ‖
//	par classe : u8 len(name) ‖ name ‖ u32be pos ‖ u32be neg ‖ u32be fn ‖ u32be fp
func MetricsLeafRecord(report MetricsReport) ([]byte, error) {
	classes := make([]ClassMetrics, len(report.Classes))
	copy(classes, report.Classes)
	sort.Slice(classes, func(i, j int) bool { return classes[i].Class < classes[j].Class })
	if len(classes) > 255 {
		return nil, fmt.Errorf("translator: %d classes — au-delà de 255", len(classes))
	}
	// Deux classes de même nom sont une entrée ambiguë : le comparateur de
	// tri ne les départage jamais (il ne compare que Class), donc leur
	// ordre relatif après tri dépend de l'ordre d'ENTRÉE fourni par
	// l'appelant — deux rapports portant les « mêmes » classes
	// produiraient alors des records DIFFÉRENTS selon l'ordre. Fail-closed :
	// rejet explicite, jamais un ordre arbitraire choisi en silence.
	for i := 1; i < len(classes); i++ {
		if classes[i].Class == classes[i-1].Class {
			return nil, fmt.Errorf("%w (%q)", ErrMetricsDuplicateClass, classes[i].Class)
		}
	}
	record := make([]byte, 0, 5+32+1+len(classes)*(1+maxMetricsClassLen+16))
	record = append(record, "TBTM1"...)
	record = append(record, report.CorpusHash[:]...)
	record = append(record, byte(len(classes)))
	for _, c := range classes {
		if err := validateClassMetrics(c); err != nil {
			return nil, err
		}
		record = append(record, byte(len(c.Class)))
		record = append(record, c.Class...)
		for _, v := range []uint32{c.Positives, c.Negatives, c.FalseNegatives, c.FalsePositives} {
			record = append(record, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
		}
	}
	return record, nil
}

// MetricsLeafSink est la couture d'inscription des feuilles de métriques.
// Même signature que la couture LeafSink de degradation.go (T25) — le
// registre tessera réel comme les fakes de test la satisfont
// structurellement. Déclarée ici pour que T26 tienne seul sur main,
// fusionnable dans n'importe quel ordre avec T25 ; si les deux sont sur
// main, l'unification des deux interfaces est un renommage sans
// comportement.
type MetricsLeafSink interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// AppendMetricsLeaf inscrit la feuille de métriques (KindTelemetry : un
// événement de mesure, pas une décision §4.1). Hash-only : le registre ne
// voit que sha256(sel ‖ record). Fail-closed : cellID et sel ≥ 16 octets
// requis — une mesure non attribuée ou non scellée n'entre pas au registre.
func AppendMetricsLeaf(ctx context.Context, leaves MetricsLeafSink, cellID string, salt []byte, report MetricsReport, at time.Time) (uint64, error) {
	if cellID == "" {
		return 0, ErrMetricsCellID
	}
	if len(salt) < 16 {
		return 0, ErrMetricsSalt
	}
	if leaves == nil {
		return 0, errors.New("translator: couture feuilles requise (§4.5 : mesure TOUJOURS tracée)")
	}
	record, err := MetricsLeafRecord(report)
	if err != nil {
		return 0, err
	}
	return leaves.Append(ctx, registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      cellID,
		PayloadHash: registry.HashPayload(salt, record),
		Timestamp:   at.UnixNano(),
	})
}
