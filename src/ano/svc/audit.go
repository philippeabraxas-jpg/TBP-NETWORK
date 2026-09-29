package svc

// audit.go — le record d'audit d'une réécriture (#178). Chaque masquage et
// chaque reconstitution laisse une feuille (« on audite tout ») : KindTelemetry
// hash-only, comme les métriques du traducteur (TBTM1). Le record est
// versionné « TBAN1 » ; le registre ne voit que sha256(sel ‖ record) (§6.2) —
// des COMPTAGES et une issue, jamais une valeur.

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// LeafSink est la couture d'inscription (même signature que pep.LeafSink).
type LeafSink interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// OutcomeCode rend le code d'issue stable d'une réécriture (« ok », le code
// d'un refus d'ano, ou « error »).
func OutcomeCode(err error) string {
	if err == nil {
		return "ok"
	}
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code
	}
	switch {
	case errors.Is(err, ErrEncodedBody):
		return "encoded"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrBodyTooLarge):
		return "too-large"
	}
	return "error"
}

// AuditRecord sérialise l'événement :
//
//	"TBAN1" ‖ op(1) ‖ jti(16) ‖ len(outcome)(1) ‖ outcome ‖
//	leaves ‖ masked_path ‖ masked_classifier ‖ masked_default ‖
//	classifier_faults ‖ spans ‖ restored   (chacun u32 big-endian)
func AuditRecord(ev pep.RewriteEvent) []byte {
	outcome := OutcomeCode(ev.Err)
	b := make([]byte, 0, 5+1+16+1+len(outcome)+7*4)
	b = append(b, "TBAN1"...)
	b = append(b, ev.Op)
	b = append(b, ev.JTI[:]...)
	b = append(b, byte(len(outcome)))
	b = append(b, outcome...)
	for _, n := range []int{
		ev.Report.Leaves, ev.Report.MaskedPath, ev.Report.MaskedClassifier,
		ev.Report.MaskedDefault, ev.Report.ClassifierFaults, ev.Report.Spans, ev.Report.Restored,
	} {
		b = binary.BigEndian.AppendUint32(b, uint32(n))
	}
	return b
}

// AppendAuditLeaf inscrit la feuille d'audit d'une réécriture. cellID et sel
// (≥ 16 octets) requis : une opération non attribuée ou non scellée n'entre
// pas au registre.
func AppendAuditLeaf(ctx context.Context, leaves LeafSink, cellID string, salt []byte, ev pep.RewriteEvent, at time.Time) (uint64, error) {
	if cellID == "" {
		return 0, errors.New("ano/svc: cellID requis (§6.2 : feuilles attribuées)")
	}
	if len(salt) < 16 {
		return 0, errors.New("ano/svc: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	if leaves == nil {
		return 0, errors.New("ano/svc: couture feuilles requise (on audite tout)")
	}
	return leaves.Append(ctx, registry.Leaf{
		Kind:        registry.KindTelemetry,
		CellID:      cellID,
		PayloadHash: registry.HashPayload(salt, AuditRecord(ev)),
		Timestamp:   at.UnixNano(),
	})
}
