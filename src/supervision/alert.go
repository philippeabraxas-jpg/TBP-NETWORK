// src/supervision/alert.go — T34a (issue #60)
//
// Record d'alerte du moniteur de supervision — format binaire canonique
// « TBPS1 » (D79, revue #60) :
//
//	"TBPS1" ‖ v(u8=1) ‖ event(u8) ‖ u8 len(cellID) ‖ cellID ‖
//	detailHash(32) ‖ verdict(u8) ‖ u8 len(reason) ‖ reason
//
// Le record N'EST PAS écrit en clair dans un registre : doctrine hash-only
// (§6.2) — la feuille KindSupervision du log de supervision porte
// sha256(sel ‖ record), le sel (≥ 16 octets) reste chez le moniteur. Le
// record est l'équivalent « off-chain » du record de manifeste T31 : il
// peut être révélé avec son sel pour prouver une alerte à un tiers.
//
// L'alerte est SIGNÉE par construction : elle est feuillée dans le log de
// supervision propre au moniteur, dont les checkpoints sont signés par la
// clé du moniteur (§2 « at least one independent monitor », §7.1 « mêmes
// mécaniques, même doctrine »). Pas de signature supplémentaire dans le
// record : le checkpoint signé du log de supervision EST l'attestation.
package supervision

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// alertMagic est la séparation de domaine du record d'alerte (§11.3).
const alertMagic = "TBPS1"

// alertVersion est la version du format de record.
const alertVersion byte = 1

// Événements d'alerte (champ event du record).
const (
	// AlertEventChainFault : faute de continuité ou d'intégrité d'une
	// chaîne surveillée (preuve de consistance rejetée, feuille qui ne se
	// re-hache pas, kind inconnu, taille en régression) — §3, §6.2.
	AlertEventChainFault byte = 1
	// AlertEventAnchorStale : ancrage d'une cellule au-delà de la borne
	// de fraîcheur (défaut 120 s, §6.2) ou jamais observé.
	AlertEventAnchorStale byte = 2
	// AlertEventManifestFault : chaîne de manifestes d'une cellule
	// illisible ou rejetée par VerifyManifestChain (T31, §6.3).
	AlertEventManifestFault byte = 3
	// AlertEventFailoverTrigger : bascule miroir déclenchée par le
	// moniteur (T34b, D80, failover.go) — numérotation attribuée en T34a
	// pour figer le format.
	AlertEventFailoverTrigger byte = 4
	// AlertEventFailoverRefused : déclenchement REFUSÉ (budget épuisé,
	// couture absente ou en faute — escalade humaine, T34b, D80).
	AlertEventFailoverRefused byte = 5
	// AlertEventOPARestart : le chien de garde d'OPA (cmd/opawatchdog, #275) a décidé de redémarrer OPA — Notice « restart-requested »
	// (feuillée AVANT l'acte : pas de redémarrage sans trace) ou Alarm « restart-failed » (la commande a échoué). CellID = la
	// cellule dont OPA est redémarré.
	AlertEventOPARestart byte = 6
	// AlertEventOPARestartRefused : OPA reste bloqué mais le chien de garde ne redémarre pas (budget horaire épuisé, ou
	// feuille impossible) — escalade humaine, jamais un silence (#275).
	AlertEventOPARestartRefused byte = 7
)

func validAlertEvent(e byte) bool {
	switch e {
	case AlertEventChainFault, AlertEventAnchorStale, AlertEventManifestFault, AlertEventFailoverTrigger, AlertEventFailoverRefused,
		AlertEventOPARestart, AlertEventOPARestartRefused:
		return true
	}
	return false
}

// Verdicts (champ verdict du record).
const (
	// AlertVerdictAlarm : divergence détectée — alarme (§5.3 : jamais
	// silencieuse).
	AlertVerdictAlarm byte = 0
	// AlertVerdictNotice : constat d'une action pré-autorisée du moniteur
	// (déclenchement de bascule dans le budget — T34b).
	AlertVerdictNotice byte = 1
)

// maxAlertReasonLen borne la raison lisible (champ de longueur u8).
const maxAlertReasonLen = 255

// maxAlertCellIDLen borne cellID (même borne que les feuilles, §6.2).
const maxAlertCellIDLen = 255

// AlertRecord est le constat canonique d'une alerte de supervision.
type AlertRecord struct {
	Event      byte     // AlertEvent*
	CellID     string   // cellule concernée (identité de la CHAÎNE fautive)
	DetailHash [32]byte // sha256 du détail diagnostique (texte libre hors registre)
	Verdict    byte     // AlertVerdict*
	Reason     string   // raison courte, stable, comparable (≤ 255 octets)
}

// MarshalAlertRecord sérialise le record selon « TBPS1 » (déterministe,
// §11.3). Fail-closed : event/verdict inconnus, cellID ou reason hors
// bornes ⇒ erreur, jamais de record tronqué.
func MarshalAlertRecord(r AlertRecord) ([]byte, error) {
	if !validAlertEvent(r.Event) {
		return nil, fmt.Errorf("supervision: event %d inconnu", r.Event)
	}
	switch r.Verdict {
	case AlertVerdictAlarm, AlertVerdictNotice:
	default:
		return nil, fmt.Errorf("supervision: verdict %d inconnu", r.Verdict)
	}
	if len(r.CellID) == 0 || len(r.CellID) > maxAlertCellIDLen {
		return nil, fmt.Errorf("supervision: cellID : longueur %d hors [1, %d]", len(r.CellID), maxAlertCellIDLen)
	}
	if len(r.Reason) == 0 || len(r.Reason) > maxAlertReasonLen {
		return nil, fmt.Errorf("supervision: reason : longueur %d hors [1, %d]", len(r.Reason), maxAlertReasonLen)
	}
	buf := make([]byte, 0, len(alertMagic)+1+1+1+len(r.CellID)+32+1+1+len(r.Reason))
	buf = append(buf, alertMagic...)
	buf = append(buf, alertVersion, r.Event, byte(len(r.CellID)))
	buf = append(buf, r.CellID...)
	buf = append(buf, r.DetailHash[:]...)
	buf = append(buf, r.Verdict, byte(len(r.Reason)))
	buf = append(buf, r.Reason...)
	return buf, nil
}

// ErrAlertRecordMalformed : octets qui ne sont pas un record « TBPS1 ».
var ErrAlertRecordMalformed = errors.New("supervision: record d'alerte malformé")

// ParseAlertRecord est l'inverse de MarshalAlertRecord — symétrie stricte
// (leçon #65 : les deux directions admettent exactement le même ensemble).
func ParseAlertRecord(data []byte) (AlertRecord, error) {
	var r AlertRecord
	if len(data) < len(alertMagic)+1 {
		return r, fmt.Errorf("%w : trop court (%d octets)", ErrAlertRecordMalformed, len(data))
	}
	if string(data[:len(alertMagic)]) != alertMagic {
		return r, fmt.Errorf("%w : magie absente", ErrAlertRecordMalformed)
	}
	if data[len(alertMagic)] != alertVersion {
		return r, fmt.Errorf("%w : version %d inconnue", ErrAlertRecordMalformed, data[len(alertMagic)])
	}
	rest := data[len(alertMagic)+1:]
	// event(1) ‖ len(1) ‖ cellID ‖ detail(32) ‖ verdict(1) ‖ len(1) ‖ reason
	if len(rest) < 1+1 {
		return r, fmt.Errorf("%w : entête tronquée", ErrAlertRecordMalformed)
	}
	r.Event = rest[0]
	if !validAlertEvent(r.Event) {
		return r, fmt.Errorf("%w : event %d inconnu", ErrAlertRecordMalformed, r.Event)
	}
	idLen := int(rest[1])
	if idLen == 0 {
		return r, fmt.Errorf("%w : cellID vide annoncé", ErrAlertRecordMalformed)
	}
	if len(rest) < 2+idLen+32+1+1 {
		return r, fmt.Errorf("%w : tronqué (cellID %d annoncé)", ErrAlertRecordMalformed, idLen)
	}
	r.CellID = string(rest[2 : 2+idLen])
	off := 2 + idLen
	copy(r.DetailHash[:], rest[off:off+32])
	off += 32
	r.Verdict = rest[off]
	switch r.Verdict {
	case AlertVerdictAlarm, AlertVerdictNotice:
	default:
		return r, fmt.Errorf("%w : verdict %d inconnu", ErrAlertRecordMalformed, r.Verdict)
	}
	off++
	reasonLen := int(rest[off])
	off++
	if reasonLen == 0 {
		return r, fmt.Errorf("%w : reason vide annoncée", ErrAlertRecordMalformed)
	}
	if len(rest) != off+reasonLen {
		return r, fmt.Errorf("%w : longueur incohérente (reason %d annoncée)", ErrAlertRecordMalformed, reasonLen)
	}
	r.Reason = string(rest[off:])
	return r, nil
}

// Alert est une alerte levée par le moniteur : le record canonique, son
// sel de feuille (conservé par le moniteur pour les preuves à tiers —
// §6.2 : le sel ne quitte jamais le producteur), et l'ancrage de la
// feuille KindSupervision dans le log de supervision.
type Alert struct {
	Record    AlertRecord // constat canonique (parsé)
	Raw       []byte      // octets canoniques du record (ce qui est hashé dans la feuille)
	Salt      []byte      // sel de la feuille (≥ 16 octets) — NE PAS publier
	Detail    []byte      // détail diagnostique dont DetailHash est le sha256
	LeafIndex uint64      // index de la feuille KindSupervision dans le log de supervision
	LeafHash  [32]byte    // payloadHash de cette feuille = sha256(Salt ‖ Raw)
}

// AlarmSink est la couture d'alarme vers T14 (§5.3). Le feuillage dans le
// log de supervision n'est JAMAIS subordonné au sink : une alerte est
// d'abord une feuille, ensuite une notification. Sink nil = pas de
// notification (la feuille, elle, est obligatoire).
type AlarmSink interface {
	Raise(ctx context.Context, a Alert) error
}

// AlarmSinkFunc adapte une fonction en AlarmSink (tests, câblage T14).
type AlarmSinkFunc func(ctx context.Context, a Alert) error

// Raise implémente AlarmSink.
func (f AlarmSinkFunc) Raise(ctx context.Context, a Alert) error { return f(ctx, a) }

// WriteAlert construit le record « TBPS1 » de (event, cellID, verdict, reason, detail) et le FEUILLE — KindSupervision, hash
// salé (§6.2), clair journalisé d'abord quand journal != nil (journal-before-leaf, #275). C'est le chemin d'écriture commun du
// moniteur et du chien de garde d'OPA : « une alerte est d'abord une feuille » (§5.3). Feuille impossible ⇒ erreur, et rien
// n'a été notifié ni exécuté sur la foi d'une alerte qui n'existe pas comme preuve. logCellID est l'identité du log qui
// feuille (celui du producteur), pas la cellule concernée.
func WriteAlert(ctx context.Context, sink registry.LeafAppender, journal *registry.RecordStore, logCellID string, now time.Time,
	event byte, cellID string, verdict byte, reason string, detail []byte) (Alert, error) {
	rec := AlertRecord{Event: event, CellID: cellID, DetailHash: sha256.Sum256(detail), Verdict: verdict, Reason: reason}
	raw, err := MarshalAlertRecord(rec)
	if err != nil {
		return Alert{}, err
	}
	salt := make([]byte, supervisionSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return Alert{}, fmt.Errorf("supervision: sel de feuille : %w", err)
	}
	leafHash := registry.HashPayload(salt, raw)
	idx, err := registry.AppendLeaf(ctx, sink, journal, registry.KindSupervision, logCellID, salt, raw, now.UnixNano())
	if err != nil {
		return Alert{}, fmt.Errorf("supervision: feuille d'alerte impossible : %w", err)
	}
	return Alert{Record: rec, Raw: raw, Salt: salt, Detail: detail, LeafIndex: idx, LeafHash: leafHash}, nil
}
