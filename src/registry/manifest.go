// manifest.go — T31 (issue #32) : l'état attesté = manifeste (§6.3).
//
// « (policy_id, config OPA, hash broker, hash conteneur IA locale, tête de
// chaîne) — tout changement de composant = transition visible, signée,
// continûme ; le hash est celui du paquet signé (§1). » (§6.3)
//
// Doctrine (§1) : « jamais par confiance, toujours par preuve vérifiable » —
// appliquée ici à l'état de la cellule ELLE-MÊME : une cellule dont l'état
// n'est pas prouvable ne peut pas rendre ses décisions vérifiables par un
// tiers, quelle que soit la qualité du reste de la chaîne. T4–T7
// transportent les feuilles ; ce fichier construit le manifeste que ces
// feuilles attestent.
//
// Deux artefacts distincts (D69/D70, revue #32) :
//
//   - le RECORD SIGNÉ « TBP-M1 » — artefact publié à côté du log (même
//     statut que les checkpoints et les AnchorRecord) : c'est lui qu'un
//     tiers vérifieur lit SANS relire le code de la cellule (critère 3 de
//     #32, VerifyManifestChain + vecteur doré) ;
//   - la FEUILLE KindManifest « TBPL2 » — hash-only (§6.2 : le sel reste
//     chez le producteur), dans le log de cellule, donc ancrée par T6
//     comme toute feuille (l'ancrage porte sur la tête de chaîne,
//     indépendamment du mélange de kinds).
//
// Distinction de nommage : le « Manifest » de scripts/genesis (T3) est le
// manifeste des CLÉS CONTRÔLEURS — autre objet, autre rôle. Ici : le
// manifeste d'ÉTAT de la pile gouvernée (glossaire §14).
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// Événements de feuille KindManifest (D69 — record « TBPL2 »).
const (
	manifestEventBoot       byte = 1 // genèse ou démarrage vérifié
	manifestEventTransition byte = 2 // changement de composant signé
	manifestEventRefuse     byte = 3 // refus (boot divergent, mesure impossible…)
)

// Erreurs du manifeste — codes stables.
var (
	ErrManifestNotInitialized  = errors.New("registre: manifeste non initialisé — la genèse (seq 0) doit précéder toute transition")
	ErrManifestAlreadyGenesis  = errors.New("registre: genèse déjà écrite — une cellule n'a qu'un manifeste 0")
	ErrManifestUnchanged       = errors.New("registre: transition sans changement de composant — une transition atteste un CHANGEMENT (§6.3)")
	ErrManifestEpochRegression = errors.New("registre: époque en régression — les manifestes sont monotone-non-décroissants en époque (§7.2)")
	ErrManifestContinuity      = errors.New("registre: rupture de chaîne de manifestes (seq/prev) — pas de saut silencieux d'un état à un autre (§6.3)")
	ErrManifestSignature       = errors.New("registre: signature de manifeste invalide (clé de cellule, §12)")
	ErrManifestRecordMalformed = errors.New("registre: record de manifeste mal formé (layout « TBP-M1 »)")
	ErrManifestLeafFault       = errors.New("registre: feuille de manifeste impossible — pas de preuve, pas de transition (faute système)")
	ErrBootNoManifest          = errors.New("registre: measured boot sans manifeste committed — rien à quoi se confronter (fail-closed)")
	ErrBootMisconfiguration    = errors.New("registre: racine attendue nulle — le measured boot exige une valeur de référence provisionnée")
	ErrBootMeasurement         = errors.New("registre: mesure de démarrage impossible (racine ou composant) — fail-closed")
	ErrBootDivergence          = errors.New("registre: état mesuré divergent du manifeste attendu — démarrage refusé (§6.3)")
)

// ManifestState est le vecteur d'état de §6.3 — cinq hashes de 32 octets,
// chacun celui du paquet signé du composant (§1). ChainHead est la racine
// Merkle du log de cellule au moment de la transition, capturée JUSTE
// AVANT l'écriture de la feuille de transition elle-même (jamais après :
// la feuille n'existe pas encore au moment du calcul du sceau — même patron
// que KindAnchor/T6, qui ancre hash(broker_id, tête, TSA) avant que la
// feuille d'ancrage n'entre dans la tête). La tête est une ANCRE DE
// CHRONOLOGIE pour l'audit, pas un invariant de boot : elle avance avec
// chaque feuille (décisions, ancrages…), CheckBoot ne la compare donc pas.
type ManifestState struct {
	PolicyID        [32]byte // hash du bundle de règles signé (claim −1 des jetons)
	OPAConfigHash   [32]byte // hash de la config OPA déployée
	BrokerHash      [32]byte // hash du binaire broker déployé
	AIContainerHash [32]byte // hash du conteneur IA local déployé
	ChainHead       [32]byte // racine du log au moment de la transition (audit)
}

// Layout du record canonique « TBP-M1 » (D68) — champs fixes, aucune map :
// déterminisme §11.3 natif.
//
//	"TBP-M1" ‖ v(u8=1) ‖ u8 len(cellID) ‖ cellID ‖ epoch(u64 BE) ‖ seq(u64 BE)
//	         ‖ prevManifestHash(32) ‖ policyID ‖ opaConfigHash ‖ brokerHash
//	         ‖ aiContainerHash ‖ chainHead ‖ issuedAt(u64 BE, unix s)
const (
	manifestRecordPrefix = "TBP-M1"
	manifestRecordVer    = 1
	// manifestRecordFixedLen est la longueur hors cellID.
	manifestRecordFixedLen = 6 + 1 + 1 + 8 + 8 + 32 + 5*32 + 8
)

// ManifestRecord est la forme PARSÉE d'un record canonique.
type ManifestRecord struct {
	CellID   string
	Epoch    uint64
	Seq      uint64
	Prev     [32]byte
	State    ManifestState
	IssuedAt time.Time
}

// marshalRecord sérialise le record canonique (layout ci-dessus).
func marshalRecord(cellID string, epoch, seq uint64, prev [32]byte, st ManifestState, issuedAt time.Time) []byte {
	r := make([]byte, 0, manifestRecordFixedLen+len(cellID))
	r = append(r, manifestRecordPrefix...)
	r = append(r, manifestRecordVer, byte(len(cellID)))
	r = append(r, cellID...)
	r = binary.BigEndian.AppendUint64(r, epoch)
	r = binary.BigEndian.AppendUint64(r, seq)
	r = append(r, prev[:]...)
	r = append(r, st.PolicyID[:]...)
	r = append(r, st.OPAConfigHash[:]...)
	r = append(r, st.BrokerHash[:]...)
	r = append(r, st.AIContainerHash[:]...)
	r = append(r, st.ChainHead[:]...)
	return binary.BigEndian.AppendUint64(r, uint64(issuedAt.Unix()))
}

// ParseManifestRecord parse un record canonique — contrôles stricts de
// forme (préfixe, version, longueur exacte, cellID non vide).
func ParseManifestRecord(r []byte) (ManifestRecord, error) {
	var m ManifestRecord
	if len(r) < manifestRecordFixedLen+1 {
		return m, fmt.Errorf("%w : %d octets, minimum %d", ErrManifestRecordMalformed, len(r), manifestRecordFixedLen+1)
	}
	if string(r[:6]) != manifestRecordPrefix {
		return m, fmt.Errorf("%w : préfixe %q", ErrManifestRecordMalformed, r[:6])
	}
	if r[6] != manifestRecordVer {
		return m, fmt.Errorf("%w : version %d inconnue", ErrManifestRecordMalformed, r[6])
	}
	idLen := int(r[7])
	if idLen == 0 {
		return m, fmt.Errorf("%w : cellID vide", ErrManifestRecordMalformed)
	}
	if len(r) != manifestRecordFixedLen+idLen {
		return m, fmt.Errorf("%w : %d octets, cellID annoncé %d", ErrManifestRecordMalformed, len(r), idLen)
	}
	m.CellID = string(r[8 : 8+idLen])
	off := 8 + idLen
	m.Epoch = binary.BigEndian.Uint64(r[off:])
	m.Seq = binary.BigEndian.Uint64(r[off+8:])
	copy(m.Prev[:], r[off+16:])
	off += 48
	copy(m.State.PolicyID[:], r[off:])
	copy(m.State.OPAConfigHash[:], r[off+32:])
	copy(m.State.BrokerHash[:], r[off+64:])
	copy(m.State.AIContainerHash[:], r[off+96:])
	copy(m.State.ChainHead[:], r[off+128:])
	off += 160
	m.IssuedAt = time.Unix(int64(binary.BigEndian.Uint64(r[off:])), 0).UTC()
	return m, nil
}

// HashManifest est le sceau d'un manifeste (D68) : SHA-256 du record
// canonique, HORS signature — c'est ce hash qui chaîne les transitions
// (prevManifestHash) et qui entre dans les feuilles KindManifest.
func HashManifest(record []byte) [32]byte {
	return sha256.Sum256(record)
}

// SignedManifest est l'artefact publié (D70) : record canonique + signature
// Ed25519 de la clé de cellule. Sérialisé en JSON hex (même convenance que
// les artefacts de genèse T3) pour tenir dans un fichier ou une réponse
// d'audit — le record, lui, reste le blob binaire canonique signé.
type SignedManifest struct {
	Record    []byte `json:"-"`
	Signature []byte `json:"-"`
}

// signedManifestJSON est la forme fil : hex des deux champs, ordre fixe.
type signedManifestJSON struct {
	Record    string `json:"record"`
	Signature string `json:"signature"`
}

// MarshalSignedManifest sérialise l'artefact publié (JSON déterministe :
// struct à champs fixes, §11.3).
func MarshalSignedManifest(sm SignedManifest) ([]byte, error) {
	if len(sm.Record) == 0 || len(sm.Signature) == 0 {
		return nil, fmt.Errorf("registre: SignedManifest incomplet")
	}
	return json.Marshal(signedManifestJSON{
		Record:    hex.EncodeToString(sm.Record),
		Signature: hex.EncodeToString(sm.Signature),
	})
}

// ParseSignedManifest est l'inverse de MarshalSignedManifest — validation
// hex stricte, record reparsé (forme) : un artefact mal formé est rejeté
// ici, pas à la vérification de chaîne.
func ParseSignedManifest(data []byte) (SignedManifest, error) {
	var j signedManifestJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return SignedManifest{}, fmt.Errorf("registre: artefact de manifeste illisible : %w", err)
	}
	rec, err := hex.DecodeString(j.Record)
	if err != nil {
		return SignedManifest{}, fmt.Errorf("%w : record non hexadécimal", ErrManifestRecordMalformed)
	}
	sig, err := hex.DecodeString(j.Signature)
	if err != nil {
		return SignedManifest{}, fmt.Errorf("registre: signature de manifeste non hexadécimale : %w", err)
	}
	if _, err := ParseManifestRecord(rec); err != nil {
		return SignedManifest{}, err
	}
	return SignedManifest{Record: rec, Signature: sig}, nil
}

// LeafAppender est la couture d'écriture des feuilles de manifeste —
// implémentée par CellLog (T7). Définie localement : registry ne peut pas
// importer pep (cycle), la forme est la même que pep.LeafSink.
type LeafAppender interface {
	Append(ctx context.Context, leaf Leaf) (uint64, error)
}

// ManifestOptions paramètre le Manifester. Fail-closed dès la construction.
type ManifestOptions struct {
	// CellID identifie la cellule (entre dans chaque record et feuille).
	CellID string
	// Signer est la clé de cellule — CELLE des checkpoints du log
	// (GenerateCellKey/LoadSigner, D69) : pas de nouvelle racine de
	// confiance. REVUE #32 : appeler UNIQUEMENT Signer.Sign(record) — les
	// fonctions de haut niveau note.Sign/note.Open produisent un format de
	// NOTE TEXTE structuré incompatible avec le record canonique « TBP-M1 ».
	// (Vérifié dans sumdb/note : pour Ed25519, Signer.Sign est littéralement
	// ed25519.Sign et Verifier.Verify littéralement ed25519.Verify — aucun
	// enrobage à ce niveau.)
	Signer note.Signer
	// Verifier est la contrepartie publique — requis pour valider la
	// reprise de chaîne (Last) à la construction.
	Verifier note.Verifier
	// Leaves reçoit la feuille KindManifest de chaque événement (§4.1).
	Leaves LeafAppender
	// Salt est le sel des feuilles (§6.2) : ≥ 16 octets, reste chez le
	// producteur.
	Salt []byte
	// Last, si non nil, restaure la chaîne publiée (dernier manifeste
	// connu) — signature et forme VÉRIFIÉES à la construction : une reprise
	// sur artefact falsifié est une erreur, pas un état silencieux.
	Last *SignedManifest
	// OnTrip est la couture d'alarme vers T14. Nil ⇒ pas d'alarme (le
	// refus reste fail-closed).
	OnTrip func(reason string)
	// Now est l'horloge NTS de la cellule (§6.2). Nil ⇒ time.Now (dev).
	Now func() time.Time
}

// Manifester produit les manifestes d'une cellule : genèse (seq 0) puis
// transitions chaînées, chacune signée et feuillée. État en mémoire,
// restauré à la construction depuis l'artefact publié (Last) — la
// persistance de la chaîne est à l'appelant (les artefacts sont publiés,
// D70 : ils ne sont pas un secret, leur intégrité est la signature).
type Manifester struct {
	cellID string
	signer note.Signer
	leaves LeafAppender
	salt   []byte
	onTrip func(reason string)
	now    func() time.Time

	mu          sync.Mutex
	initialized bool
	lastRecord  []byte // octets canoniques du dernier manifeste (chaînage)
	lastSigned  SignedManifest
	lastState   ManifestState
	lastEpoch   uint64
	lastSeq     uint64
}

// NewManifester construit le producteur de manifestes. Fail-closed :
// cellID, signer, verifier, feuilles, sel requis ; Last vérifié si fourni.
func NewManifester(opts ManifestOptions) (*Manifester, error) {
	if opts.CellID == "" || len(opts.CellID) > maxCellIDLen {
		return nil, errors.New("registre: cellID requis, ≤ 255 octets (§6.2)")
	}
	if opts.Signer == nil || opts.Verifier == nil {
		return nil, errors.New("registre: clé de cellule (signer + verifier) requise — les transitions sont SIGNÉES (§6.3, §12)")
	}
	if opts.Leaves == nil {
		return nil, errors.New("registre: LeafAppender requis (§4.1 : chaque événement de manifeste laisse une feuille)")
	}
	if len(opts.Salt) < 16 {
		return nil, errors.New("registre: sel ≥ 16 octets requis (§6.2 : feuilles hash-only)")
	}
	salt := make([]byte, len(opts.Salt))
	copy(salt, opts.Salt)
	m := &Manifester{
		cellID: opts.CellID,
		signer: opts.Signer,
		leaves: opts.Leaves,
		salt:   salt,
		onTrip: opts.OnTrip,
		now:    opts.Now,
	}
	if opts.Last != nil {
		rec, err := ParseManifestRecord(opts.Last.Record)
		if err != nil {
			return nil, err
		}
		if rec.CellID != opts.CellID {
			return nil, fmt.Errorf("%w : artefact d'une autre cellule (%q ≠ %q)", ErrManifestContinuity, rec.CellID, opts.CellID)
		}
		if !opts.Verifier.Verify(opts.Last.Record, opts.Last.Signature) {
			return nil, ErrManifestSignature
		}
		m.initialized = true
		m.lastRecord = opts.Last.Record
		m.lastSigned = *opts.Last
		m.lastState = rec.State
		m.lastEpoch = rec.Epoch
		m.lastSeq = rec.Seq
	}
	return m, nil
}

func (m *Manifester) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// Genesis écrit le manifeste 0 (D73) : seq = 0, prev = 0×32, feuille
// event=boot « genesis ». Une seule fois par cellule. st.ChainHead doit
// avoir été capturé par l'appelant JUSTE AVANT cet appel (voir
// ManifestState). Feuille impossible = faute : la genèse n'a pas lieu (pas
// de preuve, pas d'état attesté).
func (m *Manifester) Genesis(ctx context.Context, epoch uint64, st ManifestState) (SignedManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.initialized {
		return SignedManifest{}, ErrManifestAlreadyGenesis
	}
	return m.commitLocked(ctx, epoch, 0, [32]byte{}, st, manifestEventBoot, "genesis")
}

// Transition atteste un changement de composant (§6.3) : seq + 1, prev =
// sceau du manifeste précédent — le saut silencieux d'un état à un autre
// est structurellement visible (critère 1 de #32). Refuse : cellule sans
// genèse, vecteur inchangé (une transition atteste un CHANGEMENT), époque
// en régression. La feuille est écrite AVANT l'engagement d'état : feuille
// impossible = la transition n'a pas lieu, alarme (faute système).
func (m *Manifester) Transition(ctx context.Context, epoch uint64, st ManifestState) (SignedManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.initialized {
		return SignedManifest{}, ErrManifestNotInitialized
	}
	if st == m.lastState {
		return SignedManifest{}, ErrManifestUnchanged
	}
	if epoch < m.lastEpoch {
		return SignedManifest{}, ErrManifestEpochRegression
	}
	return m.commitLocked(ctx, epoch, m.lastSeq+1, HashManifest(m.lastRecord), st, manifestEventTransition, "ok")
}

// commitLocked signe le record puis écrit la feuille, DANS CET ORDRE, et
// n'engage l'état qu'après les deux — pas de preuve, pas de transition
// (même doctrine « allow sans feuille = erreur » que T9/T11/T29/T30).
//
// REVUE #32 : la signature est signer.Sign(record) DIRECTEMENT — jamais
// note.Sign() : le format de note texte signerait autre chose que le record
// canonique et casserait la correspondance sceau ↔ signature (D68).
func (m *Manifester) commitLocked(ctx context.Context, epoch, seq uint64, prev [32]byte, st ManifestState, event byte, reason string) (SignedManifest, error) {
	record := marshalRecord(m.cellID, epoch, seq, prev, st, m.clock())
	sig, err := m.signer.Sign(record)
	if err != nil {
		m.trip("manifest-sign-fault")
		return SignedManifest{}, fmt.Errorf("registre: signature du manifeste impossible : %w", err)
	}
	hash := HashManifest(record)
	if err := m.writeLeafLocked(ctx, event, hash, 1, reason); err != nil {
		m.trip("manifest-leaf-fault")
		return SignedManifest{}, ErrManifestLeafFault
	}
	m.initialized = true
	m.lastRecord = record
	m.lastSigned = SignedManifest{Record: record, Signature: sig}
	m.lastState = st
	m.lastEpoch = epoch
	m.lastSeq = seq
	return m.lastSigned, nil
}

// State rend le vecteur committed courant (intrant de CheckBoot — le
// « manifeste attendu » est le DERNIER manifeste signé de la chaîne).
func (m *Manifester) State() (ManifestState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastState, m.initialized
}

// LastSigned rend l'artefact publié courant (record + signature) — à
// reprendre à la construction suivante (ManifestOptions.Last) et à servir
// aux vérificateurs tiers (D70).
func (m *Manifester) LastSigned() (SignedManifest, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSigned, m.initialized
}

// writeLeafLocked inscrit la feuille KindManifest (D69) — hash-only (§6.2) :
//
//	payload = "TBPL2" ‖ event(u8) ‖ manifestHash(32) ‖ verdict(u8)
//	          ‖ u8 len(reason) ‖ reason
func (m *Manifester) writeLeafLocked(ctx context.Context, event byte, manifestHash [32]byte, verdict byte, reason string) error {
	payload := make([]byte, 0, 5+1+32+1+1+len(reason))
	payload = append(payload, "TBPL2"...)
	payload = append(payload, event)
	payload = append(payload, manifestHash[:]...)
	payload = append(payload, verdict, byte(len(reason)))
	payload = append(payload, reason...)
	_, err := m.leaves.Append(ctx, Leaf{
		Kind:        KindManifest,
		CellID:      m.cellID,
		PayloadHash: HashPayload(m.salt, payload),
		Timestamp:   m.clock().UnixNano(),
	})
	return err
}

// writeRefusalLocked trace un refus de boot (event=refuse, verdict 0). La
// faute de feuille sur ce chemin est alarmée mais le refus tient toujours
// (même patron que refuseApprovalLocked de T30).
func (m *Manifester) writeRefusalLocked(ctx context.Context, manifestHash [32]byte, reason string, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if werr := m.writeLeafLocked(ctx, manifestEventRefuse, manifestHash, 0, reason); werr != nil {
		m.trip("manifest-leaf-fault")
	}
	return err
}

func (m *Manifester) trip(reason string) {
	if m.onTrip != nil {
		m.onTrip(reason)
	}
}

// VerifyManifestChain est le vérificateur TIERS (critère 3 de #32, D70) :
// avec la seule clé publique de la cellule (vkey), il vérifie une chaîne
// d'artefacts publiés — forme, signatures, chaînage seq/prev depuis la
// genèse, cellID constant, époques non-décroissantes. Aucune lecture du
// code de la cellule n'est requise : le format est celui documenté dans
// src/registry/README.md, figé par le vecteur doré (manifest_test.go).
//
// REVUE #32 : verifier.Verify(record, sig) DIRECTEMENT — jamais note.Open,
// qui attend le format de note texte (utilisé pour les checkpoints du log,
// autre artefact, autre format).
func VerifyManifestChain(chain []SignedManifest, verifier note.Verifier) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w : chaîne vide", ErrManifestContinuity)
	}
	var prevHash [32]byte
	var prevSeq uint64
	var prevEpoch uint64
	var cellID string
	for i, sm := range chain {
		rec, err := ParseManifestRecord(sm.Record)
		if err != nil {
			return fmt.Errorf("manifeste %d : %w", i, err)
		}
		if i == 0 {
			// Genèse : seq 0, prev nul — l'amorce de la chaîne est fixe.
			if rec.Seq != 0 || rec.Prev != ([32]byte{}) {
				return fmt.Errorf("%w : manifeste 0 (seq=%d, prev non nul=%v)", ErrManifestContinuity, rec.Seq, rec.Prev != [32]byte{})
			}
			cellID = rec.CellID
		} else {
			if rec.CellID != cellID {
				return fmt.Errorf("%w : cellID change en cours de chaîne au manifeste %d", ErrManifestContinuity, i)
			}
			if rec.Seq != prevSeq+1 {
				return fmt.Errorf("%w : seq %d après seq %d (saut ou rejeu)", ErrManifestContinuity, rec.Seq, prevSeq)
			}
			if rec.Prev != prevHash {
				return fmt.Errorf("%w : prev du manifeste %d ne scelle pas le précédent", ErrManifestContinuity, i)
			}
		}
		if rec.Epoch < prevEpoch {
			return fmt.Errorf("%w : époque %d après époque %d", ErrManifestContinuity, rec.Epoch, prevEpoch)
		}
		if !verifier.Verify(sm.Record, sm.Signature) {
			return fmt.Errorf("manifeste %d : %w", i, ErrManifestSignature)
		}
		prevHash = HashManifest(sm.Record)
		prevSeq = rec.Seq
		prevEpoch = rec.Epoch
	}
	return nil
}
