// anchors.go — FileAnchorSource : la lecture des ancres du master (§7.4) depuis un fichier signé hors-bande.
//
// Aucun lecteur de master chain n'existe dans le dépôt (MasterAnchorSource restait une interface). Cette source
// tient la même promesse par un autre canal, avec la MÊME racine de confiance que la genèse : le fichier
// d'ancres est signé par un quorum k-of-n des contrôleurs du manifeste de genèse (clés épinglées, cérémonie
// hors-bande) — jamais par le canari, jamais par la cellule qui lit. Il porte, par époque, le hash du bundle
// ancré et la fenêtre saine [start, end) DÉFINIE ICI, pas mesurée.
//
// Fail-closed : fichier absent, illisible, mal signé, quorum insuffisant, clé en double, champ inconnu,
// époque en double, fenêtre incohérente ou démesurée ⇒ aucune ancre (ok=false). Le fichier est relu et
// revérifié À CHAQUE LECTURE : un fichier remplacé est vu, jamais mis en cache au-delà d'un appel.
package cluster

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	strictjson "github.com/philippeabraxas-jpg/TBP-NETWORK/src/strictjson"
)

// Bornes du fichier d'ancres.
const (
	// anchorsKind sépare le domaine de signature des jetons d'époque (un jeton d'époque signé ne vaut jamais ancre).
	anchorsKind = "tbp-anchors-v1"
	// MaxAnchorFileBytes borne la lecture du fichier.
	MaxAnchorFileBytes = 256 << 10
	// MaxAnchorEntries borne le nombre d'époques ancrées dans un fichier.
	MaxAnchorEntries = 1024
	// MaxAnchorWindow borne la durée d'une fenêtre saine : une fenêtre démesurée serait une confiance sans échéance.
	MaxAnchorWindow = 7 * 24 * time.Hour
)

// AnchorEntry : l'ancre d'UNE époque — hash du bundle de règles et fenêtre saine.
type AnchorEntry struct {
	Epoch       uint64 `json:"epoch"`
	BundleHash  string `json:"bundle_hash"`  // hex, 32 octets
	WindowStart string `json:"window_start"` // RFC3339 UTC
	WindowEnd   string `json:"window_end"`   // RFC3339 UTC, exclusive
}

// AnchorPayload est le contenu signé (struct à champs fixes ⇒ sérialisation JSON déterministe, §11.3).
type AnchorPayload struct {
	Kind    string        `json:"kind"`
	Anchors []AnchorEntry `json:"anchors"`
}

// AnchorFile = payload + signatures du quorum des contrôleurs de la genèse.
type AnchorFile struct {
	Payload    AnchorPayload         `json:"payload"`
	Signatures []ControllerSignature `json:"signatures"`
	// Warning marque un artefact DEV (SoftHSM) ; hors du payload signé, comme dans le jeton d'époque.
	Warning string `json:"warning,omitempty"`
}

// FileAnchorSource implémente MasterAnchorSource sur un fichier d'ancres signé.
type FileAnchorSource struct {
	path        string
	controllers map[int]ed25519.PublicKey
	quorum      int
}

// NewFileAnchorSource : controllers = clés du manifeste de genèse (key_id 1-basé), quorum = k.
func NewFileAnchorSource(path string, controllers map[int]ed25519.PublicKey, quorum int) (*FileAnchorSource, error) {
	if path == "" {
		return nil, errors.New("cluster: chemin du fichier d'ancres requis")
	}
	if len(controllers) == 0 {
		return nil, errors.New("cluster: contrôleurs de la genèse requis pour vérifier les ancres")
	}
	if quorum < 1 || quorum > len(controllers) {
		return nil, fmt.Errorf("cluster: quorum d'ancres %d hors [1, %d]", quorum, len(controllers))
	}
	ctrls := make(map[int]ed25519.PublicKey, len(controllers))
	for id, k := range controllers {
		ctrls[id] = append(ed25519.PublicKey(nil), k...)
	}
	return &FileAnchorSource{path: path, controllers: ctrls, quorum: quorum}, nil
}

// Verify lit, vérifie et rend les ancres du fichier (erreur = aucune ancre).
func (s *FileAnchorSource) Verify() (map[uint64]AnchorEntry, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, fmt.Errorf("cluster: fichier d'ancres : %w", err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, MaxAnchorFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cluster: fichier d'ancres : %w", err)
	}
	if len(buf) > MaxAnchorFileBytes {
		return nil, errors.New("cluster: fichier d'ancres trop volumineux")
	}
	return parseAnchors(buf, s.controllers, s.quorum)
}

func parseAnchors(data []byte, ctrls map[int]ed25519.PublicKey, quorum int) (map[uint64]AnchorEntry, error) {
	var af AnchorFile
	if err := strictjson.Decode(data, &af); err != nil {
		return nil, fmt.Errorf("cluster: fichier d'ancres illisible : %w", err)
	}
	if af.Payload.Kind != anchorsKind {
		return nil, errors.New("cluster: fichier d'ancres : kind inattendu")
	}
	canonical, err := json.Marshal(af.Payload)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	valid := 0
	for _, sg := range af.Signatures {
		if seen[sg.KeyID] {
			return nil, fmt.Errorf("cluster: ancres : signataire %d en double", sg.KeyID)
		}
		seen[sg.KeyID] = true
		pub, ok := ctrls[sg.KeyID]
		if !ok {
			return nil, fmt.Errorf("cluster: ancres : key_id %d hors manifeste", sg.KeyID)
		}
		raw, err := hex.DecodeString(sg.Sig)
		if err != nil || len(raw) != ed25519.SignatureSize || !ed25519.Verify(pub, canonical, raw) {
			return nil, fmt.Errorf("cluster: ancres : signature du contrôleur %d invalide", sg.KeyID)
		}
		valid++
	}
	if valid < quorum {
		return nil, fmt.Errorf("cluster: ancres : quorum non atteint (%d valide(s), %d requises)", valid, quorum)
	}
	if len(af.Payload.Anchors) == 0 || len(af.Payload.Anchors) > MaxAnchorEntries {
		return nil, errors.New("cluster: ancres : nombre d'entrées hors bornes")
	}
	out := make(map[uint64]AnchorEntry, len(af.Payload.Anchors))
	for _, e := range af.Payload.Anchors {
		if _, dup := out[e.Epoch]; dup {
			return nil, fmt.Errorf("cluster: ancres : époque %d en double", e.Epoch)
		}
		if raw, err := hex.DecodeString(e.BundleHash); err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("cluster: ancres : bundle_hash de l'époque %d illisible", e.Epoch)
		}
		start, err1 := time.Parse(time.RFC3339, e.WindowStart)
		end, err2 := time.Parse(time.RFC3339, e.WindowEnd)
		if err1 != nil || err2 != nil || !end.After(start) || end.Sub(start) > MaxAnchorWindow {
			return nil, fmt.Errorf("cluster: ancres : fenêtre de l'époque %d incohérente ou > %s", e.Epoch, MaxAnchorWindow)
		}
		out[e.Epoch] = e
	}
	return out, nil
}

// BundleAnchor rend le hash du bundle ancré pour l'époque (ok=false : pas d'ancre vérifiable).
func (s *FileAnchorSource) BundleAnchor(epoch uint64) ([32]byte, bool) {
	var h [32]byte
	m, err := s.Verify()
	if err != nil {
		return h, false
	}
	e, ok := m[epoch]
	if !ok {
		return h, false
	}
	raw, _ := hex.DecodeString(e.BundleHash) // validé par parseAnchors
	copy(h[:], raw)
	return h, true
}

// HealthyWindow rend la fenêtre saine ancrée pour l'époque (ok=false : pas d'ancre vérifiable).
func (s *FileAnchorSource) HealthyWindow(epoch uint64) (time.Time, time.Time, bool) {
	m, err := s.Verify()
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	e, ok := m[epoch]
	if !ok {
		return time.Time{}, time.Time{}, false
	}
	start, _ := time.Parse(time.RFC3339, e.WindowStart)
	end, _ := time.Parse(time.RFC3339, e.WindowEnd)
	return start, end, true
}

// SignAnchors est l'outil de cérémonie (tests, scripts de genèse) : signe un payload avec les clés données.
func SignAnchors(payload AnchorPayload, privs map[int]ed25519.PrivateKey) ([]byte, error) {
	payload.Kind = anchorsKind
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	af := AnchorFile{Payload: payload}
	for id := 1; id <= len(privs); id++ { // ordre déterministe
		priv, ok := privs[id]
		if !ok {
			continue
		}
		af.Signatures = append(af.Signatures, ControllerSignature{KeyID: id, Sig: hex.EncodeToString(ed25519.Sign(priv, canonical))})
	}
	return json.Marshal(af)
}
