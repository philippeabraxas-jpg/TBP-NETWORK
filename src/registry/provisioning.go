// provisioning.go — mesure des fichiers de provisionnement (issue #192).
//
// Le démarrage mesuré (measured_boot.go, T31) atteste QUATRE artefacts : bundle,
// config OPA, binaire, conteneur IA. Il n'atteste pas les fichiers qui portent la
// confiance de la cellule : registre d'agents (classe, quota), clés d'opérateurs,
// trousseaux de contrôleurs et d'émetteurs, registre de skills, manifeste de
// genèse. Éditer agents.json (classe W → F) supprimait plan et quorum sans la
// moindre alarme, sur toutes les échelles.
//
// Doctrine : « on ne ferme pas tout, on audite tout ». Ce fichier ferme le trou
// avec la MÊME mécanique que le démarrage mesuré, sans réécrire le manifeste
// signé TBP-M1 (champs fixes, D68) :
//
//   - au démarrage, chaque démon mesure les fichiers qu'il charge : SHA-256 de
//     chaque fichier, puis un condensé unique sur la liste triée (nom, hash) ;
//   - premier démarrage (aucun témoin ET journal vide) : GENÈSE — le condensé est
//     engagé dans un TÉMOIN signé par la clé de cellule, hors du répertoire du
//     registre (même raisonnement que #111 : effacer le registre ne doit pas
//     effacer aussi le témoin) ;
//   - démarrages suivants : le condensé mesuré doit égaler celui du témoin, sinon
//     le démarrage est REFUSÉ, l'erreur nomme les fichiers modifiés (jamais leur
//     contenu), une feuille de refus est écrite et l'alarme T14 déclenchée ;
//   - un changement DÉLIBÉRÉ (nouvel agent, clé remplacée) est une TRANSITION :
//     elle exige que l'appelant fournisse une autorisation (AuthorizeTransition).
//     Ce fichier ne décide pas COMMENT on autorise — c'est un réglage d'échelle :
//     à l'échelle 1 l'administrateur seul signe (quorum k = 1), plus haut c'est
//     un quorum k-of-n. Le démon branche ici la preuve de quorum déjà en place
//     (TBP_QUORUM_MIN), donc la brique est la même à toutes les échelles.
//
// Ce que ça ne fait PAS : ça ne détecte pas une modification faite APRÈS le
// démarrage (les registres sont chargés une fois, jamais rechargés à chaud — voir
// skill_registry.go), et un attaquant qui détient la clé de cellule ET peut
// écrire le témoin peut le refabriquer (même confiance que le manifeste TBP-M1).
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// Événements de feuille de provisionnement (record « TBPL3 », KindManifest).
const (
	provEventGenesis    byte = 1 // premier démarrage : condensé engagé
	provEventBoot       byte = 2 // démarrage conforme au témoin
	provEventTransition byte = 3 // changement délibéré, autorisé
	provEventRefuse     byte = 4 // démarrage refusé
)

// Bornes : un fichier de provisionnement est un JSON de configuration, pas une
// image disque — lecture bornée pour qu'un fichier géant ne devienne pas un vecteur mémoire.
const (
	maxProvisioningFiles = 256
	maxProvisioningBytes = 32 << 20
	maxProvisioningName  = 255
)

// Erreurs — codes stables.
var (
	ErrProvisioningConfig         = errors.New("registre: configuration du provisionnement invalide")
	ErrProvisioningMeasure        = errors.New("registre: mesure des fichiers de provisionnement impossible — fail-closed")
	ErrProvisioningWitnessBad     = errors.New("registre: témoin de provisionnement illisible, falsifié ou d'une autre cellule — démarrage refusé")
	ErrProvisioningWitnessMissing = errors.New("registre: témoin de provisionnement absent alors que le journal n'est pas vide — effacement du témoin ou premier démarrage falsifié (§111) ; une transition autorisée est requise pour le ré-engager")
	ErrProvisioningDivergence     = errors.New("registre: fichiers de provisionnement divergents du témoin — démarrage refusé (issue #192)")
	ErrProvisioningLeafFault      = errors.New("registre: feuille de provisionnement impossible — pas de preuve, pas de démarrage (faute système)")
)

// ProvisioningFile désigne un fichier qui porte la confiance de la cellule. Name
// est l'identifiant LOGIQUE (entre dans le condensé et dans les messages) : le
// chemin peut changer d'un hôte à l'autre, pas le rôle du fichier.
type ProvisioningFile struct {
	Name string
	Path string
	// Authority marque un fichier qui DÉCIDE qui peut autoriser un changement (le
	// trousseau de quorum, le manifeste de genèse). Le témoin en conserve le
	// CONTENU : une transition est autorisée par une preuve vérifiée contre ce
	// contenu ATTESTÉ, jamais contre le fichier tel qu'il est maintenant — sinon qui
	// édite le trousseau y ajoute ses clés et signe lui-même sa « transition »
	// (issue #218).
	Authority bool
	// Content non nul : réglage EN MÉMOIRE plutôt que fichier (Path ignoré). Il entre dans le
	// condensé comme un fichier et son contenu est conservé dans le témoin comme celui d'une
	// autorité : un réglage qui gouverne la sécurité — k du quorum, la topologie, c'est-à-dire
	// l'ÉCHELLE — ne peut pas être changé par l'environnement entre deux démarrages sans
	// que la mesure le voie, ni autoriser lui-même son propre changement (issue #224).
	Content []byte
}

// ProvisioningFileHash est le hash mesuré d'un fichier.
type ProvisioningFileHash struct {
	Name string
	Hash [32]byte
}

// MeasureProvisioning mesure la liste : SHA-256 de chaque fichier et condensé
//
//	SHA-256("TBPV1" ‖ pour chaque fichier trié par nom : u8 len(nom) ‖ nom ‖ hash)
//
// Liste vide, nom vide/trop long/dupliqué, fichier illisible ou trop gros : erreur
// (jamais un fichier « passé » — même doctrine que ComponentPaths).
func MeasureProvisioning(files []ProvisioningFile) ([32]byte, []ProvisioningFileHash, error) {
	digest, per, _, err := measureProvisioning(files)
	return digest, per, err
}

// maxAuthorityBytes borne le contenu d'un fichier d'autorité conservé dans le
// témoin : un trousseau de clés publiques, pas une image disque.
const maxAuthorityBytes = 64 << 10

// measureProvisioning est MeasureProvisioning qui rend en plus le contenu des
// fichiers d'AUTORITÉ. Le hash et l'instantané viennent des MÊMES octets, lus une
// seule fois : pas de fenêtre entre « ce qu'on a mesuré » et « ce qu'on retient ».
func measureProvisioning(files []ProvisioningFile) ([32]byte, []ProvisioningFileHash, map[string][]byte, error) {
	var digest [32]byte
	if len(files) == 0 {
		return digest, nil, nil, fmt.Errorf("%w : aucun fichier — un condensé vide n'atteste rien", ErrProvisioningConfig)
	}
	if len(files) > maxProvisioningFiles {
		return digest, nil, nil, fmt.Errorf("%w : %d fichiers (max %d)", ErrProvisioningConfig, len(files), maxProvisioningFiles)
	}
	seen := make(map[string]bool, len(files))
	per := make([]ProvisioningFileHash, 0, len(files))
	authorities := map[string][]byte{}
	for _, f := range files {
		if f.Name == "" || len(f.Name) > maxProvisioningName {
			return digest, nil, nil, fmt.Errorf("%w : nom vide ou > %d octets", ErrProvisioningConfig, maxProvisioningName)
		}
		if seen[f.Name] {
			return digest, nil, nil, fmt.Errorf("%w : nom en double %q", ErrProvisioningConfig, f.Name)
		}
		seen[f.Name] = true
		if f.Content != nil {
			if len(f.Content) > maxAuthorityBytes {
				return digest, nil, nil, fmt.Errorf("%w : %q : réglage de plus de %d octets", ErrProvisioningConfig, f.Name, maxAuthorityBytes)
			}
			authorities[f.Name] = append([]byte(nil), f.Content...)
			per = append(per, ProvisioningFileHash{Name: f.Name, Hash: sha256.Sum256(f.Content)})
			continue
		}
		if f.Authority {
			raw, err := readBoundedBytes(f.Path, maxAuthorityBytes)
			if err != nil {
				return digest, nil, nil, fmt.Errorf("%w : %q : %v", ErrProvisioningMeasure, f.Name, err)
			}
			authorities[f.Name] = raw
			per = append(per, ProvisioningFileHash{Name: f.Name, Hash: sha256.Sum256(raw)})
			continue
		}
		h, err := hashBoundedFile(f.Path)
		if err != nil {
			return digest, nil, nil, fmt.Errorf("%w : %q : %v", ErrProvisioningMeasure, f.Name, err)
		}
		per = append(per, ProvisioningFileHash{Name: f.Name, Hash: h})
	}
	sort.Slice(per, func(i, j int) bool { return per[i].Name < per[j].Name })
	h := sha256.New()
	h.Write([]byte("TBPV1"))
	for _, p := range per {
		h.Write([]byte{byte(len(p.Name))})
		h.Write([]byte(p.Name))
		h.Write(p.Hash[:])
	}
	copy(digest[:], h.Sum(nil))
	return digest, per, authorities, nil
}

// readBoundedBytes lit un fichier régulier d'au plus max octets.
func readBoundedBytes(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("n'est pas un fichier régulier")
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("plus de %d octets", max)
	}
	return raw, nil
}

// hashBoundedFile lit le fichier avec une borne dure : au-delà, refus.
func hashBoundedFile(path string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !st.Mode().IsRegular() {
		return out, errors.New("n'est pas un fichier régulier")
	}
	if st.Size() > maxProvisioningBytes {
		return out, fmt.Errorf("plus de %d octets", maxProvisioningBytes)
	}
	h := sha256.New()
	// LimitReader : la taille peut croître entre Stat et la lecture.
	n, err := io.Copy(h, io.LimitReader(f, maxProvisioningBytes+1))
	if err != nil {
		return out, err
	}
	if n > maxProvisioningBytes {
		return out, fmt.Errorf("plus de %d octets", maxProvisioningBytes)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// ---------------------------------------------------------------------------
// Témoin signé
// ---------------------------------------------------------------------------

// Layout du record canonique « TBP-V1 » du témoin (champs fixes, pas de map :
// déterminisme §11.3).
//
//	"TBP-V1" ‖ v(u8) ‖ u8 len(cellID) ‖ cellID ‖ u8 len(component) ‖ component
//	         ‖ seq(u64 BE) ‖ prev(32) ‖ digest(32)
//	         ‖ u16 nfiles ‖ nfiles × (u8 len(name) ‖ name ‖ hash(32))
//	         ‖ [v ≥ 2 : u8 nauth ‖ nauth × (u8 len(name) ‖ name ‖ u32 len ‖ contenu)]
//	         ‖ issuedAt(u64 BE)
//
// v1 : sans instantané des fichiers d'autorité (témoins d'avant #218). v2 : avec.
// Le préfixe reste « TBP-V1 » (identité du format) ; c'est l'octet de version qui
// distingue.
const (
	witnessPrefix = "TBP-V1"
	witnessVer    = 2
)

// ProvisioningWitness est la forme parsée du témoin.
type ProvisioningWitness struct {
	CellID    string
	Component string
	Seq       uint64
	Prev      [32]byte
	Digest    [32]byte
	Files     []ProvisioningFileHash
	// Authorities : contenu des fichiers d'autorité tel qu'ATTESTÉ (v2).
	Authorities map[string][]byte
	// Legacy : témoin v1, sans instantané. Jamais écrit, seulement lu.
	Legacy   bool
	IssuedAt time.Time
}

func marshalWitnessRecord(w ProvisioningWitness) []byte {
	r := make([]byte, 0, 6+1+1+len(w.CellID)+1+len(w.Component)+8+32+32+2+len(w.Files)*(1+16+32)+8)
	r = append(r, witnessPrefix...)
	r = append(r, witnessVer, byte(len(w.CellID)))
	r = append(r, w.CellID...)
	r = append(r, byte(len(w.Component)))
	r = append(r, w.Component...)
	r = binary.BigEndian.AppendUint64(r, w.Seq)
	r = append(r, w.Prev[:]...)
	r = append(r, w.Digest[:]...)
	r = binary.BigEndian.AppendUint16(r, uint16(len(w.Files)))
	for _, f := range w.Files {
		r = append(r, byte(len(f.Name)))
		r = append(r, f.Name...)
		r = append(r, f.Hash[:]...)
	}
	names := make([]string, 0, len(w.Authorities))
	for n := range w.Authorities {
		names = append(names, n)
	}
	sort.Strings(names) // déterministe (§11.3)
	r = append(r, byte(len(names)))
	for _, n := range names {
		r = append(r, byte(len(n)))
		r = append(r, n...)
		r = binary.BigEndian.AppendUint32(r, uint32(len(w.Authorities[n])))
		r = append(r, w.Authorities[n]...)
	}
	return binary.BigEndian.AppendUint64(r, uint64(w.IssuedAt.Unix()))
}

func parseWitnessRecord(r []byte) (ProvisioningWitness, error) {
	var w ProvisioningWitness
	bad := func(why string) (ProvisioningWitness, error) {
		return w, fmt.Errorf("%w : %s", ErrProvisioningWitnessBad, why)
	}
	if len(r) < 6+1+1 || string(r[:6]) != witnessPrefix {
		return bad("préfixe")
	}
	ver := r[6]
	if ver != 1 && ver != witnessVer {
		return bad("version inconnue")
	}
	w.Legacy = ver == 1
	p := 7
	readStr := func() (string, bool) {
		if p >= len(r) {
			return "", false
		}
		n := int(r[p])
		p++
		if n == 0 || p+n > len(r) {
			return "", false
		}
		s := string(r[p : p+n])
		p += n
		return s, true
	}
	var ok bool
	if w.CellID, ok = readStr(); !ok {
		return bad("cellID")
	}
	if w.Component, ok = readStr(); !ok {
		return bad("composant")
	}
	if p+8+32+32+2 > len(r) {
		return bad("tronqué")
	}
	w.Seq = binary.BigEndian.Uint64(r[p:])
	p += 8
	copy(w.Prev[:], r[p:])
	p += 32
	copy(w.Digest[:], r[p:])
	p += 32
	n := int(binary.BigEndian.Uint16(r[p:]))
	p += 2
	if n == 0 || n > maxProvisioningFiles {
		return bad("nombre de fichiers")
	}
	w.Files = make([]ProvisioningFileHash, 0, n)
	for i := 0; i < n; i++ {
		name, ok := readStr()
		if !ok || p+32 > len(r) {
			return bad("fichier")
		}
		var fh ProvisioningFileHash
		fh.Name = name
		copy(fh.Hash[:], r[p:])
		p += 32
		w.Files = append(w.Files, fh)
	}
	if ver >= 2 {
		if p >= len(r) {
			return bad("autorités")
		}
		nauth := int(r[p])
		p++
		if nauth > 0 {
			w.Authorities = make(map[string][]byte, nauth)
		}
		for i := 0; i < nauth; i++ {
			name, ok := readStr()
			if !ok || p+4 > len(r) {
				return bad("autorité")
			}
			n := int(binary.BigEndian.Uint32(r[p:]))
			p += 4
			if n > maxAuthorityBytes || p+n > len(r) {
				return bad("autorité : contenu")
			}
			if _, dup := w.Authorities[name]; dup {
				return bad("autorité en double")
			}
			w.Authorities[name] = append([]byte(nil), r[p:p+n]...)
			p += n
		}
	}
	if len(r)-p != 8 {
		return bad("longueur")
	}
	w.IssuedAt = time.Unix(int64(binary.BigEndian.Uint64(r[p:])), 0)
	return w, nil
}

// witnessFile est la forme persistée : record canonique + signature, en hex.
type witnessFile struct {
	Record    string `json:"record"`
	Signature string `json:"signature"`
}

// ---------------------------------------------------------------------------
// Garde
// ---------------------------------------------------------------------------

// ParseProvisioningExtra lit la liste « nom=chemin,chemin,… » de
// TBP_PROVISIONING_EXTRA_FILES (une entrée sans « = » a pour nom son chemin). Les
// noms sont préfixés « extra: » : un fichier ajouté à la main ne peut jamais usurper
// le nom d'un fichier que le démon dérive lui-même. Mutualisé par pepd et brokerd.
func ParseProvisioningExtra(list string) ([]ProvisioningFile, error) {
	var out []ProvisioningFile
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, path := item, item
		if i := strings.Index(item, "="); i > 0 {
			name, path = item[:i], item[i+1:]
		}
		if path == "" {
			return nil, fmt.Errorf("%w : entrée %q sans chemin", ErrProvisioningConfig, item)
		}
		out = append(out, ProvisioningFile{Name: "extra:" + name, Path: path})
	}
	return out, nil
}

// LogHead est la couture de lecture de la taille du journal — implémentée par
// CellLog. Elle distingue un PREMIER démarrage (journal vide) d'un redémarrage
// dont le témoin a été effacé.
type LogHead interface {
	Head(ctx context.Context) (root [32]byte, size uint64, err error)
}

// ProvisioningGuardOptions paramètre le garde. Fail-closed dès la construction.
type ProvisioningGuardOptions struct {
	// CellID et Component (« pepd », « brokerd »…) entrent dans le témoin : un
	// témoin d'un autre démon ou d'une autre cellule est refusé.
	CellID    string
	Component string
	// Files : ce que ce démon charge. Le démon les dérive de sa propre
	// configuration (jamais d'une liste que l'opérateur peut oublier de remplir).
	Files []ProvisioningFile
	// WitnessFile : chemin du témoin persisté. DOIT être hors de RegistryDir.
	WitnessFile string
	// RegistryDir : répertoire du journal de ce démon (pour la garde #111).
	RegistryDir string
	// Signer/Verifier : clé de cellule (celle des checkpoints, D69). Comme pour le
	// manifeste : Signer.Sign(record) et Verifier.Verify(record, sig) DIRECTEMENT.
	Signer   note.Signer
	Verifier note.Verifier
	// Leaves reçoit la feuille KindManifest de chaque événement (§4.1) ; Log lit la
	// taille du journal (typiquement le même CellLog).
	Leaves LeafAppender
	// Journal reçoit le clair de chaque feuille AVANT son inscription (#275, #271).
	// Optionnel ici (nil = feuille nue, historique) ; les démons le renseignent.
	Journal *RecordStore
	Log     LogHead
	Salt    []byte
	// AuthorizeTransition autorise un changement délibéré (ou le ré-engagement d'un
	// témoin effacé). Nil ⇒ toute divergence est refusée. C'est le RÉGLAGE D'ÉCHELLE :
	// preuve d'un administrateur (k = 1) ou d'un quorum k-of-n.
	//
	// prev est le contenu des fichiers d'AUTORITÉ tel que le dernier témoin l'a
	// ATTESTÉ : la preuve se vérifie contre CES clés, jamais contre le fichier
	// courant que l'attaquant vient d'éditer (issue #218). prev est nil quand il n'y
	// a rien d'attesté à opposer — premier démarrage, ou ré-engagement après
	// effacement du témoin (confiance à la première utilisation, documentée).
	//
	// from est le condensé ATTESTÉ (celui du dernier témoin ; nul en l'absence de
	// témoin) et to le condensé de l'état CIBLE mesuré. La preuve doit les lier
	// (issue #236) : sans cela une preuve valide ré-engagerait n'importe quel état
	// présent au démarrage, et se rejouerait pour revenir à un état antérieur.
	AuthorizeTransition func(prev map[string][]byte, from, to [32]byte) error
	OnTrip              func(reason string)
	Now                 func() time.Time
}

// ProvisioningGuard mesure et atteste les fichiers de provisionnement.
type ProvisioningGuard struct {
	o    ProvisioningGuardOptions
	salt []byte
	mu   sync.Mutex
}

// NewProvisioningGuard valide la configuration.
func NewProvisioningGuard(o ProvisioningGuardOptions) (*ProvisioningGuard, error) {
	switch {
	case o.CellID == "" || len(o.CellID) > maxProvisioningName:
		return nil, fmt.Errorf("%w : cellID requis, ≤ %d octets", ErrProvisioningConfig, maxProvisioningName)
	case o.Component == "" || len(o.Component) > maxProvisioningName:
		return nil, fmt.Errorf("%w : composant requis", ErrProvisioningConfig)
	case o.WitnessFile == "":
		return nil, fmt.Errorf("%w : chemin du témoin requis", ErrProvisioningConfig)
	case o.Signer == nil || o.Verifier == nil:
		return nil, fmt.Errorf("%w : clé de cellule (signer + verifier) requise", ErrProvisioningConfig)
	case o.Leaves == nil || o.Log == nil:
		return nil, fmt.Errorf("%w : journal requis (§4.1 : chaque événement laisse une feuille)", ErrProvisioningConfig)
	case len(o.Salt) < 16:
		return nil, fmt.Errorf("%w : sel ≥ 16 octets requis (§6.2)", ErrProvisioningConfig)
	}
	if o.RegistryDir != "" {
		wf, err1 := filepath.Abs(o.WitnessFile)
		rd, err2 := filepath.Abs(o.RegistryDir)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w : chemins illisibles", ErrProvisioningConfig)
		}
		if wf == rd || strings.HasPrefix(wf, rd+string(filepath.Separator)) {
			return nil, fmt.Errorf("%w : le témoin (%s) est SOUS le répertoire du registre (%s) — effacer le registre effacerait aussi le témoin, le premier démarrage falsifié (§111) passerait inaperçu ; choisir un chemin hors de ce répertoire", ErrProvisioningConfig, o.WitnessFile, o.RegistryDir)
		}
	}
	if _, _, err := MeasureProvisioning(o.Files); errors.Is(err, ErrProvisioningConfig) {
		return nil, err // liste invalide : refusée dès la construction
	}
	salt := append([]byte(nil), o.Salt...)
	return &ProvisioningGuard{o: o, salt: salt}, nil
}

func (g *ProvisioningGuard) now() time.Time {
	if g.o.Now != nil {
		return g.o.Now()
	}
	return time.Now()
}

func (g *ProvisioningGuard) trip(reason string) {
	if g.o.OnTrip != nil {
		g.o.OnTrip(reason)
	}
}

// Check est l'appel de démarrage. nil ⇒ le démon peut charger ses fichiers ; toute
// autre valeur est fatale. À appeler AVANT que le démon n'utilise les fichiers et
// avant toute autre écriture dans son journal (la taille du journal sert à
// reconnaître un premier démarrage).
func (g *ProvisioningGuard) Check(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	digest, per, authorities, err := measureProvisioning(g.o.Files)
	if err != nil {
		g.trip("provisioning-measure-fault")
		return g.refuse(ctx, [32]byte{}, 0, "measure-fault", err)
	}

	last, err := g.loadWitness()
	if err != nil {
		g.trip("provisioning-witness-invalid")
		return g.refuse(ctx, digest, 0, "witness-invalid", err)
	}

	if last == nil {
		_, size, herr := g.o.Log.Head(ctx)
		if herr != nil {
			g.trip("provisioning-log-fault")
			return g.refuse(ctx, digest, 0, "log-fault", fmt.Errorf("%w : tête du journal illisible : %v", ErrProvisioningMeasure, herr))
		}
		if size == 0 {
			// Premier démarrage : confiance à la première utilisation, assumée et
			// documentée (même scission que la genèse du manifeste TBP-M1).
			return g.commit(ctx, provEventGenesis, ProvisioningWitness{Seq: 0, Authorities: authorities}, digest, per, "genesis")
		}
		// Témoin absent alors que le journal a déjà vécu.
		if g.o.AuthorizeTransition == nil {
			g.trip("provisioning-witness-missing")
			return g.refuse(ctx, digest, 0, "witness-missing", ErrProvisioningWitnessMissing)
		}
		// Rien d'attesté à opposer (le témoin est perdu) : prev = nil, le démon
		// retombe sur le trousseau courant. C'est un acte d'installation, pas une
		// transition — documenté (issue #218).
		if aerr := g.o.AuthorizeTransition(nil, [32]byte{}, digest); aerr != nil {
			g.trip("provisioning-witness-missing")
			return g.refuse(ctx, digest, 0, "witness-missing", fmt.Errorf("%w : autorisation refusée : %v", ErrProvisioningWitnessMissing, aerr))
		}
		return g.commit(ctx, provEventTransition, ProvisioningWitness{Seq: 0, Authorities: authorities}, digest, per, "re-engaged")
	}

	if last.Digest == digest {
		if last.Legacy {
			// Témoin d'avant #218 (sans instantané des fichiers d'autorité) : les
			// fichiers n'ont pas changé, donc leur contenu courant EST l'attesté —
			// mise à niveau sur place, sans autorisation.
			next := ProvisioningWitness{Seq: last.Seq + 1, Prev: HashManifest(marshalWitnessRecord(*last)), Authorities: authorities}
			return g.commit(ctx, provEventTransition, next, digest, per, "witness-upgraded")
		}
		return g.leaf(ctx, provEventBoot, digest, last.Seq, 1, "ok")
	}

	changed := changedNames(last.Files, per)
	if last.Legacy {
		// Divergence face à un témoin SANS instantané : il n'y a pas de trousseau
		// attesté contre lequel vérifier une preuve, et retomber sur le trousseau
		// courant serait précisément la faille #218 (rétrogradation par rejeu d'un
		// vieux témoin). Refus : le ré-engagement (effacer le témoin) est l'acte
		// d'installation explicite.
		g.trip("provisioning-divergence")
		return g.refuse(ctx, digest, last.Seq, "divergence", fmt.Errorf("%w : %s (témoin d'avant #218 sans instantané des fichiers d'autorité : ré-engager explicitement)", ErrProvisioningDivergence, changed))
	}
	if g.o.AuthorizeTransition != nil {
		if aerr := g.o.AuthorizeTransition(last.Authorities, last.Digest, digest); aerr == nil {
			next := ProvisioningWitness{Seq: last.Seq + 1, Prev: HashManifest(marshalWitnessRecord(*last)), Authorities: authorities}
			return g.commit(ctx, provEventTransition, next, digest, per, "transition")
		} else {
			g.trip("provisioning-divergence")
			return g.refuse(ctx, digest, last.Seq, "divergence", fmt.Errorf("%w : %s ; transition refusée : %v", ErrProvisioningDivergence, changed, aerr))
		}
	}
	g.trip("provisioning-divergence")
	return g.refuse(ctx, digest, last.Seq, "divergence", fmt.Errorf("%w : %s (aucune transition autorisée)", ErrProvisioningDivergence, changed))
}

// changedNames décrit la différence par NOM de fichier (jamais le contenu).
func changedNames(old, cur []ProvisioningFileHash) string {
	om := make(map[string][32]byte, len(old))
	for _, f := range old {
		om[f.Name] = f.Hash
	}
	cm := make(map[string][32]byte, len(cur))
	for _, f := range cur {
		cm[f.Name] = f.Hash
	}
	var mod, add, del []string
	for n, h := range cm {
		if oh, ok := om[n]; !ok {
			add = append(add, n)
		} else if oh != h {
			mod = append(mod, n)
		}
	}
	for n := range om {
		if _, ok := cm[n]; !ok {
			del = append(del, n)
		}
	}
	sort.Strings(mod)
	sort.Strings(add)
	sort.Strings(del)
	var parts []string
	if len(mod) > 0 {
		parts = append(parts, "modifié(s) : "+strings.Join(mod, ", "))
	}
	if len(add) > 0 {
		parts = append(parts, "ajouté(s) : "+strings.Join(add, ", "))
	}
	if len(del) > 0 {
		parts = append(parts, "retiré(s) : "+strings.Join(del, ", "))
	}
	if len(parts) == 0 {
		return "condensé différent"
	}
	return strings.Join(parts, " ; ")
}

// commit signe et persiste un nouveau témoin, puis écrit la feuille. Ordre : la
// feuille PRÉCÈDE la persistance — pas de preuve, pas d'état attesté.
func (g *ProvisioningGuard) commit(ctx context.Context, event byte, base ProvisioningWitness, digest [32]byte, per []ProvisioningFileHash, reason string) error {
	w := ProvisioningWitness{
		CellID: g.o.CellID, Component: g.o.Component,
		Seq: base.Seq, Prev: base.Prev, Digest: digest, Files: per, Authorities: base.Authorities, IssuedAt: g.now(),
	}
	rec := marshalWitnessRecord(w)
	sig, err := g.o.Signer.Sign(rec)
	if err != nil {
		g.trip("provisioning-sign-fault")
		return fmt.Errorf("%w : signature du témoin : %v", ErrProvisioningLeafFault, err)
	}
	if err := g.leaf(ctx, event, digest, w.Seq, 1, reason); err != nil {
		return err
	}
	if err := g.persist(witnessFile{Record: hex.EncodeToString(rec), Signature: hex.EncodeToString(sig)}); err != nil {
		g.trip("provisioning-persist-fault")
		return fmt.Errorf("%w : %v", ErrProvisioningLeafFault, err)
	}
	return nil
}

func (g *ProvisioningGuard) persist(wf witnessFile) error {
	data, err := json.Marshal(wf)
	if err != nil {
		return err
	}
	tmp := g.o.WitnessFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, g.o.WitnessFile)
}

// loadWitness lit et VÉRIFIE le témoin : absent ⇒ (nil, nil) ; tout défaut (JSON,
// signature, autre cellule ou autre composant) est une erreur.
func (g *ProvisioningGuard) loadWitness() (*ProvisioningWitness, error) {
	return readProvisioningWitness(g.o.WitnessFile, g.o.CellID, g.o.Component, g.o.Verifier)
}

// readProvisioningWitness est la lecture vérifiée du témoin, partagée par le garde et par
// PreviewProvisioning : UNE seule implémentation de ce qui fait foi comme état attesté.
func readProvisioningWitness(path, cellID, component string, verifier note.Verifier) (*ProvisioningWitness, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w : lecture : %v", ErrProvisioningWitnessBad, err)
	}
	var wf witnessFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("%w : JSON : %v", ErrProvisioningWitnessBad, err)
	}
	rec, err1 := hex.DecodeString(wf.Record)
	sig, err2 := hex.DecodeString(wf.Signature)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%w : hex", ErrProvisioningWitnessBad)
	}
	w, err := parseWitnessRecord(rec)
	if err != nil {
		return nil, err
	}
	if !verifier.Verify(rec, sig) {
		return nil, fmt.Errorf("%w : signature invalide", ErrProvisioningWitnessBad)
	}
	if w.CellID != cellID || w.Component != component {
		return nil, fmt.Errorf("%w : témoin de %s/%s, attendu %s/%s", ErrProvisioningWitnessBad, w.CellID, w.Component, cellID, component)
	}
	return &w, nil
}

// ProvisioningPreview est ce qu'un contrôleur doit RECALCULER lui-même avant de signer une
// transition (#264) : l'état de départ attesté par le témoin et l'état cible mesuré sur les fichiers
// qu'il a relus. Rien n'est écrit, rien n'est signé, aucune feuille n'est inscrite.
type ProvisioningPreview struct {
	// WitnessPresent : un témoin vérifié a été lu. Faux ⇒ From est nul (premier démarrage, ou
	// ré-engagement d'un témoin effacé : la condition à signer a alors « from » nul).
	WitnessPresent bool
	From           [32]byte // condensé ATTESTÉ (celui du témoin) ; nul sans témoin
	Seq            uint64
	To             [32]byte // condensé de l'état CIBLE, mesuré sur les fichiers donnés
	Files          []ProvisioningFileHash
	Conforming     bool   // To == From : aucune transition à autoriser
	Changed        string // noms des fichiers qui diffèrent du témoin (jamais leur contenu)
}

// PreviewProvisioning mesure files et lit le témoin avec le MÊME code que ProvisioningGuard.Check
// (measureProvisioning, readProvisioningWitness) : le condensé que le contrôleur recalcule hors de
// la machine est, par construction, celui que le démon calculera. verifier est la clé PUBLIQUE de la
// cellule (cell_log.vkey) : un témoin falsifié ou d'une autre cellule est refusé, jamais lu « tel quel ».
func PreviewProvisioning(files []ProvisioningFile, witnessFile, cellID, component string, verifier note.Verifier) (ProvisioningPreview, error) {
	var pv ProvisioningPreview
	if verifier == nil || cellID == "" || component == "" || witnessFile == "" {
		return pv, fmt.Errorf("%w : cellule, composant, témoin et clé publique requis", ErrProvisioningConfig)
	}
	digest, per, _, err := measureProvisioning(files)
	if err != nil {
		return pv, err
	}
	pv.To, pv.Files = digest, per
	w, err := readProvisioningWitness(witnessFile, cellID, component, verifier)
	if err != nil {
		return pv, err
	}
	if w == nil {
		return pv, nil
	}
	pv.WitnessPresent, pv.From, pv.Seq = true, w.Digest, w.Seq
	pv.Conforming = w.Digest == digest
	if !pv.Conforming {
		pv.Changed = changedNames(w.Files, per)
	}
	return pv, nil
}

// Layout de la feuille « TBPL3 » (hash-only, §6.2) :
//
//	"TBPL3" ‖ event(u8) ‖ u8 len(component) ‖ component ‖ digest(32) ‖ seq(u64 BE)
//	        ‖ verdict(u8) ‖ u8 len(reason) ‖ reason
func (g *ProvisioningGuard) leaf(ctx context.Context, event byte, digest [32]byte, seq uint64, verdict byte, reason string) error {
	rec := make([]byte, 0, 5+1+1+len(g.o.Component)+32+8+1+1+len(reason))
	rec = append(rec, "TBPL3"...)
	rec = append(rec, event, byte(len(g.o.Component)))
	rec = append(rec, g.o.Component...)
	rec = append(rec, digest[:]...)
	rec = binary.BigEndian.AppendUint64(rec, seq)
	rec = append(rec, verdict, byte(len(reason)))
	rec = append(rec, reason...)
	_, err := AppendLeaf(ctx, g.o.Leaves, g.o.Journal, KindManifest, g.o.CellID, g.salt, rec, g.now().UnixNano())
	if err != nil {
		g.trip("provisioning-leaf-fault")
		return fmt.Errorf("%w : %v", ErrProvisioningLeafFault, err)
	}
	return nil
}

// refuse trace le refus (feuille best-effort : le démarrage est déjà refusé, une
// feuille impossible ne le rend pas plus refusé) et rend l'erreur d'origine.
func (g *ProvisioningGuard) refuse(ctx context.Context, digest [32]byte, seq uint64, reason string, cause error) error {
	_ = g.leaf(ctx, provEventRefuse, digest, seq, 0, reason)
	return cause
}
