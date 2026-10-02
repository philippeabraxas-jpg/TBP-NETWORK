// src/registry/cell_log.go — T4 (issue #8)
//
// Registre de cellule : log chaîné par hash (pattern CT / RFC 6962) adossé
// au driver POSIX de Tessera — un répertoire = un log de cellule (§6).
//
// Chemin « chaud » (§6.2) : l'écriture est locale et synchrone, SANS
// coordination — elle ne bloque jamais sur la master chain, qu'elle soit
// joignable ou non. C'est ce qui rend l'écriture « tiède » vers la master
// chain asynchrone plutôt que bloquante.
//
// Pas de full homebrew : le chaînage Merkle (séparation de domaine
// feuille/nœud RFC 6962, preuves de consistance) est celui de Tessera,
// publiquement audité — une preuve vérifiable par un tiers perd sa valeur
// si l'auditeur doit relire notre code (§6).
//
// Backpressure disque (voir README de ce répertoire) : le quota et son
// seuil de 80 % sont implémentés par T5 ; T4 fournit le POINT DE COUTURE
// (BackpressureChecker) dans le chemin d'écriture. Quand il est engagé,
// Append refuse avec ErrBackpressure — fail-closed, pas un crash. Doctrine
// README : l'arrêt est lui-même une feuille (KindBackpressure) écrite
// AVANT l'engagement, et une alarme (classe W, §5.3).
package registry

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
)

// ErrBackpressure est retourné par Append quand le backpressure disque (T5)
// est engagé : aucune écriture ne passe — arrêt propre, pas un crash.
var ErrBackpressure = errors.New("registre : backpressure disque engagé — écriture refusée (fail-closed)")

// BackpressureChecker est la couture vers T5 (quota disque de la cellule).
// Une implémentation nil signifie « jamais engagé » (dev minimal).
type BackpressureChecker interface {
	// Engaged rapporte si le quota disque de la cellule a franchi son seuil.
	Engaged() bool
}

// BackpressureFunc adapte une fonction en BackpressureChecker (tests, T5).
type BackpressureFunc func() bool

// Engaged implémente BackpressureChecker.
func (f BackpressureFunc) Engaged() bool { return f() }

// Options paramètre l'ouverture d'un CellLog.
type Options struct {
	// Dir est le répertoire du log de la cellule (un répertoire = un log).
	Dir string
	// Signer signe les checkpoints du log (clé note Ed25519 — §12 : Ed25519
	// partout). Le nom de la clé est l'origine du log, ex.
	// "tbp/registry/cell-a" — voir GenerateCellKey.
	Signer note.Signer
	// Verifier vérifie les checkpoints lus (Head) — la contrepartie publique
	// du Signer. La vérification rend la tête opposable à un tiers (§6).
	Verifier note.Verifier
	// Backpressure, si non nil, est consulté avant chaque écriture (T5).
	Backpressure BackpressureChecker
	// BatchSize / BatchAge / CheckpointInterval : réglages Tessera.
	// Zéro = défauts (256 feuilles, 200 ms, 100 ms — le minimum POSIX).
	BatchSize          uint
	BatchAge           time.Duration
	CheckpointInterval time.Duration
}

const (
	defaultBatchSize          = 256
	defaultBatchAge           = 200 * time.Millisecond
	defaultCheckpointInterval = 100 * time.Millisecond // minimum accepté par le driver POSIX
	awaitPollPeriod           = 50 * time.Millisecond
)

// CellLog est le registre local d'une cellule.
type CellLog struct {
	appender *tessera.Appender
	shutdown func(context.Context) error
	reader   tessera.LogReader
	await    *tessera.PublicationAwaiter
	verifier note.Verifier
	bp       BackpressureChecker
	// bgCancel arrête les tâches d'arrière-plan de Tessera (file, appender,
	// ramasse-miettes, statistiques d'intégration, scrutation de
	// l'awaiter). Doctrine documentée par tessera.NewAppender lui-même :
	// « the correct process for shutting down an Appender cleanly is to
	// first call the shutdown function that is returned, and then cancel
	// the context » — le contexte en question est celui passé à
	// NewAppender/NewPublicationAwaiter, JAMAIS celui de l'appelant d'Open
	// (qui ne sert qu'à l'ouverture elle-même et peut rester vivant après,
	// voire ne jamais être annulé — context.Background() dans la quasi-
	// totalité des appelants). Avant ce champ, Close() n'appelait QUE
	// shutdown() sans jamais annuler ce contexte : les 5 goroutines
	// Tessera par CellLog ne s'arrêtaient JAMAIS (confirmé par dump de
	// goroutines, y compris 10 s après Close() — pas un délai, une fuite
	// permanente), quel que soit le soin apporté par l'appelant à fermer
	// le CellLog.
	bgCancel context.CancelFunc
	// cpInterval est l'intervalle de checkpoint résolu à l'ouverture —
	// lu par AsyncWriter (T38, #71) pour borner sa fenêtre d'opposabilité.
	cpInterval time.Duration
	// inflight suit les Append acceptés et pas encore terminés — T5 :
	// quand le backpressure s'engage, le moniteur attend leur drainage
	// (waitInflight) avant d'écrire la feuille d'arrêt, ce qui garantit
	// que KindBackpressure est littéralement la DERNIÈRE feuille du log.
	// Mutex+cond plutôt que sync.WaitGroup : Add concurrent à Wait quand
	// le compteur est à zéro est un motif interdit (le double contrôle
	// d'Append peut produire exactement cet entrelacement).
	inflightMu sync.Mutex
	inflightN  int64
	inflightCh chan struct{} // créé au premier enter, fermé et remis à nil au retour à zéro
}

// Open ouvre (ou crée) le log de la cellule dans opts.Dir. L'opération est
// purement locale : aucun réseau, aucune master chain.
func Open(ctx context.Context, opts Options) (*CellLog, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("Options.Dir requis")
	}
	if opts.Signer == nil || opts.Verifier == nil {
		return nil, fmt.Errorf("Signer et Verifier requis (checkpoints signés Ed25519, §12)")
	}
	driver, err := posix.New(ctx, posix.Config{Path: opts.Dir})
	if err != nil {
		return nil, fmt.Errorf("driver posix: %w", err)
	}

	batchSize := opts.BatchSize
	if batchSize == 0 {
		batchSize = defaultBatchSize
	}
	batchAge := opts.BatchAge
	if batchAge == 0 {
		batchAge = defaultBatchAge
	}
	cpInterval := opts.CheckpointInterval
	if cpInterval == 0 {
		cpInterval = defaultCheckpointInterval
	}

	// Contexte D'ARRIÈRE-PLAN propre au CellLog — JAMAIS celui de l'appelant
	// (ctx ci-dessus ne sert qu'à cette ouverture). Tessera référence ce
	// contexte pour la durée de vie de ses goroutines internes (doc de
	// NewAppender) ; bgCancel, appelé par Close() APRÈS shutdown() (jamais
	// avant : annuler avant shutdown risquerait de perdre des entrées non
	// encore publiées, même doc), est ce qui les arrête réellement.
	bgCtx, bgCancel := context.WithCancel(context.Background())
	appender, shutdown, reader, err := tessera.NewAppender(bgCtx, driver,
		tessera.NewAppendOptions().
			WithCheckpointSigner(opts.Signer).
			WithBatching(batchSize, batchAge).
			WithCheckpointInterval(cpInterval))
	if err != nil {
		bgCancel()
		return nil, fmt.Errorf("appender: %w", err)
	}

	return &CellLog{
		appender:   appender,
		shutdown:   shutdown,
		reader:     reader,
		await:      tessera.NewPublicationAwaiter(bgCtx, reader.ReadCheckpoint, awaitPollPeriod),
		verifier:   opts.Verifier,
		bp:         opts.Backpressure,
		cpInterval: cpInterval,
		bgCancel:   bgCancel,
	}, nil
}

// Append ajoute une feuille au log et attend qu'un checkpoint signé la
// couvre (synchrone côté POSIX). Retourne l'index de la feuille.
//
// Jamais de blocage sur la master chain : l'écriture est strictement
// locale. Si le backpressure (T5) est engagé, l'écriture est REFUSÉE avec
// ErrBackpressure — doctrine README : la dernière feuille écrite avant
// l'engagement doit être une feuille KindBackpressure (l'arrêt est tracé).
//
// Double contrôle autour du compteur in-flight : un Append peut passer le
// premier Engaged() juste avant que le moniteur ne verrouille ; le second
// contrôle (après Add) le rattrape alors, et l'append n'a jamais lieu —
// le moniteur attend le drainage (waitInflight) avant la feuille d'arrêt,
// donc tout append accepté AVANT le verrouillage est terminé avant elle.
func (l *CellLog) Append(ctx context.Context, leaf Leaf) (uint64, error) {
	if l.bp != nil && l.bp.Engaged() {
		return 0, ErrBackpressure
	}
	l.inflightEnter()
	defer l.inflightExit()
	if l.bp != nil && l.bp.Engaged() {
		// Le verrou est tombé entre le premier contrôle et l'entrée en
		// vol : waitInflight côté moniteur peut déjà être reparti
		// (compteur à zéro) — on refuse plutôt que d'écrire après la
		// feuille d'arrêt.
		return 0, ErrBackpressure
	}
	return l.appendInternal(ctx, leaf)
}

// appendInternal écrit sans consulter le backpressure — réservé à la
// feuille d'arrêt KindBackpressure du moniteur T5 (qui a déjà verrouillé
// et drainé). Append reste le seul point d'entrée métier.
func (l *CellLog) appendInternal(ctx context.Context, leaf Leaf) (uint64, error) {
	data, err := encodeLeaf(leaf)
	if err != nil {
		return 0, err
	}
	idx, _, err := l.await.Await(ctx, l.appender.Add(ctx, tessera.NewEntry(data)))
	if err != nil {
		return 0, fmt.Errorf("append: %w", err)
	}
	return idx.Index, nil
}

// encodeLeaf sérialise une feuille pour le batcher tessera — partagé par
// le chemin synchrone (appendInternal) et le chemin async borné
// (AsyncWriter, T38/#71) : mêmes octets, seul le moment d'attente change.
func encodeLeaf(leaf Leaf) ([]byte, error) {
	if leaf.Timestamp == 0 {
		// Défaut dev : horloge locale. En production, l'appelant fournit
		// l'horodatage NTS de la cellule (src/registry/README.md).
		leaf.Timestamp = time.Now().UTC().UnixNano()
	}
	data, err := leaf.Marshal()
	if err != nil {
		return nil, fmt.Errorf("feuille invalide: %w", err)
	}
	return data, nil
}

// waitInflight bloque jusqu'au drainage des Append en vol — utilisé par le
// moniteur T5 entre le verrouillage et l'écriture de la feuille d'arrêt.
func (l *CellLog) waitInflight() {
	for {
		l.inflightMu.Lock()
		if l.inflightN == 0 {
			l.inflightMu.Unlock()
			return
		}
		ch := l.inflightCh
		l.inflightMu.Unlock()
		<-ch // fermé au prochain passage à zéro
	}
}

// inflightEnter / inflightExit gèrent le compteur d'Append en vol. Le canal
// n'est créé que s'il n'existe pas, fermé et remis à nil au retour à zéro :
// un waitInflight qui observe n>0 capture LE canal courant et est sûr d'être
// réveillé au prochain drainage complet — sans la course Add/Wait interdite
// de sync.WaitGroup (compteur à zéro).
func (l *CellLog) inflightEnter() {
	l.inflightMu.Lock()
	l.inflightN++
	if l.inflightCh == nil {
		l.inflightCh = make(chan struct{})
	}
	l.inflightMu.Unlock()
}

func (l *CellLog) inflightExit() {
	l.inflightMu.Lock()
	l.inflightN--
	if l.inflightN == 0 && l.inflightCh != nil {
		close(l.inflightCh)
		l.inflightCh = nil
	}
	l.inflightMu.Unlock()
}

// Head retourne la tête courante du log : racine Merkle (32 octets) et
// taille (nombre de feuilles), extraites du dernier checkpoint dont la
// signature est VÉRIFIÉE (note Ed25519, §12) — c'est ce qui rend la tête
// opposable. Utilisée par l'ancrage T6 : hash(broker_id, head, TSA).
func (l *CellLog) Head(ctx context.Context) (root [32]byte, size uint64, err error) {
	raw, err := l.reader.ReadCheckpoint(ctx)
	if err != nil {
		return root, 0, fmt.Errorf("checkpoint: %w", err)
	}
	cp, err := ParseCheckpoint(raw, l.verifier)
	if err != nil {
		return root, 0, err
	}
	copy(root[:], cp.Hash)
	return root, cp.Size, nil
}

// ParseCheckpoint vérifie la signature d'un checkpoint et le décode.
// Séparé de Head pour qu'un TIERS (auditeur, entrant tardif §3.2) puisse
// vérifier un checkpoint avec la seule clé publique du log.
func ParseCheckpoint(raw []byte, verifier note.Verifier) (*log.Checkpoint, error) {
	n, err := note.Open(raw, note.VerifierList(verifier))
	if err != nil {
		return nil, fmt.Errorf("signature de checkpoint invalide: %w", err)
	}
	cp := &log.Checkpoint{}
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil {
		return nil, fmt.Errorf("checkpoint malformé: %w", err)
	}
	return cp, nil
}

// Close termine proprement : flush des feuilles en vol et publication du
// checkpoint final, PUIS arrêt réel des goroutines Tessera d'arrière-plan
// (bgCancel) — dans cet ordre, jamais l'inverse (doc tessera.NewAppender :
// annuler avant shutdown risquerait de perdre des entrées non publiées).
func (l *CellLog) Close(ctx context.Context) error {
	err := l.shutdown(ctx)
	l.bgCancel()
	return err
}

// ---------------------------------------------------------------------------
// Gestion de clé note (dev/test) — §12 : Ed25519 partout.
// La cérémonie de genèse (T3) fournit l'autorité ; la clé de log de cellule
// est une clé opérationnelle locale. En production elle vivra dans le HSM
// de la cellule ; ce helper fichier est l'équivalent dev.
// ---------------------------------------------------------------------------

// GenerateCellKey génère une paire de clés note (Ed25519) pour l'origine
// donnée (ex. "tbp/registry/cell-a"). Retourne (clé privée, clé publique)
// au format note.
func GenerateCellKey(origin string) (skey, vkey string, err error) {
	if origin == "" {
		return "", "", fmt.Errorf("origine requise (identité du log)")
	}
	return note.GenerateKey(rand.Reader, origin)
}

// SaveSignerKey écrit la clé privée note en 0600 — jamais en clair ailleurs.
func SaveSignerKey(dir, skey string) error {
	return os.WriteFile(filepath.Join(dir, "cell_log.key"), []byte(skey+"\n"), 0o600)
}

// LoadSigner recharge le signataire depuis le fichier écrit par SaveSignerKey.
func LoadSigner(dir string) (note.Signer, error) {
	data, err := os.ReadFile(filepath.Join(dir, "cell_log.key"))
	if err != nil {
		return nil, err
	}
	return note.NewSigner(strings.TrimSpace(string(data)))
}

// LoadOrGenerateCellKey charge la clef note du CellLog d'un démon ou la génère au premier
// démarrage : clef signante 0600 (SaveSignerKey), clef de vérification en clair à côté
// (cell_log.vkey) pour reconstruire le Verifier. Toute incohérence (clef présente mais illisible)
// est fatale — fail-closed (§1). Même comportement que les copies de pepd et de brokerd.
func LoadOrGenerateCellKey(dir, cellID string) (note.Signer, string, error) {
	vkeyPath := filepath.Join(dir, "cell_log.vkey")
	signer, err := LoadSigner(dir)
	if err == nil {
		vkeyB, rerr := os.ReadFile(vkeyPath)
		if rerr != nil {
			return nil, "", fmt.Errorf("clef de vérification illisible: %w", rerr)
		}
		return signer, string(vkeyB), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, "", err
	}
	skey, vkey, gerr := GenerateCellKey(cellID)
	if gerr != nil {
		return nil, "", gerr
	}
	if serr := SaveSignerKey(dir, skey); serr != nil {
		return nil, "", serr
	}
	if werr := os.WriteFile(vkeyPath, []byte(vkey), 0o644); werr != nil {
		return nil, "", werr
	}
	ns, nerr := note.NewSigner(skey)
	if nerr != nil {
		return nil, "", nerr
	}
	return ns, vkey, nil
}

// NewVerifier construit le vérificateur public à partir de la clé publique note.
func NewVerifier(vkey string) (note.Verifier, error) {
	return note.NewVerifier(strings.TrimSpace(vkey))
}
