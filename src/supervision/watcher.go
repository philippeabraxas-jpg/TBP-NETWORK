// src/supervision/watcher.go — T34a (issue #60)
//
// ChainWatcher : lecture VÉRIFIANTE d'un log Tessera POSIX que le moniteur
// n'écrit pas (D77, revue #60). Trois contrôles à chaque tick :
//
//  1. signature du checkpoint (clé note Ed25519 de la cellule — §12) ;
//  2. consistance Merkle checkpoint N-1 → N (LogStateTracker.Update →
//     proof.VerifyConsistency — la « preuve de consistance » de §3,
//     O(log n), sans relire les feuilles déjà vérifiées) ;
//  3. re-hash des NOUVELLES feuilles : octets lus dans les entry bundles
//     (GetEntryBundle) re-hachés RFC 6962 et comparés aux nœuds feuilles
//     des tuiles (FetchLeafHashes) — deux copies stockées indépendamment,
//     une corruption de l'une ne passe pas l'autre.
//
// Le moniteur ne touche JAMAIS au contenu métier : les payloads sont des
// hashs salés opaques (§6.2) ; seuls kind + timestamp sont lus en clair,
// et le kind est contrôlé par la whitelist d'UnmarshalLeaf — une feuille
// d'un kind que ce binaire ne connaît pas est une anomalie, pas une
// feuille à ignorer.
//
// Faute STICKY : une divergence prouvée (inconsistance, re-hash rejeté,
// feuille illisible) verrouille le watcher — chaque Tick suivant rend la
// même faute. Sans ça, le tracker interne aurait déjà avancé et le tick
// suivant verrait une chaîne « à jour » : la faute serait alarmée une
// fois puis oubliée — exactement le silence que §5.3 interdit.
package supervision

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"

	"github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// ErrChainDivergence : la chaîne surveillée a cessé d'être la continuation
// prouvée d'elle-même — discontinuité inexpliquée = corruption (§3).
var ErrChainDivergence = errors.New("supervision: divergence de chaîne")

// ErrChainRewind : le nouveau checkpoint est plus petit que l'état déjà
// vérifié — une chaîne append-only ne recule jamais.
var ErrChainRewind = errors.New("supervision: régression de taille de chaîne")

// ChainWatcher suit un log de cellule (ou la master chain) en lecture
// seule vérifiée. Zéro écriture dans la chaîne surveillée : les seuls
// accès sont FileFetcher (ReadCheckpoint/ReadTile/ReadEntryBundle).
type ChainWatcher struct {
	cellID  string // identité de la chaîne (dans les alertes)
	fetcher client.FileFetcher
	tracker *client.LogStateTracker
	size    uint64 // taille du dernier état vérifié ET feuilles contrôlées
	fault   error  // divergence sticky — rendue à chaque Tick une fois prouvée
}

// NewChainWatcher ouvre la surveillance du log POSIX dans dir. origin est
// le nom de la clé de checkpoint (ex. "tbp/registry/cell-a") et verifier
// la clé publique correspondante — le checkpoint initial est vérifié à la
// construction (fail-closed : un log dont le checkpoint ne vérifie pas
// n'est pas « une chaîne saine en attente », c'est une faute immédiate).
//
// bootstrapFrom : les feuilles [bootstrapFrom, taille) sont contrôlées
// (re-hash + UnmarshalLeaf) et rendues immédiatement — le moniteur en a
// besoin pour la master chain (l'état de fraîcheur d'ancrage existe AVANT
// le premier tick : un ancrage échu ne doit pas attendre une nouvelle
// feuille pour être vu). Passer la taille courante (mode « tail » pur)
// rend nil sans contrôle historique. Le contrôle complet depuis 0 est
// O(n) — borne assumée du pilote P1 (§1 : volumes de démonstration).
func NewChainWatcher(ctx context.Context, cellID, dir, origin string, verifier note.Verifier, bootstrapFrom uint64) ([]registry.Leaf, *ChainWatcher, error) {
	if cellID == "" {
		return nil, nil, fmt.Errorf("supervision: cellID requis (identité dans les alertes)")
	}
	if verifier == nil {
		return nil, nil, fmt.Errorf("supervision: verifier de checkpoint requis (%s)", cellID)
	}
	ff := client.FileFetcher{Root: dir}
	cpRaw, err := ff.ReadCheckpoint(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("supervision: checkpoint initial de %s illisible : %w", cellID, err)
	}
	// UnilateralConsensus : pas de témoin externe en P1 — la confiance est
	// la signature de la cellule + la consistance prouvée tick après tick.
	tr, err := client.NewLogStateTracker(ctx, ff.ReadTile, cpRaw, verifier, origin, client.UnilateralConsensus(ff.ReadCheckpoint))
	if err != nil {
		return nil, nil, fmt.Errorf("supervision: tracker de %s : %w", cellID, err)
	}
	w := &ChainWatcher{cellID: cellID, fetcher: ff, tracker: tr}
	w.size = tr.Latest().Size
	if bootstrapFrom >= w.size {
		return nil, w, nil
	}
	leaves, err := w.fetchAndVerifyLeaves(ctx, bootstrapFrom, w.size)
	if err != nil {
		return nil, nil, err
	}
	return leaves, w, nil
}

// Size rend la taille du dernier état vérifié (feuilles contrôlées
// incluses). Utile à T34b : « aucune feuille nouvelle » = Size stable.
func (w *ChainWatcher) Size() uint64 { return w.size }

// Tick vérifie l'état courant de la chaîne et rend les NOUVELLES feuilles
// vérifiées depuis le tick précédent (nil si aucune). Toute erreur est
// une faute de la chaîne surveillée — à feuiller et alarmer par l'appelant
// (Monitor le fait ; un appelant direct ne doit jamais ignorer l'erreur).
func (w *ChainWatcher) Tick(ctx context.Context) ([]registry.Leaf, error) {
	if w.fault != nil {
		return nil, w.fault
	}
	leaves, err := w.tick(ctx)
	if err != nil {
		// Les divergences prouvées sont sticky ; les erreurs de lecture
		// pures (I/O transitoire, checkpoint en cours d'écriture) ne
		// verrouillent pas — mais elles remontent quand même, jamais
		// silencieuses (§5.3). Distinction : ErrChainDivergence et
		// ErrChainRewind (et ErrInconsistency du client) verrouillent.
		var incons client.ErrInconsistency
		if errors.As(err, &incons) || errors.Is(err, ErrChainDivergence) || errors.Is(err, ErrChainRewind) {
			w.fault = err
		}
		return nil, err
	}
	return leaves, nil
}

func (w *ChainWatcher) tick(ctx context.Context) ([]registry.Leaf, error) {
	if _, _, _, err := w.tracker.Update(ctx); err != nil {
		return nil, fmt.Errorf("%w : %s : %v", ErrChainDivergence, w.cellID, err)
	}
	newSize := w.tracker.Latest().Size
	if newSize < w.size {
		return nil, fmt.Errorf("%w : %s : %d → %d", ErrChainRewind, w.cellID, w.size, newSize)
	}
	if newSize == w.size {
		return nil, nil
	}
	leaves, err := w.fetchAndVerifyLeaves(ctx, w.size, newSize)
	if err != nil {
		return nil, err
	}
	// N'avancer qu'APRÈS contrôle complet : un état dont une feuille est
	// corrompue n'est jamais marqué « vérifié ».
	w.size = newSize
	return leaves, nil
}

// fetchAndVerifyLeaves lit les feuilles [from, to) et les contrôle :
// re-hash RFC 6962 contre les nœuds des tuiles, puis UnmarshalLeaf
// (version, whitelist de kinds, longueurs — leçon #65, la symétrie est
// déjà fail-closed côté registre).
func (w *ChainWatcher) fetchAndVerifyLeaves(ctx context.Context, from, to uint64) ([]registry.Leaf, error) {
	hashes, err := client.FetchLeafHashes(ctx, w.fetcher.ReadTile, from, to-from, to)
	if err != nil {
		return nil, fmt.Errorf("%w : %s : nœuds feuilles [%d,%d) : %v", ErrChainDivergence, w.cellID, from, to, err)
	}
	raw := make([][]byte, 0, to-from)
	for i, end := from/layout.EntryBundleWidth, (to-1)/layout.EntryBundleWidth; i <= end; i++ {
		bundle, err := client.GetEntryBundle(ctx, w.fetcher.ReadEntryBundle, i, to)
		if err != nil {
			return nil, fmt.Errorf("%w : %s : bundle %d : %v", ErrChainDivergence, w.cellID, i, err)
		}
		raw = append(raw, bundle.Entries...)
	}
	// Le premier bundle peut commencer avant `from` et le dernier être
	// partiel : il faut off+(to-from) feuilles au cumul, pas to-from.
	off := uint64(from % layout.EntryBundleWidth)
	if uint64(len(raw)) < off+(to-from) {
		return nil, fmt.Errorf("%w : %s : %d feuilles lues, %d attendues", ErrChainDivergence, w.cellID, len(raw), off+(to-from))
	}
	raw = raw[off : off+to-from]
	leaves := make([]registry.Leaf, 0, to-from)
	for j, entry := range raw {
		if got := rfc6962.DefaultHasher.HashLeaf(entry); !bytes.Equal(got, hashes[j]) {
			return nil, fmt.Errorf("%w : %s : feuille %d ne se re-hache pas dans l'arbre", ErrChainDivergence, w.cellID, from+uint64(j))
		}
		leaf, err := registry.UnmarshalLeaf(entry)
		if err != nil {
			return nil, fmt.Errorf("%w : %s : feuille %d illisible : %v", ErrChainDivergence, w.cellID, from+uint64(j), err)
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}
