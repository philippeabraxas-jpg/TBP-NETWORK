package pep

// rewriter.go — couture de réécriture du proxy bloquant (#178).
//
// Quand le backend d'un proxy est une destination HORS cellule, ce qui sort
// doit être anonymisé et ce qui revient doit être reconstitué. Le proxy n'a
// pas cette logique : il appelle un Rewriter (en pratique le client d'ano,
// processus séparé et sandboxé) et ne transmet QUE si la réécriture a
// réussi. Toute faute — ano injoignable, contenu non analysable, coffre
// saturé, jeton inconnu au retour — est un refus (fail-closed) : la requête
// ne sort pas, la réponse non reconstituée n'est pas rendue.
//
// L'évaluation (jeton, OPA, quota, sceau du corps) se fait sur le trafic en
// CLAIR, à l'intérieur de la cellule, AVANT la réécriture : le sceau d'objet
// (#108) couvre bien ce que l'agent a réellement émis. La réécriture ne
// touche que ce qui franchit la frontière.

import (
	"context"
	"net/http"
)

// RewriteReport résume une réécriture : des COMPTAGES, jamais de valeurs
// (feuilles hash-only, §6.2).
type RewriteReport struct {
	Leaves           int
	MaskedPath       int
	MaskedClassifier int
	MaskedDefault    int
	ClassifierFaults int
	Spans            int
	Restored         int
}

// Rewriter réécrit ce qui traverse la frontière de la cellule.
type Rewriter interface {
	// RewriteRequest masque la requête sortante EN PLACE (corps, query).
	// wire est le jeton porteur déjà validé par la chaîne de décision.
	RewriteRequest(ctx context.Context, wire []byte, r *http.Request) (RewriteReport, error)
	// RewriteResponse reconstitue la réponse EN PLACE.
	RewriteResponse(ctx context.Context, wire []byte, resp *http.Response) (RewriteReport, error)
	// Done libère l'échange (efface la correspondance) — au mieux, sans erreur.
	Done(ctx context.Context, wire []byte)
}

// Opérations d'un RewriteEvent.
const (
	RewriteOpMask   byte = 1
	RewriteOpUnmask byte = 2
)

// RewriteEvent est ce que le proxy remet à OnRewrite pour chaque réécriture :
// de quoi écrire une feuille d'audit hash-only (comptages + issue). Une erreur
// de OnRewrite est un REFUS : une sortie qu'on ne peut pas auditer ne sort pas
// (« on audite tout », même doctrine que ContractStore : pas de preuve, pas
// de contrat).
type RewriteEvent struct {
	Op     byte
	JTI    [16]byte
	Report RewriteReport
	Err    error // nil ⇒ réussite
}

type rewriteCtxKey struct{}

type rewriteCtx struct {
	wire []byte
	jti  [16]byte
}
