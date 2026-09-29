package ano

// classifier_socket.go — branchement d'une IA locale de type JEV sur ano
// (#178) par un socket Unix : aucun accès réseau, comme le traducteur (§4.5).
// Le modèle lui-même n'est pas dans ce dépôt ; ce fichier n'en définit que le
// contrat d'appel.
//
// Contrat (HTTP sur socket Unix) :
//
//	POST /v1/classify   {"path": "beneficiary.name", "value": "Mme Machin"}
//	200                 {"mask": true}   — le champ doit être anonymisé
//	200                 {"mask": false}  — le champ peut sortir en clair
//
// Toute autre réponse (statut, JSON illisible, champ « mask » absent) est une
// ERREUR — donc un masquage (fail-closed, voir classifier.go). Le délai est
// imposé par ano (ClassifierTimeout), pas par ce client.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
)

// SocketClassifier interroge un classifieur local sur un socket Unix.
type SocketClassifier struct {
	hc *http.Client
}

// NewSocketClassifier construit le client. Le transport ne sait dialoguer
// qu'avec le socket Unix donné.
func NewSocketClassifier(socketPath string) *SocketClassifier {
	return &SocketClassifier{hc: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
			DisableCompression: true,
		},
	}}
}

// Decide implémente Classifier.
func (c *SocketClassifier) Decide(ctx context.Context, path, value string) (bool, error) {
	body, err := json.Marshal(map[string]string{"path": path, "value": value})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://classifier/v1/classify", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return false, fmt.Errorf("ano: classifieur injoignable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("ano: classifieur: statut %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, err
	}
	var out struct {
		Mask *bool `json:"mask"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false, fmt.Errorf("ano: classifieur: réponse illisible: %w", err)
	}
	if out.Mask == nil {
		return false, errors.New("ano: classifieur: champ « mask » absent")
	}
	return *out.Mask, nil
}

var _ Classifier = (*SocketClassifier)(nil)
