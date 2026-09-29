package svc

// client.go — le client d'ano pour le proxy bloquant de pepd : implémente
// pep.Rewriter. Tout échec est une erreur, que le proxy traduit en refus
// (la requête ne sort pas, la réponse non reconstituée n'est pas rendue).
//
// Limites assumées (v1), documentées plutôt que découvertes : seuls le CORPS
// et les VALEURS de la query string sont masqués — le chemin de l'URL, les
// noms de paramètres et les en-têtes HTTP (Cookie, en-têtes applicatifs)
// traversent tels quels. Un corps non JSON, compressé ou multipart est
// REFUSÉ (ce qu'on ne sait pas analyser ne sort pas). La réponse est lue en
// entier avant reconstitution (pas de flux : borne de charge).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	ano "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

// Erreurs du client (le proxy les traite toutes comme un refus).
var (
	ErrUnsupported  = errors.New("ano/svc: requête ou réponse non prise en charge (upgrade) — refus")
	ErrEncodedBody  = errors.New("ano/svc: contenu encodé/compressé — ne peut être ni masqué ni reconstitué, refus")
	ErrBodyTooLarge = errors.New("ano/svc: corps trop volumineux — refus")
)

// Error est une erreur rendue par le serveur d'ano.
type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return fmt.Sprintf("ano/svc: refus d'ano (%d, %s)", e.Status, e.Code) }

// Client parle à un serveur ano.
type Client struct {
	hc      *http.Client
	base    string
	maxBody int64
}

// NewClient construit un client sur un http.Client et une URL de base
// (tests, ou transport dédié).
func NewClient(hc *http.Client, base string) *Client {
	return &Client{hc: hc, base: base, maxBody: ano.DefaultMaxPayloadBytes}
}

// NewUnixClient construit un client sur le socket Unix d'ano. timeout borne
// chaque appel (0 ⇒ 3 s).
func NewUnixClient(socketPath string, timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", socketPath)
			},
			DisableCompression: true,
		},
		Timeout: timeout,
	}
	return NewClient(hc, "http://ano")
}

func (c *Client) do(ctx context.Context, path string, wire, body []byte) ([]byte, wireReport, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, wireReport{}, err
	}
	req.Header.Set(pep.DefaultTokenHeader, "Bearer "+base64.StdEncoding.EncodeToString(wire))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, wireReport{}, fmt.Errorf("ano/svc: ano injoignable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, wireReport{}, fmt.Errorf("ano/svc: réponse d'ano illisible: %w", err)
	}
	if int64(len(out)) > c.maxBody {
		return nil, wireReport{}, ErrBodyTooLarge
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(out, &e)
		return nil, wireReport{}, &Error{Status: resp.StatusCode, Code: e.Error}
	}
	var rep wireReport
	if h := resp.Header.Get(HeaderReport); h != "" {
		_ = json.Unmarshal([]byte(h), &rep)
	}
	return out, rep, nil
}

func (c *Client) readAll(r io.ReadCloser) ([]byte, error) {
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, c.maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.maxBody {
		return nil, ErrBodyTooLarge
	}
	return b, nil
}

func encoded(h http.Header) bool {
	e := h.Get("Content-Encoding")
	return e != "" && e != "identity"
}

// RewriteRequest masque le corps et la query de r, en place.
func (c *Client) RewriteRequest(ctx context.Context, wire []byte, r *http.Request) (pep.RewriteReport, error) {
	var total wireReport
	if r.Header.Get("Upgrade") != "" {
		return total.toPEP(), ErrUnsupported
	}
	if r.Body != nil && r.Body != http.NoBody {
		body, err := c.readAll(r.Body)
		if err != nil {
			return total.toPEP(), err
		}
		if len(body) > 0 {
			if encoded(r.Header) {
				return total.toPEP(), ErrEncodedBody
			}
			out, rep, err := c.do(ctx, "/v1/mask", wire, body)
			if err != nil {
				return total.toPEP(), err
			}
			total = total.add(rep)
			r.Body = io.NopCloser(bytes.NewReader(out))
			r.ContentLength = int64(len(out))
			r.Header.Set("Content-Length", strconv.Itoa(len(out)))
		} else {
			r.Body = http.NoBody
			r.ContentLength = 0
		}
	}
	if r.URL != nil && r.URL.RawQuery != "" {
		out, rep, err := c.do(ctx, "/v1/mask-query", wire, []byte(r.URL.RawQuery))
		if err != nil {
			return total.toPEP(), err
		}
		total = total.add(rep)
		r.URL.RawQuery = string(out)
	}
	return total.toPEP(), nil
}

// RewriteResponse reconstitue le corps de resp, en place.
func (c *Client) RewriteResponse(ctx context.Context, wire []byte, resp *http.Response) (pep.RewriteReport, error) {
	var total wireReport
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return total.toPEP(), ErrUnsupported
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		return total.toPEP(), nil
	}
	body, err := c.readAll(resp.Body)
	if err != nil {
		return total.toPEP(), err
	}
	if len(body) == 0 {
		resp.Body = http.NoBody
		return total.toPEP(), nil
	}
	if encoded(resp.Header) {
		return total.toPEP(), ErrEncodedBody
	}
	out, rep, err := c.do(ctx, "/v1/unmask", wire, body)
	if err != nil {
		return total.toPEP(), err
	}
	total = total.add(rep)
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.TransferEncoding = nil
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return total.toPEP(), nil
}

// Health sonde le serveur (GET /healthz) : nil si ano répond.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("ano/svc: ano injoignable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return &Error{Status: resp.StatusCode}
	}
	return nil
}

// Done efface l'échange côté ano (au mieux).
func (c *Client) Done(ctx context.Context, wire []byte) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _, _ = c.do(cctx, "/v1/close", wire, nil)
}

var _ pep.Rewriter = (*Client)(nil)
