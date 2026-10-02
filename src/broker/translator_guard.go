package broker

// translator_guard.go — la dégradation contrôlée du traducteur (T25, §4.5) devant le chemin d'admission
// du broker. Le contrôleur (src/translator) tient l'état « sain / dégradé » établi par la sonde ; ce
// wrapper le consulte AVANT toute traduction : tant que la sonde n'est pas verte (le contrôleur démarre
// dégradé, §1), la demande est refusée — un refus sain (translation-failed), jamais une admission.
//
// Ce qui n'est PAS câblé ici : ni cellule miroir (§7.4) ni file d'arbitrage humain. Sans eux le contrôleur
// ne rend jamais ModeMirrorFailover ni ModeHumanEscalation : dégradé ⇒ default-deny, y compris pour le
// structuré. C'est la direction d'échec voulue (« chemin déterministe ou rien »), pas un manque silencieux.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// AdmissionGate est la couture vers le contrôleur de dégradation (src/translator). Elle est NEUTRE à dessein :
// le broker n'importe pas le paquet translator (supervision → broker, et translator teste contre supervision :
// un import directe fermerait un cycle). L'adaptateur vers *translator.Controller vit dans brokerd.
// Admit rend nil pour admettre ; toute autre issue est un refus.
type AdmissionGate interface {
	Admit(ctx context.Context, subject string, natural bool, intent string) error
}

// PendingArbitrationError : la garde a mis la demande en file d'arbitrage HUMAIN (§4.5) — verdict différé, PAS un
// refus. ID est l'identifiant (hex) de la demande, que l'arbitre signera.
type PendingArbitrationError struct{ ID string }

func (e *PendingArbitrationError) Error() string {
	return "broker: demande en attente d'arbitrage humain (verdict différé, §4.5)"
}

// ErrArbitrationRefused : l'arbitre humain a refusé cette demande.
var ErrArbitrationRefused = errors.New("broker: demande refusée par l'arbitre humain (§4.5)")

// GuardedTranslator interpose la garde d'admission devant un Translator.
type GuardedTranslator struct {
	inner   Translator
	gate    AdmissionGate
	natural bool
}

// NewGuardedTranslator : natural dit si inner traite du langage naturel (le contrôleur le rejette alors
// en mode dégradé) ou du structuré (StructuredTranslator : false). Fail-closed dès la configuration.
func NewGuardedTranslator(inner Translator, gate AdmissionGate, natural bool) (*GuardedTranslator, error) {
	if inner == nil {
		return nil, errors.New("broker: traducteur interne requis")
	}
	if gate == nil {
		return nil, errors.New("broker: garde d'admission requise (§4.5 : la dégradation n'est jamais présumée absente)")
	}
	return &GuardedTranslator{inner: inner, gate: gate, natural: natural}, nil
}

// Translate refuse tant que la garde n'admet pas, puis délègue. Le refus ne porte AUCUN détail vers l'agent
// (le message d'erreur reste côté broker) : l'état de santé du traducteur n'est pas un oracle. L'intention
// n'est transmise à la garde que pour être HACHÉE par la file d'arbitrage (no-DPI : jamais retenue en clair).
func (g *GuardedTranslator) Translate(ctx context.Context, subject, intent string) (Translation, error) {
	if err := g.gate.Admit(ctx, subject, g.natural, intent); err != nil {
		return Translation{}, fmt.Errorf("broker: traducteur non admis : %w", err)
	}
	return g.inner.Translate(ctx, subject, intent)
}

// HTTPProbe sonde la santé du service traducteur : GET sur une URL de LOOPBACK, 200 exigé. Le service
// vLLM n'écoute que sur 127.0.0.1 (tbp-translator.service) ; une sonde qui sortirait de la machine
// donnerait au réseau un moyen de déclarer le traducteur sain.
type HTTPProbe struct {
	url    string
	client *http.Client
}

// maxProbeBody borne ce qu'on lit (et jette) du corps de la réponse de santé.
const maxProbeBody = 64 << 10

// NewHTTPProbe valide l'URL : http, hôte = IP de loopback littérale (pas de nom : pas de résolution
// détournable), pas d'identifiants, pas de redirection suivie, pas de proxy.
func NewHTTPProbe(rawURL string, timeout time.Duration) (*HTTPProbe, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("broker: URL de sonde illisible : %w", err)
	}
	if u.Scheme != "http" {
		return nil, errors.New("broker: URL de sonde : schéma http requis (loopback uniquement)")
	}
	if u.User != nil {
		return nil, errors.New("broker: URL de sonde : identifiants refusés")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return nil, errors.New("broker: URL de sonde : hôte = IP de loopback littérale requis (127.0.0.0/8 ou ::1)")
	}
	if timeout <= 0 {
		return nil, errors.New("broker: délai de sonde > 0 requis")
	}
	return &HTTPProbe{
		url: u.String(),
		client: &http.Client{
			Timeout:       timeout,
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Healthy implémente translator.Probe : toute erreur est une indisponibilité.
func (p *HTTPProbe) Healthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBody))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sonde du traducteur : HTTP %d", resp.StatusCode)
	}
	return nil
}
