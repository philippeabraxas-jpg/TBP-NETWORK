// Package devtrace : la trace de décision des environnements de TEST (dev-test, issue #329).
//
// Un testeur veut suivre une requête de son émission à son exécution ou à son rejet, en sachant quel composant l'a
// arrêtée et pourquoi. Le courtier le sait, mais n'en dit rien hors de la réponse faite à l'agent : ni le sujet, ni
// l'identité du certificat, ni l'intention reçue, ni la durée n'existent ailleurs que dans des feuilles hash-seulement
// (§6.2). Ce paquet écrit, pour un banc d'essai, une ligne JSON par décision dans un fichier local.
//
// Doctrine :
//   - c'est une ÉCHAPPATOIRE DEV, au même titre que TBP_ISSUER_SEED_FILE : le démon qui l'active exige le sentinel
//     devmode (#113), lève l'alarme haute priorité au démarrage et consigne la feuille des échappatoires actives (#208).
//     Elle n'existe pas en production ;
//   - elle ne peut PAS changer une décision : l'émission se fait après le verdict, ses erreurs sont comptées et
//     jamais propagées, un Sink nul ne fait rien ;
//   - elle ne reçoit jamais de jeton ni de clé : seulement ce que l'agent a lui-même envoyé (sujet, intention) et ce
//     que le courtier a décidé. Le fichier est en 0600, sans suivre de lien symbolique ;
//   - le clair (sujet, intention) y figure : c'est précisément ce que le test veut voir, et pourquoi c'est dev seul.
package devtrace

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Header porte l'identifiant de corrélation posé par l'émetteur de la requête (le test), de bout en bout.
const Header = "X-TBP-Trace-Id"

// maxField borne chaque champ texte : une trace ne doit pas devenir un canal d'écriture illimité.
const maxField = 256

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Event est une ligne de la trace. Les champs vides sont omis.
type Event struct {
	TS        string `json:"ts"`
	TraceID   string `json:"trace_id,omitempty"`
	Component string `json:"component"`
	Stage     string `json:"stage"`
	Outcome   string `json:"outcome"`
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Intent    string `json:"intent,omitempty"`
	PeerCN    string `json:"peer_cn,omitempty"`
	Transport string `json:"transport,omitempty"`
	Peer      string `json:"peer,omitempty"` // adresse distante de la connexion (vide sur un socket Unix)
	JTI       string `json:"jti,omitempty"`
	ElapsedUs int64  `json:"elapsed_us,omitempty"`
}

// Sink écrit des Event. Le Sink nul est valide et ne fait rien.
type Sink struct {
	mu      sync.Mutex
	f       *os.File
	dropped atomic.Uint64
}

// Open ouvre (crée) le fichier de trace en ajout, 0600, sans suivre un lien symbolique.
func Open(path string) (*Sink, error) {
	if path == "" {
		return nil, errors.New("devtrace: chemin vide")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("devtrace: %w", err)
	}
	return &Sink{f: f}, nil
}

// Emit écrit un événement. Jamais d'erreur ni de panique vers l'appelant : une trace qui échoue est comptée
// (Dropped), pas une raison de changer une décision.
func (s *Sink) Emit(e Event) {
	if s == nil {
		return
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	e.TraceID = clean(e.TraceID, 64)
	e.Reason = clean(e.Reason, maxField)
	e.Detail = clean(e.Detail, maxField)
	e.Subject = clean(e.Subject, maxField)
	e.Intent = clean(e.Intent, maxField)
	e.PeerCN = clean(e.PeerCN, maxField)
	e.Peer = clean(e.Peer, maxField)
	line, err := json.Marshal(e)
	if err != nil {
		s.dropped.Add(1)
		return
	}
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		s.dropped.Add(1)
	}
}

// Dropped compte les événements qui n'ont pas pu être écrits.
func (s *Sink) Dropped() uint64 {
	if s == nil {
		return 0
	}
	return s.dropped.Load()
}

// Close ferme le fichier.
func (s *Sink) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// ID rend l'identifiant de corrélation de la requête, ou "" s'il est absent ou mal formé (jamais une valeur
// arbitraire recopiée dans un fichier : [A-Za-z0-9._-], 64 caractères au plus).
func ID(r *http.Request) string {
	v := r.Header.Get(Header)
	if !idPattern.MatchString(v) {
		return ""
	}
	return v
}

// Peer rend l'adresse distante de la requête, ou "" sur un socket Unix (où RemoteAddr n'est pas une adresse).
func Peer(r *http.Request) string {
	if r.TLS == nil {
		return ""
	}
	return r.RemoteAddr
}

// clean borne un champ texte et remplace les caractères de contrôle : une valeur choisie par l'agent ne peut pas
// fabriquer une fausse ligne de trace.
func clean(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	b := []byte(s)
	for i, c := range b {
		if c < 0x20 || c == 0x7f {
			b[i] = '?'
		}
	}
	return string(b)
}
