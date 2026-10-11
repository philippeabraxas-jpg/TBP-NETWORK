package devconsole

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed web
var webFS embed.FS

const (
	cookieName      = "tbp_console"
	maxIngestBytes  = 256 << 10
	maxIngestLines  = 500
	maxLineBytes    = 8 << 10
	heartbeatPeriod = 15 * time.Second
)

// Config : deux clés distinctes. La clé de LECTURE ouvre la page (elle montre des noms d'agents, des ressources, des
// adresses) ; la clé d'INGESTION laisse une machine du test envoyer ses événements. Aucune des deux ne donne de
// pouvoir sur le test lui-même : la console n'a pas de route qui agisse.
type Config struct {
	ViewKey   string
	IngestKey string
	Label     string // l'étiquette d'environnement donnée à `init`, affichée en en-tête
}

// Server sert la page, l'API de lecture, le flux temps réel et l'ingestion.
type Server struct {
	cfg   Config
	store *Store
	mux   *http.ServeMux
}

// NewServer refuse des clés trop courtes ou identiques : fail-closed dès la configuration.
func NewServer(cfg Config, store *Store) (*Server, error) {
	if len(cfg.ViewKey) < 16 || len(cfg.IngestKey) < 16 {
		return nil, fmt.Errorf("devconsole: les clés de lecture et d'ingestion font au moins 16 caractères")
	}
	if cfg.ViewKey == cfg.IngestKey {
		return nil, fmt.Errorf("devconsole: la clé de lecture et la clé d'ingestion doivent différer (qui peut envoyer ne doit pas pouvoir lire)")
	}
	s := &Server{cfg: cfg, store: store, mux: http.NewServeMux()}
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, err
	}
	static := http.FileServerFS(sub)
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return nil, err
	}
	s.mux.HandleFunc("GET /{$}", s.page(index))
	s.mux.Handle("GET /app.js", s.guardRead(static))
	s.mux.Handle("GET /app.css", s.guardRead(static))
	s.mux.HandleFunc("GET /api/snapshot", s.guardReadFunc(s.handleSnapshot))
	s.mux.HandleFunc("GET /api/request/{id}", s.guardReadFunc(s.handleRequest))
	s.mux.HandleFunc("GET /api/stream", s.guardReadFunc(s.handleStream))
	s.mux.HandleFunc("POST /ingest", s.handleIngest)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		secure(w)
		_, _ = io.WriteString(w, "ok\n")
	})
	return s, nil
}

// Handler rend le routeur, avec les en-têtes de sécurité sur toutes les réponses.
func (s *Server) Handler() http.Handler { return s.mux }

func secure(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *Server) readAuthorised(r *http.Request) bool {
	if c, err := r.Cookie(cookieName); err == nil && equal(c.Value, s.cfg.ViewKey) {
		return true
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") && equal(strings.TrimPrefix(h, "Bearer "), s.cfg.ViewKey) {
		return true
	}
	return false
}

func (s *Server) guardRead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		if !s.readAuthorised(r) {
			http.Error(w, "unauthorised: open the address printed by `site.sh m1 up` (or `site.sh console up`), it carries the key", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) guardReadFunc(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.guardRead(f).ServeHTTP(w, r)
	}
}

// page : la clé arrive une fois dans l'adresse, devient un cookie (HttpOnly, SameSite=Strict) et disparaît de l'adresse
// par une redirection, pour ne pas rester dans l'historique du navigateur.
func (s *Server) page(indexHTML []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secure(w)
		if k := r.URL.Query().Get("key"); k != "" {
			if !equal(k, s.cfg.ViewKey) {
				http.Error(w, "unauthorised: wrong key", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookieName, Value: s.cfg.ViewKey, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !s.readAuthorised(r) {
			http.Error(w, "unauthorised: open the address printed by `site.sh m1 up` (or `site.sh console up`), it carries the key", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	}
}

type snapshotJSON struct {
	Snapshot
	Label string `json:"label"`
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(snapshotJSON{Snapshot: s.store.Snapshot(limit), Label: s.cfg.Label})
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	v, ok := s.store.Request(r.PathValue("id"))
	if !ok {
		http.Error(w, "no such request", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// handleStream : Server-Sent Events. Un abonné trop lent est coupé ; le navigateur se reconnecte et relit l'instantané.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := s.store.Subscribe()
	defer s.store.Unsubscribe(ch)
	_, _ = io.WriteString(w, ": connected\n\n")
	fl.Flush()
	tick := time.NewTicker(heartbeatPeriod)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return
			}
			fl.Flush()
		case u, open := <-ch:
			if !open {
				return
			}
			b, err := json.Marshal(u)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", u.Kind, b); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// handleIngest : une ligne JSON par événement ou par état. Bornes strictes sur la taille, le nombre et la longueur des lignes.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	secure(w)
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") || !equal(strings.TrimPrefix(h, "Bearer "), s.cfg.IngestKey) {
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxIngestBytes))
	if err != nil {
		http.Error(w, "body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}
	accepted, rejected := 0, 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
	lines := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if lines++; lines > maxIngestLines {
			rejected++
			break
		}
		if s.store.AddLine(line) {
			accepted++
		} else {
			rejected++
		}
	}
	if sc.Err() != nil {
		rejected++
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": accepted, "rejected": rejected})
}
