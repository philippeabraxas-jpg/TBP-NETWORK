package broker

// Serveur HTTP du broker (T33, §5.1) — le point d'entrée unique des
// demandes d'actions : « no direct client → server path ; the server
// accepts only the broker ».
//
// Choix de transport (D33, posé à la revue dans #59) : net/http stdlib
// uniquement, JSON borné — PAS de gRPC en v1 (grpc/protobuf ajouterait un
// arbre de dépendances lourd au chemin chaud ; le go.mod du dépôt reste
// inchangé). L'évolution vers gRPC, si elle se justifie, est une décision
// séparée.
//
// AVERTISSEMENT D'HONNÊTETÉ (§5.3 : un trou non instrumenté est une
// porte) : ce Server lui-même n'implémente NI TLS NI authentification
// applicative — il sert du texte en clair sur le net.Listener qu'on lui
// donne, quel qu'il soit. Le socket Unix par défaut (0660, utilisateur/
// groupe tbp-broker) reste la forme d'exposition attendue pour un broker
// INTERNE à la cellule (§7.1). Une exposition RÉSEAU n'est offerte que
// par brokerd/cmd/brokerd (revue #124) : un net.Listener TLS mutuel
// (TLS 1.3 minimum, ClientAuth: RequireAndVerifyClientCert) construit AU-
// DESSUS de ce Server — jamais un TCP en clair, jamais un mode dégradé.
// Cette authentification de TRANSPORT ne résout PAS pour autant l'identité
// applicative de l'appelant (classe, quota) : brokerd fait aujourd'hui
// encore confiance à la déclaration {subject, intent} du corps de requête
// — voir #125. NAC/EAP-TLS (§5.1) et l'exposition inter-cellules
// (T29/T35) restent des couches de déploiement séparées, hors de ce
// fichier.
//
// Un deny n'est PAS une erreur HTTP : une demande bien formée qui reçoit
// un refus obtient 200 avec {"allow": false, "reason": …} — le refus est
// une décision valide du greffe (§1), pas une panne du service. Seules
// les demandes mal formées (JSON illisible, corps trop grand) obtiennent
// un statut d'erreur.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Défauts du serveur.
const (
	// defaultMaxBody borne le corps d'une demande (64 Kio — une intention
	// bornée par maxIntentBytes y tient très largement).
	defaultMaxBody = 64 << 10
	// defaultReadHeaderTimeout borne la lecture des en-têtes (slowloris).
	defaultReadHeaderTimeout = 5 * time.Second
	// socketPerm est le mode du socket Unix de cellule : propriétaire et
	// groupe uniquement (le broker est interne à la cellule, §7.1).
	socketPerm = 0o660
)

// Erreurs de configuration du serveur.
var (
	ErrBrokerRequired = errors.New("broker: instance Broker requise (le serveur n'est que la porte, pas la chaîne)")
)

// actionRequestJSON est la demande d'action sur le fil.
type actionRequestJSON struct {
	Subject string `json:"subject"` // entité gouvernée (claim 2)
	Intent  string `json:"intent"`  // intention — langage naturel ou structuré selon le Translator configuré
}

// actionResponseJSON est la décision rendue. Un refus est une décision
// valide (200, allow=false) — jamais une erreur de transport.
type actionResponseJSON struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Token  string `json:"token,omitempty"` // fil CWT/COSE_Sign1, hex — présent si allow
	JTI    string `json:"jti"`             // hex — identifiant des feuilles (§4.3)
}

// Server est la porte HTTP du broker. Sans état mutable après construction.
type Server struct {
	broker  *Broker
	maxBody int64
	mux     *http.ServeMux
}

// ServerOptions paramètre le serveur. Fail-closed dès la configuration.
type ServerOptions struct {
	// Broker est l'orchestrateur (broker.go). Requis.
	Broker *Broker
	// MaxBody borne le corps des demandes. 0 ⇒ 64 Kio. Négatif ⇒ erreur.
	MaxBody int64
}

// NewServer construit la porte. Fail-closed : broker requis.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Broker == nil {
		return nil, ErrBrokerRequired
	}
	if opts.MaxBody < 0 {
		return nil, errors.New("broker: MaxBody négatif refusé")
	}
	maxBody := opts.MaxBody
	if maxBody == 0 {
		maxBody = defaultMaxBody
	}
	s := &Server{broker: opts.Broker, maxBody: maxBody}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/actions", s.handleAction)
	s.mux = mux
	return s, nil
}

// Handler expose le routeur (tests httptest, montage dans un serveur
// existant de la cellule).
func (s *Server) Handler() http.Handler { return s.mux }

// handleAction reçoit une demande, la borne, la fait orchestrer et rend la
// décision. Jamais de contenu métier dans les logs ni les feuilles (§6.2).
func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	var req actionRequestJSON
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // fail-closed : aucun champ de contrebande (§1)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, `{"allow":false,"reason":"request-invalid"}`, http.StatusBadRequest)
		return
	}

	res := s.broker.HandleAction(r.Context(), req.Subject, req.Intent)

	resp := actionResponseJSON{
		Allow:  res.Allow,
		Reason: res.Reason,
		JTI:    hex.EncodeToString(res.JTI[:]),
	}
	if res.Allow {
		resp.Token = hex.EncodeToString(res.Token)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp) // encodage de types fixes — rien à fail-closed
}

// Serve sert sur le listener jusqu'à l'annulation du contexte (arrêt
// propre : Shutdown, pas de coupure de requête en vol — une requête
// interrompue au milieu de la chaîne laisserait une feuille sans jeton,
// ou pire un jeton sans feuille si l'ordre change un jour).
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
	}
	go func() {
		<-ctx.Done()
		// Budget d'arrêt généreux : une évaluation OPA tient en 5 ms (T11),
		// un appel de traducteur peut durer — on laisse finir la chaîne.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(lis)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ListenUnix ouvre le socket Unix de cellule (défaut de déploiement v1) :
// supprime un socket résiduel, écoute, restreint les permissions au
// propriétaire/groupe (0660). Le fichier est supprimé à la fermeture par
// le runtime Go — un arrêt brutal peut laisser le fichier, d'où la
// suppression préalable à l'écoute.
func ListenUnix(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("broker: chemin de socket vide refusé")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("broker: suppression du socket résiduel : %w", err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("broker: écoute unix %s : %w", path, err)
	}
	if err := os.Chmod(path, socketPerm); err != nil {
		_ = lis.Close()
		return nil, fmt.Errorf("broker: permissions du socket : %w", err)
	}
	return lis, nil
}
