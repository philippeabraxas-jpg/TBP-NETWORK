package pep

// Transport OPA sur socket Unix + vérification SO_PEERCRED (revue de
// sécurité #92, finding A3) : OPA en HTTP sur 127.0.0.1:8181 SANS
// authentification est indétectable d'un imposteur — tuer le vrai OPA,
// occuper le port, répondre allow à tout trompe pepd ET brokerd, aucun
// des deux ne peut distinguer le vrai service de l'imposteur.
//
// Un socket Unix aux permissions restreintes réduit déjà la surface
// (accès filesystem requis) mais n'authentifie PERSONNE à lui seul :
// n'importe quel processus du même groupe pourrait encore écouter
// dessus, ou un processus déjà présent sur la machine pourrait avoir créé
// le fichier avant OPA. SO_PEERCRED ferme ce trou : à CHAQUE connexion,
// c'est le NOYAU — pas le pair, qui pourrait mentir — qui rapporte l'UID
// réel du processus à l'autre bout du socket. Comparé à l'UID attendu du
// service OPA (épinglé par déploiement, jamais résolu dynamiquement) :
// tout écart refuse la connexion, fail-closed (§1).
//
// Linux uniquement — SO_PEERCRED est spécifique à AF_UNIX sous Linux
// (même cible que clock.go, T13 : ntp_adjtime).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/sys/unix"
)

// opaUnixDialTimeout borne l'établissement de la connexion (hors chemin
// chaud d'évaluation — c'est la connexion TCP-équivalente, pas l'appel).
const opaUnixDialTimeout = 5 * time.Second

// NewOPAUnixTransport construit un *http.Transport qui dialogue avec OPA
// exclusivement via le socket Unix `path`, en vérifiant à CHAQUE
// connexion que le processus pair tourne sous `expectedUID` (SO_PEERCRED,
// revue de sécurité #92, finding A3). Un pair d'UID différent — ou
// l'échec de la vérification elle-même — refuse la connexion : jamais un
// canal non vérifié servi en silence.
func NewOPAUnixTransport(path string, expectedUID uint32) (*http.Transport, error) {
	if path == "" {
		return nil, errors.New("pep: chemin de socket OPA requis (§92.A3)")
	}
	dialer := &net.Dialer{Timeout: opaUnixDialTimeout}
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, "unix", path)
			if err != nil {
				return nil, err
			}
			uc, ok := conn.(*net.UnixConn)
			if !ok {
				// Inatteignable : un Dial "unix" réussi rend toujours un
				// *net.UnixConn — fail-closed quand même plutôt que de
				// laisser passer une connexion dont le type est incertain.
				_ = conn.Close()
				return nil, errors.New("pep: connexion OPA non-Unix inattendue")
			}
			peerUID, err := peerCredUID(uc)
			if err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("pep: SO_PEERCRED OPA illisible: %w", err)
			}
			if peerUID != expectedUID {
				_ = conn.Close()
				return nil, fmt.Errorf("pep: OPA imposteur — UID pair %d, attendu %d (§92.A3)", peerUID, expectedUID)
			}
			return conn, nil
		},
	}, nil
}

// peerCredUID lit l'UID réel du processus à l'autre bout du socket Unix
// via SO_PEERCRED — une information fournie par le NOYAU au moment de la
// connexion, que le pair ne peut pas falsifier (contrairement à tout ce
// qu'il enverrait lui-même sur le fil applicatif).
func peerCredUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var ucred *unix.Ucred
	var sockErr error
	if ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return 0, ctrlErr
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return ucred.Uid, nil
}
