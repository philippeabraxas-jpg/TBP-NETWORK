// Assemblage de l'arbitrage OPA (T11) durci — revue de sécurité #92.
// Isolé dans son propre fichier, testable en dehors de run() (même
// patron que measured_boot.go, #96).
//
// Trois constats liés (#92), trois portillons composés ici, chacun
// fail-closed :
//
//   - A2 : sans TBP_OPA_ENDPOINT, pepd démarrait et servait quand même
//     (jeton seul, aucun arbitrage). OPA est désormais OBLIGATOIRE, sauf
//     TBP_OPA_DISABLED_DEV_UNSAFE=1 déclaré EXPLICITEMENT (dev/lab).
//   - A3 : OPA en HTTP non authentifié est indétectable d'un imposteur
//     qui occupe le port. TBP_OPA_SOCKET + TBP_OPA_EXPECTED_UID
//     branchent le transport Unix + SO_PEERCRED (pep.NewOPAUnixTransport)
//     — désormais OBLIGATOIRE, sauf TBP_OPA_INSECURE_TCP_DEV=1 déclaré
//     EXPLICITEMENT.
//   - A5 : TBP_POLICY_ID est auto-déclaré — rien ne vérifiait que la
//     révision RÉELLEMENT servie par OPA lui correspond. Vérifié une
//     première fois ICI (échec ⇒ démarrage refusé), puis PÉRIODIQUEMENT
//     par le pep.OPARevisionWatcher rendu (l'appelant lance Run(ctx)).
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// opaSetup porte le résultat de l'assemblage : client nil ET watcher nil
// SEULEMENT si OPA a été explicitement désactivé (TBP_OPA_DISABLED_DEV_UNSAFE).
type opaSetup struct {
	client  *pep.OPAClient
	watcher *pep.OPARevisionWatcher
}

// setupOPA assemble l'arbitrage OPA selon la configuration déclarée par
// getenv — fail-closed à chaque étape (§1), voir l'en-tête du fichier
// pour les trois portillons (A2/A3/A5).
func setupOPA(ctx context.Context, cellID string, salt []byte, policyID [32]byte, cellLog *registry.CellLog, onTrip func(string), getenv func(string) string) (*opaSetup, error) {
	endpoint := getenv("TBP_OPA_ENDPOINT")
	disabledDev := getenv("TBP_OPA_DISABLED_DEV_UNSAFE") == "1"

	switch {
	case endpoint == "" && !disabledDev:
		return nil, errors.New("pepd: TBP_OPA_ENDPOINT requis (revue de sécurité #92, A2 : l'arbitrage OPA est obligatoire) — TBP_OPA_DISABLED_DEV_UNSAFE=1 pour l'exempter EXPLICITEMENT (dev/lab uniquement, jamais en production)")
	case endpoint != "" && disabledDev:
		return nil, errors.New("pepd: TBP_OPA_ENDPOINT et TBP_OPA_DISABLED_DEV_UNSAFE sont mutuellement exclusifs")
	case endpoint == "" && disabledDev:
		log.Printf("pepd: OPA DÉSACTIVÉ explicitement (TBP_OPA_DISABLED_DEV_UNSAFE=1, revue #92) — DEV/LAB UNIQUEMENT, jamais en production : aucun arbitrage de règles")
		return &opaSetup{}, nil
	}

	hc, err := opaHTTPClient(getenv)
	if err != nil {
		return nil, err
	}

	client, err := pep.NewOPAClient(pep.OPAOptions{
		Endpoint:   endpoint,
		HTTPClient: hc,
		CellID:     cellID,
		Salt:       salt,
		Leaves:     cellLog,
		OnTrip:     onTrip,
	})
	if err != nil {
		return nil, err
	}

	revisionInterval, err := opaRevisionInterval(getenv)
	if err != nil {
		return nil, err
	}
	watcher, err := pep.NewOPARevisionWatcher(pep.OPARevisionWatcherOptions{
		Endpoint:   endpoint,
		Expected:   hex.EncodeToString(policyID[:]),
		HTTPClient: hc,
		Interval:   revisionInterval,
		CellID:     cellID,
		Salt:       salt,
		Leaves:     cellLog,
		OnTrip:     onTrip,
	})
	if err != nil {
		return nil, err
	}
	// Première vérification SYNCHRONE avant de servir (§92.A5) : jamais
	// une cellule qui sert avant même sa première preuve de révision.
	watcher.Check(ctx)
	if watcher.Mismatch() {
		return nil, fmt.Errorf("pepd: révision OPA non vérifiée au démarrage (%s) — refus (§92.A5)", watcher.Reason())
	}

	return &opaSetup{client: client, watcher: watcher}, nil
}

// opaHTTPClient construit le transport OPA — Unix + SO_PEERCRED (§92.A3,
// nominal) ou TCP non authentifié (dev/lab, EXPLICITEMENT déclaré). Nil
// en retour signifie « http.Client par défaut » (TCP).
func opaHTTPClient(getenv func(string) string) (*http.Client, error) {
	sock := getenv("TBP_OPA_SOCKET")
	insecureDev := getenv("TBP_OPA_INSECURE_TCP_DEV") == "1"

	switch {
	case sock != "" && insecureDev:
		return nil, errors.New("pepd: TBP_OPA_SOCKET et TBP_OPA_INSECURE_TCP_DEV sont mutuellement exclusifs (§92.A3)")
	case sock == "" && !insecureDev:
		return nil, errors.New("pepd: TBP_OPA_SOCKET+TBP_OPA_EXPECTED_UID requis (revue de sécurité #92, A3 : OPA authentifié par SO_PEERCRED) — TBP_OPA_INSECURE_TCP_DEV=1 pour l'exempter EXPLICITEMENT (dev/lab uniquement, jamais en production)")
	case sock == "" && insecureDev:
		log.Printf("pepd: OPA en TCP NON authentifié (TBP_OPA_INSECURE_TCP_DEV=1, revue #92.A3) — DEV/LAB UNIQUEMENT, jamais en production : un imposteur qui occupe ce port est indétectable")
		return nil, nil
	}

	uidStr := getenv("TBP_OPA_EXPECTED_UID")
	if uidStr == "" {
		return nil, errors.New("pepd: TBP_OPA_EXPECTED_UID requis avec TBP_OPA_SOCKET (§92.A3)")
	}
	uid, err := strconv.ParseUint(uidStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("pepd: TBP_OPA_EXPECTED_UID invalide %q: %w", uidStr, err)
	}
	tr, err := pep.NewOPAUnixTransport(sock, uint32(uid))
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: tr}, nil
}

// opaRevisionInterval lit TBP_OPA_REVISION_CHECK_INTERVAL_MS (optionnel).
// Absent ⇒ 0 (pep.NewOPARevisionWatcher applique alors son défaut,
// DefaultOPARevisionCheckInterval, 10 s) ; présent mais illisible ou
// ≤ 0 ⇒ erreur — jamais un défaut silencieux sur une valeur déclarée
// fautive (§1).
func opaRevisionInterval(getenv func(string) string) (time.Duration, error) {
	s := getenv("TBP_OPA_REVISION_CHECK_INTERVAL_MS")
	if s == "" {
		return 0, nil
	}
	ms, err := strconv.Atoi(s)
	if err != nil || ms <= 0 {
		return 0, fmt.Errorf("pepd: TBP_OPA_REVISION_CHECK_INTERVAL_MS invalide %q (entier > 0 attendu)", s)
	}
	return time.Duration(ms) * time.Millisecond, nil
}
