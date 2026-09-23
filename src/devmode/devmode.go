// Package devmode ferme la revue de sécurité #113 : plusieurs
// échappatoires « dev » (TBP_OPA_DISABLED_DEV_UNSAFE,
// TBP_OPA_INSECURE_TCP_DEV, TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE côté
// pepd ; TBP_OPA_INSECURE_TCP_DEV et TBP_ISSUER_SEED_FILE côté brokerd)
// ne dépendaient QUE d'une variable du MÊME fichier d'environnement que
// celui qui active la protection qu'elles contournent — quiconque peut
// écrire ce fichier peut donc, seul, désarmer silencieusement une bonne
// partie des protections #92/#90 en production.
//
// RequireDeclared exige un second signal, INDÉPENDANT de ce fichier :
// l'existence d'un fichier sentinelle à un chemin FIXE, câblé dans le
// binaire (jamais lu depuis une variable d'environnement — sinon le même
// fichier compromis pourrait le déplacer). Sans ce sentinel, l'un
// quelconque des drapeaux « dev » refuse le démarrage. Avec lui, le
// démarrage continue mais trace une ALARME haute priorité — jamais un
// simple log discret — puisqu'un déploiement qui tourne avec ces
// échappatoires actives reste un fait à surveiller, sentinel ou non.
package devmode

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
)

// DefaultSentinelPath est le chemin fixe dont la seule EXISTENCE déclare
// un environnement dev/lab (revue #113). Volontairement câblé en dur —
// jamais dérivé d'une variable d'environnement, pour rester hors
// d'atteinte d'un fichier .env compromis ou mal configuré.
const DefaultSentinelPath = "/etc/tbp/DEV_ENVIRONMENT"

// Declared rapporte si le sentinel désigné par path existe, via stat
// (production : os.Stat toujours appelé sur DefaultSentinelPath ; les
// tests injectent stat sur un chemin temporaire, jamais /etc).
func Declared(path string, stat func(string) (os.FileInfo, error)) (bool, error) {
	_, err := stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("devmode: sentinel %s illisible: %w", path, err)
}

// RequireDeclared refuse le démarrage si l'un des drapeaux « dev » listés
// dans activeFlags est actif SANS que le sentinel n'existe. Si le
// sentinel existe, autorise le démarrage mais trace une ALARME (T14) —
// jamais un simple log discret : la revue #113 exige une trace haute
// priorité, pas seulement un refus contournable.
func RequireDeclared(path string, stat func(string) (os.FileInfo, error), activeFlags []string) error {
	if len(activeFlags) == 0 {
		return nil
	}
	declared, err := Declared(path, stat)
	if err != nil {
		return err
	}
	flags := strings.Join(activeFlags, ", ")
	if !declared {
		return fmt.Errorf("devmode: %s actif(s) mais %s absent (revue #113) — une échappatoire dev déclarée uniquement DANS le fichier d'environnement de production n'est plus acceptée seule ; créer %s (hors de ce fichier, 0644 root:root suffit) pour déclarer EXPLICITEMENT un environnement dev/lab, jamais en production", flags, path, path)
	}
	log.Printf("ALARME sécurité (revue #113) : environnement dev déclaré (%s) ET échappatoire(s) « dev » active(s) : %s — DEV/LAB UNIQUEMENT, jamais en production", path, flags)
	return nil
}
