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
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
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

// LeafSink est la couture vers le registre de la cellule — *registry.CellLog
// l'implémente nativement (même signature que pep.LeafSink).
type LeafSink interface {
	Append(ctx context.Context, leaf registry.Leaf) (uint64, error)
}

// ActiveRecord sérialise le record de la feuille « TBDV1 » : les noms des
// échappatoires dev actives, triés et sans doublon (déterministe, §11.3), hash
// seulement une fois salé (§6.2) :
//
//	"TBDV1" ‖ u8 nombre ‖ pour chaque nom : u8 longueur ‖ nom
//
// Exporté pour qu'un vérificateur (selftest, audit) recalcule la feuille.
func ActiveRecord(flags []string) []byte {
	seen := map[string]bool{}
	names := make([]string, 0, len(flags))
	for _, f := range flags {
		if !seen[f] {
			seen[f] = true
			names = append(names, f)
		}
	}
	sort.Strings(names)
	rec := append([]byte("TBDV1"), byte(len(names)))
	for _, n := range names {
		rec = append(rec, byte(len(n)))
		rec = append(rec, n...)
	}
	return rec
}

// RecordActive consigne dans le registre les échappatoires dev actives. Sans
// échappatoire : aucune feuille. Avec : une feuille KindTelemetry, et une
// erreur si elle ne peut pas être écrite — un démarrage dev qui ne laisse pas
// de trace est refusé (fail-closed, même doctrine que toute décision §4.1).
//
// store (optionnel, #275/#271) reçoit le clair de la feuille AVANT son inscription :
// journal refusé ⇒ aucune feuille ⇒ démarrage refusé. Nil ⇒ feuille nue (historique).
func RecordActive(ctx context.Context, sink LeafSink, store *registry.RecordStore, cellID string, salt []byte, flags []string, now func() time.Time) error {
	if len(flags) == 0 {
		return nil
	}
	if sink == nil {
		return errors.New("devmode: couture feuilles requise pour consigner les échappatoires dev actives")
	}
	if cellID == "" || len(salt) < 16 {
		return errors.New("devmode: cellID et sel ≥ 16 octets requis (§6.2)")
	}
	if now == nil {
		now = time.Now
	}
	_, err := registry.AppendLeaf(ctx, sink, store, registry.KindTelemetry, cellID, salt, ActiveRecord(flags), now().UnixNano())
	if err != nil {
		return fmt.Errorf("devmode: feuille des échappatoires dev actives (%s) impossible : %w — démarrage refusé", strings.Join(flags, ", "), err)
	}
	return nil
}
