package pep

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// QuorumSettings sérialise les réglages qui font l'ÉCHELLE d'une cellule — k du quorum et
// topologie — sous la forme que le témoin de provisionnement engage (« clé=valeur », une
// par ligne, triées). Ils sont lus de l'environnement ; sans cet engagement, abaisser
// TBP_QUORUM_MIN entre deux démarrages affaiblissait tous les actes gouvernés sans la moindre
// alarme (issue #224). Les engager les fait aussi entrer dans le condensé qu'une feuille de
// démarrage enregistre : « quel profil tournait ce jour-là » se recalcule depuis le journal.
func QuorumSettings(k int, topology string) []byte {
	return []byte(fmt.Sprintf("quorum-min=%d\ntopology=%s\n", k, topology))
}

// ParseQuorumSettings relit k dans des réglages ATTESTÉS (le contenu conservé par le témoin).
// Une ligne illisible est une erreur : l'autorisation d'une transition ne se replie jamais sur
// une valeur par défaut.
func ParseQuorumSettings(raw []byte) (k int, err error) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	found := false
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			return 0, fmt.Errorf("pep: réglages attestés illisibles (ligne %q)", sc.Text())
		}
		if key == "quorum-min" {
			n, err := strconv.Atoi(val)
			if err != nil || n < 1 {
				return 0, fmt.Errorf("pep: quorum-min attesté invalide %q", val)
			}
			k, found = n, true
		}
	}
	if !found {
		return 0, fmt.Errorf("pep: quorum-min absent des réglages attestés")
	}
	return k, nil
}
