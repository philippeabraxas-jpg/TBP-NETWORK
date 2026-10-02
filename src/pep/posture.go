package pep

import (
	"fmt"
	"sort"
	"strings"
)

// ProvisioningPostureName est le nom, dans le témoin de provisionnement, du fichier des INTERRUPTEURS de sécurité (revue
// tierce du 2 octobre, 4.6).
const ProvisioningPostureName = "security-posture"

// Posture : les réglages d'environnement qui changent la POSTURE de sécurité d'un démon — ce qui est actif, pas
// comment c'est réglé (taille de file, durées, TTL : volontairement hors de l'engagement, un opérateur les ajuste sans
// preuve de quorum). Même classe que TBP_QUORUM_MIN (#224) : sans engagement, retirer TBP_PROXY_ANO_SOCKET (qui désactive
// l'anonymisation), relever TBP_OPA_TRIP_AFTER ou couper la file d'admission d'OPA entre deux démarrages changeait le
// comportement sans divergence ni alarme. Engagée dans le témoin, toute dérive diverge : le démon refuse jusqu'à une
// transition signée par le quorum.
type Posture map[string]string

// OnOff : la forme canonique d'un interrupteur.
func OnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// Bytes sérialise la posture sous la forme que le témoin engage : « clé=valeur », une par ligne, TRIÉES (déterministe).
// Une clé ou une valeur vide, ou portant « = » / saut de ligne, est une erreur de programmation : panique, jamais un
// engagement ambigu.
func (p Posture) Bytes() []byte {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := p[k]
		if k == "" || v == "" || strings.ContainsAny(k, "=\n\r") || strings.ContainsAny(v, "\n\r") {
			panic(fmt.Sprintf("pep: posture : entrée invalide %q=%q", k, v))
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// OPAPosture ajoute à p les interrupteurs de la file d'admission d'OPA et de la détection de blocage (communs à pepd et
// brokerd) : « actif » ou non, pas les valeurs de réglage.
func (p Posture) OPAPosture(t OPATuning) {
	p["opa-admission"] = OnOff(t.Admission.MaxInflight > 0)
	p["opa-stall-detection"] = OnOff(t.StallWindow > 0)
}
