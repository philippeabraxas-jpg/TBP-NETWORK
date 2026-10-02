package pep

// strict_body_test.go — #289 : les corps JSON des plans de pepd sont décodés STRICTEMENT. Clé en double,
// champ inconnu, casse inexacte, contenu après l'objet ⇒ 400 avec le détail que le client peut lire, et
// AUCUN effet (pas de feuille, pas de compteur décrémenté, pas de bascule de posture, condition toujours
// levée). Le corps propre, lui, passe : un refus qui refuserait tout ne prouverait rien.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type strictCase struct {
	name, body string
	code, key  string
}

// badBodies : une variante fautive de chaque classe, à partir des champs réels des corps.
func badBodies(base func(extra string) string, dupField, dupValue, caseField, caseValue string) []strictCase {
	return []strictCase{
		{"clé en double", base(`,"` + dupField + `":` + dupValue), "duplicate-key", dupField},
		{"champ inconnu", base(`,"extra":1`), "unknown-field", "extra"},
		{"casse inexacte", strings.Replace(base(""), `"`+strings.ToLower(caseField)+`":`, `"`+caseField+`":`, 1), "unknown-field", caseField},
		{"contenu après l'objet", base("") + ` {"x":1}`, "trailing-content", ""},
	}
}

func requireRefusal(t *testing.T, status int, body []byte, c strictCase) {
	t.Helper()
	if status != http.StatusBadRequest {
		t.Fatalf("%s : status=%d, veut 400 (%s)", c.name, status, body)
	}
	var out struct {
		Detail struct {
			Code     string   `json:"code"`
			Key      string   `json:"key"`
			Accepted []string `json:"accepted"`
		} `json:"detail"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%s : réponse illisible : %v (%s)", c.name, err, body)
	}
	if out.Detail.Code != c.code || out.Detail.Key != c.key {
		t.Fatalf("%s : détail %+v, veut code=%s key=%q", c.name, out.Detail, c.code, c.key)
	}
	if c.code == "unknown-field" && len(out.Detail.Accepted) == 0 {
		t.Fatalf("%s : le refus ne dit pas quels champs sont acceptés", c.name)
	}
}

func TestEvaluateBodyIsStrictAndHasNoEffectWhenRefused(t *testing.T) {
	f := newListenerFixture(t, false)
	tok := mintToken(t, nominalClaims())
	b64 := base64.StdEncoding.EncodeToString(tok)
	base := func(extra string) string {
		return `{"token":"` + b64 + `","action":"read","resource":"doc-1"` + extra + `}`
	}
	// voisin : le corps propre est évalué (200) — et laisse une feuille
	status, data := postJSON(t, f.srv.URL+"/v1/evaluate", []byte(base("")))
	if status != http.StatusOK {
		t.Fatalf("corps propre refusé : %d %s", status, data)
	}
	f.sink.mu.Lock()
	before := len(f.sink.leaves)
	f.sink.mu.Unlock()

	for _, c := range badBodies(base, "action", `"delete"`, "ACTION", "") {
		status, data := postJSON(t, f.srv.URL+"/v1/evaluate", []byte(c.body))
		requireRefusal(t, status, data, c)
	}
	f.sink.mu.Lock()
	after := len(f.sink.leaves)
	f.sink.mu.Unlock()
	if after != before {
		t.Fatalf("%d feuille(s) écrite(s) par des corps refusés : le refus doit être sans effet", after-before)
	}
}

func TestConsumeBodyIsStrictAndDoesNotDecrement(t *testing.T) {
	f := newListenerFixture(t, true)
	tok := mintToken(t, quotaClaims(100, 60))
	if out := evaluate(t, f, tok); !out.Allow || !out.PassportOpened {
		t.Fatalf("ouverture du passeport : %+v", out)
	}
	b64 := base64.StdEncoding.EncodeToString(tok)
	base := func(extra string) string { return `{"token":"` + b64 + `","n":5` + extra + `}` }

	status, c0 := consume(t, f, tok, 1)
	if status != http.StatusOK || !c0.OK {
		t.Fatalf("consume propre : %d %+v", status, c0)
	}
	for _, c := range badBodies(base, "n", "50", "N", "") {
		status, data := postJSON(t, f.srv.URL+"/v1/passport/consume", []byte(c.body))
		requireRefusal(t, status, data, c)
	}
	// aucun des corps refusés n'a décrémenté : le prochain décrément propre part de l'état d'avant
	status, c1 := consume(t, f, tok, 1)
	if status != http.StatusOK || !c1.OK || c1.Remaining != c0.Remaining-1 {
		t.Fatalf("compteur déplacé par des corps refusés : avant=%d après=%d (%+v)", c0.Remaining, c1.Remaining, c1)
	}
}

func TestModeBodyIsStrictAndDoesNotSwitchPosture(t *testing.T) {
	f := newListenerFixture(t, false)
	base := func(extra string) string { return `{"mode":"closed","expiry":1,"signatures":[]` + extra + `}` }
	for _, c := range badBodies(base, "mode", `"monitor"`, "Mode", "") {
		status, data := postJSON(t, f.adminSrv.URL+"/v1/mode", []byte(c.body))
		requireRefusal(t, status, data, c)
		if f.mc.Mode() != ModeMonitor {
			t.Fatalf("%s : la posture a basculé sur un corps refusé", c.name)
		}
	}
	// une signature mal nommée, DANS le tableau, est refusée de même (la marche descend dans les structures)
	nested := `{"mode":"closed","expiry":1,"signatures":[{"KEY_ID":"aa","signature":"bb"}]}`
	status, data := postJSON(t, f.adminSrv.URL+"/v1/mode", []byte(nested))
	requireRefusal(t, status, data, strictCase{"imbriqué", nested, "unknown-field", "KEY_ID"})
	// voisin : le corps propre arrive à la vérification de quorum (jamais un 400 de forme)
	status, data = postJSON(t, f.adminSrv.URL+"/v1/mode", []byte(base("")))
	if status == http.StatusBadRequest && strings.Contains(string(data), `"detail"`) {
		t.Fatalf("corps propre refusé pour sa forme : %s", data)
	}
}

func TestFailClosedClearBodyIsStrictAndKeepsTheConditionTripped(t *testing.T) {
	h, fc := newFailClosedAdmin(t)
	fc.Trip(ReasonOPAUnreachable, "test")
	base := func(extra string) string { return `{"condition":"` + ReasonOPAUnreachable + `"` + extra + `}` }
	for _, c := range badBodies(base, "condition", `"autre"`, "Condition", "") {
		rec := adminPost(h, "/v1/failclosed/clear", c.body)
		requireRefusal(t, rec.Code, rec.Body.Bytes(), c)
		if fc.Gate() == nil {
			t.Fatalf("%s : la condition a été levée par un corps refusé", c.name)
		}
	}
	// voisin : le corps propre lève la condition de classe I
	if rec := adminPost(h, "/v1/failclosed/clear", base("")); rec.Code != http.StatusOK || fc.Gate() != nil {
		t.Fatalf("corps propre : %d %s (condition encore basculée : %v)", rec.Code, rec.Body.String(), fc.Gate() != nil)
	}
}
