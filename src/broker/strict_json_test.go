package broker

// strict_json_test.go — #289 : le corps de POST /v1/actions ET l'intention structurée qu'il porte sont
// décodés STRICTEMENT. Clé en double, champ inconnu, casse inexacte, contenu après l'objet ⇒ refus avec le
// détail que l'agent peut lire pour corriger sa demande — jamais de « dernier gagne », jamais de jeton.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postActions(t *testing.T, url, body string) (int, actionResponseJSON) {
	t.Helper()
	resp, err := http.Post(url+"/v1/actions", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST : %v", err)
	}
	defer resp.Body.Close()
	var out actionResponseJSON
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func strictFixture(t *testing.T) (*httptest.Server, *leafRecorder) {
	t.Helper()
	opa := opaServer(t, func(map[string]any) bool { return true }, 0)
	t.Cleanup(opa.Close)
	b, _, leaves, _ := newTestBroker(t, opa.URL, StructuredTranslator{})
	s, err := NewServer(ServerOptions{Broker: b})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, leaves
}

func TestActionsBodyIsStrictAndRefusalHasNoEffect(t *testing.T) {
	srv, leaves := strictFixture(t)
	intent := fmt.Sprintf("%q", simpleIntent(t, "a", "r"))
	good := `{"subject":"agent-1","intent":` + intent + `}`

	// voisin : le corps propre est accepté et rend un jeton
	if status, out := postActions(t, srv.URL, good); status != http.StatusOK || !out.Allow || out.Token == "" {
		t.Fatalf("corps propre : %d %+v", status, out)
	}
	before := len(leaves.all())

	cases := []struct{ name, body, code, key string }{
		{"sujet en double", `{"subject":"agent-1","subject":"agent-2","intent":` + intent + `}`, "duplicate-key", "subject"},
		{"champ inconnu", `{"subject":"agent-1","intent":` + intent + `,"backdoor":true}`, "unknown-field", "backdoor"},
		{"casse inexacte", `{"Subject":"agent-1","intent":` + intent + `}`, "unknown-field", "Subject"},
		{"contenu après l'objet", good + ` {"subject":"agent-2"}`, "trailing-content", ""},
	}
	for _, c := range cases {
		resp, err := http.Post(srv.URL+"/v1/actions", "application/json", strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		var out struct {
			Allow  bool   `json:"allow"`
			Reason string `json:"reason"`
			Token  string `json:"token"`
			Detail struct {
				Code     string   `json:"code"`
				Key      string   `json:"key"`
				Accepted []string `json:"accepted"`
			} `json:"detail"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || out.Allow || out.Token != "" || out.Reason != ReasonRequestInvalid {
			t.Fatalf("%s : %d %+v, veut 400 request-invalid sans jeton", c.name, resp.StatusCode, out)
		}
		if out.Detail.Code != c.code || out.Detail.Key != c.key {
			t.Fatalf("%s : détail %+v, veut code=%s key=%q", c.name, out.Detail, c.code, c.key)
		}
		if c.code == "unknown-field" && strings.Join(out.Detail.Accepted, ",") != "intent,subject" {
			t.Fatalf("%s : champs acceptés %v, veut [intent subject] — l'agent doit savoir quoi envoyer", c.name, out.Detail.Accepted)
		}
	}
	if after := len(leaves.all()); after != before {
		t.Fatalf("%d feuille(s) écrite(s) par des corps refusés : le 400 doit être sans effet", after-before)
	}
}

func TestStructuredIntentIsStrictAndTheAgentIsToldWhy(t *testing.T) {
	srv, _ := strictFixture(t)
	post := func(intent string) (int, actionResponseJSON) {
		body, _ := json.Marshal(map[string]string{"subject": "agent-1", "intent": intent})
		return postActions(t, srv.URL, string(body))
	}
	cases := []struct{ name, intent, code, key string }{
		{"action en double (dernier gagnait : read → delete)", `{"action":"read","action":"delete","resource":"r"}`, "duplicate-key", "action"},
		{"champ inconnu", `{"action":"read","resource":"r","bogus":1}`, "unknown-field", "bogus"},
		{"casse inexacte", `{"ACTION":"delete","resource":"r"}`, "unknown-field", "ACTION"},
		{"quota imbriqué à la casse inexacte", `{"action":"a","resource":"r","quota":{"Resource":"x","operation":"o","volume_max":1,"window_s":1}}`, "unknown-field", "Resource"},
		{"contenu après l'objet", `{"action":"read","resource":"r"} {"action":"delete"}`, "trailing-content", ""},
		{"action absente", `{"resource":"r"}`, "missing-field", "action"},
		{"ressource absente", `{"action":"read"}`, "missing-field", "resource"},
		{"classe hors bornes", `{"action":"a","resource":"r","class":9}`, "out-of-range", "class"},
	}
	for _, c := range cases {
		status, out := post(c.intent)
		if status != http.StatusOK || out.Allow || out.Reason != ReasonTranslationFailed || out.Token != "" {
			t.Fatalf("%s : %d %+v, veut allow=false translation-failed sans jeton", c.name, status, out)
		}
		if out.Detail == nil || out.Detail.Code != c.code || out.Detail.Key != c.key {
			t.Fatalf("%s : détail %+v, veut code=%s key=%q", c.name, out.Detail, c.code, c.key)
		}
		if c.code == "unknown-field" && len(out.Detail.Accepted) == 0 {
			t.Fatalf("%s : le refus ne dit pas quels champs sont acceptés", c.name)
		}
	}
	// un refus de DÉCISION (OPA, quorum…) ne porte aucun détail de forme : le détail n'est pas un oracle
	// sur la politique
	if _, out := post(simpleIntent(t, "a", "r")); !out.Allow || out.Detail != nil {
		t.Fatalf("intention propre : %+v", out)
	}
}

func TestRefusalDetailNeverCarriesRequestValues(t *testing.T) {
	srv, _ := strictFixture(t)
	body, _ := json.Marshal(map[string]string{"subject": "agent-1", "intent": `{"action":"valeur-secrete","resource":"r","bogus":"autre-secret"}`})
	resp, err := http.Post(srv.URL+"/v1/actions", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var raw strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		raw.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if strings.Contains(raw.String(), "valeur-secrete") || strings.Contains(raw.String(), "autre-secret") {
		t.Fatalf("le refus renvoie le CONTENU de la demande : %s", raw.String())
	}
	if !strings.Contains(raw.String(), `"bogus"`) {
		t.Fatalf("le refus ne nomme pas la clé fautive : %s", raw.String())
	}
}
