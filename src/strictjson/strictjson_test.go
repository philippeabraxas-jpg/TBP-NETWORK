package strictjson

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type inner struct {
	N int `json:"n"`
}

type embedded struct {
	E string `json:"e"`
}

type selfDecoded struct{ v string }

func (s *selfDecoded) UnmarshalJSON(b []byte) error { s.v = string(b); return nil }

type doc struct {
	embedded
	A      string            `json:"a"`
	B      *inner            `json:"b,omitempty"`
	L      []inner           `json:"l"`
	M      map[string]inner  `json:"m"`
	R      json.RawMessage   `json:"r"`
	X      any               `json:"x"`
	U      selfDecoded       `json:"u"`
	Plain  string            // sans tag : le nom du champ fait foi
	Skip   string            `json:"-"`
	hidden string            //nolint:unused
	Any    map[string]string `json:"any"`
}

var _ = doc{}.hidden

func decode(t *testing.T, in string) (*doc, error) {
	t.Helper()
	var d doc
	return &d, Decode([]byte(in), &d)
}

func wantCode(t *testing.T, in, code string) *Error {
	t.Helper()
	_, err := decode(t, in)
	e, ok := As(err)
	if !ok {
		t.Fatalf("%s : accepté ou erreur non typée (%v), attendu %s", in, err, code)
	}
	if e.Detail.Code != code {
		t.Fatalf("%s : code %q, attendu %q (%v)", in, e.Detail.Code, code, err)
	}
	return e
}

func TestAcceptsTheExactDocument(t *testing.T) {
	good := []string{
		`{}`,
		`{"a":"x"}`,
		" \n{\"a\":\"x\"}\n\n", // espaces autour : pas du contenu
		`{"e":"promu","a":"x","b":{"n":1},"l":[{"n":1},{"n":2}],"m":{"nom-libre":{"n":3},"AUTRE":{"n":4}}}`,
		`{"r":{"Casse":1,"casse":2},"x":{"AnyKey":1,"anykey":2}}`, // RawMessage et interface : noms libres (opaques)
		`{"u":{"Libre":1}}`, // json.Unmarshaler : opaque
		`{"Plain":"x"}`,
		`{"any":{"Clé":"v","clé":"w"}}`, // table de chaînes : les clés sont des données
		`{"a":"x","b":null}`,
	}
	for _, in := range good {
		if _, err := decode(t, in); err != nil {
			t.Errorf("%q refusé : %v", in, err)
		}
	}
	d, err := decode(t, `{"e":"promu","a":"x","Plain":"p"}`)
	if err != nil || d.E != "promu" || d.A != "x" || d.Plain != "p" {
		t.Fatalf("valeurs : %+v, %v", d, err)
	}
}

func TestRefusesDuplicateKeys(t *testing.T) {
	for _, in := range []string{
		`{"a":"x","a":"y"}`,
		`{"l":[{"n":1},{"n":2,"n":3}]}`,
		`{"b":{"n":1,"n":2}}`,
		`{"a":"x","a":"y"}`,   // même clé après décodage des échappements
		`{"r":{"k":1,"k":2}}`, // même dans une valeur opaque : le différentiel est le même
	} {
		e := wantCode(t, in, CodeDuplicateKey)
		if e.Detail.Key == "" {
			t.Errorf("%s : clé en double non citée", in)
		}
	}
	// voisin : la même clé dans deux objets DIFFÉRENTS n'est pas un doublon
	if _, err := decode(t, `{"l":[{"n":1},{"n":2}],"b":{"n":3}}`); err != nil {
		t.Errorf("même clé dans des objets distincts refusée : %v", err)
	}
}

func TestRefusesUnknownAndMisCasedFields(t *testing.T) {
	e := wantCode(t, `{"A":"x"}`, CodeUnknownField)
	if e.Detail.Key != "A" || e.Detail.Path != "" {
		t.Fatalf("détail : %+v", e.Detail)
	}
	// les noms acceptés sont ceux d'encoding/json : promus inclus, non exportés et « - » exclus, triés
	want := []string{"Plain", "a", "any", "b", "e", "l", "m", "r", "u", "x"}
	if !reflect.DeepEqual(e.Detail.Accepted, want) {
		t.Fatalf("acceptés %v, attendu %v", e.Detail.Accepted, want)
	}
	for _, in := range []string{
		`{"a":"x","bogus":1}`,
		`{"hidden":"x"}`, // non exporté
		`{"Skip":"x"}`,   // json:"-"
		`{"E":"promu"}`,  // champ promu, mauvaise casse
		`{"plain":"x"}`,  // sans tag : « Plain » exactement
	} {
		wantCode(t, in, CodeUnknownField)
	}
	e = wantCode(t, `{"b":{"N":1}}`, CodeUnknownField)
	if e.Detail.Path != "b" || !reflect.DeepEqual(e.Detail.Accepted, []string{"n"}) {
		t.Fatalf("objet imbriqué : %+v", e.Detail)
	}
	e = wantCode(t, `{"l":[{"n":1},{"N":2}]}`, CodeUnknownField)
	if e.Detail.Path != "l[1]" {
		t.Fatalf("élément de tableau : %+v", e.Detail)
	}
	e = wantCode(t, `{"m":{"agent-1":{"N":2}}}`, CodeUnknownField)
	if e.Detail.Path != "m.agent-1" {
		t.Fatalf("valeur de table : %+v", e.Detail)
	}
}

func TestRefusesTrailingContentBadUTF8AndSyntax(t *testing.T) {
	for _, in := range []string{`{"a":"x"} {"a":"y"}`, `{"a":"x"} x`, `{"a":"x"}{`, `{"a":"x"} 1`} {
		wantCode(t, in, CodeTrailingContent)
	}
	wantCode(t, "{\"a\":\"x\xffy\"}", CodeInvalidUTF8)
	wantCode(t, `{"a":`, CodeSyntax)
	wantCode(t, `[1,2]`, CodeType) // pas un objet
	wantCode(t, `{"a":1}`, CodeType)
	e := wantCode(t, `{"b":{"n":"x"}}`, CodeType)
	if !strings.Contains(e.Error(), "n") || errors.Unwrap(e) == nil {
		t.Fatalf("la cause du décodeur doit rester accessible : %v", e)
	}
}

func TestKeyEchoIsBoundedAndNeverTheValue(t *testing.T) {
	long := strings.Repeat("é", 200) // clé énorme : citée tronquée, sur une frontière de rune
	e := wantCode(t, `{"`+long+`":"valeur-secrete"}`, CodeUnknownField)
	if len(e.Detail.Key) > maxKeyEcho+len("…") || !strings.HasSuffix(e.Detail.Key, "…") {
		t.Fatalf("clé non bornée : %d octets", len(e.Detail.Key))
	}
	raw, _ := json.Marshal(e.Detail)
	if strings.Contains(string(raw), "valeur-secrete") || strings.Contains(e.Error(), "valeur-secrete") {
		t.Fatal("le refus laisse fuir une VALEUR de la demande")
	}
}

func TestDetailJSONShape(t *testing.T) {
	e := wantCode(t, `{"A":"x"}`, CodeUnknownField)
	raw, err := json.Marshal(e.Detail)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	if back["code"] != "unknown-field" || back["key"] != "A" || back["accepted"] == nil {
		t.Fatalf("forme du détail : %s", raw)
	}
}

// Les décodeurs de registres (#241) cartographient des tables de structures : la marche vérifie les valeurs.
func TestMapOfStructsTarget(t *testing.T) {
	var m map[string]inner
	if err := Decode([]byte(`{"agent-1":{"n":1},"Agent-2":{"n":2}}`), &m); err != nil {
		t.Fatalf("clés de table libres refusées : %v", err)
	}
	if err := Decode([]byte(`{"agent-1":{"N":1}}`), &m); err == nil {
		t.Fatal("casse inexacte dans une valeur de table acceptée")
	}
	if err := Decode([]byte(`{"agent-1":{"n":1},"agent-1":{"n":2}}`), &m); err == nil {
		t.Fatal("agent en double accepté")
	}
}

// Le refus est déterministe : deux clés fautives, c'est toujours la même qui est citée.
func TestRefusalIsDeterministic(t *testing.T) {
	for i := 0; i < 60; i++ {
		e := wantCode(t, `{"Zz":1,"Mm":2,"Aa":3}`, CodeUnknownField)
		if e.Detail.Key != "Aa" {
			t.Fatalf("clé citée %q au tour %d, attendu toujours « Aa »", e.Detail.Key, i)
		}
	}
}

func TestDuplicateJSONKeyDetector(t *testing.T) {
	cases := []struct {
		in   string
		key  string
		want bool
	}{
		{`{}`, "", false},
		{`{"a":1,"b":2}`, "", false},
		{`{"a":1,"a":2}`, "a", true},
		{`{"a":{"x":1},"b":{"x":2}}`, "", false},
		{`{"a":{"x":1,"x":2}}`, "x", true},
		{`{"a":[{"x":1},{"x":2}],"b":[1,2,3]}`, "", false},
		{`{"a":[{"x":1,"x":2}]}`, "x", true},
		{`{"a":[1,2],"a":3}`, "a", true},
		{`{"a":"b","b":"a"}`, "", false}, // une valeur chaîne n'est pas une clé
		{`[{"a":1},{"a":1}]`, "", false},
	}
	for _, c := range cases {
		k, got := duplicateKey([]byte(c.in))
		if got != c.want || k != c.key {
			t.Fatalf("%s : (%q,%v), veut (%q,%v)", c.in, k, got, c.key, c.want)
		}
	}
}
