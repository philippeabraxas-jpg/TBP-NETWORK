// Package strictjson décode UN document JSON en refusant tout ce que le décodeur standard de Go
// accepte en silence et qui crée un différentiel de parseur (#241, #274, #289) :
//
//   - une clé en double, à n'importe quelle profondeur (encoding/json garde la dernière) ;
//   - une clé qui n'est pas EXACTEMENT un nom de champ de la structure cible : champ inconnu, mais
//     aussi casse différente (encoding/json apparie « ACTION » au champ « action ») ;
//   - du contenu après le document (Decoder.Decode s'arrête au premier objet) ;
//   - de l'UTF-8 invalide (encoding/json le remplace silencieusement par U+FFFD).
//
// Ce qu'un proxy, un WAF, un journal ou un outil de revue lit doit être ce que le démon applique :
// un client légitime n'émet que les champs documentés, avec leur casse exacte.
//
// Le refus est une *Error : un code stable lisible par une machine et, pour un champ inconnu, la
// liste des noms acceptés à cet endroit — de quoi dire à l'agent « voici la bonne structure » sans
// jamais renvoyer le contenu de sa demande (seul le NOM fautif, borné, est cité).
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"unicode/utf8"
)

// Codes de refus (stables : ils sont rendus aux clients).
const (
	CodeDuplicateKey    = "duplicate-key"
	CodeUnknownField    = "unknown-field" // inconnu, ou casse différente du nom exact
	CodeTrailingContent = "trailing-content"
	CodeInvalidUTF8     = "invalid-utf8"
	CodeSyntax          = "syntax"
	CodeType            = "type" // un champ n'a pas le type attendu
)

// maxKeyEcho borne le nom de clé cité dans un refus (la clé vient du client).
const maxKeyEcho = 64

// Detail est ce que le client reçoit : un code stable, la clé fautive (bornée), son chemin et, pour un
// champ inconnu, les noms exacts acceptés à cet endroit.
type Detail struct {
	Code     string   `json:"code"`
	Key      string   `json:"key,omitempty"`
	Path     string   `json:"path,omitempty"`
	Accepted []string `json:"accepted,omitempty"`
}

// Error est le refus d'un document.
type Error struct {
	Detail Detail
	cause  error
}

func (e *Error) Error() string {
	d := e.Detail
	switch d.Code {
	case CodeDuplicateKey:
		return fmt.Sprintf("clé JSON %q en double%s (un « dernier gagne » silencieux est refusé)", d.Key, atPath(d.Path))
	case CodeUnknownField:
		return fmt.Sprintf("champ JSON %q inconnu ou de casse inexacte%s (acceptés : %s)", d.Key, atPath(d.Path), strings.Join(d.Accepted, ", "))
	case CodeTrailingContent:
		return "contenu après le document JSON"
	case CodeInvalidUTF8:
		return "UTF-8 invalide dans le document JSON"
	case CodeType:
		if e.cause != nil {
			return "champ JSON de mauvais type : " + e.cause.Error()
		}
	case CodeSyntax:
		if e.cause != nil {
			return "JSON illisible : " + e.cause.Error()
		}
	}
	return "JSON refusé : " + d.Code
}

// Unwrap rend la cause du décodeur standard, s'il y en a une.
func (e *Error) Unwrap() error { return e.cause }

func atPath(p string) string {
	if p == "" {
		return ""
	}
	return " dans " + p
}

// As rend l'*Error portée par err, s'il y en a une.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func truncKey(k string) string {
	if len(k) <= maxKeyEcho {
		return k
	}
	cut := maxKeyEcho
	for cut > 0 && !utf8.RuneStart(k[cut]) {
		cut--
	}
	return k[:cut] + "…"
}

func fail(code, key, path string, accepted []string, cause error) *Error {
	return &Error{Detail: Detail{Code: code, Key: truncKey(key), Path: path, Accepted: accepted}, cause: cause}
}

// Decode décode data (UN document) dans v, strictement. v est un pointeur, comme pour json.Unmarshal.
func Decode(data []byte, v any) error {
	if !utf8.Valid(data) {
		return fail(CodeInvalidUTF8, "", "", nil, nil)
	}
	if key, dup := duplicateKey(data); dup {
		return fail(CodeDuplicateKey, key, "", nil, nil)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return fail(CodeSyntax, "", "", nil, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fail(CodeTrailingContent, "", "", nil, nil)
	}
	if t := reflect.TypeOf(v); t != nil && t.Kind() == reflect.Pointer {
		if e := walk(raw, t.Elem(), ""); e != nil {
			return e
		}
	}
	d2 := json.NewDecoder(bytes.NewReader(raw))
	d2.DisallowUnknownFields() // ceinture : la marche ci-dessus est la vérification exacte
	if err := d2.Decode(v); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) {
			return fail(CodeType, ute.Field, "", nil, err)
		}
		return fail(CodeSyntax, "", "", nil, err)
	}
	return nil
}

var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

func selfDecodes(t reflect.Type) bool {
	return t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType)
}

// walk vérifie que chaque clé de chaque objet de raw est EXACTEMENT un nom de champ de t à cet endroit.
// Les types qui se décodent eux-mêmes (json.Unmarshaler, json.RawMessage) et les interfaces sont opaques.
func walk(raw []byte, t reflect.Type, path string) *Error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if selfDecodes(t) {
		return nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if raw[0] != '{' {
			return nil // mauvais type : rapporté par le décodeur
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return nil
		}
		fields := fieldTypes(t)
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys) // refus déterministe : toujours la même clé citée
		for _, k := range keys {
			ft, ok := fields[k]
			if !ok {
				return fail(CodeUnknownField, k, path, sortedNames(fields), nil)
			}
			if e := walk(obj[k], ft, joinPath(path, k)); e != nil {
				return e
			}
		}
	case reflect.Slice, reflect.Array:
		if raw[0] != '[' {
			return nil
		}
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return nil
		}
		for i, el := range arr {
			if e := walk(el, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); e != nil {
				return e
			}
		}
	case reflect.Map:
		if raw[0] != '{' {
			return nil
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return nil
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys { // les clés d'une table sont des DONNÉES (noms d'agents…) : seules les valeurs sont vérifiées
			if e := walk(obj[k], t.Elem(), joinPath(path, truncKey(k))); e != nil {
				return e
			}
		}
	}
	return nil
}

func joinPath(path, key string) string {
	if path == "" {
		return truncKey(key)
	}
	return path + "." + truncKey(key)
}

func sortedNames(fields map[string]reflect.Type) []string {
	names := make([]string, 0, len(fields))
	for n := range fields {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// fieldTypes rend nom JSON exact → type, comme encoding/json les voit (tags, champs promus des
// structures embarquées, champs non exportés et « - » exclus).
func fieldTypes(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	var collect func(t reflect.Type)
	collect = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := f.Name
			if tag != "" {
				if n, _, _ := strings.Cut(tag, ","); n != "" {
					name = n
				}
			}
			if f.Anonymous && (tag == "" || strings.HasPrefix(tag, ",")) {
				ft := f.Type
				for ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					collect(ft)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if _, taken := out[name]; !taken {
				out[name] = f.Type
			}
		}
	}
	collect(t)
	return out
}

// duplicateKey rend la première clé d'objet présente deux fois dans un MÊME objet, à n'importe quelle
// profondeur. Les clés sont comparées APRÈS décodage des échappements (« a » et « a » sont la
// même clé). Les erreurs de syntaxe sont laissées au décodeur qui suit.
func duplicateKey(data []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	// pile d'ensembles de clés : un par objet ouvert ; nil pour un tableau
	var keys []map[string]bool
	var expectKey []bool // vrai quand le prochain token d'un objet est une clé
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				keys = append(keys, map[string]bool{})
				expectKey = append(expectKey, true)
			case '[':
				keys = append(keys, nil)
				expectKey = append(expectKey, false)
			default: // '}' ou ']'
				keys = keys[:len(keys)-1]
				expectKey = expectKey[:len(expectKey)-1]
				if n := len(expectKey); n > 0 && keys[n-1] != nil {
					expectKey[n-1] = true // la valeur de l'objet parent est finie
				}
			}
			continue
		case string:
			if n := len(keys); n > 0 && keys[n-1] != nil && expectKey[n-1] {
				if keys[n-1][t] {
					return t, true
				}
				keys[n-1][t] = true
				expectKey[n-1] = false // la valeur suit
				continue
			}
		}
		// valeur scalaire : si on est dans un objet, la prochaine entrée est une clé
		if n := len(keys); n > 0 && keys[n-1] != nil {
			expectKey[n-1] = true
		}
	}
}
