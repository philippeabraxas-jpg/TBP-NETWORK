package ano

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testExpiry = time.Now().Add(time.Hour)

func mustRules(t *testing.T, cfg RulesConfig) *Rules {
	t.Helper()
	r, err := NewRules(cfg)
	if err != nil {
		t.Fatalf("NewRules: %v", err)
	}
	return r
}

func newAno(t *testing.T, opts Options) *Ano {
	t.Helper()
	if opts.Rules == nil {
		opts.Rules = mustRules(t, RulesConfig{})
	}
	a, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func open(t *testing.T, a *Ano, id string) {
	t.Helper()
	if err := a.Open(id, testExpiry); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

type fakeClassifier struct {
	fn    func(ctx context.Context, path, value string) (bool, error)
	calls atomic.Int64
}

func (f *fakeClassifier) Decide(ctx context.Context, path, value string) (bool, error) {
	f.calls.Add(1)
	return f.fn(ctx, path, value)
}

func answer(mask bool) *fakeClassifier {
	return &fakeClassifier{fn: func(context.Context, string, string) (bool, error) { return mask, nil }}
}

func jsonEqual(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("sortie non JSON %q: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("attendu non JSON: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("JSON différent:\n got %s\nwant %s", got, want)
	}
}

func TestRulesKeepMaskAndOrderPreserved(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{
		KeepPaths: []string{"action", "currency"},
		MaskPaths: []string{"beneficiary", "items.*.iban"},
	}), Classifier: answer(false)})
	open(t, a, "ex1")
	in := `{"action":"transfer","beneficiary":{"name":"Mme Machin","account":"12345"},"currency":"EUR","items":[{"iban":"FR7630006000011234567890189","label":"loyer"}]}`
	out, rep, err := a.MaskJSON(context.Background(), "ex1", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, secret := range []string{"Mme Machin", "12345", "FR7630006000011234567890189"} {
		if strings.Contains(s, secret) {
			t.Fatalf("la valeur %q sort en clair: %s", secret, s)
		}
	}
	if !strings.Contains(s, `"action":"transfer"`) || !strings.Contains(s, `"currency":"EUR"`) || !strings.Contains(s, `"label":"loyer"`) {
		t.Fatalf("champs gardés altérés: %s", s)
	}
	// ordre des clés d'origine conservé
	if strings.Index(s, `"action"`) > strings.Index(s, `"beneficiary"`) || strings.Index(s, `"beneficiary"`) > strings.Index(s, `"currency"`) {
		t.Fatalf("ordre des clés non conservé: %s", s)
	}
	if rep.MaskedPath != 3 {
		t.Fatalf("MaskedPath=%d, veut 3 (name, account, iban)", rep.MaskedPath)
	}
}

func TestPrecedenceLongestPrefixThenMask(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{
		MaskPaths: []string{"beneficiary", "same"},
		KeepPaths: []string{"beneficiary.country", "same"},
	}), Classifier: answer(false)})
	open(t, a, "ex")
	out, _, err := a.MaskJSON(context.Background(), "ex", []byte(`{"beneficiary":{"country":"FR","name":"X"},"same":"v"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"country":"FR"`) {
		t.Fatalf("keep plus spécifique aurait dû garder country: %s", s)
	}
	if strings.Contains(s, `"name":"X"`) {
		t.Fatalf("name devait être masqué: %s", s)
	}
	if strings.Contains(s, `"same":"v"`) {
		t.Fatalf("à longueur égale le masquage doit l'emporter: %s", s)
	}
}

func TestDefaultDenyWithoutClassifier(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{KeepPaths: []string{"action"}})})
	open(t, a, "ex")
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(`{"action":"pay","amount":50000,"note":"salut","empty":""}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "50000") || strings.Contains(s, "salut") {
		t.Fatalf("default-deny: valeur non gardée sortie en clair: %s", s)
	}
	if !strings.Contains(s, `"action":"pay"`) || !strings.Contains(s, `"empty":""`) {
		t.Fatalf("garde/vide altérés: %s", s)
	}
	if rep.MaskedDefault != 2 {
		t.Fatalf("MaskedDefault=%d, veut 2", rep.MaskedDefault)
	}
}

func TestClassifierYesNoAndCannotWeakenRules(t *testing.T) {
	c := &fakeClassifier{fn: func(_ context.Context, path, value string) (bool, error) {
		return value == "secret", nil
	}}
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{MaskPaths: []string{"forced"}}), Classifier: c})
	open(t, a, "ex")
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(`{"a":"secret","b":"public","forced":"public"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, `"a":"secret"`) {
		t.Fatalf("le classifieur a dit oui: a devait être masqué: %s", s)
	}
	if !strings.Contains(s, `"b":"public"`) {
		t.Fatalf("le classifieur a dit non: b devait rester: %s", s)
	}
	if strings.Contains(s, `"forced":"public"`) {
		t.Fatalf("l'IA ne peut pas affaiblir une règle de masquage: %s", s)
	}
	if rep.MaskedClassifier != 1 || rep.MaskedPath != 1 || rep.ClassifierCalls != 2 {
		t.Fatalf("rapport inattendu: %+v (le classifieur ne doit pas être appelé pour un champ règlé)", rep)
	}
}

func TestClassifierFaultsMask(t *testing.T) {
	cases := map[string]*fakeClassifier{
		"erreur": {fn: func(context.Context, string, string) (bool, error) { return false, errors.New("boom") }},
		"retard": {fn: func(ctx context.Context, _, _ string) (bool, error) {
			time.Sleep(60 * time.Millisecond) // ignore le contexte : doit être coupé quand même
			return false, nil
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var trips atomic.Int64
			a := newAno(t, Options{Classifier: c, OnTrip: func(string) { trips.Add(1) }})
			open(t, a, "ex")
			start := time.Now()
			out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(`{"x":"valeur"}`))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(out), "valeur") {
				t.Fatalf("faute du classifieur ⇒ le champ doit être masqué: %s", out)
			}
			if rep.ClassifierFaults != 1 || trips.Load() == 0 {
				t.Fatalf("faute non comptée / non alarmée: %+v trips=%d", rep, trips.Load())
			}
			if time.Since(start) > 40*time.Millisecond {
				t.Fatalf("l'attente du classifieur n'est pas bornée: %v", time.Since(start))
			}
		})
	}
}

func TestClassifierInflightBoundAndCallBudget(t *testing.T) {
	block := make(chan struct{})
	c := &fakeClassifier{fn: func(context.Context, string, string) (bool, error) {
		<-block
		return false, nil
	}}
	a := newAno(t, Options{Classifier: c, ClassifierMaxInflight: 1, ClassifierTimeout: time.Millisecond})
	open(t, a, "ex")
	// deux champs : le premier occupe l'unique place puis expire, le second est
	// refusé par saturation — les deux masqués.
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(`{"a":"1x","b":"2y"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "1x") || strings.Contains(string(out), "2y") {
		t.Fatalf("champs non masqués: %s", out)
	}
	if rep.ClassifierFaults != 2 {
		t.Fatalf("ClassifierFaults=%d, veut 2", rep.ClassifierFaults)
	}
	close(block)

	// budget d'appels par charge
	c2 := answer(false)
	a2 := newAno(t, Options{Classifier: c2, MaxClassifierCalls: 2})
	open(t, a2, "ex")
	out, rep, err = a2.MaskJSON(context.Background(), "ex", []byte(`{"a":"1x","b":"2y","c":"3z","d":"4w"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c2.calls.Load() != 2 {
		t.Fatalf("appels=%d, veut 2 (budget)", c2.calls.Load())
	}
	if strings.Contains(string(out), "3z") || strings.Contains(string(out), "4w") || rep.MaskedDefault != 2 {
		t.Fatalf("au-delà du budget les champs doivent être masqués: %s %+v", out, rep)
	}
}

func TestPatternsSpansDedupeAndOverlap(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{Patterns: []PatternRule{
		{Name: "iban", Regex: `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`},
		{Name: "email", Regex: `[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}`},
		{Name: "long", Regex: `FR76[0-9]{5}`}, // chevauche l'IBAN, plus court : écarté
	}}), Classifier: answer(false)})
	open(t, a, "ex")
	in := `{"note":"vire FR7630006000011234567890189 puis FR7630006000011234567890189 a jean.dupont@example.org ok"}`
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "FR76300060") || strings.Contains(s, "jean.dupont") {
		t.Fatalf("motif non masqué: %s", s)
	}
	if rep.Spans != 3 {
		t.Fatalf("Spans=%d, veut 3", rep.Spans)
	}
	// même IBAN ⇒ même jeton dans l'échange
	if strings.Count(s, "TBP_VAR_1") != 2 {
		t.Fatalf("la déduplication n'a pas réutilisé le jeton: %s", s)
	}
	// aller-retour
	back, _, err := a.Unmask("ex", out)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, back, in)
}

func TestClassifierNoStillScrubbedByPatterns(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{Patterns: []PatternRule{
		{Name: "email", Regex: `[a-z]+@[a-z]+\.org`},
	}}), Classifier: answer(false)})
	open(t, a, "ex")
	out, _, err := a.MaskJSON(context.Background(), "ex", []byte(`{"m":"contact bob@site.org merci"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "bob@site.org") {
		t.Fatalf("l'IA ne peut pas désactiver un motif: %s", out)
	}
}

func TestRoundTripTypesAndText(t *testing.T) {
	a := newAno(t, Options{Classifier: answer(true)})
	open(t, a, "ex")
	in := `{"amount":50000,"ratio":1.50,"ok":true,"none":null,"list":["a",2,{"k":"v"}],"txt":"é<>&\"x"}`
	masked, rep, err := a.MaskJSON(context.Background(), "ex", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(masked), "50000") {
		t.Fatalf("nombre en clair: %s", masked)
	}
	if rep.Restored != 0 {
		t.Fatal("Restored ne doit compter que l'Unmask")
	}
	back, rep2, err := a.Unmask("ex", masked)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, back, in)
	if rep2.Restored == 0 {
		t.Fatal("Restored non compté")
	}
	// le type nombre est restitué (pas une chaîne)
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(string(back)))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if _, isNum := m["amount"].(json.Number); !isNum {
		t.Fatalf("amount restitué avec le mauvais type: %T", m["amount"])
	}
}

func TestUnmaskTextAndEmbeddedTokens(t *testing.T) {
	a := newAno(t, Options{Classifier: answer(true)})
	open(t, a, "ex")
	masked, _, err := a.MaskJSON(context.Background(), "ex", []byte(`{"n":"Mme Machin","c":"12345"}`))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(masked, &m); err != nil {
		t.Fatal(err)
	}
	// réponse d'une IA externe : texte libre reprenant les jetons
	resp := "Le compte " + m["c"] + " appartient à " + m["n"] + "."
	back, rep, err := a.Unmask("ex", []byte(resp))
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != "Le compte 12345 appartient à Mme Machin." || rep.Restored != 2 {
		t.Fatalf("texte mal reconstitué: %q %+v", back, rep)
	}
	// jeton inclus dans une chaîne JSON
	back, _, err = a.Unmask("ex", []byte(`{"r":"pour `+m["n"]+` seulement"}`))
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, back, `{"r":"pour Mme Machin seulement"}`)
}

func TestUnknownAndForeignPlaceholdersRefused(t *testing.T) {
	a := newAno(t, Options{Classifier: answer(true)})
	open(t, a, "A")
	open(t, a, "B")
	if _, _, err := a.MaskJSON(context.Background(), "A", []byte(`{"x":"secretA"}`)); err != nil {
		t.Fatal(err)
	}
	// TBP_VAR_1 existe dans A, pas dans B
	if _, _, err := a.Unmask("B", []byte(`{"x":"TBP_VAR_1"}`)); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("jeton d'un autre échange: err=%v, veut ErrUnknownPlaceholder", err)
	}
	if _, _, err := a.Unmask("A", []byte(`réponse TBP_VAR_99`)); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("jeton inconnu (texte): err=%v", err)
	}
	// un jeton plus long ne doit pas être résolu par son préfixe
	if _, _, err := a.Unmask("A", []byte(`TBP_VAR_10`)); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Fatalf("TBP_VAR_10 ne doit pas se résoudre en TBP_VAR_1: err=%v", err)
	}
	// un jeton ALTÉRÉ n'est pas reconnu : il passe tel quel, sans fuite
	out, _, err := a.Unmask("A", []byte(`TBP-VAR-1`))
	if err != nil || string(out) != "TBP-VAR-1" {
		t.Fatalf("jeton altéré: %q %v", out, err)
	}
}

func TestReservedTokenInInputRefused(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{KeepPaths: []string{"k"}}), Classifier: answer(false)})
	open(t, a, "ex")
	for _, in := range []string{`{"k":"TBP_VAR_1"}`, `{"x":"a TBP_VAR_7 b"}`} {
		if _, _, err := a.MaskJSON(context.Background(), "ex", []byte(in)); !errors.Is(err, ErrReservedToken) {
			t.Fatalf("%s: err=%v, veut ErrReservedToken (même sur un champ gardé)", in, err)
		}
	}
}

func TestUnparsableAndBounds(t *testing.T) {
	a := newAno(t, Options{MaxPayloadBytes: 64})
	open(t, a, "ex")
	ctx := context.Background()
	for name, in := range map[string]string{
		"texte":        `simplement du texte`,
		"binaire":      "\x00\x01\x02",
		"tronqué":      `{"a":`,
		"trailing":     `{"a":"b"} {"c":"d"}`,
		"vide":         ``,
		"trailing-2":   `{"a":"b"}x`,
		"cle-inconnue": `{a:1}`,
	} {
		if _, _, err := a.MaskJSON(ctx, "ex", []byte(in)); !errors.Is(err, ErrUnparsable) {
			t.Errorf("%s: err=%v, veut ErrUnparsable", name, err)
		}
	}
	if _, _, err := a.MaskJSON(ctx, "ex", []byte(`{"a":"`+strings.Repeat("x", 100)+`"}`)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("charge trop grande: err=%v", err)
	}
	// profondeur : testée avec la borne de charge par défaut (80 octets > 64)
	deep := newAno(t, Options{})
	open(t, deep, "ex")
	if _, _, err := deep.MaskJSON(ctx, "ex", []byte(strings.Repeat("[", 40)+strings.Repeat("]", 40))); !errors.Is(err, ErrUnparsable) {
		t.Fatalf("profondeur: err=%v, veut ErrUnparsable", err)
	}
}

func TestUnmaskOutputBounded(t *testing.T) {
	a := newAno(t, Options{Classifier: answer(true), MaxPayloadBytes: 4096})
	open(t, a, "ex")
	big := strings.Repeat("v", 3000)
	if _, _, err := a.MaskJSON(context.Background(), "ex", []byte(`{"x":"`+big+`"}`)); err != nil {
		t.Fatal(err)
	}
	// une réponse de 1000 jetons pointant chacun vers 3000 octets ne doit pas gonfler
	resp := strings.Repeat("TBP_VAR_1 ", 400) // 4000 octets d'entrée ⇒ ~1,2 Mo de sortie
	ex, _ := a.v.get("ex")
	_, _, err := a.Unmask("ex", []byte(resp))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("amplification non bornée: err=%v", err)
	}
	// la borne doit jouer PENDANT la reconstitution, pas seulement à la fin :
	// 400 jetons dans la charge, mais on s'arrête dès que la sortie dépasse.
	if n := ex.lookups.Load(); n > 3 {
		t.Fatalf("la reconstitution a résolu %d jetons avant de refuser (borne en cours de route absente)", n)
	}
	resp = `["` + strings.Repeat("TBP_VAR_1 ", 350) + `"]`
	if _, _, err := a.Unmask("ex", []byte(resp)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("amplification JSON non bornée: err=%v", err)
	}
}

func TestVaultBoundsExpiryAndWipe(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	var trips []string
	a := newAno(t, Options{
		Classifier: answer(true), MaxExchanges: 2, MaxEntriesPerExchange: 2, Now: clock,
		OnTrip: func(r string) { trips = append(trips, r) },
	})
	exp := func(d time.Duration) time.Time { return now.Add(d) }

	if err := a.Open("e1", exp(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := a.Open("e2", exp(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// saturation : refus, JAMAIS d'éviction, alarme
	if err := a.Open("e3", exp(time.Hour)); !errors.Is(err, ErrVaultSaturated) {
		t.Fatalf("err=%v, veut ErrVaultSaturated", err)
	}
	if len(trips) != 1 || trips[0] != TripVaultSaturated {
		t.Fatalf("alarme attendue: %v", trips)
	}
	if a.Exchanges() != 2 {
		t.Fatalf("un échange vivant a été évincé: %d", a.Exchanges())
	}
	// entrées par échange plafonnées
	ctx := context.Background()
	if _, _, err := a.MaskJSON(ctx, "e2", []byte(`{"a":"1","b":"2"}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.MaskJSON(ctx, "e2", []byte(`{"c":"3"}`)); !errors.Is(err, ErrTooManyEntries) {
		t.Fatalf("err=%v, veut ErrTooManyEntries", err)
	}
	// une valeur déjà connue ne consomme pas d'entrée
	if _, _, err := a.MaskJSON(ctx, "e2", []byte(`{"z":"1"}`)); err != nil {
		t.Fatalf("valeur dédupliquée refusée: %v", err)
	}
	// expiration : l'échange disparaît (et libère la place)
	ex1, _ := a.v.get("e1")
	if _, _, err := a.MaskJSON(ctx, "e1", []byte(`{"a":"secret"}`)); err != nil {
		t.Fatal(err)
	}
	advance(2 * time.Minute)
	if _, _, err := a.MaskJSON(ctx, "e1", []byte(`{"a":"x"}`)); !errors.Is(err, ErrExchangeUnknown) {
		t.Fatalf("échange expiré: err=%v", err)
	}
	if _, _, err := a.Unmask("e1", []byte(`TBP_VAR_1`)); !errors.Is(err, ErrExchangeUnknown) {
		t.Fatalf("Unmask sur échange expiré: err=%v", err)
	}
	// les valeurs ont été effacées
	for tok, ent := range ex1.byTok {
		t.Fatalf("entrée %s encore présente après expiration", tok)
		_ = ent
	}
	if err := a.Open("e3", exp(time.Hour)); err != nil {
		t.Fatalf("la place libérée par l'expiration doit servir: %v", err)
	}
}

func TestOpenValidationAndTTLCap(t *testing.T) {
	now := time.Now()
	a := newAno(t, Options{MaxTTL: time.Hour, Now: func() time.Time { return now }})
	if err := a.Open("", now.Add(time.Minute)); !errors.Is(err, ErrBadExchangeID) {
		t.Fatalf("id vide: %v", err)
	}
	if err := a.Open(strings.Repeat("x", 200), now.Add(time.Minute)); !errors.Is(err, ErrBadExchangeID) {
		t.Fatalf("id trop long: %v", err)
	}
	if err := a.Open("p", now.Add(-time.Second)); !errors.Is(err, ErrBadExpiry) {
		t.Fatalf("expiration passée: %v", err)
	}
	if err := a.Open("far", now.Add(1000*time.Hour)); err != nil {
		t.Fatal(err)
	}
	ex, _ := a.v.get("far")
	if got := ex.expires.Sub(now); got != time.Hour {
		t.Fatalf("TTL non plafonné: %v", got)
	}
	// rouvrir un échange vivant garde son expiration d'origine
	if err := a.Open("far", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ex2, _ := a.v.get("far"); ex2.expires != ex.expires {
		t.Fatal("la réouverture ne doit pas changer l'expiration")
	}
	a.Close("far")
	if _, _, err := a.Unmask("far", []byte("x")); !errors.Is(err, ErrExchangeUnknown) {
		t.Fatalf("après Close: %v", err)
	}
}

func TestMaskField(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{KeepPaths: []string{"query.page"}, MaskPaths: []string{"query.account"}}), Classifier: answer(false)})
	open(t, a, "ex")
	got, rep, err := a.MaskField(context.Background(), "ex", []string{"query", "account"}, "4471829")
	if err != nil || got == "4471829" || !strings.HasPrefix(got, "TBP_VAR_") || rep.MaskedPath != 1 {
		t.Fatalf("MaskField masqué: %q %+v %v", got, rep, err)
	}
	got, _, err = a.MaskField(context.Background(), "ex", []string{"query", "page"}, "2")
	if err != nil || got != "2" {
		t.Fatalf("MaskField gardé: %q %v", got, err)
	}
}

func TestConcurrentUse(t *testing.T) {
	a := newAno(t, Options{Classifier: answer(true)})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := string(rune('a' + i))
			if err := a.Open(id, testExpiry); err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 50; j++ {
				in := `{"v":"valeur-` + id + `","n":` + `12` + `}`
				m, _, err := a.MaskJSON(context.Background(), id, []byte(in))
				if err != nil {
					t.Error(err)
					return
				}
				b, _, err := a.Unmask(id, m)
				if err != nil {
					t.Error(err)
					return
				}
				var x, y any
				_ = json.Unmarshal([]byte(in), &x)
				_ = json.Unmarshal(b, &y)
				if !reflect.DeepEqual(x, y) {
					t.Errorf("aller-retour: %s != %s", in, b)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestRulesValidation(t *testing.T) {
	bad := map[string]string{
		"json":            `{`,
		"champ inconnu":   `{"nope":[]}`,
		"chemin vide":     `{"mask_paths":[""]}`,
		"segment vide":    `{"mask_paths":["a..b"]}`,
		"trop profond":    `{"mask_paths":["a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q"]}`,
		"regex invalide":  `{"patterns":[{"name":"x","regex":"("}]}`,
		"regex vide":      `{"patterns":[{"name":"x","regex":"a*"}]}`,
		"nom invalide":    `{"patterns":[{"name":"X Y","regex":"a"}]}`,
		"nom dupliqué":    `{"patterns":[{"name":"x","regex":"a"},{"name":"x","regex":"b"}]}`,
		"regex trop long": `{"patterns":[{"name":"x","regex":"` + strings.Repeat("a", 600) + `"}]}`,
	}
	for name, in := range bad {
		if _, err := ParseRules([]byte(in)); !errors.Is(err, ErrRules) {
			t.Errorf("%s: err=%v, veut ErrRules", name, err)
		}
	}
	if _, err := ParseRules([]byte(`{"keep_paths":["a"],"mask_paths":["b.*"],"patterns":[{"name":"iban","regex":"[A-Z]{2}[0-9]{2}"}]}`)); err != nil {
		t.Fatalf("règles valides refusées: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("règles absentes doivent être refusées")
	}
	rules := mustRules(t, RulesConfig{})
	for name, o := range map[string]Options{
		"timeout trop court": {Rules: rules, ClassifierTimeout: time.Nanosecond},
		"timeout trop long":  {Rules: rules, ClassifierTimeout: time.Second},
		"ttl > 24 h":         {Rules: rules, MaxTTL: 48 * time.Hour},
		"borne négative":     {Rules: rules, MaxExchanges: -1},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: doit être refusé", name)
		}
	}
}

// Issue #237 : « garder » dispense du classifieur, pas des motifs. Un chemin gardé qui
// porte un IBAN ne le laisse pas sortir en clair ; sans motif, la valeur est inchangée.
func TestKeepPathStillScrubbedByPatterns(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{
		KeepPaths: []string{"note", "meta"},
		Patterns:  []PatternRule{{Name: "iban", Regex: `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`}},
	}), Classifier: answer(false)})
	open(t, a, "ex")

	in := `{"note":"virement vers FR7630006000011234567890189 merci","meta":{"ref":"rien de sensible"},"autre":"x"}`
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "FR7630006000011234567890189") {
		t.Fatalf("un IBAN sous keep_paths sort en clair (#237) : %s", s)
	}
	if rep.Spans != 1 {
		t.Fatalf("Spans=%d, veut 1", rep.Spans)
	}
	// le reste de la chaîne gardée, et les chaînes gardées sans motif, sont inchangés
	if !strings.Contains(s, `virement vers `) || !strings.Contains(s, ` merci`) || !strings.Contains(s, `"ref":"rien de sensible"`) {
		t.Fatalf("la chaîne gardée est altérée au-delà de la plage masquée : %s", s)
	}
	// le classifieur n'est PAS appelé pour un chemin gardé (« garder » le dispense)
	if c := a.classifier.(*fakeClassifier).calls.Load(); c != 1 { // « autre » seulement
		t.Fatalf("ClassifierCalls=%d, veut 1 (le chemin gardé ne passe pas par le classifieur)", c)
	}
	// aller-retour : la plage est restituée
	back, _, err := a.Unmask("ex", out)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, back, in)
}

// Issue #238 : un motif s'applique aussi à la forme texte d'un nombre JSON — « l'IA ne peut que
// renforcer ». Un classifieur qui répond « garder » ne laisse plus sortir 4111111111111111 en
// nombre alors qu'il est masqué en chaîne ; un nombre sans motif reste inchangé.
func TestNumberStillScrubbedByPatterns(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{
		KeepPaths: []string{"kept"},
		Patterns:  []PatternRule{{Name: "pan", Regex: `[0-9]{16}`}},
	}), Classifier: answer(false)})
	open(t, a, "ex")

	in := `{"card":4111111111111111,"card_s":"4111111111111111","kept":4111111111111111,"n":42,"f":1.5}`
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "4111111111111111") {
		t.Fatalf("un nombre correspondant à un motif sort en clair (#238) : %s", s)
	}
	// même valeur en nombre et en chaîne : masquée dans les deux cas ; trois feuilles touchées
	if rep.Spans != 3 {
		t.Fatalf("Spans=%d, veut 3 (nombre classifié, chaîne, nombre sous keep_paths) : %s", rep.Spans, s)
	}
	// les nombres sans motif sont inchangés
	if !strings.Contains(s, `"n":42`) || !strings.Contains(s, `"f":1.5`) {
		t.Fatalf("un nombre sans motif est altéré : %s", s)
	}
	// aller-retour : le nombre d'origine est restitué AVEC son type
	back, _, err := a.Unmask("ex", out)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, back, in)
	var dec map[string]any
	if err := json.Unmarshal(back, &dec); err != nil {
		t.Fatal(err)
	}
	if _, isNum := dec["card"].(float64); !isNum {
		t.Fatalf("le nombre masqué n'est pas restitué comme nombre : %T", dec["card"])
	}
}

// #238, re-revue de 8873638 : « 4.111111111111111e15 » EST le nombre 4111111111111111 ; un motif sur la
// forme pleine ne doit pas être contourné par la notation exponentielle.
func TestExpandExponent(t *testing.T) {
	for in, want := range map[string]string{
		"4.111111111111111e15": "4111111111111111",
		"4111111111111111E0":   "4111111111111111",
		"4.1e3":                "4100",
		"-4.1E+3":              "-4100",
		"1.5e-3":               "0.0015",
		"123e-2":               "1.23",
		"0.5e1":                "5",
		"1e0":                  "1",
		"0e5":                  "0",
	} {
		got, ok := expandExponent(in)
		if !ok || got != want {
			t.Fatalf("expandExponent(%q) = (%q,%v), veut %q", in, got, ok, want)
		}
	}
	// formes hors périmètre : pas d'expansion (et surtout pas d'allocation pilotée par l'entrée)
	for _, in := range []string{"42", "1.5", "1e100", "1e999999999", "abc", "1e", "e5", "--1e2", "1.e2"} {
		if got, ok := expandExponent(in); ok {
			t.Fatalf("expandExponent(%q) = %q, veut pas d'expansion", in, got)
		}
	}
}

func TestExponentNumberStillScrubbedByPatterns(t *testing.T) {
	a := newAno(t, Options{Rules: mustRules(t, RulesConfig{
		Patterns: []PatternRule{{Name: "pan", Regex: `[0-9]{16}`}},
	}), Classifier: answer(false)})
	open(t, a, "ex")
	in := `{"plain":4111111111111111,"exp":4.111111111111111e15,"exp2":4111111111111111E0,"neg":-4.111111111111111e15,"small":4.1e3,"f":1.5}`
	out, rep, err := a.MaskJSON(context.Background(), "ex", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, leak := range []string{"4111111111111111", "4.111111111111111e15", "4111111111111111E0"} {
		if strings.Contains(s, leak) {
			t.Fatalf("%q sort en clair : %s", leak, s)
		}
	}
	if rep.Spans != 4 {
		t.Fatalf("Spans=%d, veut 4 (plain, exp, exp2, neg) : %s", rep.Spans, s)
	}
	// voisins : un nombre exponentiel sans motif, et un décimal, sont inchangés
	if !strings.Contains(s, `"small":4.1e3`) || !strings.Contains(s, `"f":1.5`) {
		t.Fatalf("un nombre sans motif est altéré : %s", s)
	}
	back, _, err := a.Unmask("ex", out)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, back, in)
}
