// Package ano — anonymisation des données à la SORTIE de la cellule TBP
// (issue #178).
//
// Principe : la chaîne interne d'une cellule (broker, OPA, IA locale,
// registre) est de confiance et surveillée — les données y circulent en
// clair. Ce qui sort vers une destination hors cellule est masqué ; le
// destinataire ne voit que des jetons (TBP_VAR_n) et doit redemander à TBP
// la reconstitution. ano ne décide pas de l'action (le filtre d'action est
// OPA) : il ne décide que de ce que les DONNÉES révèlent à l'extérieur.
//
// Qui décide quoi masquer : des règles déclaratives fixées au déploiement
// (chemins « garder » / « masquer », motifs RE2) et, pour les champs
// ambigus, un classifieur local de type JEV (interface Classifier). L'IA ne
// peut que renforcer les règles ; tout doute ou toute faute masque
// (default-deny). Voir rules.go et classifier.go.
//
// Mécanisme : une table jeton ↔ valeur, en mémoire, par échange, bornée,
// jamais persistée (vault.go).
//
// Limites assumées (v1) : les clés d'objets JSON ne sont pas masquées ; un
// contenu à masquer qui n'est pas du JSON est refusé (fail-closed) ; des
// règles ne trouvent pas tout (un nom en texte libre peut leur échapper —
// le classifieur réduit ce risque, il ne le supprime pas). On ne ferme pas
// tout, on audite tout : chaque opération rend un Report (comptages, jamais
// de valeurs) destiné à une feuille hash-only.
package ano

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Erreurs d'ano (toutes fail-closed).
var (
	ErrUnparsable         = errors.New("ano: contenu non analysable — il ne sort pas (fail-closed)")
	ErrTooLarge           = errors.New("ano: charge trop volumineuse — refus")
	ErrUnknownPlaceholder = errors.New("ano: jeton inconnu de cet échange — reconstitution refusée")
	ErrReservedToken      = errors.New("ano: la charge contient déjà un jeton réservé (TBP_VAR_n) — refus")
)

// Bornes par défaut.
const (
	DefaultMaxExchanges    = 1024
	DefaultMaxEntries      = 1024
	DefaultMaxPayloadBytes = 1 << 20 // 1 MiB — comme le scellé du proxy (#108)
	DefaultMaxTTL          = 24 * time.Hour
	DefaultMaxClassifyCall = 64
	maxJSONDepth           = 32
)

var (
	// tokenRe reconnaît un jeton n'importe où dans un texte.
	tokenRe = regexp.MustCompile(`TBP_VAR_[0-9]{1,9}`)
	// exactTokenRe reconnaît une valeur qui EST un jeton.
	exactTokenRe = regexp.MustCompile(`^TBP_VAR_[0-9]{1,9}$`)
)

// Options paramètre ano. Fail-closed dès la configuration.
type Options struct {
	// Rules : règles de détection. Requis.
	Rules *Rules
	// Classifier : IA locale pour les champs ambigus. Nil ⇒ default-deny
	// (tout champ non explicitement gardé est masqué).
	Classifier Classifier
	// ClassifierTimeout borne un appel. 0 ⇒ 5 ms ; borné [1 ms, 100 ms].
	ClassifierTimeout time.Duration
	// ClassifierMaxInflight borne les appels simultanés. 0 ⇒ 16.
	ClassifierMaxInflight int
	// MaxClassifierCalls borne les appels par charge : au-delà, les champs
	// ambigus restants sont masqués sans appel (latence bornée). 0 ⇒ 64.
	MaxClassifierCalls int
	// MaxExchanges / MaxEntriesPerExchange bornent l'état. 0 ⇒ 1024.
	MaxExchanges          int
	MaxEntriesPerExchange int
	// MaxPayloadBytes borne les charges entrantes ET sortantes. 0 ⇒ 1 MiB.
	MaxPayloadBytes int
	// MaxTTL plafonne la vie d'un échange. 0 ⇒ 24 h ; jamais au-delà.
	MaxTTL time.Duration
	// OnTrip : couture d'alarme (saturation, faute du classifieur). Nil ⇒
	// pas d'alarme (le refus / le masquage reste fail-closed).
	OnTrip func(reason string)
	// Now : horloge (défaut time.Now).
	Now func() time.Time
}

// Ano est le moteur d'anonymisation. Sûr pour un usage concurrent.
type Ano struct {
	rules             *Rules
	classifier        Classifier
	classifierTimeout time.Duration
	maxClassifyCalls  int
	inflight          chan struct{}
	v                 *vault
	maxPayload        int
	onTrip            func(string)
}

// Report résume une opération : des COMPTAGES, jamais de valeurs (feuilles
// hash-only, §6.2).
type Report struct {
	Leaves           int // feuilles scalaires inspectées
	Kept             int // laissées en clair
	MaskedPath       int // masquées par une règle de chemin
	MaskedClassifier int // masquées sur décision du classifieur
	MaskedDefault    int // masquées par default-deny (pas de classifieur, ou budget d'appels épuisé)
	ClassifierFaults int // fautes du classifieur (le champ est masqué)
	ClassifierCalls  int
	Spans            int // plages masquées par motif
	Restored         int // jetons reconstitués (Unmask)
}

// Masked rend le nombre total de champs entièrement masqués.
func (r Report) Masked() int {
	return r.MaskedPath + r.MaskedClassifier + r.MaskedDefault + r.ClassifierFaults
}

// New construit ano.
func New(opts Options) (*Ano, error) {
	if opts.Rules == nil {
		return nil, errors.New("ano: règles requises (default-deny sans règles serait un choix, pas un oubli — passer des règles vides)")
	}
	timeout := opts.ClassifierTimeout
	if timeout == 0 {
		timeout = DefaultClassifierTimeout
	}
	if timeout < minClassifierTimeout || timeout > maxClassifierTimeout {
		return nil, fmt.Errorf("ano: ClassifierTimeout %v hors bornes [%v, %v]", timeout, minClassifierTimeout, maxClassifierTimeout)
	}
	inflight := opts.ClassifierMaxInflight
	if inflight == 0 {
		inflight = DefaultClassifierInflight
	}
	calls := opts.MaxClassifierCalls
	if calls == 0 {
		calls = DefaultMaxClassifyCall
	}
	maxEx := opts.MaxExchanges
	if maxEx == 0 {
		maxEx = DefaultMaxExchanges
	}
	maxEnt := opts.MaxEntriesPerExchange
	if maxEnt == 0 {
		maxEnt = DefaultMaxEntries
	}
	maxPayload := opts.MaxPayloadBytes
	if maxPayload == 0 {
		maxPayload = DefaultMaxPayloadBytes
	}
	ttl := opts.MaxTTL
	if ttl == 0 {
		ttl = DefaultMaxTTL
	}
	if inflight < 0 || calls < 0 || maxEx < 0 || maxEnt < 0 || maxPayload < 0 || ttl < 0 || ttl > DefaultMaxTTL {
		return nil, errors.New("ano: bornes invalides (négatives, ou TTL > 24 h)")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	a := &Ano{
		rules:             opts.Rules,
		classifier:        opts.Classifier,
		classifierTimeout: timeout,
		maxClassifyCalls:  calls,
		inflight:          make(chan struct{}, inflight),
		maxPayload:        maxPayload,
		onTrip:            opts.OnTrip,
	}
	a.v = &vault{
		ex:           map[string]*exchange{},
		maxExchanges: maxEx,
		maxEntries:   maxEnt,
		maxTTL:       ttl,
		now:          now,
		trip:         opts.OnTrip,
	}
	return a, nil
}

func (a *Ano) trip(reason string) {
	if a.onTrip != nil {
		a.onTrip(reason)
	}
}

// Open ouvre (ou retrouve) l'échange id, valable jusqu'à expiry (plafonné à
// MaxTTL). id est en pratique le jti du jeton broker.
func (a *Ano) Open(id string, expiry time.Time) error {
	_, err := a.v.open(id, expiry)
	return err
}

// Close efface l'échange id.
func (a *Ano) Close(id string) { a.v.close(id) }

// Exchanges rend le nombre d'échanges vivants.
func (a *Ano) Exchanges() int { return a.v.size() }

// MaskJSON masque une charge JSON pour l'échange id (déjà ouvert). L'ordre
// des clés est conservé ; la sortie est compacte. Toute charge qui n'est pas
// du JSON valide est refusée : ce qu'on ne sait pas analyser ne sort pas.
func (a *Ano) MaskJSON(ctx context.Context, id string, payload []byte) ([]byte, Report, error) {
	var rep Report
	if len(payload) > a.maxPayload {
		return nil, rep, ErrTooLarge
	}
	ex, err := a.v.get(id)
	if err != nil {
		return nil, rep, err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var out bytes.Buffer
	if err := a.maskValue(ctx, ex, dec, nil, &out, &rep, 0); err != nil {
		return nil, rep, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, rep, fmt.Errorf("%w: données après la valeur JSON", ErrUnparsable)
	}
	if out.Len() > a.maxPayload {
		return nil, rep, ErrTooLarge
	}
	return out.Bytes(), rep, nil
}

// MaskField masque la valeur texte d'un champ isolé (ex. un paramètre de
// query), au chemin donné, avec les mêmes règles que MaskJSON.
func (a *Ano) MaskField(ctx context.Context, id string, path []string, value string) (string, Report, error) {
	var rep Report
	if len(value) > a.maxPayload {
		return "", rep, ErrTooLarge
	}
	ex, err := a.v.get(id)
	if err != nil {
		return "", rep, err
	}
	var out bytes.Buffer
	if err := a.maskLeaf(ctx, ex, path, jsonString(value), value, true, &out, &rep); err != nil {
		return "", rep, err
	}
	var s string
	if err := unmarshalString(out.Bytes(), &s); err != nil {
		return "", rep, fmt.Errorf("%w: %v", ErrUnparsable, err)
	}
	return s, rep, nil
}

func (a *Ano) maskValue(ctx context.Context, ex *exchange, dec *json.Decoder, path []string, out *bytes.Buffer, rep *Report, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: profondeur > %d", ErrUnparsable, maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnparsable, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			out.WriteByte('{')
			first := true
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return fmt.Errorf("%w: %v", ErrUnparsable, err)
				}
				key, ok := kt.(string)
				if !ok {
					return fmt.Errorf("%w: clé d'objet inattendue", ErrUnparsable)
				}
				if !first {
					out.WriteByte(',')
				}
				first = false
				out.Write(jsonString(key))
				out.WriteByte(':')
				if err := a.maskValue(ctx, ex, dec, append(path, key), out, rep, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("%w: %v", ErrUnparsable, err)
			}
			out.WriteByte('}')
		case '[':
			out.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := a.maskValue(ctx, ex, dec, append(path, strconv.Itoa(i)), out, rep, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("%w: %v", ErrUnparsable, err)
			}
			out.WriteByte(']')
		default:
			return fmt.Errorf("%w: délimiteur inattendu", ErrUnparsable)
		}
	case string:
		return a.maskLeaf(ctx, ex, path, jsonString(t), t, true, out, rep)
	case json.Number:
		return a.maskLeaf(ctx, ex, path, []byte(t.String()), t.String(), false, out, rep)
	case bool:
		// un booléen ne porte pas de donnée identifiante
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	default:
		return fmt.Errorf("%w: type inattendu", ErrUnparsable)
	}
	return nil
}

// maskLeaf décide du sort d'une feuille : règles d'abord (garder / masquer),
// puis classifieur (ou default-deny), puis motifs sur ce qui reste.
func (a *Ano) maskLeaf(ctx context.Context, ex *exchange, path []string, raw []byte, text string, isString bool, out *bytes.Buffer, rep *Report) error {
	rep.Leaves++
	if isString && tokenRe.MatchString(text) {
		return ErrReservedToken
	}
	verdict := a.rules.decide(path)
	if verdict == verdictMask {
		rep.MaskedPath++
		return a.writeLeafToken(ex, raw, out)
	}
	if verdict == verdictKeep {
		// « garder » dispense du CLASSIFIEUR, jamais des motifs (#237) : rules.go
		// l'annonce — les motifs s'appliquent à toute chaîne non masquée en entier.
		// Un chemin gardé (« note ») qui porte un IBAN ne le laisse pas sortir.
		return a.emitKept(ex, raw, text, isString, out, rep)
	}
	if text == "" {
		rep.Kept++
		out.Write(raw)
		return nil
	}
	var mask bool
	if a.classifier != nil && rep.ClassifierCalls >= a.maxClassifyCalls {
		// budget d'appels épuisé : default-deny, sans appel (latence bornée)
		rep.MaskedDefault++
		return a.writeLeafToken(ex, raw, out)
	}
	if a.classifier != nil {
		rep.ClassifierCalls++
	}
	mask, fault := a.classify(ctx, strings.Join(path, "."), text)
	switch {
	case fault:
		rep.ClassifierFaults++
	case a.classifier == nil:
		rep.MaskedDefault++
	case mask:
		rep.MaskedClassifier++
	}
	if mask {
		return a.writeLeafToken(ex, raw, out)
	}
	return a.emitKept(ex, raw, text, isString, out, rep)
}

// emitKept écrit une feuille NON masquée en entier : les motifs de détection
// remplacent les plages qu'ils trouvent dans une chaîne (jetons de plage), le
// reste passe tel quel. Commun aux feuilles gardées par chemin et à celles que le
// classifieur laisse passer.
func (a *Ano) emitKept(ex *exchange, raw []byte, text string, isString bool, out *bytes.Buffer, rep *Report) error {
	if !isString && len(a.rules.findSpans(text)) > 0 {
		// Un nombre ne peut pas porter un jeton partiel : la correspondance d'un motif sur sa
		// forme texte masque la feuille ENTIÈRE (#238). Sans cela « l'IA ne peut que renforcer »
		// était faux — un classifieur répondant « garder » laissait sortir 4111111111111111.
		// Le jeton restitue le nombre d'origine, avec son type, au retour (Unmask).
		rep.Spans++
		return a.writeLeafToken(ex, raw, out)
	}
	if isString {
		if spans := a.rules.findSpans(text); len(spans) > 0 {
			var sb strings.Builder
			last := 0
			for _, sp := range spans {
				sb.WriteString(text[last:sp.start])
				tok, err := ex.intern(kindSpan, []byte(text[sp.start:sp.end]), a.v.maxEntries)
				if err != nil {
					a.trip(TripEntriesSaturated)
					return err
				}
				sb.WriteString(tok)
				last = sp.end
			}
			sb.WriteString(text[last:])
			rep.Spans += len(spans)
			rep.Kept++
			out.Write(jsonString(sb.String()))
			return nil
		}
	}
	rep.Kept++
	out.Write(raw)
	return nil
}

func (a *Ano) writeLeafToken(ex *exchange, raw []byte, out *bytes.Buffer) error {
	tok, err := ex.intern(kindLeaf, raw, a.v.maxEntries)
	if err != nil {
		a.trip(TripEntriesSaturated)
		return err
	}
	out.Write(jsonString(tok))
	return nil
}

// Unmask reconstitue les jetons de l'échange id dans payload. Une charge JSON
// est parcourue (un jeton qui EST une valeur restitue la valeur d'origine avec
// son type ; un jeton dans une chaîne est remplacé par son texte) ; toute
// autre charge est traitée comme du texte. Un jeton inconnu de l'échange est
// refusé — jamais laissé passer, jamais deviné. La sortie est bornée comme
// l'entrée (une réponse pleine de jetons ne peut pas gonfler sans limite).
func (a *Ano) Unmask(id string, payload []byte) ([]byte, Report, error) {
	var rep Report
	if len(payload) > a.maxPayload {
		return nil, rep, ErrTooLarge
	}
	ex, err := a.v.get(id)
	if err != nil {
		return nil, rep, err
	}
	if !json.Valid(payload) {
		s, n, err := a.resolveText(ex, string(payload))
		if err != nil {
			return nil, rep, err
		}
		rep.Restored = n
		return []byte(s), rep, nil
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var out bytes.Buffer
	if err := a.unmaskValue(ex, dec, &out, &rep, 0); err != nil {
		return nil, rep, err
	}
	return out.Bytes(), rep, nil
}

func (a *Ano) unmaskValue(ex *exchange, dec *json.Decoder, out *bytes.Buffer, rep *Report, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: profondeur > %d", ErrUnparsable, maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnparsable, err)
	}
	if out.Len() > a.maxPayload {
		return ErrTooLarge
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			out.WriteByte('{')
			first := true
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return fmt.Errorf("%w: %v", ErrUnparsable, err)
				}
				key, _ := kt.(string)
				if !first {
					out.WriteByte(',')
				}
				first = false
				out.Write(jsonString(key))
				out.WriteByte(':')
				if err := a.unmaskValue(ex, dec, out, rep, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("%w: %v", ErrUnparsable, err)
			}
			out.WriteByte('}')
		case '[':
			out.WriteByte('[')
			for i := 0; dec.More(); i++ {
				if i > 0 {
					out.WriteByte(',')
				}
				if err := a.unmaskValue(ex, dec, out, rep, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return fmt.Errorf("%w: %v", ErrUnparsable, err)
			}
			out.WriteByte(']')
		}
	case string:
		switch {
		case exactTokenRe.MatchString(t):
			ent, ok := ex.lookup(t)
			if !ok {
				return ErrUnknownPlaceholder
			}
			rep.Restored++
			if ent.kind == kindLeaf {
				out.Write(ent.orig)
			} else {
				out.Write(jsonString(string(ent.orig)))
			}
		case tokenRe.MatchString(t):
			s, n, err := a.resolveText(ex, t)
			if err != nil {
				return err
			}
			rep.Restored += n
			out.Write(jsonString(s))
		default:
			out.Write(jsonString(t))
		}
	case json.Number:
		out.WriteString(t.String())
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case nil:
		out.WriteString("null")
	}
	if out.Len() > a.maxPayload {
		return ErrTooLarge
	}
	return nil
}

// resolveText remplace chaque jeton de s par son texte. Refus si un jeton est
// inconnu, ou si le résultat dépasse la borne de charge.
func (a *Ano) resolveText(ex *exchange, s string) (string, int, error) {
	locs := tokenRe.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return s, 0, nil
	}
	var sb strings.Builder
	last := 0
	for _, loc := range locs {
		sb.WriteString(s[last:loc[0]])
		ent, ok := ex.lookup(s[loc[0]:loc[1]])
		if !ok {
			return "", 0, ErrUnknownPlaceholder
		}
		sb.WriteString(ent.text())
		if sb.Len() > a.maxPayload {
			return "", 0, ErrTooLarge
		}
		last = loc[1]
	}
	sb.WriteString(s[last:])
	if sb.Len() > a.maxPayload {
		return "", 0, ErrTooLarge
	}
	return sb.String(), len(locs), nil
}

// jsonString encode s en chaîne JSON sans échapper < > & (la sortie reste
// sémantiquement identique, sans altérer inutilement la forme).
func jsonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

func unmarshalString(raw []byte, s *string) error { return json.Unmarshal(raw, s) }
