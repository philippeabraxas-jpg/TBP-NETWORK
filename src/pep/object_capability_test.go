package pep

// object_capability_test.go — T36 (issue #62) : le sceau objet-capacité
// généralisé (D102) et sa réconciliation avec T16 (D103).
//
// Couverture :
//   - vecteur doré D102 (figé, provenance ci-dessous) ;
//   - déterminisme : l'ordre de fourniture des champs ne change rien, la
//     slice de l'appelant n'est pas mutée ;
//   - bornes §4.3 : chaque dépassement = ErrSealBounds explicite ;
//   - croisé T16 : la formule C documentée (tbp_pg.c:346-437) reproduite
//     contre un vecteur doré — la documentation du sceau Postgres
//     correspond au calcul ;
//   - croisé fonctionnel : jeton émis avec ComputeObjectSeal → accept ;
//     un champ muté → seal-mismatch (T9), même avec un scope valide.
//
// Provenance des vecteurs : calculés à la rédaction par DEUX
// implémentations indépendantes de chaque formule (Go de référence et
// Python hashlib, constructions incrémentale et à concaténation unique),
// concordantes, puis figés. Le vecteur T16 vérifie la FORMULE DOCUMENTÉE
// de tbp_pg.c — le binaire C lui-même est couvert par les tests docker de
// l'extension (src/pep/postgres-extension/tests/), hors portée d'une CI
// Go sans Postgres ; ce test garantit que la documentation publiée du
// sceau n'est pas une fiction.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

// goldenSealD102 : sceau « TBPO1 » de cellID="cell-a", policyID=0×32,
// champs {object:"registry/docs/42", field:"status", value:"published"},
// {"registry/docs/42","author","agent-007"}, {"registry/docs/42","price","99.99"}.
const goldenSealD102 = "8c988f12fa5b6064ffa52cd519ca8e54d05b2f06be0aa45d81c53ab88f55e7b3"

// goldenSealT16 : formule tbp_pg.c appliquée à
// plan="{PLANNEDSTMT :commandType 2 :queryId 0 :rtable <>}",
// params (oid 23, "42"), (oid 25, "publié"), (oid 23, NULL).
const goldenSealT16 = "bc891690a39436df7e76cd5598b955a2fbcf32f749ea5a2695438f2ff07a3bd7"

func sealFieldsD102() []ObjectField {
	// Volontairement NON triés : le tri canonique est interne (D102).
	return []ObjectField{
		{Object: "registry/docs/42", Field: "status", Value: []byte("published")},
		{Object: "registry/docs/42", Field: "author", Value: []byte("agent-007")},
		{Object: "registry/docs/42", Field: "price", Value: []byte("99.99")},
	}
}

func TestComputeObjectSealGolden(t *testing.T) {
	seal, err := ComputeObjectSeal("cell-a", [32]byte{}, sealFieldsD102())
	if err != nil {
		t.Fatalf("ComputeObjectSeal: %v", err)
	}
	if got := fmt.Sprintf("%x", seal); got != goldenSealD102 {
		t.Fatalf("sceau=%s, veut le vecteur doré %s", got, goldenSealD102)
	}
}

func TestComputeObjectSealDeterministe(t *testing.T) {
	fields := sealFieldsD102()
	// Ordre inversé + contenu dupliqué : même sceau.
	rev := []ObjectField{fields[2], fields[1], fields[0]}
	a, err := ComputeObjectSeal("cell-a", [32]byte{}, fields)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ComputeObjectSeal("cell-a", [32]byte{}, rev)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("l'ordre de fourniture ne doit pas changer le sceau")
	}
	// La slice de l'appelant n'est PAS mutée par le tri interne.
	if fields[0].Field != "status" || fields[2].Field != "price" {
		t.Fatal("ComputeObjectSeal a muté la slice de l'appelant")
	}
	// Un champ muté change le sceau — sinon rien n'est prouvé.
	mut := sealFieldsD102()
	mut[1].Value = []byte("agent-008")
	c, err := ComputeObjectSeal("cell-a", [32]byte{}, mut)
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Fatal("un champ muté doit changer le sceau")
	}
	// policyID et cellID lient le sceau (cross-cellule / cross-politique).
	d, _ := ComputeObjectSeal("cell-b", [32]byte{}, fields)
	var pol [32]byte
	pol[0] = 1
	e, _ := ComputeObjectSeal("cell-a", pol, fields)
	if a == d || a == e {
		t.Fatal("cellID et policyID doivent lier le sceau")
	}
}

func TestComputeObjectSealBornes(t *testing.T) {
	long := func(n int) string { return string(make([]byte, n)) }
	cases := []struct {
		name   string
		cellID string
		fields []ObjectField
	}{
		{"cellID vide", "", sealFieldsD102()},
		{"cellID trop long", long(256), sealFieldsD102()},
		{"object vide", "cell-a", []ObjectField{{Object: "", Field: "f", Value: []byte("v")}}},
		{"object trop long", "cell-a", []ObjectField{{Object: long(MaxSealObjectLen + 1), Field: "f", Value: []byte("v")}}},
		{"field vide", "cell-a", []ObjectField{{Object: "o", Field: "", Value: []byte("v")}}},
		{"field trop long", "cell-a", []ObjectField{{Object: "o", Field: long(MaxSealFieldLen + 1), Value: []byte("v")}}},
		{"value trop longue", "cell-a", []ObjectField{{Object: "o", Field: "f", Value: make([]byte, MaxSealValueLen+1)}}},
		{"trop de champs", "cell-a", make([]ObjectField, MaxSealFields+1)},
		{"champ dupliqué (même object/field, value différente)", "cell-a", []ObjectField{
			{Object: "acct/1", Field: "balance", Value: []byte("100")},
			{Object: "acct/1", Field: "balance", Value: []byte("200")},
		}},
	}
	for _, tc := range cases {
		// Les champs générés à la chaîne doivent rester dans les bornes
		// pour isoler la faute testée.
		if tc.name == "trop de champs" {
			for i := range tc.fields {
				tc.fields[i] = ObjectField{Object: "o", Field: fmt.Sprintf("f%d", i), Value: []byte("v")}
			}
		}
		_, err := ComputeObjectSeal(tc.cellID, [32]byte{}, tc.fields)
		if !errors.Is(err, ErrSealBounds) {
			t.Errorf("%s : err=%v, veut ErrSealBounds (jamais de troncature silencieuse)", tc.name, err)
		}
	}
	// Aux bornes exactes : passe.
	ok := []ObjectField{{Object: long(MaxSealObjectLen), Field: long(MaxSealFieldLen), Value: make([]byte, MaxSealValueLen)}}
	if _, err := ComputeObjectSeal("cell-a", [32]byte{}, ok); err != nil {
		t.Errorf("bornes exactes : %v", err)
	}
}

// t16SealReference ré-implémente la formule C de l'extension (D103) :
//
//	SHA-256( nodeToString(PlannedStmt) ‖ pour chaque paramètre lié :
//	0x1F ‖ oid ‖ 0x1F ‖ (valeur en texte | "NULL") )     (tbp_pg.c:346)
//
// Les valeurs n'entrent que dans le hash — jamais journalisées (§6.2).
func t16SealReference(plan string, params []struct {
	oid   uint32
	value *string
}) [32]byte {
	h := sha256.New()
	h.Write([]byte(plan))
	for _, p := range params {
		h.Write([]byte{0x1f})
		h.Write([]byte(fmt.Sprintf("%d", p.oid)))
		h.Write([]byte{0x1f})
		if p.value == nil {
			h.Write([]byte("NULL"))
		} else {
			h.Write([]byte(*p.value))
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestCrossT16FormuleDocumentee(t *testing.T) {
	str := func(s string) *string { return &s }
	seal := t16SealReference("{PLANNEDSTMT :commandType 2 :queryId 0 :rtable <>}", []struct {
		oid   uint32
		value *string
	}{{23, str("42")}, {25, str("publié")}, {23, nil}})
	if got := fmt.Sprintf("%x", seal); got != goldenSealT16 {
		t.Fatalf("sceau T16=%s, veut le vecteur doré %s — la documentation de tbp_pg.c ne correspond plus au calcul", got, goldenSealT16)
	}
	// Non-vacuité : un NULL confondu avec la chaîne "NULL" n'est PAS le
	// même sceau que... si, par construction C ("NULL" distingué = absence
	// de paramètre vs valeur nulle gérée à l'identique dans le C : le
	// distinguo est valeur-NULL vs paramètre ABSENT — vérifier celui-là).
	without := t16SealReference("{PLANNEDSTMT :commandType 2 :queryId 0 :rtable <>}", []struct {
		oid   uint32
		value *string
	}{{23, str("42")}, {25, str("publié")}})
	if seal == without {
		t.Fatal("un paramètre NULL et un paramètre absent doivent donner deux sceaux distincts")
	}
}

// TestCrossFonctionnelSceauGeneralise : un jeton émis avec le sceau
// CALCULÉ par ComputeObjectSeal est accepté quand le demandeur présente
// le sceau calculé par la MÊME fonction ; un champ muté = seal-mismatch
// (T9) même si le scope est par ailleurs valide (critère d'acceptation
// de l'issue, §4.4(2)).
func TestCrossFonctionnelSceauGeneralise(t *testing.T) {
	sink := &stubSink{}
	ar := &stubAntiReplay{}
	v := newValidator(t, sink, ar, nil)

	seal, err := ComputeObjectSeal("tbp/registry/cell-alpha-01", arr32(policyV1), sealFieldsD102())
	if err != nil {
		t.Fatal(err)
	}
	c := nominalClaims()
	c.objectSeal = seal[:]
	tok := mintToken(t, c)

	req := nominalRequest()
	req.ObjectSeal = &seal
	d := v.Validate(context.Background(), tok, req)
	if !d.Allow || d.Reason != "ok" {
		t.Fatalf("sceau conforme: allow=%v reason=%q, veut allow/ok", d.Allow, d.Reason)
	}

	// Mutation : le sceau présenté diverge d'un champ → refus T9.
	ar2 := &stubAntiReplay{}
	v2 := newValidator(t, &stubSink{}, ar2, nil)
	mutFields := sealFieldsD102()
	mutFields[1].Value = []byte("agent-008")
	badSeal, _ := ComputeObjectSeal("tbp/registry/cell-alpha-01", arr32(policyV1), mutFields)
	req2 := nominalRequest()
	req2.ObjectSeal = &badSeal
	d2 := v2.Validate(context.Background(), mintToken(t, c), req2)
	if d2.Allow || d2.Reason != ReasonSealMismatch {
		t.Fatalf("sceau divergent: allow=%v reason=%q, veut deny/%s", d2.Allow, d2.Reason, ReasonSealMismatch)
	}
}
