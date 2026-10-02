package pep

import (
	"strings"
	"testing"
	"time"
)

func TestPostureBytesIsSortedAndDeterministic(t *testing.T) {
	p := Posture{"zeta": "on", "alpha": "off", "mid": "3"}
	want := "alpha=off\nmid=3\nzeta=on\n"
	for i := 0; i < 20; i++ { // l'ordre des cartes Go est aléatoire : le contenu ne doit jamais l'être
		if got := string(p.Bytes()); got != want {
			t.Fatalf("got %q, veut %q", got, want)
		}
	}
}

func TestPostureRefusesAmbiguousEntries(t *testing.T) {
	for name, p := range map[string]Posture{
		"clé vide":       {"": "on"},
		"valeur vide":    {"a": ""},
		"= dans la clé":  {"a=b": "on"},
		"saut de ligne":  {"a": "on\nb=off"},
		"retour chariot": {"a": "on\r"},
		"clé multiligne": {"a\nb": "on"},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s : une entrée ambiguë doit paniquer, jamais être engagée", name)
				}
			}()
			p.Bytes()
		}()
	}
}

func TestOPAPostureCommitsSwitchesNotValues(t *testing.T) {
	on := Posture{}
	on.OPAPosture(OPATuning{Admission: AdmissionOptions{MaxInflight: 2, MaxQueue: 16, SubjectShare: 25}, StallWindow: 3 * time.Second})
	tuned := Posture{}
	tuned.OPAPosture(OPATuning{Admission: AdmissionOptions{MaxInflight: 8, MaxQueue: 999, SubjectShare: 90}, StallWindow: time.Minute})
	if string(on.Bytes()) != string(tuned.Bytes()) {
		t.Fatalf("les valeurs de réglage ne sont pas la posture :\n%s\n%s", on.Bytes(), tuned.Bytes())
	}
	off := Posture{}
	off.OPAPosture(OPATuning{})
	if !strings.Contains(string(off.Bytes()), "opa-admission=off") || !strings.Contains(string(off.Bytes()), "opa-stall-detection=off") {
		t.Fatalf("interrupteurs coupés non reflétés :\n%s", off.Bytes())
	}
	if string(off.Bytes()) == string(on.Bytes()) {
		t.Fatal("couper un interrupteur doit changer la posture")
	}
}
