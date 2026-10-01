package main

import (
	"os"
	"testing"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func TestOPATripAfterParsing(t *testing.T) {
	if n, err := opaTripAfter(envOf(nil)); err != nil || n != 3 {
		t.Fatalf("défaut = %d (%v), veut 3", n, err)
	}
	if n, err := opaTripAfter(envOf(map[string]string{"TBP_OPA_TRIP_AFTER": "1"})); err != nil || n != 1 {
		t.Fatalf("1 (comportement historique) = %d (%v)", n, err)
	}
	for _, bad := range []string{"0", "-2", "x", "1.5"} {
		if _, err := opaTripAfter(envOf(map[string]string{"TBP_OPA_TRIP_AFTER": bad})); err == nil {
			t.Errorf("TBP_OPA_TRIP_AFTER=%q accepté — jamais un défaut silencieux sur une valeur fautive", bad)
		}
	}
}

func TestOPAAutoClearConfigParsing(t *testing.T) {
	p, i, err := opaAutoClearConfig(envOf(nil))
	if err != nil || p != pep.DefaultOPAAutoClearProbes || i != 0 {
		t.Fatalf("défaut = %d/%v (%v)", p, i, err)
	}
	p, i, err = opaAutoClearConfig(envOf(map[string]string{"TBP_OPA_AUTOCLEAR_PROBES": "0", "TBP_OPA_AUTOCLEAR_INTERVAL_MS": "250"}))
	if err != nil || p != 0 || i != 250*time.Millisecond {
		t.Fatalf("0 = désactivé : %d/%v (%v)", p, i, err)
	}
	for _, env := range []map[string]string{
		{"TBP_OPA_AUTOCLEAR_PROBES": "-1"},
		{"TBP_OPA_AUTOCLEAR_PROBES": "x"},
		{"TBP_OPA_AUTOCLEAR_INTERVAL_MS": "0"},
		{"TBP_OPA_AUTOCLEAR_INTERVAL_MS": "x"},
	} {
		if _, _, err := opaAutoClearConfig(envOf(env)); err == nil {
			t.Errorf("%v accepté", env)
		}
	}
}

// Les conditions candidates à la levée automatique sont EXACTEMENT les
// conditions OPA transitoires : jamais un contrat rompu ni un bundle
// substitué, dont la levée reste une décision humaine.
func TestAutoClearCandidatesExcludeBadResponseAndMismatch(t *testing.T) {
	got := map[string]bool{}
	for _, c := range opaAutoClearConditions {
		got[c] = true
	}
	for _, must := range []string{pep.ReasonOPATimeout, pep.ReasonOPAUnreachable, pep.ReasonOPAError, pep.ReasonOPARevisionUnverifiable} {
		if !got[must] {
			t.Errorf("%s absent des candidats", must)
		}
	}
	for _, never := range []string{pep.ReasonOPABadResponse, pep.ReasonOPARevisionMismatch, pep.ReasonClockSkew, pep.CondAnchorLag} {
		if got[never] {
			t.Errorf("%s ne doit JAMAIS être levé automatiquement", never)
		}
	}
}

// Issue #208 : la liste des échappatoires dev qui alimente la feuille d'audit
// est EXACTEMENT celle que la garde du sentinel contrôle — pas une seconde
// liste qui pourrait dériver.
func TestDevEscapeHatchFlagsFeedBothTheGuardAndTheLeaf(t *testing.T) {
	all := map[string]string{
		"TBP_OPA_DISABLED_DEV_UNSAFE":           "1",
		"TBP_OPA_INSECURE_TCP_DEV":              "1",
		"TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE": "1",
		"TBP_PROVISIONING_DISABLED_DEV_UNSAFE":  "1",
	}
	if got := devEscapeHatchFlags(envOf(all)); len(got) != 4 {
		t.Fatalf("échappatoires listées = %v, veut les 4", got)
	}
	if got := devEscapeHatchFlags(envOf(nil)); len(got) != 0 {
		t.Fatalf("sans échappatoire : %v", got)
	}
	if got := devEscapeHatchFlags(envOf(map[string]string{"TBP_OPA_INSECURE_TCP_DEV": "0"})); len(got) != 0 {
		t.Fatalf("valeur « 0 » comptée comme active : %v", got)
	}
	// Sans sentinel, la garde refuse exactement quand la liste est non vide.
	statAbsent := func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	if err := checkDevEscapeHatches(envOf(all), statAbsent); err == nil {
		t.Fatal("quatre échappatoires sans sentinel acceptées")
	}
}
