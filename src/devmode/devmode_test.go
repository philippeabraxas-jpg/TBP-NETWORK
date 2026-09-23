package devmode

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func statAlwaysExists(string) (os.FileInfo, error) { return nil, nil }
func statAlwaysAbsent(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
func statAlwaysErrors(string) (os.FileInfo, error) {
	return nil, errors.New("disque en panne")
}

func TestDeclaredExists(t *testing.T) {
	ok, err := Declared("/whatever", statAlwaysExists)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v, veut true/nil", ok, err)
	}
}

func TestDeclaredAbsent(t *testing.T) {
	ok, err := Declared("/whatever", statAlwaysAbsent)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v, veut false/nil", ok, err)
	}
}

func TestDeclaredStatErrorPropagates(t *testing.T) {
	_, err := Declared("/whatever", statAlwaysErrors)
	if err == nil {
		t.Fatal("erreur de stat non propagée")
	}
}

func TestRequireDeclaredNoActiveFlagsAlwaysOK(t *testing.T) {
	// Même sentinel absent ET stat en erreur : aucun drapeau actif ⇒
	// rien à exiger, jamais consulté.
	if err := RequireDeclared("/whatever", func(string) (os.FileInfo, error) {
		t.Fatal("stat ne doit pas être appelé sans drapeau actif")
		return nil, nil
	}, nil); err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
}

func TestRequireDeclaredRefusesWithoutSentinel(t *testing.T) {
	err := RequireDeclared("/etc/tbp/DEV_ENVIRONMENT", statAlwaysAbsent, []string{"TBP_OPA_DISABLED_DEV_UNSAFE"})
	if err == nil {
		t.Fatal("erreur attendue (drapeau dev actif sans sentinel), obtenu nil")
	}
	if !strings.Contains(err.Error(), "TBP_OPA_DISABLED_DEV_UNSAFE") || !strings.Contains(err.Error(), "/etc/tbp/DEV_ENVIRONMENT") {
		t.Fatalf("erreur doit nommer le drapeau et le sentinel: %v", err)
	}
}

func TestRequireDeclaredAllowsWithSentinel(t *testing.T) {
	if err := RequireDeclared("/etc/tbp/DEV_ENVIRONMENT", statAlwaysExists, []string{"TBP_OPA_INSECURE_TCP_DEV"}); err != nil {
		t.Fatalf("erreur inattendue (sentinel présent): %v", err)
	}
}

func TestRequireDeclaredPropagatesStatError(t *testing.T) {
	err := RequireDeclared("/etc/tbp/DEV_ENVIRONMENT", statAlwaysErrors, []string{"TBP_ISSUER_SEED_FILE"})
	if err == nil {
		t.Fatal("erreur de stat non propagée")
	}
}

func TestRequireDeclaredMultipleFlagsNamedInError(t *testing.T) {
	err := RequireDeclared("/etc/tbp/DEV_ENVIRONMENT", statAlwaysAbsent, []string{"TBP_OPA_DISABLED_DEV_UNSAFE", "TBP_OPA_INSECURE_TCP_DEV"})
	if err == nil {
		t.Fatal("erreur attendue, obtenu nil")
	}
	if !strings.Contains(err.Error(), "TBP_OPA_DISABLED_DEV_UNSAFE") || !strings.Contains(err.Error(), "TBP_OPA_INSECURE_TCP_DEV") {
		t.Fatalf("erreur doit nommer TOUS les drapeaux actifs: %v", err)
	}
}
