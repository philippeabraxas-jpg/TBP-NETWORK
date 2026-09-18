// src/registry/tsa_test.go — T6 (issue #6)
//
// Tests du client TSA RFC 3161. La fixture golden est une VRAIE réponse
// de freetsa.org capturée le 2026-09-18 pour une requête déterministe
// (digest = 32×0xAB, nonce = 0xC0FFEE42, certReq=true) : le genTime, la
// liaison empreinte et le nonce sont donc des valeurs attendues stables.
package registry

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// goldenTSR : réponse TimeStampResp réelle (freetsa.org, 4638 octets) au
// digest 32×0xAB + nonce 0xC0FFEE42. genTime = 2026-09-18T21:18:56Z,
// policy = 1.2.3.4.1, serial = 083c2a8e.
const goldenTSR = "MIISGjADAgEAMIISEQYJKoZIhvcNAQcCoIISAjCCEf4CAQMxDzANBglghkgBZQMEAgMFADCCAYsGCyqGSIb3DQEJEAEEoIIB" +
	"egSCAXYwggFyAgEBBgQqAwQBMC8wCwYJYIZIAWUDBAIBBCCrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqwIECDwq" +
	"jhgPMjAyNjA5MTgyMTE4NTZaAQH/AgUAwP/uQqCCAROkggEPMIIBCzERMA8GA1UECgwIRnJlZSBUU0ExDDAKBgNVBAsMA1RT" +
	"QTF2MHQGA1UEDQxtVGhpcyBjZXJ0aWZpY2F0ZSBkaWdpdGFsbHkgc2lnbnMgZG9jdW1lbnRzIGFuZCB0aW1lIHN0YW1wIHJl" +
	"cXVlc3RzIG1hZGUgdXNpbmcgdGhlIGZyZWV0c2Eub3JnIG9ubGluZSBzZXJ2aWNlczEYMBYGA1UEAwwPd3d3LmZyZWV0c2Eu" +
	"b3JnMSQwIgYJKoZIhvcNAQkBFhVidXNpbGV6YXNAbWFpbGJveC5vcmcxEjAQBgNVBAcMCVd1ZXJ6YnVyZzELMAkGA1UEBhMC" +
	"REUxDzANBgNVBAgMBkJheWVybqCCDmcwggZgMIIESKADAgECAgkAwumGFg2o6c0wDQYJKoZIhvcNAQENBQAwgZUxETAPBgNV" +
	"BAoTCEZyZWUgVFNBMRAwDgYDVQQLEwdSb290IENBMRgwFgYDVQQDEw93d3cuZnJlZXRzYS5vcmcxIjAgBgkqhkiG9w0BCQEW" +
	"E2J1c2lsZXphc0BnbWFpbC5jb20xEjAQBgNVBAcTCVd1ZXJ6YnVyZzEPMA0GA1UECBMGQmF5ZXJuMQswCQYDVQQGEwJERTAe" +
	"Fw0yNjAyMTUxOTQ0MjJaFw00MDAyMDIxOTQ0MjJaMIIBCzERMA8GA1UECgwIRnJlZSBUU0ExDDAKBgNVBAsMA1RTQTF2MHQG" +
	"A1UEDQxtVGhpcyBjZXJ0aWZpY2F0ZSBkaWdpdGFsbHkgc2lnbnMgZG9jdW1lbnRzIGFuZCB0aW1lIHN0YW1wIHJlcXVlc3Rz" +
	"IG1hZGUgdXNpbmcgdGhlIGZyZWV0c2Eub3JnIG9ubGluZSBzZXJ2aWNlczEYMBYGA1UEAwwPd3d3LmZyZWV0c2Eub3JnMSQw" +
	"IgYJKoZIhvcNAQkBFhVidXNpbGV6YXNAbWFpbGJveC5vcmcxEjAQBgNVBAcMCVd1ZXJ6YnVyZzELMAkGA1UEBhMCREUxDzAN" +
	"BgNVBAgMBkJheWVybjB2MBAGByqGSM49AgEGBSuBBAAiA2IABKIV4aGy1suHGLHSjhQC6Y1LAdRSU57cMG+zx9iznzTAANbn" +
	"2ioZILHXlunrVNKZeTAubUlbjxedssuLM/pm2Ny+yFXcf27PZtLneyANeGDXAtsiEC2toL58cLK0d65Vq6OCAeYwggHiMAkG" +
	"A1UdEwQCMAAwHQYDVR0OBBYEFBXAvSbr1F2C0V2TJjEv73Cyi0ZeMB8GA1UdIwQYMBaAFPpVDYw0ZlFDTPfns6dsla965qSX" +
	"MAsGA1UdDwQEAwIGwDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBsBggrBgEFBQcBAQRgMF4wMwYIKwYBBQUHMAKGJ2h0dHA6" +
	"Ly93d3cuZnJlZXRzYS5vcmcvZmlsZXMvY2FjZXJ0LnBlbTAnBggrBgEFBQcwAYYbaHR0cDovL3d3dy5mcmVldHNhLm9yZzoy" +
	"NTYwMDcGA1UdHwQwMC4wLKAqoCiGJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvY3JsL3Jvb3RfY2EuY3JsMIHIBgNVHSAEgcAw" +
	"gb0wgboGAysFCDCBsjAzBggrBgEFBQcCARYnaHR0cDovL3d3dy5mcmVldHNhLm9yZy9mcmVldHNhX2Nwcy5odG1sMDIGCCsG" +
	"AQUFBwIBFiZodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLnBkZjBHBggrBgEFBQcCAjA7GjlGcmVlVFNBIHRy" +
	"dXN0ZWQgdGltZXN0YW1waW5nIFNvZnR3YXJlIGFzIGEgU2VydmljZSAoU2FhUykwDQYJKoZIhvcNAQENBQADggIBAGsxVL9h" +
	"+d8yvTOJmd6wFQ6sM1Gs02C3ciAw0PA2HCXqgpYdUiGVicz/luiWN9ullMBuq/EcjfO1PT+zDFA6pNq3moElEBj9UfWf9Pgz" +
	"24ONK67ep+HRkfk8v0Q2qhVbjiLk1P/OdB6/YwZc4AfDP2RnDDPP0wVfqFsaEGpZr6eUCpvtjvYoXOPfebU5UfFXZaXhgP1/" +
	"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"

func goldenResp(t *testing.T) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(goldenTSR)
	if err != nil {
		t.Fatalf("fixture base64: %v", err)
	}
	return body
}

var (
	goldenDigest = [32]byte{0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB}
	goldenNonce  = big.NewInt(0xC0FFEE42)
)

// TestMarshalTimeStampReq : la requête encodée se réanalyse avec les
// champs exacts (aller-retour ASN.1, déterminisme §11.3).
func TestMarshalTimeStampReq(t *testing.T) {
	nonce := big.NewInt(0xC0FFEE42)
	der, err := marshalTimeStampReq(goldenDigest, nonce)
	if err != nil {
		t.Fatalf("marshalTimeStampReq: %v", err)
	}
	var back timeStampReq
	rest, err := asn1.Unmarshal(der, &back)
	if err != nil {
		t.Fatalf("réanalyse: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("%d octets traînants", len(rest))
	}
	if back.Version != 1 {
		t.Errorf("version %d, attendu 1", back.Version)
	}
	if !back.MessageImprint.Algorithm.Algorithm.Equal(oidSHA256) {
		t.Errorf("algorithme %s, attendu SHA-256", back.MessageImprint.Algorithm.Algorithm)
	}
	if !bytes.Equal(back.MessageImprint.Digest, goldenDigest[:]) {
		t.Errorf("digest %x, attendu %x", back.MessageImprint.Digest, goldenDigest)
	}
	if back.Nonce == nil || back.Nonce.Cmp(nonce) != 0 {
		t.Errorf("nonce %v, attendu %v", back.Nonce, nonce)
	}
	if !back.CertReq {
		t.Error("certReq absent, attendu true")
	}
	// Stabilité : deux encodages identiques octet pour octet.
	der2, _ := marshalTimeStampReq(goldenDigest, nonce)
	if !bytes.Equal(der, der2) {
		t.Error("encodage non déterministe")
	}
}

// TestParseTimeStampRespGolden : la réponse réelle freetsa.org est
// analysée et sa liaison vérifiée — c'est le parseur contre le monde
// réel, pas contre lui-même.
func TestParseTimeStampRespGolden(t *testing.T) {
	stamp, err := parseTimeStampResp(goldenResp(t), goldenDigest, goldenNonce)
	if err != nil {
		t.Fatalf("parseTimeStampResp: %v", err)
	}
	wantTime := time.Date(2026, 9, 18, 21, 18, 56, 0, time.UTC)
	if !stamp.GenTime.Equal(wantTime) {
		t.Errorf("genTime %s, attendu %s", stamp.GenTime, wantTime)
	}
	if stamp.Policy != "1.2.3.4.1" {
		t.Errorf("policy %s, attendu 1.2.3.4.1", stamp.Policy)
	}
	wantSerial := []byte{0x08, 0x3c, 0x2a, 0x8e}
	if !bytes.Equal(stamp.Serial, wantSerial) {
		t.Errorf("serial %x, attendu %x", stamp.Serial, wantSerial)
	}
	if len(stamp.Token) == 0 {
		t.Error("token CMS vide")
	}
}

// TestParseTimeStampRespNonceMismatch : un jeton lié à une AUTRE requête
// est rejeté — anti-substitution (fail-closed).
func TestParseTimeStampRespNonceMismatch(t *testing.T) {
	_, err := parseTimeStampResp(goldenResp(t), goldenDigest, big.NewInt(12345))
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("attendu un rejet de nonce, obtenu %v", err)
	}
}

// TestParseTimeStampRespDigestMismatch : même rejet sur l'empreinte.
func TestParseTimeStampRespDigestMismatch(t *testing.T) {
	other := [32]byte{0xCD}
	_, err := parseTimeStampResp(goldenResp(t), other, goldenNonce)
	if err == nil || !strings.Contains(err.Error(), "empreinte") {
		t.Fatalf("attendu un rejet d'empreinte, obtenu %v", err)
	}
}

// TestParseTimeStampRespRejection : un statut PKI non-granted est une
// erreur explicite, jamais un jeton vide accepté.
func TestParseTimeStampRespRejection(t *testing.T) {
	// TimeStampResp { status { status = rejection(2) } }
	status, err := asn1.Marshal(pkiStatusInfo{Status: 2})
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	// La TimeStampResp enveloppe la PKIStatusInfo dans sa SEQUENCE propre.
	body, err := asn1.Marshal(struct {
		Status asn1.RawValue
	}{Status: asn1.RawValue{FullBytes: status}})
	if err != nil {
		t.Fatalf("marshal resp: %v", err)
	}
	_, err = parseTimeStampResp(body, goldenDigest, goldenNonce)
	if err == nil || !strings.Contains(err.Error(), "statut PKI 2") {
		t.Fatalf("attendu un rejet de statut, obtenu %v", err)
	}
}

// TestParseTimeStampRespGarbage : entrée non-ASN.1 → erreur, pas de panic.
func TestParseTimeStampRespGarbage(t *testing.T) {
	for _, junk := range [][]byte{nil, {}, []byte("pas du DER"), bytes.Repeat([]byte{0xFF}, 100)} {
		if _, err := parseTimeStampResp(junk, goldenDigest, goldenNonce); err == nil {
			t.Errorf("entrée %x… acceptée", junk[:min(4, len(junk))])
		}
	}
}

// TestHTTPTSA : chemin complet HTTP contre un serveur local qui rejoue
// la fixture — méthode, content-type et corps de requête valide vérifiés.
func TestHTTPTSA(t *testing.T) {
	fixture := goldenResp(t)
	var gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		buf, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("lecture corps: %v", err)
		}
		gotBody = buf
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(fixture)
	}))
	defer srv.Close()

	// Nonce fixé : la fixture signée ne répond qu'au nonce 0xC0FFEE42.
	stamp, err := (HTTPTSA{
		URL:         srv.URL,
		NonceSource: func() (*big.Int, error) { return goldenNonce, nil },
	}).Timestamp(context.Background(), goldenDigest)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if gotCT != tsQueryContentType {
		t.Errorf("content-type %q, attendu %q", gotCT, tsQueryContentType)
	}
	// La requête reçue est une TimeStampReq bien formée.
	var req timeStampReq
	if _, err := asn1.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("corps de requête illisible: %v", err)
	}
	if !bytes.Equal(req.MessageImprint.Digest, goldenDigest[:]) {
		t.Errorf("digest requête %x", req.MessageImprint.Digest)
	}
	if stamp.Source != srv.URL {
		t.Errorf("source %q, attendu %q", stamp.Source, srv.URL)
	}
	if !stamp.GenTime.Equal(time.Date(2026, 9, 18, 21, 18, 56, 0, time.UTC)) {
		t.Errorf("genTime %s", stamp.GenTime)
	}
}

// TestHTTPTSAHTTPError : HTTP ≠ 200 → erreur (jamais de parse d'une page
// d'erreur comme si c'était un jeton).
func TestHTTPTSAHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := (HTTPTSA{URL: srv.URL}).Timestamp(context.Background(), goldenDigest); err == nil {
		t.Fatal("HTTP 500 accepté")
	}
}

// TestFallbackTSA : le premier TSA valide gagne ; tous en échec = erreur
// agrégée nommant les causes.
func TestFallbackTSA(t *testing.T) {
	stamp := Stamp{GenTime: time.Now(), Source: "tsa-2"}
	ok := TSAFunc(func(context.Context, [32]byte) (Stamp, error) { return stamp, nil })
	ko1 := TSAFunc(func(context.Context, [32]byte) (Stamp, error) { return Stamp{}, errors.New("tsa-1 en rade") })
	ko2 := TSAFunc(func(context.Context, [32]byte) (Stamp, error) { return Stamp{}, errors.New("tsa-2 en rade") })

	got, err := (FallbackTSA{ko1, ok}).Timestamp(context.Background(), goldenDigest)
	if err != nil {
		t.Fatalf("fallback: %v", err)
	}
	if got.Source != "tsa-2" {
		t.Errorf("source %q, attendu tsa-2", got.Source)
	}

	if _, err := (FallbackTSA{ko1, ko2}).Timestamp(context.Background(), goldenDigest); err == nil ||
		!strings.Contains(err.Error(), "tsa-1") || !strings.Contains(err.Error(), "tsa-2") {
		t.Fatalf("attendu une erreur agrégée des deux TSA, obtenu %v", err)
	}

	if _, err := (FallbackTSA{}).Timestamp(context.Background(), goldenDigest); err == nil {
		t.Fatal("FallbackTSA vide accepté")
	}
}
