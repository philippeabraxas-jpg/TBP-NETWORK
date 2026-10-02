package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	arbiter "github.com/philippeabraxas-jpg/TBP-NETWORK/src/arbiter"
	broker "github.com/philippeabraxas-jpg/TBP-NETWORK/src/broker"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

func TestArbitrationFromEnv(t *testing.T) {
	get := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if cfg, err := arbitrationFromEnv(get(nil), false); err != nil || cfg.enabled {
		t.Fatalf("absent : %+v %v", cfg, err)
	}
	if cfg, err := arbitrationFromEnv(get(map[string]string{"TBP_ARBITRATION": "1"}), true); err != nil || !cfg.enabled ||
		cfg.presenceTTL != arbiter.DefaultPresenceTTL || cfg.entryTTL != arbiter.DefaultEntryTTL || cfg.maxPending != arbiter.DefaultMaxEntries {
		t.Fatalf("défauts : %+v %v", cfg, err)
	}
	full := map[string]string{"TBP_ARBITRATION": "1", "TBP_ARBITRATION_PRESENCE_TTL_S": "10", "TBP_ARBITRATION_ENTRY_TTL_S": "3600", "TBP_ARBITRATION_MAX_PENDING": "4096"}
	if cfg, err := arbitrationFromEnv(get(full), true); err != nil || cfg.presenceTTL != 10*time.Second || cfg.entryTTL != time.Hour || cfg.maxPending != 4096 {
		t.Fatalf("bornes : %+v %v", cfg, err)
	}
	with := func(kv ...string) map[string]string {
		m := map[string]string{"TBP_ARBITRATION": "1"}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for name, c := range map[string]struct {
		env   map[string]string
		guard bool
		want  string
	}{
		"invalide":           {map[string]string{"TBP_ARBITRATION": "oui"}, true, "TBP_ARBITRATION invalide"},
		"sans_garde":         {with(), false, "sans TBP_TRANSLATOR_GUARD=1"},
		"reglage_sans_actif": {map[string]string{"TBP_ARBITRATION_MAX_PENDING": "5"}, true, "sans TBP_ARBITRATION=1"},
		"presence_basse":     {with("TBP_ARBITRATION_PRESENCE_TTL_S", "9"), true, "PRESENCE_TTL_S invalide"},
		"presence_haute":     {with("TBP_ARBITRATION_PRESENCE_TTL_S", "601"), true, "PRESENCE_TTL_S invalide"},
		"entree_basse":       {with("TBP_ARBITRATION_ENTRY_TTL_S", "59"), true, "ENTRY_TTL_S invalide"},
		"entree_haute":       {with("TBP_ARBITRATION_ENTRY_TTL_S", "3601"), true, "ENTRY_TTL_S invalide"},
		"file_zero":          {with("TBP_ARBITRATION_MAX_PENDING", "0"), true, "MAX_PENDING invalide"},
		"file_enorme":        {with("TBP_ARBITRATION_MAX_PENDING", "4097"), true, "MAX_PENDING invalide"},
		"texte":              {with("TBP_ARBITRATION_MAX_PENDING", "beaucoup"), true, "MAX_PENDING invalide"},
	} {
		if _, err := arbitrationFromEnv(get(c.env), c.guard); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s : refus %q attendu, got %v", name, c.want, err)
		}
	}
	env := validConfigEnv()
	env["TBP_ARBITRATION"] = "1"
	if _, err := loadConfig(mapGetenv(env), statPresent); err == nil || !strings.Contains(err.Error(), "TBP_TRANSLATOR_GUARD=1") {
		t.Fatalf("loadConfig doit refuser l'arbitrage sans garde : %v", err)
	}
}

type fixedClock struct{ t time.Time }

func (c *fixedClock) now() time.Time { return c.t }

// La porte : un STANDARD dégradé est mis en file si un arbitre est joignable, puis admis UNE fois après approbation ;
// un CRITIQUE n'est jamais mis en file ; sans arbitre joignable, default-deny.
func TestControllerGateArbitration(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	opPub, opPriv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{3}, 64)))
	clk := &fixedClock{t: time.Now()}
	q, err := arbiter.NewQueue(arbiter.Options{
		CellID: "cell-a", Salt: make([]byte, 16), Leaves: &sinkLeaves{}, OperatorKeys: []ed25519.PublicKey{opPub}, Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := broker.StaticAgentRegistry{"std": {Class: pep.ClassOut}, "crit": {Class: pep.ClassW}}
	cfg := translatorGuardConfig{enabled: true, probeURL: down.URL + "/h", interval: time.Hour, timeout: time.Second}
	tr, start, err := setupTranslatorGuard(cfg, broker.StructuredTranslator{}, "cell-a", make([]byte, 16), &sinkLeaves{}, nil, nil, nil, systemClassOf(reg), q)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start(ctx)
	intent := `{"action":"read","resource":"r"}`
	id := arbiter.IntentID("std", []byte(intent))
	hexID := hex.EncodeToString(id[:])

	// pas d'arbitre joignable : default-deny (pas de mise en file implicite)
	_, err = tr.Translate(ctx, "std", intent)
	var pend *broker.PendingArbitrationError
	if err == nil || errors.As(err, &pend) {
		t.Fatalf("sans arbitre joignable : refus simple attendu, got %v", err)
	}
	if len(q.Snapshot()) != 0 {
		t.Fatal("demande mise en file sans arbitre joignable")
	}

	// un arbitre se manifeste : la demande est mise en file, verdict DIFFÉRÉ avec l'id à signer
	_ = q.Heartbeat(ctx, clk.t, ed25519.Sign(opPriv, arbiter.PresenceMessage(clk.t)))
	_, err = tr.Translate(ctx, "std", intent)
	if !errors.As(err, &pend) || pend.ID != hexID {
		t.Fatalf("verdict différé attendu avec l'id %s : %v", hexID, err)
	}
	// représentée avant décision : toujours en attente, sans doublon
	_, err = tr.Translate(ctx, "std", intent)
	if !errors.As(err, &pend) || len(q.Snapshot()) != 1 {
		t.Fatalf("représentation avant décision : %v (file %d)", err, len(q.Snapshot()))
	}
	// un CRITIQUE n'est jamais mis en file (pas d'escalade humaine, §4.5)
	if _, err := tr.Translate(ctx, "crit", intent); err == nil || errors.As(err, &pend) {
		t.Fatalf("critique : refus simple attendu, got %v", err)
	}
	if len(q.Snapshot()) != 1 {
		t.Fatal("un système critique a été mis en file")
	}

	// l'opérateur approuve : la même demande est admise UNE fois
	exp := clk.t.Add(5 * time.Minute)
	if err := q.Decide(ctx, id, arbiter.VerdictApprove, exp, ed25519.Sign(opPriv, arbiter.DecisionMessage(id, arbiter.VerdictApprove, exp))); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Translate(ctx, "std", intent); err != nil {
		t.Fatalf("demande approuvée refusée : %v", err)
	}
	if _, err := tr.Translate(ctx, "std", intent); !errors.As(err, &pend) {
		t.Fatalf("l'approbation est à usage UNIQUE : la 2e présentation doit repartir en file : %v", err)
	}
	// une demande DIFFÉRENTE n'hérite de rien
	if _, err := tr.Translate(ctx, "std", intent+" "); !errors.As(err, &pend) {
		t.Fatalf("autre demande : %v", err)
	}

	// refus de l'arbitre : refus propre, consommé
	exp = clk.t.Add(5 * time.Minute)
	if err := q.Decide(ctx, id, arbiter.VerdictRefuse, exp, ed25519.Sign(opPriv, arbiter.DecisionMessage(id, arbiter.VerdictRefuse, exp))); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Translate(ctx, "std", intent); !errors.Is(err, broker.ErrArbitrationRefused) {
		t.Fatalf("refus de l'arbitre : %v", err)
	}
}

// Sans file câblée, un standard dégradé est refusé : aucune escalade implicite.
func TestControllerGateWithoutArbitrationQueue(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer down.Close()
	cfg := translatorGuardConfig{enabled: true, probeURL: down.URL + "/h", interval: time.Hour, timeout: time.Second}
	tr, start, err := setupTranslatorGuard(cfg, broker.StructuredTranslator{}, "cell-a", make([]byte, 16), &sinkLeaves{}, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start(ctx)
	var pend *broker.PendingArbitrationError
	if _, err := tr.Translate(ctx, "std", `{"action":"read","resource":"r"}`); err == nil || errors.As(err, &pend) {
		t.Fatalf("refus simple attendu, got %v", err)
	}
}

// De bout en bout avec le vrai run : traducteur tombé ⇒ verdict différé, présence et décision SIGNÉES sur le plan
// d'administration, la même demande représentée est admise une fois (puis jugée par la chaîne : OPA autorise ici).
func TestBrokerdArbitrationEndToEnd(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "broker.sock")
	fx := newRunFixture(t, sock)
	opa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("provenance") == "true" {
			_, _ = w.Write([]byte(`{"result":{"allow":true},"provenance":{"bundles":{"/opa/bundle.tar.gz":{"revision":"` + fx.env["TBP_POLICY_ID"] + `"}}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"result":{"allow":true}}`))
	}))
	defer opa.Close()
	fx.env["TBP_OPA_ENDPOINT"] = opa.URL
	tr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer tr.Close()
	fx.env["TBP_TRANSLATOR_GUARD"] = "1"
	fx.env["TBP_TRANSLATOR_PROBE_URL"] = tr.URL + "/health"
	fx.env["TBP_TRANSLATOR_PROBE_INTERVAL_MS"] = "500"
	fx.env["TBP_ARBITRATION"] = "1"

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, mapGetenv(fx.env), statPresent) }()
	waitSocket(t, sock)
	waitSocket(t, fx.adminSock)
	hc := unixClient(t, sock)
	adminHC := unixClient(t, fx.adminSock)
	const intent = `{"action":"read","resource":"doc-1","class":0}`

	post := func(path string, v any) (int, string) {
		b, _ := json.Marshal(v)
		resp, err := adminHC.Post("http://brokerd"+path, "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out bytes.Buffer
		_, _ = out.ReadFrom(resp.Body)
		return resp.StatusCode, out.String()
	}
	postRaw := func(subject string) (map[string]any, int) {
		b, _ := json.Marshal(map[string]string{"subject": subject, "intent": intent})
		resp, err := hc.Post("http://brokerd/v1/actions", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return m, resp.StatusCode
	}
	id := arbiter.IntentID("agent-1", []byte(intent))
	hexID := hex.EncodeToString(id[:])

	// 1. aucun arbitre joignable : refus simple (translation-failed), rien en file
	m, _ := postRaw("agent-1")
	if m["reason"] != "translation-failed" || m["arbitration_id"] != nil {
		t.Fatalf("sans arbitre : %v", m)
	}
	var st arbStatusView
	getJSON(t, adminHC, "http://brokerd/v1/supervision/degraded", &st)
	if st.Reachable || len(st.Pending) != 0 {
		t.Fatalf("état initial : %+v", st)
	}

	// 2. présence : signature d'un intrus refusée, celle de l'opérateur acceptée
	now := time.Now().UTC().Truncate(time.Second)
	_, otherPriv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	if code, _ := post("/v1/supervision/degraded/presence", arbPresenceRequest{At: now, Signature: hex.EncodeToString(ed25519.Sign(otherPriv, arbiter.PresenceMessage(now)))}); code != http.StatusBadRequest {
		t.Fatalf("présence d'un intrus : %d", code)
	}
	if code, body := post("/v1/supervision/degraded/presence", arbPresenceRequest{At: now, Signature: hex.EncodeToString(ed25519.Sign(fx.opPriv, arbiter.PresenceMessage(now)))}); code != http.StatusOK {
		t.Fatalf("présence valide : %d %s", code, body)
	}

	// 3. verdict différé : arbitration-pending + l'id (que l'agent recalcule), la file le montre sans l'intention
	m, _ = postRaw("agent-1")
	if m["reason"] != "arbitration-pending" || m["arbitration_id"] != hexID || m["allow"] != false || m["token"] != nil {
		t.Fatalf("verdict différé attendu : %v", m)
	}
	getJSON(t, adminHC, "http://brokerd/v1/supervision/degraded", &st)
	if !st.Reachable || len(st.Pending) != 1 || st.Pending[0].ID != hexID || st.Pending[0].Subject != "agent-1" || st.Pending[0].Status != "pending" {
		t.Fatalf("file : %+v", st)
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "doc-1") {
		t.Fatalf("la file ne doit jamais exposer l'intention : %s", raw)
	}

	// 4. décisions invalides : intrus, mauvais verdict signé, échéance trop proche — la demande reste en attente
	exp := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	sign := func(priv ed25519.PrivateKey, v arbiter.Verdict, e time.Time) string {
		return hex.EncodeToString(ed25519.Sign(priv, arbiter.DecisionMessage(id, v, e)))
	}
	for name, body := range map[string]arbDecideRequest{
		"intrus":          {ID: hexID, Verdict: "approve", ExpiresAt: exp, Signature: sign(otherPriv, arbiter.VerdictApprove, exp)},
		"verdict_inverse": {ID: hexID, Verdict: "approve", ExpiresAt: exp, Signature: sign(fx.opPriv, arbiter.VerdictRefuse, exp)},
		"echeance_proche": {ID: hexID, Verdict: "approve", ExpiresAt: time.Now().Add(time.Second).UTC(), Signature: sign(fx.opPriv, arbiter.VerdictApprove, time.Now().Add(time.Second).UTC())},
		"verdict_inconnu": {ID: hexID, Verdict: "peut-etre", ExpiresAt: exp, Signature: sign(fx.opPriv, arbiter.VerdictApprove, exp)},
		"id_invalide":     {ID: "zz", Verdict: "approve", ExpiresAt: exp, Signature: sign(fx.opPriv, arbiter.VerdictApprove, exp)},
	} {
		if code, _ := post("/v1/supervision/degraded/decide", body); code != http.StatusBadRequest {
			t.Fatalf("%s : 400 attendu, got %d", name, code)
		}
	}
	if m, _ = postRaw("agent-1"); m["reason"] != "arbitration-pending" {
		t.Fatalf("des décisions invalides ne doivent rien débloquer : %v", m)
	}

	// 5. approbation de l'opérateur : la même demande est admise (la chaîne la juge ensuite : OPA autorise)
	if code, body := post("/v1/supervision/degraded/decide", arbDecideRequest{ID: hexID, Verdict: "approve", ExpiresAt: exp, Signature: sign(fx.opPriv, arbiter.VerdictApprove, exp)}); code != http.StatusOK || !strings.Contains(body, `"approve"`) {
		t.Fatalf("approbation : %d %s", code, body)
	}
	if m, _ = postRaw("agent-1"); m["allow"] != true || m["token"] == nil {
		t.Fatalf("la demande approuvée doit être admise puis jugée par la chaîne (OPA autorise) : %v", m)
	}
	// à usage unique : la représentation suivante repart en file
	if m, _ = postRaw("agent-1"); m["reason"] != "arbitration-pending" {
		t.Fatalf("approbation consommée deux fois : %v", m)
	}

	// 6. refus de l'arbitre
	exp2 := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	if code, _ := post("/v1/supervision/degraded/decide", arbDecideRequest{ID: hexID, Verdict: "refuse", ExpiresAt: exp2, Signature: sign(fx.opPriv, arbiter.VerdictRefuse, exp2)}); code != http.StatusOK {
		t.Fatalf("refus : %d", code)
	}
	if m, _ = postRaw("agent-1"); m["reason"] != "arbitration-refused" || m["allow"] != false {
		t.Fatalf("refus de l'arbitre : %v", m)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run: %v", err)
	}
}

// Traducteur REVENU : la file n'intervient plus — la demande est admise normalement et une approbation en
// attente n'est pas consommée pour rien (elle reste valable tant que son échéance court).
func TestControllerGateIgnoresQueueWhenTranslatorHealthy(t *testing.T) {
	var healthy atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	opPub, opPriv, _ := ed25519.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{4}, 64)))
	q, err := arbiter.NewQueue(arbiter.Options{CellID: "cell-a", Salt: make([]byte, 16), Leaves: &sinkLeaves{}, OperatorKeys: []ed25519.PublicKey{opPub}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := translatorGuardConfig{enabled: true, probeURL: srv.URL + "/h", interval: 50 * time.Millisecond, timeout: time.Second}
	tr, start, err := setupTranslatorGuard(cfg, broker.StructuredTranslator{}, "cell-a", make([]byte, 16), &sinkLeaves{}, nil, nil, nil, nil, q)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start(ctx)
	now := time.Now()
	_ = q.Heartbeat(ctx, now, ed25519.Sign(opPriv, arbiter.PresenceMessage(now)))
	intent := `{"action":"read","resource":"r"}`
	var pend *broker.PendingArbitrationError
	if _, err := tr.Translate(ctx, "std", intent); !errors.As(err, &pend) {
		t.Fatalf("en file : %v", err)
	}
	id := arbiter.IntentID("std", []byte(intent))
	exp := now.Add(5 * time.Minute)
	if err := q.Decide(ctx, id, arbiter.VerdictApprove, exp, ed25519.Sign(opPriv, arbiter.DecisionMessage(id, arbiter.VerdictApprove, exp))); err != nil {
		t.Fatal(err)
	}
	healthy.Store(true)
	waitFor(t, 5*time.Second, "traducteur revenu", func() bool { _, err := tr.Translate(ctx, "std", intent+" "); return err == nil })
	// la demande approuvée est admise NORMALEMENT (traducteur sain) et l'approbation n'a pas été consommée
	if _, err := tr.Translate(ctx, "std", intent); err != nil {
		t.Fatalf("traducteur sain : %v", err)
	}
	approved := false
	for _, e := range q.Snapshot() { // (l'attente du retour du traducteur a pu mettre en file d'autres demandes)
		approved = approved || (e.ID == id && e.Status == "approved")
	}
	if !approved {
		t.Fatalf("l'approbation ne doit pas être consommée tant que le traducteur est sain : %+v", q.Snapshot())
	}
}
