package main

import (
	"os/exec"
	"testing"
	"time"
)

func TestSummarize(t *testing.T) {
	ds := []time.Duration{}
	for i := 1; i <= 100; i++ {
		ds = append(ds, time.Duration(i)*100*time.Microsecond) // 0,1 … 10 ms
	}
	ds = append(ds, -1) // un échec de transport
	st := summarize(ds, 5*time.Millisecond)
	if st.N != 101 || st.Failures != 1 {
		t.Fatalf("n/échecs : %+v", st)
	}
	if st.P50ms < 5.0 || st.P50ms > 5.2 || st.MaxMS != 10 {
		t.Fatalf("p50=%v max=%v", st.P50ms, st.MaxMS)
	}
	// 50 valeurs strictement > 5 ms (5,1 … 10) + 1 échec = 51 sur 101
	if st.Over != 50 || st.OverPct < 50.4 || st.OverPct > 50.6 {
		t.Fatalf("au-delà du budget : %+v", st)
	}
	// strictement au-delà : exactement le budget n'est PAS un dépassement
	if got := summarize([]time.Duration{5 * time.Millisecond}, 5*time.Millisecond); got.Over != 0 {
		t.Fatalf("le budget exact n'est pas un dépassement : %+v", got)
	}
	// tout en échec : pas de division par zéro, pas de percentile inventé
	if got := summarize([]time.Duration{-1, -1}, time.Millisecond); got.Failures != 2 || got.P50ms != 0 {
		t.Fatalf("tout en échec : %+v", got)
	}
}

func TestVerdictsPct(t *testing.T) {
	v := verdicts{"ok": 90, "opa-timeout": 10}
	if got := v.pct("opa-timeout"); got != 10 {
		t.Fatalf("pct = %v", got)
	}
	if got := (verdicts{}).pct("x"); got != 0 {
		t.Fatalf("vide : %v", got)
	}
}

// Bout en bout, minuscule : le vrai OPA, la vraie politique, les deux transports. Sauté sans binaire OPA.
func TestToolEndToEndTiny(t *testing.T) {
	if _, err := exec.LookPath("opa"); err != nil {
		t.Skip("binaire opa absent")
	}
	c := config{opaBin: "opa", regoDir: "../../policies/rego", path: "/v1/data/tbp/example/action", port: 18992}
	tmp := t.TempDir()
	for _, tr := range []string{"tcp", "unix"} {
		res, err := cold(c, tr, tmp, 2, 5*time.Millisecond)
		if err != nil {
			t.Fatalf("%s : %v", tr, err)
		}
		if res.First.N != 2 || res.Second.N != 2 || res.First.Failures != 0 {
			t.Fatalf("%s : %+v", tr, res)
		}
		healthy := res.Verdicts["ok"] + res.Verdicts["opa-timeout"] + res.Verdicts["opa-deny"]
		if healthy != 2 {
			t.Fatalf("%s : verdicts inattendus %v (OPA injoignable ?)", tr, res.Verdicts)
		}
		srv, err := c.start(tr, tmp, 99)
		if err != nil {
			t.Fatal(err)
		}
		st := steady(c, srv, 2, 40, 5*time.Millisecond)
		srv.stop()
		if st.Raw.N != 40 || st.Raw.Failures != 0 {
			t.Fatalf("%s : charge %+v", tr, st.Raw)
		}
	}
}
