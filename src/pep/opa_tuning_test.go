package pep

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestOPATuningDefaults(t *testing.T) {
	tu, err := OPATuningFromEnv(envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := AdmissionOptions{MaxInflight: 2, MaxQueue: 16, SubjectShare: 25}
	if tu.Admission != want || tu.StallWindow != 3*time.Second {
		t.Fatalf("défauts = %+v", tu)
	}
}

func TestOPATuningFromEnv(t *testing.T) {
	tu, err := OPATuningFromEnv(envOf(map[string]string{
		"TBP_OPA_MAX_INFLIGHT": "3", "TBP_OPA_MAX_QUEUE": "40", "TBP_OPA_SUBJECT_SHARE": "50", "TBP_OPA_STALL_WINDOW_MS": "1500",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if tu.Admission.MaxInflight != 3 || tu.Admission.MaxQueue != 40 || tu.Admission.SubjectShare != 50 || tu.StallWindow != 1500*time.Millisecond {
		t.Fatalf("tuning = %+v", tu)
	}
	// 0 désactive la file (seul) et la détection
	tu, err = OPATuningFromEnv(envOf(map[string]string{"TBP_OPA_MAX_INFLIGHT": "0", "TBP_OPA_STALL_WINDOW_MS": "0"}))
	if err != nil || newAdmission(tu.Admission, time.Now) != nil || tu.StallWindow != 0 {
		t.Fatalf("0 doit désactiver : %+v %v", tu, err)
	}
}

func TestOPATuningRejectsBadValues(t *testing.T) {
	for _, c := range []map[string]string{
		{"TBP_OPA_MAX_INFLIGHT": "-1"}, {"TBP_OPA_MAX_INFLIGHT": "257"}, {"TBP_OPA_MAX_INFLIGHT": "deux"},
		{"TBP_OPA_MAX_QUEUE": "-1"}, {"TBP_OPA_MAX_QUEUE": "4097"},
		{"TBP_OPA_SUBJECT_SHARE": "0"}, {"TBP_OPA_SUBJECT_SHARE": "101"},
		{"TBP_OPA_STALL_WINDOW_MS": "499"}, {"TBP_OPA_STALL_WINDOW_MS": "600001"}, {"TBP_OPA_STALL_WINDOW_MS": "-5"}, {"TBP_OPA_STALL_WINDOW_MS": "1s"},
		{"TBP_OPA_MAX_INFLIGHT": "0", "TBP_OPA_MAX_QUEUE": "8"},
		{"TBP_OPA_MAX_INFLIGHT": "0", "TBP_OPA_SUBJECT_SHARE": "30"},
	} {
		if _, err := OPATuningFromEnv(envOf(c)); err == nil {
			t.Errorf("%v : refus attendu", c)
		}
	}
}

func TestOPAStatusHandler(t *testing.T) {
	srv := allowServer(t, true)
	c := opaWith(t, srv.URL, &stubSink{}, nil, newFakeClock(), func(o *OPAOptions) { o.Admission = AdmissionOptions{MaxInflight: 2, MaxQueue: 4} })
	h := OPAStatusHandler(c)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/supervision/opa", nil))
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("code=%d ct=%q", rr.Code, rr.Header().Get("Content-Type"))
	}
	var st OPAStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil || st.State != "healthy" || st.Admission == nil {
		t.Fatalf("corps=%s err=%v", rr.Body.String(), err)
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(m, "/v1/supervision/opa", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s → %d, 405 attendu", m, rr.Code)
		}
	}
}
