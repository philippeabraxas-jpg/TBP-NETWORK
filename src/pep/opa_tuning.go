package pep

// opa_tuning.go — la configuration commune (pepd, brokerd) de la file bornée devant OPA et de la détection de blocage,
// et le handler de statut que lit le superviseur.
//
//	TBP_OPA_MAX_INFLIGHT     requêtes simultanées vers OPA, [0, 256], défaut 2 ; 0 DÉSACTIVE la file (concurrence non bornée)
//	TBP_OPA_MAX_QUEUE        demandes en attente au-delà, [0, 4096], défaut 16
//	TBP_OPA_SUBJECT_SHARE    part maximale d'un même sujet (en vol + en attente), en %, [1, 100], défaut 25
//	TBP_OPA_STALL_WINDOW_MS  silence d'OPA qui le fait tenir pour bloqué, [500, 600000], défaut 3000 ; 0 désactive la détection
//
// Défauts posés par tests/opa_latency (voir son README) : 2 requêtes en vol tiennent le budget de 5 ms sur 2 cœurs
// d'OPA ; à ce régime, une inondation par UN sujet laisse 95-99 % des demandes légitimes servies (contre 0,5 % sans
// file). Une valeur illisible ou hors bornes est une erreur de démarrage, jamais un défaut silencieux (§1).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	DefaultOPAMaxInflight  = 2
	DefaultOPAMaxQueue     = 16
	DefaultOPASubjectShare = 25
	DefaultOPAStallWindow  = 3 * time.Second
	minOPAStallWindow      = 500 * time.Millisecond
	maxOPAStallWindow      = 10 * time.Minute
)

// OPATuning : ce que la configuration d'environnement dit de la file et de la détection de blocage.
type OPATuning struct {
	Admission   AdmissionOptions
	StallWindow time.Duration
}

// OPATuningFromEnv lit TBP_OPA_MAX_INFLIGHT / MAX_QUEUE / SUBJECT_SHARE / STALL_WINDOW_MS.
func OPATuningFromEnv(getenv func(string) string) (OPATuning, error) {
	t := OPATuning{
		Admission:   AdmissionOptions{MaxInflight: DefaultOPAMaxInflight, MaxQueue: DefaultOPAMaxQueue, SubjectShare: DefaultOPASubjectShare},
		StallWindow: DefaultOPAStallWindow,
	}
	intIn := func(name string, lo, hi int, dst *int) error {
		s := getenv(name)
		if s == "" {
			return nil
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("%s invalide %q (entier dans [%d, %d] attendu)", name, s, lo, hi)
		}
		*dst = n
		return nil
	}
	if err := intIn("TBP_OPA_MAX_INFLIGHT", 0, 256, &t.Admission.MaxInflight); err != nil {
		return t, err
	}
	if err := intIn("TBP_OPA_MAX_QUEUE", 0, 4096, &t.Admission.MaxQueue); err != nil {
		return t, err
	}
	if err := intIn("TBP_OPA_SUBJECT_SHARE", 1, 100, &t.Admission.SubjectShare); err != nil {
		return t, err
	}
	if s := getenv("TBP_OPA_STALL_WINDOW_MS"); s != "" {
		ms, err := strconv.Atoi(s)
		if err != nil || (ms != 0 && (ms < int(minOPAStallWindow/time.Millisecond) || ms > int(maxOPAStallWindow/time.Millisecond))) {
			return t, fmt.Errorf("TBP_OPA_STALL_WINDOW_MS invalide %q (0 pour désactiver, sinon [%d, %d])", s,
				int(minOPAStallWindow/time.Millisecond), int(maxOPAStallWindow/time.Millisecond))
		}
		t.StallWindow = time.Duration(ms) * time.Millisecond
	}
	if t.Admission.MaxInflight == 0 {
		// file désactivée : ses autres réglages n'ont pas d'objet — un réglage explicite est une incohérence
		for _, k := range []string{"TBP_OPA_MAX_QUEUE", "TBP_OPA_SUBJECT_SHARE"} {
			if getenv(k) != "" {
				return t, fmt.Errorf("%s sans file (TBP_OPA_MAX_INFLIGHT=0) — configuration incohérente", k)
			}
		}
	}
	return t, nil
}

// OPAStatusHandler sert l'état d'OPA vu du client (GET, JSON) sur le plan d'ADMINISTRATION : « healthy » / « overloaded » /
// « stalled ». C'est ce qu'un superviseur lit pour redémarrer OPA — le PEP ne tue rien lui-même.
func OPAStatusHandler(c *OPAClient) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"méthode non autorisée"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.Status())
	})
}
