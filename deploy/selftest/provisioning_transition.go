package main

// provisioning_transition.go — critères de fermeture de #218 et #272, sur les VRAIS démons.
//
// #218 : une transition du trousseau de quorum (ou du manifeste de genèse) était autorisée par une
// preuve vérifiée contre le fichier MODIFIÉ — qui peut écrire le fichier y ajoutait ses clés et
// signait. Elle se vérifie désormais contre les clés ATTESTÉES. L'attaque est jouée ici de bout en
// bout : le fichier d'autorité reçoit k clés d'attaquant, l'attaquant signe la condition annoncée,
// le démon doit REFUSER ; le cas voisin (les vrais contrôleurs signent la même transition) passe.
//
// #272 : anod mesure ses règles, son trousseau et son binaire. Règles modifiées entre deux
// démarrages ⇒ refus sans preuve valide ; redémarrage sans changement ⇒ accepté.
//
// Aucun démon n'est simulé : mêmes binaires, mêmes variables d'environnement que la production.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

// provDaemon décrit un démon mesuré à relancer.
type provDaemon struct {
	phase string // phase du rapport (daemons, mono, scale1…)
	name  string
	bin   string
	env   []string // environnement SANS preuve de transition
	dir   string   // journaux et preuves de ce démon
	cell  string   // cellule liée dans la preuve de quorum
	ready func() bool
	prep  func() error // avant CHAQUE démarrage (époque fraîche, socket périmé)
	n     int          // numéro de tentative, pour des journaux distincts
}

// attempt lance le démon (avec la preuve éventuelle) et rend s'il a REFUSÉ de démarrer (sortie avant
// d'être prêt), son journal, et le processus s'il est entré en service (à arrêter par l'appelant).
func (d *provDaemon) attempt(proofFile string) (refused bool, logText string, proc *daemonProc, err error) {
	if d.prep != nil {
		if err := d.prep(); err != nil {
			return false, "", nil, err
		}
	}
	d.n++
	logPath := filepath.Join(d.dir, fmt.Sprintf("%s-%02d.log", d.name, d.n))
	env := append([]string{}, d.env...)
	if proofFile != "" {
		env = append(env, "TBP_PROVISIONING_TRANSITION_PROOF_FILE="+proofFile)
	}
	p, err := startDaemon(d.bin, env, logPath)
	if err != nil {
		return false, "", nil, err
	}
	exited := make(chan error, 1)
	go func() { exited <- p.cmd.Wait() }()
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-exited:
			b, _ := os.ReadFile(logPath)
			return true, string(b), nil, nil
		case <-tick.C:
			if d.ready() {
				b, _ := os.ReadFile(logPath)
				return false, string(b), p, nil
			}
		case <-deadline:
			p.stop()
			b, _ := os.ReadFile(logPath)
			return false, string(b), nil, nil
		}
	}
}

// proofKey : une clé de signature et l'identifiant sous lequel le trousseau du démon la connaît.
type proofKey struct {
	kid  [16]byte
	priv ed25519.PrivateKey
}

// byPub : identifiant dérivé de la clé publique (trousseaux de brokerd et d'anod).
func byPub(privs ...ed25519.PrivateKey) []proofKey {
	out := make([]proofKey, 0, len(privs))
	for _, p := range privs {
		out = append(out, proofKey{kid: pep.KeyIDFromPublicKey(p.Public().(ed25519.PublicKey)), priv: p})
	}
	return out
}

// signedProof écrit une preuve de quorum de la condition, signée par ces clés (format de
// TBP_PROVISIONING_TRANSITION_PROOF_FILE, celui de `quorumproof sign`).
func signedProof(path, condition, cell string, signers ...proofKey) error {
	expiry := time.Now().Add(4 * time.Minute)
	msg := pep.QuorumMessage(condition, cell, expiry)
	type sigWire struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}
	var sigs []sigWire
	for _, k := range signers {
		sigs = append(sigs, sigWire{KeyID: hex.EncodeToString(k.kid[:]), Signature: hex.EncodeToString(ed25519.Sign(k.priv, msg))})
	}
	b, _ := json.Marshal(map[string]any{"expiry": expiry.Unix(), "signatures": sigs})
	return os.WriteFile(path, b, 0o600)
}

// keyringJSON : trousseau {kid: clé publique} au format de pepd/anod.
func keyringJSON(keys ...proofKey) []byte {
	m := map[string]string{}
	for _, k := range keys {
		m[hex.EncodeToString(k.kid[:])] = hex.EncodeToString(k.priv.Public().(ed25519.PublicKey))
	}
	b, _ := json.Marshal(m)
	return b
}

// transitionAttack joue #218 sur un démon : edit modifie le fichier d'autorité pour y ajouter les
// clés des attaquants. Le démon doit refuser l'édition sans preuve, refuser la preuve signée par les
// seuls attaquants, et accepter la même transition signée par les contrôleurs attestés.
func transitionAttack(s *suite, d *provDaemon, what string, edit func() error, honest, attackers []proofKey) {
	label := "#218 " + d.name + " : "
	if err := edit(); err != nil {
		s.fail(d.phase, label+"édition du fichier d'autorité", err)
		return
	}
	refused, out, p, err := d.attempt("")
	if err != nil {
		s.fail(d.phase, label+"démarrage sans preuve", err)
		return
	}
	cond, announced := conditionToSign(out)
	p.stop()
	s.add(d.phase, label+what+" édité ⇒ refus sans preuve, condition à signer annoncée",
		refused && announced, strings.TrimSpace(cond))
	if !refused || !announced {
		return
	}

	forged := filepath.Join(d.dir, d.name+"-preuve-attaquant.json")
	if err := signedProof(forged, cond, d.cell, attackers...); err != nil {
		s.fail(d.phase, label+"preuve de l'attaquant", err)
		return
	}
	refused, out, p, err = d.attempt(forged)
	if err != nil {
		s.fail(d.phase, label+"démarrage avec la preuve de l'attaquant", err)
		return
	}
	p.stop()
	s.add(d.phase, label+"k clés d'attaquant ajoutées au fichier, condition signée par elles ⇒ REFUS (la preuve se vérifie contre le trousseau attesté)",
		refused && strings.Contains(out, "transition refusée"), strings.TrimSpace(firstLineWith(out, "transition refusée")))

	genuine := filepath.Join(d.dir, d.name+"-preuve-controleurs.json")
	if err := signedProof(genuine, cond, d.cell, honest...); err != nil {
		s.fail(d.phase, label+"preuve des contrôleurs", err)
		return
	}
	refused, out, p, err = d.attempt(genuine)
	if err != nil {
		s.fail(d.phase, label+"démarrage avec la preuve des contrôleurs", err)
		return
	}
	s.add(d.phase, label+"cas voisin : les vrais contrôleurs signent la même transition ⇒ acceptée, le démon entre en service",
		!refused && p != nil, strings.TrimSpace(firstLineWith(out, "transition")))
	p.stop()
}

func firstLineWith(text, sub string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

// runProvisioningTransitionStage : #218 sur brokerd (manifeste de genèse) puis #218 et #272 sur anod.
// Dernière étape de la phase : elle modifie la genèse de la cellule.
func runProvisioningTransitionStage(s *suite, cfg config, base, brokerdBin string, brokerEnv []string, genesisDir string,
	brokerAdminHC *http.Client, writeEpoch0 func() error, controllers map[int]ed25519.PrivateKey) {
	honest := byPub(controllers[1], controllers[2]) // k = 2
	attackers := byPub(devKey("attacker-1"), devKey("attacker-2"))

	// --- brokerd : le manifeste de genèse est le fichier d'autorité ---
	bd := &provDaemon{
		phase: phaseDaemons, name: "brokerd", bin: brokerdBin, env: brokerEnv, dir: base, cell: daemonsCellID,
		ready: func() bool {
			st, _, err := getUnix(brokerAdminHC, "http://brokerd/v1/supervision/epoch")
			return err == nil && st == http.StatusOK
		},
		prep: writeEpoch0, // l'époque 0 DEV expire : jeton frais, signé par les contrôleurs d'origine
	}
	manifestPath := filepath.Join(genesisDir, "manifest.json")
	transitionAttack(s, bd, "manifeste de genèse", func() error {
		pubs := []string{}
		for _, id := range []int{1, 2, 3} {
			pubs = append(pubs, hex.EncodeToString(controllers[id].Public().(ed25519.PublicKey)))
		}
		for _, a := range attackers {
			pubs = append(pubs, hex.EncodeToString(a.priv.Public().(ed25519.PublicKey)))
		}
		b, _ := json.Marshal(map[string][]string{"pubkeys": pubs})
		return os.WriteFile(manifestPath, b, 0o644)
	}, honest, attackers)

	// --- anod : règles, trousseau d'émetteurs et trousseau de contrôleurs sont mesurés ---
	anodBin := filepath.Join(base, "bin", "anod")
	if _, errB, err := runCmd(cfg.repo, nil, cfg.goBin, "build", "-o", anodBin, "./src/ano/cmd/anod"); err != nil {
		s.fail(phaseDaemons, "build anod", fmt.Errorf("%v — %s", err, errB))
		return
	}
	s.add(phaseDaemons, "build anod (#272)", true, anodBin)
	dir := filepath.Join(base, "anod")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.fail(phaseDaemons, "répertoire d'anod", err)
		return
	}
	rulesPath := filepath.Join(dir, "rules.json")
	issuerRing := filepath.Join(dir, "issuer-keyring.json")
	quorumRing := filepath.Join(dir, "quorum-keyring.json")
	sock := filepath.Join(dir, "ano.sock")
	auditKey := filepath.Join(dir, "audit.key")
	if err := registry.GenerateRecordKey(auditKey); err != nil {
		s.fail(phaseDaemons, "clé du journal d'audit d'anod", err)
		return
	}
	rulesV1 := `{"mask_paths":["user.email","user.phone"]}`
	for path, content := range map[string][]byte{
		rulesPath:  []byte(rulesV1),
		issuerRing: keyringJSON(byPub(devKey("anod-issuer"))...),
		quorumRing: keyringJSON(byPub(controllers[1], controllers[2], controllers[3])...),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			s.fail(phaseDaemons, "fichiers d'anod", err)
			return
		}
	}
	ad := &provDaemon{
		phase: phaseDaemons, name: "anod", bin: anodBin, dir: dir, cell: "cell-anod",
		env: append(os.Environ(),
			"TBP_CELL_ID=cell-anod",
			"TBP_SALT="+hex.EncodeToString([]byte("selftest-anod-salt-0123456789abc")),
			"TBP_REGISTRY_DIR="+filepath.Join(dir, "registry"),
			"TBP_PROVISIONING_WITNESS_FILE="+filepath.Join(dir, "witness.json"),
			"TBP_AUDIT_RECORDS="+filepath.Join(dir, "audit-records.jsonl"),
			"TBP_AUDIT_RECORDS_KEY_FILE="+auditKey,
			"TBP_KEYRING_FILE="+issuerRing,
			"TBP_QUORUM_KEYRING_FILE="+quorumRing,
			"TBP_QUORUM_MIN=2",
			"TBP_ANO_RULES_FILE="+rulesPath,
			"TBP_ANO_SOCKET="+sock,
		),
		ready: func() bool {
			fi, err := os.Stat(sock)
			return err == nil && fi.Mode()&os.ModeSocket != 0
		},
		prep: func() error { // un socket du démarrage précédent ferait croire à un démon prêt
			if err := os.Remove(sock); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		},
	}

	// Premier démarrage (confiance à la première utilisation, documentée) puis redémarrage SANS changement.
	refused, out, p, err := ad.attempt("")
	if err != nil {
		s.fail(phaseDaemons, "#272 anod : premier démarrage", err)
		return
	}
	p.stop()
	s.add(phaseDaemons, "#272 anod : premier démarrage, règles et trousseaux engagés dans le témoin", !refused && p != nil, strings.TrimSpace(firstLineWith(out, "anod")))
	if refused || p == nil {
		return
	}
	refused, out, p, err = ad.attempt("")
	if err != nil {
		s.fail(phaseDaemons, "#272 anod : redémarrage sans changement", err)
		return
	}
	p.stop()
	s.add(phaseDaemons, "#272 anod : redémarrage sans aucun changement ⇒ accepté (cas voisin)", !refused && p != nil, strings.TrimSpace(firstLineWith(out, "anod")))

	// Règles modifiées : retirer un motif suffirait à laisser passer des données qui devaient être masquées.
	if err := os.WriteFile(rulesPath, []byte(`{"mask_paths":["user.email"]}`), 0o600); err != nil {
		s.fail(phaseDaemons, "#272 anod : édition des règles", err)
		return
	}
	refused, out, p, err = ad.attempt("")
	if err != nil {
		s.fail(phaseDaemons, "#272 anod : démarrage, règles éditées", err)
		return
	}
	p.stop()
	cond, announced := conditionToSign(out)
	s.add(phaseDaemons, "#272 anod : règles modifiées entre deux démarrages (un champ n'est plus masqué) ⇒ refus sans preuve, fichier nommé, condition à signer annoncée",
		refused && announced && strings.Contains(out, "ano-rules"), strings.TrimSpace(cond))
	if !refused || !announced {
		return
	}
	forged := filepath.Join(dir, "anod-preuve-sans-droit.json")
	if err := signedProof(forged, cond, "cell-anod", attackers...); err != nil {
		s.fail(phaseDaemons, "#272 anod : preuve d'un non-contrôleur", err)
		return
	}
	refused, out, p, err = ad.attempt(forged)
	if err != nil {
		s.fail(phaseDaemons, "#272 anod : démarrage, preuve d'un non-contrôleur", err)
		return
	}
	p.stop()
	s.add(phaseDaemons, "#272 anod : la preuve de personnes qui ne sont pas contrôleurs ⇒ refus", refused && strings.Contains(out, "transition refusée"), strings.TrimSpace(firstLineWith(out, "transition refusée")))
	genuine := filepath.Join(dir, "anod-preuve-controleurs.json")
	if err := signedProof(genuine, cond, "cell-anod", honest...); err != nil {
		s.fail(phaseDaemons, "#272 anod : preuve des contrôleurs", err)
		return
	}
	refused, out, p, err = ad.attempt(genuine)
	if err != nil {
		s.fail(phaseDaemons, "#272 anod : démarrage, preuve des contrôleurs", err)
		return
	}
	p.stop()
	s.add(phaseDaemons, "#272 anod : les contrôleurs signent exactement cette transition ⇒ acceptée", !refused && p != nil, strings.TrimSpace(firstLineWith(out, "transition")))

	// #218 sur anod : son fichier d'autorité est le trousseau de contrôleurs.
	transitionAttack(s, ad, "trousseau de contrôleurs", func() error {
		return os.WriteFile(quorumRing, keyringJSON(append(byPub(controllers[1], controllers[2], controllers[3]), attackers...)...), 0o600)
	}, honest, attackers)
}

// runPepdTransitionStage : #218 sur le vrai pepd (phase mono/scale1/scale2). Le fichier d'autorité de pepd
// est le trousseau de quorum ; ring est son contenu d'origine, honest les clés qu'il épingle (avec leurs
// identifiants), k le quorum attesté — l'attaquant ajoute k clés à lui.
func runPepdTransitionStage(s *suite, phase, pepdBin string, env []string, dir, cell, quorumKeyringPath string,
	ring map[string]string, honest []proofKey, k int, ready func() bool) {
	var attackers []ed25519.PrivateKey
	for i := 1; i <= k; i++ {
		attackers = append(attackers, devKey(fmt.Sprintf("attacker-pepd-%d", i)))
	}
	atk := byPub(attackers...)
	d := &provDaemon{phase: phase, name: "pepd", bin: pepdBin, env: env, dir: dir, cell: cell, ready: ready}
	transitionAttack(s, d, "trousseau de quorum", func() error {
		forged := map[string]string{}
		for kid, pub := range ring {
			forged[kid] = pub
		}
		for _, a := range atk {
			forged[hex.EncodeToString(a.kid[:])] = hex.EncodeToString(a.priv.Public().(ed25519.PublicKey))
		}
		b, _ := json.Marshal(forged)
		return os.WriteFile(quorumKeyringPath, b, 0o600)
	}, honest, atk)
}
