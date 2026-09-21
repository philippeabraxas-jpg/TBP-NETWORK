// fencing.go — T35 (issue #61) : phase fencing 2-cellules IN-PROCESS.
//
// Exigence de relecture : la séquence multi-cellules des guides (deploy/
// README.md ordre d'installation, deploy/cellule.md, monitor-to-closed.md)
// est jouée ici contre les VRAIS composants cluster (trackers d'époques,
// QuorumGate, PromotionController) sur registres tessera réels, avec
// horloge manuelle — motif T27/T28. La cohérence « les guides citent le
// code » est ainsi prouvée directement, pas par renvoi aux tests unitaires.
//
// Séquence (§7.2/§7.3/§7.4/§7.5) :
//
//	epoch 0 (autorité cell-a) → seul le détenteur sert ;
//	équivoque (même N, autre payload) → refus tracé + alarme ;
//	rotation émise AVANT expiration → aucune fenêtre à deux autorités ;
//	roster=[cell-b] → cell-a révoquée (§7.3) ;
//	QuorumGate classe W : 1-of-3 refusé, 2-of-3 admis, les deux tracés ;
//	promotion miroir→canari : source saine OK, partition refusée.
//
// Clés de contrôleurs et de cellules dérivées de seeds fixes — SUBSTITUTION
// DEV (pas de HSM ici) ; la vraie genèse est scripts/genesis (§12).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
	registry "github.com/philippeabraxas-jpg/TBP-NETWORK/src/registry"
)

const phaseFencing = "fencing"

// manualClock — horloge contrôlée (motif cluster_test.go).
type manualClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *manualClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *manualClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// alarmRec capte les alarmes OnAlarm (couture T14).
type alarmRec struct {
	mu      sync.Mutex
	reasons []string
}

func (a *alarmRec) fire(reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reasons = append(a.reasons, reason)
}

func (a *alarmRec) len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.reasons)
}

// masterStub simule la master chain : ancres de bundles + fenêtres saines.
// down=true = PARTITION — le master est injoignable (fail-closed §7.4).
type masterStub struct {
	bundles map[uint64][32]byte
	windows map[uint64][2]time.Time
	down    bool
}

func (m *masterStub) BundleAnchor(epoch uint64) ([32]byte, bool) {
	if m.down {
		return [32]byte{}, false
	}
	h, ok := m.bundles[epoch]
	return h, ok
}

func (m *masterStub) HealthyWindow(epoch uint64) (time.Time, time.Time, bool) {
	if m.down {
		return time.Time{}, time.Time{}, false
	}
	w, ok := m.windows[epoch]
	return w[0], w[1], ok
}

// devControllers dérive 3 contrôleurs de test (seeds fixes, DEV).
func devControllers() (map[int]ed25519.PublicKey, map[int]ed25519.PrivateKey) {
	pubs, privs := map[int]ed25519.PublicKey{}, map[int]ed25519.PrivateKey{}
	for i := 1; i <= 3; i++ {
		priv := devKey(fmt.Sprintf("controller-%d", i))
		privs[i], pubs[i] = priv, priv.Public().(ed25519.PublicKey)
	}
	return pubs, privs
}

// mintEpoch frappe un jeton d'époque signé par les contrôleurs donnés.
// Forme canonique signée = payload seul — exactement scripts/genesis (T3).
func mintEpoch(privs map[int]ed25519.PrivateKey, p cluster.EpochPayload, signers ...int) ([]byte, error) {
	canonical, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	tok := cluster.EpochToken{Payload: p, Quorum: "2-of-3"}
	for _, id := range signers {
		sig := ed25519.Sign(privs[id], canonical)
		tok.Signatures = append(tok.Signatures, cluster.ControllerSignature{KeyID: id, Sig: hex.EncodeToString(sig)})
	}
	return json.Marshal(tok)
}

// mintProof frappe une preuve de quorum classe W liée à (action, resource,
// policyID, epoch), expirant à expiry (motif quorum_test.go).
func mintProof(privs map[int]ed25519.PrivateKey, action, resource string, policyID [32]byte, epoch uint64, expiry time.Time, signers ...int) ([]byte, error) {
	st := cluster.QuorumStatement{
		Action:   action,
		Resource: resource,
		PolicyID: hex.EncodeToString(policyID[:]),
		Epoch:    epoch,
		Expiry:   expiry.UTC().Format(time.RFC3339),
	}
	canonical, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("statement: %w", err)
	}
	proof := cluster.QuorumProof{Statement: st, Quorum: "2-of-3"}
	for _, id := range signers {
		sig := ed25519.Sign(privs[id], canonical)
		proof.Signatures = append(proof.Signatures, cluster.ControllerSignature{KeyID: id, Sig: hex.EncodeToString(sig)})
	}
	return json.Marshal(proof)
}

// mintReceipt frappe une réception de bundle signée par la cellule
// candidate (motif promotion_test.go).
func mintReceipt(priv ed25519.PrivateKey, cellID string, epoch uint64, bundle [32]byte, at time.Time) ([]byte, error) {
	r := cluster.Receipt{
		CellID:     cellID,
		Epoch:      epoch,
		BundleHash: hex.EncodeToString(bundle[:]),
		ReceivedAt: at.UTC().Format(time.RFC3339),
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("receipt: %w", err)
	}
	sig := ed25519.Sign(priv, canonical)
	return json.Marshal(cluster.SignedReceipt{Receipt: r, Sig: hex.EncodeToString(sig)})
}

// waitKind poll le registre jusqu'à ce que le kind atteigne want (tessera
// intègre de façon asynchrone) ou que le délai expire.
func waitKind(ctx context.Context, cellID, regDir string, kind byte, want int) (int, error) {
	var n int
	var err error
	for i := 0; i < 20; i++ {
		var counts map[byte]int
		counts, err = countKinds(ctx, cellID, regDir)
		if err != nil {
			return 0, err
		}
		n = counts[kind]
		if n >= want {
			return n, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return n, nil
}

// runFencing exécute la phase 2-cellules in-process.
func runFencing(s *suite, cfg config) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	clk := &manualClock{t: t0}
	pubs, privs := devControllers()
	salt := sha256.Sum256([]byte("tbp-t35-fencing-salt-dev"))
	members := []string{"cell-a", "cell-b"}

	// --- Étape : deux registres tessera réels (un par cellule, §4.1) -------
	regDirA := filepath.Join(cfg.out, "fencing", "cell-a")
	regDirB := filepath.Join(cfg.out, "fencing", "cell-b")
	logA, err := openCellRegistry(ctx, regDirA, "cell-a")
	if err != nil {
		s.fail(phaseFencing, "registre cell-a", err)
		return
	}
	defer func() { c, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel(); _ = logA.Close(c) }()
	logB, err := openCellRegistry(ctx, regDirB, "cell-b")
	if err != nil {
		s.fail(phaseFencing, "registre cell-b", err)
		return
	}
	defer func() { c, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel(); _ = logB.Close(c) }()
	s.add(phaseFencing, "deux registres tessera réels (un par cellule)", true, regDirA+" | "+regDirB)

	// --- Étape : trackers d'époques 2-of-3 sur les deux cellules ------------
	alarmsA, alarmsB := &alarmRec{}, &alarmRec{}
	newTracker := func(cellID string, leaves cluster.LeafSink, alarms *alarmRec) (*cluster.Tracker, error) {
		return cluster.NewTracker(cluster.TrackerConfig{
			CellID: cellID, Salt: salt[:16], Leaves: leaves,
			Controllers: pubs, Quorum: 2, Members: members,
			MinTTLSeconds: 10, MaxTTLSeconds: 3600,
			Now: clk.now, OnAlarm: alarms.fire,
		})
	}
	trA, err := newTracker("cell-a", logA, alarmsA)
	if err != nil {
		s.fail(phaseFencing, "tracker cell-a (fail-closed à la config)", err)
		return
	}
	trB, err := newTracker("cell-b", logB, alarmsB)
	if err != nil {
		s.fail(phaseFencing, "tracker cell-b (fail-closed à la config)", err)
		return
	}
	s.add(phaseFencing, "trackers 2-of-3 assemblés (membres cell-a, cell-b)", true, "")

	// --- Étape : epoch 0, autorité cell-a -----------------------------------
	epoch0, err := mintEpoch(privs, cluster.EpochPayload{
		N: 0, Authority: "cell-a",
		IssuedAt: t0.UTC().Format(time.RFC3339), TTLSeconds: 300,
	}, 1, 2)
	if err != nil {
		s.fail(phaseFencing, "menthe epoch 0", err)
		return
	}
	if err := trA.Accept(ctx, epoch0); err != nil {
		s.fail(phaseFencing, "epoch 0 accepté par cell-a", err)
		return
	}
	if err := trB.Accept(ctx, epoch0); err != nil {
		s.fail(phaseFencing, "epoch 0 accepté par cell-b", err)
		return
	}
	s.add(phaseFencing, "epoch 0 (autorité cell-a) accepté par les deux cellules", true, "")

	nA, err := trA.CurrentEpoch()
	s.add(phaseFencing, "seul le détenteur sert : cell-a sert l'époque 0", err == nil && nA == 0,
		fmt.Sprintf("n=%d err=%v", nA, err))
	_, errB := trB.CurrentEpoch()
	s.add(phaseFencing, "seul le détenteur sert : cell-b refuse de servir (fail-closed)", errB != nil,
		fmt.Sprintf("err=%v", errB))
	obsA, okA := trA.ObservedEpoch()
	obsB, okB := trB.ObservedEpoch()
	s.add(phaseFencing, "époque observée = 0 sur les deux cellules",
		okA && okB && obsA == 0 && obsB == 0, fmt.Sprintf("a=(%d,%v) b=(%d,%v)", obsA, okA, obsB, okB))

	// --- Témoin : équivoque — même N, autre autorité (faute byzantine) ------
	epoch0Rogue, _ := mintEpoch(privs, cluster.EpochPayload{
		N: 0, Authority: "cell-b", // MÊME N, autorité différente = équivoque
		IssuedAt: t0.UTC().Format(time.RFC3339), TTLSeconds: 300,
	}, 1, 2)
	err = trA.Accept(ctx, epoch0Rogue)
	s.add(phaseFencing, "témoin: équivoque (N=0, autorité cell-b) refusée par cell-a", err != nil,
		fmt.Sprintf("err=%v", err))
	s.add(phaseFencing, "témoin: équivoque alarmée (couture T14)", alarmsA.len() >= 1,
		fmt.Sprintf("alarmes=%d", alarmsA.len()))
	n, err := waitKind(ctx, "cell-a", regDirA, registry.KindEpoch, 2)
	s.add(phaseFencing, "témoin: refus d'équivoque TRACÉ (KindEpoch +1)", err == nil && n >= 2,
		fmt.Sprintf("KindEpoch=%d", n))

	// --- Étape : rotation émise AVANT expiration (pas de dual-authority) ----
	clk.set(t0.Add(150 * time.Second))
	epoch1, _ := mintEpoch(privs, cluster.EpochPayload{
		N: 1, Authority: "cell-b",
		IssuedAt: clk.now().UTC().Format(time.RFC3339), TTLSeconds: 600,
	}, 1, 2)
	if err := trA.Accept(ctx, epoch1); err != nil {
		s.fail(phaseFencing, "epoch 1 accepté par cell-a", err)
		return
	}
	if err := trB.Accept(ctx, epoch1); err != nil {
		s.fail(phaseFencing, "epoch 1 accepté par cell-b", err)
		return
	}
	// Sémantique RÉELLE du tracker (src/cluster/epoch.go CurrentEpoch) :
	// dès qu'un jeton plus récent est accepté, t.current bascule — l'ancienne
	// autorité est SUPPLANTÉE (ErrNotAuthority) et la nouvelle attend
	// l'expiration de l'ancienne (ErrEpochNotYetEffective). La garantie
	// notBefore produit donc un TROU DE SERVICE fail-closed, jamais une
	// fenêtre à deux autorités. À t0+299 : personne ne sert.
	clk.set(t0.Add(299 * time.Second))
	_, errA := trA.CurrentEpoch()
	_, errB = trB.CurrentEpoch()
	s.add(phaseFencing, "rotation: à t0+299 cell-a est supplantée (ErrNotAuthority, fail-closed)",
		errors.Is(errA, cluster.ErrNotAuthority), fmt.Sprintf("err=%v", errA))
	s.add(phaseFencing, "rotation: à t0+299 cell-b ne sert PAS encore (ErrEpochNotYetEffective)",
		errors.Is(errB, cluster.ErrEpochNotYetEffective), fmt.Sprintf("err=%v", errB))
	// À t0+301 : bascule effective — cell-b sert l'époque 1. Jamais deux
	// autorités simultanées : à AUCUN instant du scénario les deux ne
	// servent (prouvé ci-dessus et ci-dessous).
	clk.set(t0.Add(301 * time.Second))
	_, errA = trA.CurrentEpoch()
	nB, errB := trB.CurrentEpoch()
	s.add(phaseFencing, "rotation: à t0+301 cell-a ne sert plus (epoch 0 expirée)", errA != nil,
		fmt.Sprintf("err=%v", errA))
	s.add(phaseFencing, "rotation: à t0+301 cell-b sert l'époque 1", errB == nil && nB == 1,
		fmt.Sprintf("n=%d err=%v", nB, errB))

	// Balayage fin (pas de 15 s) de toute la fenêtre de rotation : à AUCUN
	// instant les deux cellules ne servent simultanément — invariant
	// notBefore §7.2. (Le trou de service autour de t0+300 est la contrepartie
	// fail-closed documentée, pas une faute.)
	dualAt := []string{}
	for ts := t0; !ts.After(t0.Add(750*time.Second)); ts = ts.Add(15 * time.Second) {
		clk.set(ts)
		_, eA := trA.CurrentEpoch()
		_, eB := trB.CurrentEpoch()
		serving := 0
		if eA == nil {
			serving++
		}
		if eB == nil {
			serving++
		}
		if serving > 1 {
			dualAt = append(dualAt, ts.Format(time.RFC3339))
		}
	}
	clk.set(t0.Add(301 * time.Second)) // retour à l'instant du scénario
	s.add(phaseFencing, "invariant notBefore §7.2: jamais deux autorités simultanées (balayage 15 s)",
		len(dualAt) == 0, fmt.Sprintf("instants à deux autorités=%v", dualAt))

	// --- Étape : révocation roster (§7.3) — cell-a expulsée ------------------
	epoch2, _ := mintEpoch(privs, cluster.EpochPayload{
		N: 2, Authority: "cell-b",
		IssuedAt: clk.now().UTC().Format(time.RFC3339), TTLSeconds: 600,
		Roster: []string{"cell-b"}, // présent ⇒ révocation : cell-a sortie
	}, 1, 2)
	if err := trB.Accept(ctx, epoch2); err != nil {
		s.fail(phaseFencing, "epoch 2 (roster) accepté par cell-b", err)
		return
	}
	s.add(phaseFencing, "révocation §7.3: cell-b voit cell-a en quarantaine",
		containsStr(trB.Quarantined(), "cell-a"),
		fmt.Sprintf("quarantaine=%v", trB.Quarantined()))
	if err := trA.Accept(ctx, epoch2); err != nil {
		s.fail(phaseFencing, "epoch 2 (roster) accepté par cell-a", err)
		return
	}
	s.add(phaseFencing, "révocation §7.3: cell-a se voit elle-même expulsée",
		containsStr(trA.Quarantined(), "cell-a"),
		fmt.Sprintf("quarantaine=%v", trA.Quarantined()))

	// --- Étape : QuorumGate classe W (§7.5) sur le registre de cell-a -------
	var policyZero [32]byte
	gate, err := cluster.NewQuorumGate(cluster.QuorumGateConfig{
		CellID: "cell-a", Salt: salt[:16], Leaves: logA,
		Controllers: pubs, K: 2, PolicyID: policyZero,
		MaxProofTTLSeconds: 3600, Now: clk.now,
	})
	if err != nil {
		s.fail(phaseFencing, "quorum gate (fail-closed à la config)", err)
		return
	}
	expiry := clk.now().Add(60 * time.Second)
	proof1, _ := mintProof(privs, "seal", "vault-1", policyZero, 2, expiry, 1)
	err = gate.VerifyClassW(ctx, proof1, "seal", "vault-1", 2)
	s.add(phaseFencing, "quorum §7.5: preuve 1-of-3 refusée (k=2)", err != nil,
		fmt.Sprintf("err=%v", err))
	n, err = waitKind(ctx, "cell-a", regDirA, registry.KindQuorum, 1)
	s.add(phaseFencing, "quorum §7.5: refus 1-of-3 tracé (KindQuorum)", err == nil && n >= 1,
		fmt.Sprintf("KindQuorum=%d", n))
	proof2, _ := mintProof(privs, "seal", "vault-1", policyZero, 2, expiry, 1, 2)
	err = gate.VerifyClassW(ctx, proof2, "seal", "vault-1", 2)
	s.add(phaseFencing, "quorum §7.5: preuve 2-of-3 admise", err == nil, fmt.Sprintf("err=%v", err))
	n, err = waitKind(ctx, "cell-a", regDirA, registry.KindQuorum, 2)
	s.add(phaseFencing, "quorum §7.5: admission 2-of-3 tracée (KindQuorum)", err == nil && n >= 2,
		fmt.Sprintf("KindQuorum=%d", n))

	// --- Étape : promotion miroir→canari (§7.4) — saine puis partition ------
	cellBPriv := devKey("cell-b")
	cellBPub := cellBPriv.Public().(ed25519.PublicKey)
	bundle := sha256.Sum256([]byte("tbp-t35-bundle-epoch2"))
	master := &masterStub{
		bundles: map[uint64][32]byte{2: bundle},
		windows: map[uint64][2]time.Time{2: {t0.Add(301 * time.Second), t0.Add(900 * time.Second)}},
	}
	promo, err := cluster.NewPromotionController(cluster.PromotionConfig{
		CellID: "cell-a", Salt: salt[:16], Leaves: logA,
		Source: master, CellKeys: map[string]ed25519.PublicKey{"cell-b": cellBPub},
		Now: clk.now,
	})
	if err != nil {
		s.fail(phaseFencing, "promotion controller (fail-closed à la config)", err)
		return
	}
	receipt, _ := mintReceipt(cellBPriv, "cell-b", 2, bundle, clk.now())
	err = promo.Promote(ctx, receipt)
	s.add(phaseFencing, "promotion §7.4: fenêtre saine + ancre conforme → admise", err == nil,
		fmt.Sprintf("err=%v", err))
	master.down = true // PARTITION : le master est injoignable
	receipt3, _ := mintReceipt(cellBPriv, "cell-b", 3, sha256.Sum256([]byte("tbp-t35-bundle-epoch3")), clk.now())
	err = promo.Promote(ctx, receipt3)
	s.add(phaseFencing, "promotion §7.4: partition master → refus fail-closed",
		err != nil && errors.Is(err, cluster.ErrPromotionAnchorUnavailable),
		fmt.Sprintf("err=%v", err))
	n, err = waitKind(ctx, "cell-a", regDirA, registry.KindPromotion, 2)
	s.add(phaseFencing, "promotion §7.4: admission ET refus tracés (KindPromotion=2)",
		err == nil && n >= 2, fmt.Sprintf("KindPromotion=%d", n))

	// --- Bilan registres : volumes par kind sur les DEUX cellules -----------
	n, _ = waitKind(ctx, "cell-a", regDirA, registry.KindEpoch, 4)
	s.add(phaseFencing, "bilan cell-a: 4 événements d'époque tracés (2 accept + équivoque + 1 accept…)",
		n >= 4, fmt.Sprintf("KindEpoch=%d", n))
	n, _ = waitKind(ctx, "cell-b", regDirB, registry.KindEpoch, 3)
	s.add(phaseFencing, "bilan cell-b: 3 événements d'époque tracés (epochs 0, 1, 2)",
		n >= 3, fmt.Sprintf("KindEpoch=%d", n))
	s.add(phaseFencing, "bilan: aucune alarme parasite sur cell-b", alarmsB.len() == 0,
		fmt.Sprintf("alarmes=%d", alarmsB.len()))
}
