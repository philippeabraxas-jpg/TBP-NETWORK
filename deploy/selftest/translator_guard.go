// translator_guard.go — #275 (suite) : la dégradation contrôlée du traducteur (T25, §4.5) devant brokerd, vérifiée
// contre le vrai binaire. Un service de santé de test (loopback, piloté par le harnais) tient le rôle du service
// traducteur : brokerd le sonde (TBP_TRANSLATOR_GUARD=1), refuse tant qu'il est rouge, admet quand il est vert.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	cluster "github.com/philippeabraxas-jpg/TBP-NETWORK/src/cluster"
)

// healthStub est le faux service de santé du traducteur.
type healthStub struct {
	URL     string
	healthy atomic.Bool
	srv     *http.Server
}

func startHealthStub() (*healthStub, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := &healthStub{URL: "http://" + ln.Addr().String() + "/health"}
	h.healthy.Store(true)
	h.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !h.healthy.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})}
	go func() { _ = h.srv.Serve(ln) }()
	return h, nil
}

func (h *healthStub) set(ok bool) { h.healthy.Store(ok) }
func (h *healthStub) stop()       { _ = h.srv.Close() }

// mirrorFixture : la cellule miroir (§7.4) de la phase daemons — clés de cellule et ancres signées 2-of-3 par les
// contrôleurs de la genèse, épingles que brokerd lit au démarrage.
type mirrorFixture struct {
	AnchorsFile, CellKeysFile string
	cellPriv                  ed25519.PrivateKey
	bundle                    [32]byte
}

func newMirrorFixture(dir string, bundle [32]byte, epoch uint64, privs map[int]ed25519.PrivateKey) (*mirrorFixture, error) {
	cellPriv := devKey("mirror-cell-b")
	keys, err := json.Marshal(map[string]string{"cell-b": hex.EncodeToString(cellPriv.Public().(ed25519.PublicKey))})
	if err != nil {
		return nil, err
	}
	f := &mirrorFixture{
		AnchorsFile: filepath.Join(dir, "mirror-anchors.json"), CellKeysFile: filepath.Join(dir, "mirror-cell-keys.json"),
		cellPriv: cellPriv, bundle: bundle,
	}
	now := time.Now()
	anchors, err := cluster.SignAnchors(cluster.AnchorPayload{Anchors: []cluster.AnchorEntry{{
		Epoch: epoch, BundleHash: hex.EncodeToString(bundle[:]),
		WindowStart: now.Add(-time.Hour).UTC().Format(time.RFC3339), WindowEnd: now.Add(6 * time.Hour).UTC().Format(time.RFC3339),
	}}}, map[int]ed25519.PrivateKey{1: privs[1], 2: privs[2]})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(f.CellKeysFile, keys, 0o600); err != nil {
		return nil, err
	}
	return f, os.WriteFile(f.AnchorsFile, anchors, 0o600)
}

// receipt signe la réception du bundle ancré de l'époque (par la cellule miroir).
func (f *mirrorFixture) receipt(epoch uint64) []byte {
	rc := cluster.Receipt{CellID: "cell-b", Epoch: epoch, BundleHash: hex.EncodeToString(f.bundle[:]), ReceivedAt: time.Now().UTC().Format(time.RFC3339)}
	canon, _ := json.Marshal(rc)
	b, _ := json.Marshal(cluster.SignedReceipt{Receipt: rc, Sig: hex.EncodeToString(ed25519.Sign(f.cellPriv, canon))})
	return b
}
