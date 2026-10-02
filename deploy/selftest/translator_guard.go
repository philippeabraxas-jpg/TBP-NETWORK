// translator_guard.go — #275 (suite) : la dégradation contrôlée du traducteur (T25, §4.5) devant brokerd, vérifiée
// contre le vrai binaire. Un service de santé de test (loopback, piloté par le harnais) tient le rôle du service
// traducteur : brokerd le sonde (TBP_TRANSLATOR_GUARD=1), refuse tant qu'il est rouge, admet quand il est vert.
package main

import (
	"net"
	"net/http"
	"sync/atomic"
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
