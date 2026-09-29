package main

// proxy_ano.go — branchement d'ano sur le proxy bloquant (#178).
//
// TBP_PROXY_ANO_SOCKET déclare que le backend du proxy est une destination
// HORS cellule : tout ce qui sort est alors anonymisé par ano (processus
// séparé, socket Unix) et tout ce qui revient est reconstitué. Absent ⇒
// comportement historique (destination dans la cellule : trafic transmis tel
// quel). Une « liste blanche » de destinations locales, sans anonymisation, est
// simplement un proxy configuré SANS ce socket.
//
//	TBP_PROXY_ANO_SOCKET      socket Unix d'anod
//	TBP_PROXY_ANO_TIMEOUT_MS  délai par appel à ano, 100–30000 (défaut 3000)
//
// Fail-closed : ano injoignable au démarrage ⇒ pepd refuse de démarrer (une
// faute de configuration ne doit pas se découvrir au premier trafic) ; en
// service, toute faute d'ano refuse la requête (voir pep/rewriter.go). Chaque
// masquage et chaque reconstitution laisse une feuille hash-only « TBAN1 » ;
// si la feuille ne peut pas être écrite, l'opération est refusée.

import (
	"context"
	"fmt"
	"strconv"
	"time"

	svc "github.com/philippeabraxas-jpg/TBP-NETWORK/src/ano/svc"
	pep "github.com/philippeabraxas-jpg/TBP-NETWORK/src/pep"
)

const defaultAnoTimeout = 3 * time.Second

// anoProbeWindow est la fenêtre de la sonde de démarrage (variable : les
// tests la raccourcissent).
var anoProbeWindow = 5 * time.Second

// applyAno configure opts.Rewriter / opts.OnRewrite si TBP_PROXY_ANO_SOCKET est
// déclaré. leaves reçoit les feuilles d'audit (cellID/salt : §6.2).
func applyAno(ctx context.Context, getenv func(string) string, opts *pep.ProxyOptions, leaves svc.LeafSink, cellID string, salt []byte) error {
	sock := getenv("TBP_PROXY_ANO_SOCKET")
	if sock == "" {
		if getenv("TBP_PROXY_ANO_TIMEOUT_MS") != "" {
			return fmt.Errorf("TBP_PROXY_ANO_TIMEOUT_MS sans TBP_PROXY_ANO_SOCKET — configuration incohérente")
		}
		return nil
	}
	timeout := defaultAnoTimeout
	if v := getenv("TBP_PROXY_ANO_TIMEOUT_MS"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil || ms < 100 || ms > 30000 {
			return fmt.Errorf("TBP_PROXY_ANO_TIMEOUT_MS: entier dans [100, 30000] requis, reçu %q", v)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}
	client := svc.NewUnixClient(sock, timeout)

	// sonde de démarrage : ano peut démarrer un peu après pepd — on laisse
	// une courte fenêtre, puis on refuse (fail-closed, §1)
	deadline := time.Now().Add(anoProbeWindow)
	var err error
	for {
		if err = client.Health(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("ano injoignable sur %s au démarrage (TBP_PROXY_ANO_SOCKET): %w", sock, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	opts.Rewriter = client
	opts.OnRewrite = func(ctx context.Context, ev pep.RewriteEvent) error {
		_, err := svc.AppendAuditLeaf(ctx, leaves, cellID, salt, ev, time.Now())
		return err
	}
	return nil
}
