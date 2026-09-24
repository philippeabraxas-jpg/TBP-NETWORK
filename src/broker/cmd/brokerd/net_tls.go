package main

// net_tls.go — transport réseau mTLS du plan de données (revue de
// sécurité #124). brokerd émet des jetons de gouvernance : l'exposer sur
// le réseau sans authentification mutuelle serait la même faute que
// #92.A3 (OPA en TCP non authentifié, indétectable d'un imposteur), côté
// émission cette fois — un imposteur qui occupe TBP_BROKER_LISTEN_ADDR
// deviendrait indétectable d'un vrai broker. mTLS est donc la SEULE forme
// d'exposition réseau offerte, jamais un TCP en clair : TLS 1.3 minimum,
// certificat client vérifié contre TBP_BROKER_TLS_CLIENT_CA_FILE — un
// pair qui ne présente aucun certificat, ou un certificat signé par une
// autre autorité, est rejeté à la poignée de main, jamais atteint par le
// mux applicatif (isolé ici, testable sans toucher au réseau réel — même
// patron que opa_setup.go/measured_boot.go).

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// buildBrokerTLSConfig charge le certificat serveur et l'autorité cliente
// depuis le disque et rend une configuration mTLS prête à servir.
// Fail-closed : tout fichier illisible ou mal formé est une erreur de
// démarrage, jamais un TLS dégradé (pas de repli sur un ClientAuth plus
// faible, pas de version TLS antérieure).
func buildBrokerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("certificat serveur (%s / %s): %w", certFile, keyFile, err)
	}
	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("autorité cliente (%s): %w", clientCAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("autorité cliente (%s): aucun certificat PEM valide", clientCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
