// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	rdm "math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/open-ness/common/log"
	"github.com/open-ness/common/proxy/progutil"
	nodegmock "github.com/open-ness/edgecontroller/mock/node/grpc"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
	"github.com/open-ness/edgecontroller/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const name = "test-node"

func main() {
	log.Info(name, ": starting")

	// CLI flags
	var (
		controllerPort uint
	)
	flag.UintVar(&controllerPort, "controller-port", 8081, "Port for EVA service to listen on")
	flag.Parse()

	// Set up channels to capture SIGINT and SIGTERM
	sigChan := make(chan os.Signal, 2)
	defer close(sigChan)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	abrtChan := make(chan os.Signal, 1)
	signal.Notify(abrtChan, syscall.SIGABRT)

	// Create the mock node
	mockNode := nodegmock.NewMockNode()

	tlsConf := credentials.NewTLS(newTLSConf(loadCA(), loadCAKey(), "*."))

	// Register the services with the grpc servers
	elaServer := grpc.NewServer(grpc.Creds(tlsConf))
	elapb.RegisterApplicationPolicyServiceServer(elaServer, mockNode.AppPolicySvc)
	elapb.RegisterInterfaceServiceServer(elaServer, mockNode.InterfaceSvc)
	elapb.RegisterInterfacePolicyServiceServer(elaServer, mockNode.IfPolicySvc)
	elapb.RegisterZoneServiceServer(elaServer, mockNode.ZoneSvc)
	elapb.RegisterDNSServiceServer(elaServer, mockNode.DNSSvc)
	evaServer := grpc.NewServer(grpc.Creds(tlsConf))
	evapb.RegisterApplicationDeploymentServiceServer(evaServer, mockNode.AppDeploySvc)
	evapb.RegisterApplicationLifecycleServiceServer(evaServer, mockNode.AppLifeSvc)

	// Shut down the servers gracefully
	go func() {
		defer close(abrtChan)

		<-sigChan
		log.Info(name, ": shutting down")

		elaServer.GracefulStop()
		evaServer.GracefulStop()
	}()

	// Reset and start on each SIGABRT
	var prevELALis, prevEVALis net.Listener
	for range abrtChan {
		var id string
		_, err := fmt.Scanln(&id)
		if err != nil {
			log.Errf("%s: error scanning id: %s", name, err)
		}
		log.Infof("%s: resetting with id %s", name, id)

		if prevELALis != nil {
			prevELALis.Close()
		}
		if prevEVALis != nil {
			prevEVALis.Close()
		}
		mockNode.Reset()

		// Start the listeners
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", controllerPort))
		if err != nil {
			log.Alert("Failed to resolve controller address:", err)
			os.Exit(1)
		}

		elaLis := &progutil.DialListener{RemoteAddr: addr, Name: "ELA"}
		prevELALis = elaLis

		evaLis := &progutil.DialListener{RemoteAddr: addr, Name: "EVA"}
		prevEVALis = evaLis

		// Start the servers
		go func() {
			log.Info("elaServer connecting to port ", controllerPort)
			log.Alert("ELA GRPC server exited:", elaServer.Serve(elaLis))
		}()
		go func() {
			log.Info("evaServer connecting to port ", controllerPort)
			log.Alert("EVA GRPC server exited:", evaServer.Serve(evaLis))
		}()
	}
}

func loadCA() []*x509.Certificate {
	path := filepath.Join(".", "certificates", "ca", "cert.pem")
	ca, err := pki.LoadCertificate(path)
	if err != nil {
		log.Alert("Error loading CA cert:", err)
		os.Exit(1)
	}
	return []*x509.Certificate{ca}
}

func loadCAKey() *ecdsa.PrivateKey {
	path := filepath.Join(".", "certificates", "ca", "key.pem")
	key, err := pki.LoadKey(path)
	if err != nil {
		log.Alert("Error loading CA key:", err)
		os.Exit(1)
	}
	return key.(*ecdsa.PrivateKey)
}

func newTLSConf(ca []*x509.Certificate, caKey crypto.Signer, sni string) *tls.Config {
	tlsKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Alertf("error generating TLS key for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsCert := newTLSServerCert(ca, caKey, tlsKey, sni)
	tlsChain := [][]byte{tlsCert.Raw}
	for _, caCert := range ca {
		tlsChain = append(tlsChain, caCert.Raw)
	}
	tlsRoots := x509.NewCertPool()
	tlsRoots.AddCert(ca[len(ca)-1])
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: tlsChain,
			PrivateKey:  tlsKey,
			Leaf:        tlsCert,
		}},
		ClientCAs:    tlsRoots,
		RootCAs:      tlsRoots,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

func newTLSServerCert(ca []*x509.Certificate, caKey, key crypto.Signer, sni string) *x509.Certificate {
	// Pick random serial number
	source := rdm.NewSource(time.Now().UnixNano())
	serial := big.NewInt(int64(rdm.New(source).Uint64()))

	// Generate certificate
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: sni},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:    time.Now(),
		NotAfter:     ca[0].NotAfter, // Valid until CA expires
	}
	certDER, err := x509.CreateCertificate(
		rand.Reader, template, ca[0], key.Public(), caKey)
	if err != nil {
		log.Alertf("error generating TLS cert for server %q: %v", sni, err)
		os.Exit(1)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Alertf("error parsing TLS cert for server %q: %v", sni, err)
		os.Exit(1)
	}
	return cert
}
