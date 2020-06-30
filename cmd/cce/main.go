// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/gorilla/handlers"
	"golang.org/x/sync/errgroup"

	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	logger "github.com/open-ness/common/log"
	"github.com/open-ness/common/proxy/progutil"
	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/gorilla"
	"github.com/open-ness/edgecontroller/grpc"
	"github.com/open-ness/edgecontroller/http"
	"github.com/open-ness/edgecontroller/jose"
	"github.com/open-ness/edgecontroller/k8s"
	"github.com/open-ness/edgecontroller/mysql"
	"github.com/open-ness/edgecontroller/pki"
	"github.com/open-ness/edgecontroller/telemetry"
)

const certsDir = "./certificates"

var log = logger.DefaultLogger.WithField("pkg", "main")

// CLI flags
var (
	dsn        string
	adminPass  string
	logLevel   string
	httpPort   int
	grpcPort   int
	elaPort    int
	evaPort    int
	syslogPort int
	statsdPort int
	syslogOut  string
	statsdOut  string
	orchMode   string
	k8sClient  k8s.Client
)

func init() {
	flag.StringVar(&dsn, "dsn", "", "Data source name")
	flag.StringVar(&adminPass, "adminPass", "", "Admin user password")
	flag.StringVar(&logLevel, "log-level", "info", "Syslog level")
	flag.IntVar(&httpPort, "httpPort", 8080, "Controller HTTP port")
	flag.IntVar(&grpcPort, "grpcPort", 8081, "Controller gRPC port")
	flag.IntVar(&elaPort, "elaPort", 42101, "Port to dial ELA on edge node")
	flag.IntVar(&evaPort, "evaPort", 42102, "Port to dial EVA on edge node")
	flag.IntVar(&syslogPort, "syslogPort", 6514, "Telemetry ingress port for syslog")
	flag.IntVar(&statsdPort, "statsdPort", 8125, "Telemetry ingress port for statsd")
	flag.StringVar(&syslogOut, "syslog-path", "./syslog.log", "Syslog output file path")
	flag.StringVar(&statsdOut, "statsd-path", "./statsd.log", "StatsD output file path")

	// application orchestration mode
	flag.StringVar(&orchMode, "orchestration-mode", "native", "Orchestration mode."+
		"options [native, kubernetes, kubernetes-ovn] ")

	// k8s
	flag.StringVar(&k8sClient.CAFile, "k8s-client-ca-path", "", "Kubernetes root certificate path")
	flag.StringVar(&k8sClient.CertFile, "k8s-client-cert-path", "", "Kubernetes client certificate path")
	flag.StringVar(&k8sClient.KeyFile, "k8s-client-key-path", "", "Kubernetes client private key path")
	flag.StringVar(&k8sClient.Host, "k8s-master-host", "", "Kubernetes master host")
	flag.StringVar(&k8sClient.APIPath, "k8s-api-path", "", "Kubernetes api path")
	flag.StringVar(&k8sClient.Username, "k8s-master-user", "", "Kubernetes default user")
}

func setupOrchestrator() (cce.OrchestrationMode, error) {
	var orchestrationMode cce.OrchestrationMode
	var err error

	switch orchMode {
	case "native":
		orchestrationMode = cce.OrchestrationModeNative
	case "kubernetes":
		orchestrationMode = cce.OrchestrationModeKubernetes
		err = k8sClient.Ping()
	case "kubernetes-ovn":
		orchestrationMode = cce.OrchestrationModeKubernetesOVN
		err = k8sClient.Ping()
	default:
		err = errors.New("Invalid orchestration mode " + orchMode)
	}

	return orchestrationMode, err
}

func main() {
	flag.Parse()

	// Validate flags
	if adminPass == "" {
		log.Alert("User admin password cannot be empty")
		os.Exit(1)
	}

	// Set log level
	lvl, err := logger.ParseLevel(logLevel)
	if err != nil {
		log.Alert("Bad log level %q: %v", logLevel, err)
		os.Exit(1)
	}
	log.Infof("Setting log level to: %s", logLevel)
	logger.SetLevel(lvl)

	log.Info("Controller CE starting")

	// Setup orchestrator
	var orchestrationMode cce.OrchestrationMode
	if orchestrationMode, err = setupOrchestrator(); err != nil {
		log.Alertf("Error getting orchestration mode: %v", err)
		os.Exit(1)
	}

	// Connect to the db and verify
	db := connectDB(dsn)

	// Initialize self-signed root CA
	rootCA, err := pki.InitRootCA(filepath.Join(certsDir, "ca"))
	if err != nil {
		log.Alertf("Error initializing Controller CA: %v", err)
		os.Exit(1)
	}
	log.Info("Initialized Controller CA")

	// TODO: Replace printing to STDERR with writing to a file or making the
	// certificate available via an HTTP endpoint.
	log.Infof("Root CA:\n%s", encodeCA(rootCA))

	// Define controller service
	controller := &cce.Controller{
		PersistenceService: &mysql.PersistenceService{DB: db},
		AuthorityService:   rootCA,
		TokenService:       getTokenSigner(),
		AdminCreds: &cce.AuthCreds{
			Username: "admin",
			Password: adminPass,
		},
		OrchestrationMode: orchestrationMode,
		KubernetesClient:  &k8sClient,
		ELAPort:           strconv.Itoa(elaPort),
		EVAPort:           strconv.Itoa(evaPort),
		EdgeNodeCreds:     newClientTLSConf(rootCA, "controller.openness"),
	}

	// Create an error group to manage server goroutines
	eg, ctx := errgroup.WithContext(context.Background())

	// Catch SIGINT/SIGTERM and initiate shutdown
	var errSignalShutdown = errors.New("received INT/TERM signal, shutting down")
	eg.Go(func() error {
		ch := make(chan os.Signal, 2)

		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			return errSignalShutdown
		}
	})

	// Serve handlers
	httpAddr := fmt.Sprintf(":%d", httpPort)
	grpcAddr := fmt.Sprintf(":%d", grpcPort)
	syslogAddr := fmt.Sprintf(":%d", syslogPort)
	statsdAddr := fmt.Sprintf(":%d", statsdPort)
	eg.Go(serveHTTP(ctx, controller, httpAddr))
	eg.Go(serveGRPC(ctx, controller, grpcAddr, getGRPCTLS(rootCA)))
	eg.Go(serveTelemetry(ctx, syslogOut, syslogAddr, newTLSConf(rootCA, telemetry.SyslogSNI)))
	eg.Go(serveTelemetry(ctx, statsdOut, statsdAddr, newTLSConf(rootCA, telemetry.StatsdSNI)))

	log.Info("Controller CE ready")

	// Wait until all servers exit. The context is canceled upon any server
	// shutting down unexpectedly or a SIGINT/SIGTERM being received, causing
	// all running servers to start shutting down, but Wait does not return
	// until all shutdowns have completed.
	if err := eg.Wait(); err != nil && err != errSignalShutdown {
		log.Alert(err)
		os.Exit(1)
	}
}

func registerAllNodes(ctx context.Context, ps cce.PersistenceService) {
	persisted, err := ps.ReadAll(ctx, &cce.Node{})
	if err == nil {
		for _, n := range persisted {
			node := n.(*cce.Node)
			id := node.ID
			cce.RegisterToProxy(ctx, ps, id)
		}
	}
}

// Connect to a mysql DB and ping it for readiness.
func connectDB(dsn string) *sql.DB {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Alertf("Error opening db: %v", err)
		os.Exit(1)
	}
	// TODO: retry ping with backoff rather than exiting because DB may still
	// be initializing
	if err = db.Ping(); err != nil {
		log.Alertf("DB ping failed: %v", err)
		os.Exit(1)
	}
	log.Info("DB connection established")
	return db
}

// Encode self-signed Controller CA. This is used to manually configure the
// Appliance by adding the Controller to its trust anchor pool for TLS
// connections.
func encodeCA(rootCA *pki.RootCA) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: rootCA.Cert.Raw,
		},
	))
}

// Generate a key for signing authentication tokens. The key is only stored
// in memory and will be re-generated upon Controller restart.
//
// TODO: Persist the key to avoid having API/UI users have to login and get a
// new token every time the Controller is restarted.
func getTokenSigner() *jose.JWSTokenIssuer {
	joseKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Alertf("error generating token signing key: %v", err)
		os.Exit(1)
	}
	return &jose.JWSTokenIssuer{
		Key:          joseKey,
		KeyAlgorithm: "ES384",
	}
}

func serveHTTP(ctx context.Context, controller *cce.Controller, addr string) func() error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Alertf("Could not listen on %q: %v", addr, err)
		os.Exit(1)
	}

	// Define Cross-Origin Resource Sharing (CORS) policy to allow the UI to be
	// served from a separate host. This policy restricts received API requests
	// based on the request origin, headers, and method type. The CORS policy
	// handler must be applied at the top-level router.
	cors := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedHeaders([]string{"Authorization", "Content-Type", "ContentType"}),
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "PATCH", "DELETE"}),
	)

	// Configure http server
	koko := gorilla.NewGorilla(controller)

	httpServer := http.NewServer(cors(koko))

	// Shutdown http server on exit signal
	go func() {
		<-ctx.Done()

		ctxShutdown, cancel := context.WithTimeout(context.TODO(), time.Minute)
		defer cancel()

		if err := httpServer.Shutdown(ctxShutdown); err != nil {
			log.Info("HTTP graceful shutdown exceeded timeout, using force")
			if err := httpServer.Close(); err != nil {
				log.Errf("error closing HTTP server: %v", err)
			}
		}
	}()

	// Start the http server
	log.Infof("HTTP server serving on %q", addr)
	return func() error {
		defer lis.Close()
		return httpServer.Serve(lis)
	}
}

func serveGRPC(ctx context.Context, controller *cce.Controller, addr string, conf *tls.Config) func() error {

	lis, err := net.Listen("tcp", addr)
	cce.PrefaceLis = progutil.NewPrefaceListener(lis)

	if err != nil {
		log.Alertf("Could not listen on %q: %v", addr, err)
		os.Exit(1)
	}

	// Configure grpc server
	grpcServer := grpc.NewServer(controller, conf)

	// Shutdown grpc server on exit signal
	go func() {
		<-ctx.Done()

		// Try to gracefully shutdown
		stopped := make(chan struct{})
		go func() {
			grpcServer.GracefulStop()
			close(stopped)
		}()

		select {
		case <-time.After(time.Minute):
			log.Info("gRPC server shutdown exceeded timeout, using force")
			grpcServer.Stop()
		case <-stopped:
			return
		}
	}()

	registerAllNodes(context.TODO(), controller.PersistenceService)

	// Start the grpc server
	log.Infof("gRPC server serving on %q", addr)
	return func() error {
		defer cce.PrefaceLis.Close()
		return grpcServer.Serve(cce.PrefaceLis)
	}
}

func serveTelemetry(ctx context.Context, outfile, addr string, conf *tls.Config) func() error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Alertf("Could not listen on %q: %v", addr, err)
		os.Exit(1)
	}

	// Upgrade to TLS
	conf.ClientAuth = tls.RequireAndVerifyClientCert
	lis = tls.NewListener(lis, conf)

	// Shutdown syslog server on exit signal
	go func() {
		defer lis.Close()
		<-ctx.Done()
	}()

	// Start the syslog server
	if err = os.MkdirAll(filepath.Dir(outfile), 0750); err != nil {
		log.Alertf("Error creating directory for telemetry file %q: %v", outfile, err)
		os.Exit(1)
	}
	f, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Alertf("Error opening telemetry file %q: %v", outfile, err)
		os.Exit(1)
	}
	log.Infof("Telemetry server serving on %q, writing to %q", addr, outfile)
	return func() error {
		defer f.Close()

		// TODO: Buffer writes for performance. This currently causes telemetry
		// integration tests to fail, because writes won't occur until shutdown
		// of the Controller is initiated and the buffered writer is flushed.
		//
		//     w := bufio.NewWriter(f)
		//     defer w.Flush()
		w := io.Writer(f)

		return telemetry.WriteToByLine(w, 0, telemetry.AcceptTCP(lis))
	}
}

// Generate a TLS config that handles two server names:
//
//     controller.openness: requires and verifies peer cert
//     enroll.controller.openness: no peer cert required
//
// In the gRPC server the servername will be considered for the particular RPCs
// authorized to the client.
func getGRPCTLS(rootCA *pki.RootCA) *tls.Config {
	// Generate server TLS config for post-enrollment
	serverConf := newTLSConf(rootCA, grpc.SNI)
	serverConf.NextProtos = []string{"h2"}
	serverConf.ClientAuth = tls.RequireAndVerifyClientCert

	// Generate server TLS config for enrollment
	enrollmentConf := newTLSConf(rootCA, grpc.EnrollmentSNI)
	enrollmentConf.NextProtos = []string{"h2"}
	enrollmentConf.ClientAuth = tls.NoClientCert

	// Dynamically fetch TLS config by server name
	return &tls.Config{
		GetConfigForClient: func(
			hello *tls.ClientHelloInfo,
		) (*tls.Config, error) {
			switch hello.ServerName {
			case grpc.SNI:
				return serverConf, nil
			case grpc.EnrollmentSNI:
				return enrollmentConf, nil
			default:
				return nil, fmt.Errorf("unexpected server name: %s", hello.ServerName)
			}
		},
	}
}

// Generate a new TLS key/cert pair from a root CA for use in a TLS server with
// some server name.
func newTLSConf(rootCA *pki.RootCA, sni string) *tls.Config {
	tlsKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Alertf("error generating TLS key for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsCert, err := rootCA.NewTLSServerCert(tlsKey, sni)
	if err != nil {
		log.Alertf("error generating TLS cert for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsCAChain, err := rootCA.CAChain()
	if err != nil {
		log.Alertf("error getting TLS CA chain for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsChain := [][]byte{tlsCert.Raw}
	for _, caCert := range tlsCAChain {
		tlsChain = append(tlsChain, caCert.Raw)
	}
	tlsRoots := x509.NewCertPool()
	tlsRoots.AddCert(tlsCAChain[len(tlsCAChain)-1])
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: tlsChain,
			PrivateKey:  tlsKey,
			Leaf:        tlsCert,
		}},
		ClientCAs:    tlsRoots,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}

// Generate a new TLS key/cert pair from a root CA for use in a TLS server with
// some server name.
func newClientTLSConf(rootCA *pki.RootCA, sni string) *tls.Config {
	tlsKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Alertf("error generating TLS key for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsCert, err := rootCA.NewTLSClientCert(tlsKey, sni)
	if err != nil {
		log.Alertf("error generating TLS cert for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsCAChain, err := rootCA.CAChain()
	if err != nil {
		log.Alertf("error getting TLS CA chain for server %q: %v", sni, err)
		os.Exit(1)
	}
	tlsChain := [][]byte{tlsCert.Raw}
	for _, caCert := range tlsCAChain {
		tlsChain = append(tlsChain, caCert.Raw)
	}
	tlsRoots := x509.NewCertPool()
	tlsRoots.AddCert(tlsCAChain[len(tlsCAChain)-1])
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: tlsChain,
			PrivateKey:  tlsKey,
			Leaf:        tlsCert,
		}},
		RootCAs:      tlsRoots,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}
