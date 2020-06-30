// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package main

import (
	"context"
	"flag"
	logger "github.com/open-ness/common/log"
	"github.com/open-ness/edgecontroller/nfd-master"
	"os"
	"os/signal"
	"syscall"
)

var log = logger.DefaultLogger.WithField("nfd-master", nil)

var (
	dsn        string
	grpcPort   int
	caCertPath string
	caKeyPath  string
	sni        string
)

func init() {
	flag.StringVar(&dsn, "dsn", "", "Data source name")
	flag.IntVar(&grpcPort, "grpcPort", 8082, "NFD Server gRPC port")
	flag.StringVar(&caCertPath, "caCertPath", "/ca/cert.pem", "Root CA certificate file path")
	flag.StringVar(&caKeyPath, "caKeyPath", "/ca/key.pem", "Root CA private key file path")
	flag.StringVar(&sni, "sni", "nfd-master.openness", "Server name for NFD-master certificate certificate")
}

func main() {
	flag.Parse()

	log.Info("Openness NFD Master starting")

	// Handle SIGINT and SIGTERM by calling cancel()
	// which is propagated to services
	ctx, cancel := context.WithCancel(context.Background())
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-osSignals
		log.Infof("Received signal: %#v", sig)
		cancel()
	}()

	nfdSrv := &nfd.ServerNFD{
		Endpoint:   grpcPort,
		CaCertPath: caCertPath,
		CaKeyPath:  caKeyPath,
		Sni:        sni,
		Dsn:        dsn,
	}

	err := nfdSrv.ServeGRPC(ctx)
	if err != nil {
		log.Err("Failed to start NFD master server")
		os.Exit(1)
	}
}
