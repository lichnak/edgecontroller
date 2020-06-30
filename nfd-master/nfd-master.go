// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package nfd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	logger "github.com/open-ness/common/log"
	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/mysql"
	"github.com/open-ness/edgecontroller/pki"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"net"
	"path/filepath"
	pb "sigs.k8s.io/node-feature-discovery/pkg/labeler"
	"time"
)

var log = logger.DefaultLogger.WithField("nfd-master", nil)

// GetDB gets DB for passed data source name
var GetDB = func(dsn string) (mysql.CceDB, error) {
	return sql.Open("mysql", dsn)
}

var GetPersistenceService = func(db mysql.CceDB) cce.PersistenceService {
	return &mysql.PersistenceService{DB: db}
}

// ServerNFD describes NFD Master server object
type ServerNFD struct {
	Endpoint   int
	CaCertPath string
	CaKeyPath  string
	Sni        string
	Dsn        string
}

type labeler struct {
	persistenceService cce.PersistenceService
}

func (s ServerNFD) connectDB() (cce.PersistenceService, error) {
	db, err := GetDB(s.Dsn)
	if err != nil {
		log.Errf("Error opening db: %v", err)
		return nil, err
	}

	for {
		if err = db.Ping(); err != nil {
			log.Errf("DB ping failed: %v", err)
			time.Sleep(10 * time.Second)
		} else {
			log.Info("DB connection established")
			break
		}
	}

	return GetPersistenceService(db), nil
}

func (s ServerNFD) createCredentialsTLS() (credentials.TransportCredentials, error) {

	var caCert *x509.Certificate
	var caKey crypto.PrivateKey
	var err error

	caCert, err = pki.LoadCertificate(filepath.Clean(s.CaCertPath))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load CA certificate")
	}

	caKey, err = pki.LoadKey(filepath.Clean(s.CaKeyPath))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load CA key")
	}

	nfdKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate server key")
	}

	rootCA := pki.RootCA{
		Cert: caCert,
		Key:  caKey,
	}

	nfdCert, err := rootCA.NewTLSServerCert(nfdKey, s.Sni)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate server certificate")
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	return credentials.NewTLS(&tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{nfdCert.Raw},
			PrivateKey:  nfdKey,
		}},
		ClientCAs: certPool,
	}), nil
}

// ServeGRPC creates and starts NFD Master server
func (s ServerNFD) ServeGRPC(ctx context.Context) error {

	pers, err := s.connectDB()
	if err != nil {
		return err
	}

	creds, err := s.createCredentialsTLS()
	if err != nil {
		log.Errf("Failed to create TLS credentials: %v", err)
		return err
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Endpoint))
	if err != nil {
		log.Errf("net.Listen error: %+v", err)
		return err
	}

	grpcServer := grpc.NewServer(grpc.Creds(creds))
	labelerServer := labeler{persistenceService: pers}

	pb.RegisterLabelerServer(grpcServer, &labelerServer)

	go func() {
		<-ctx.Done()
		log.Info("Executing graceful stop")
		grpcServer.GracefulStop()
	}()

	err = grpcServer.Serve(lis)
	if err != nil {
		log.Errf("Failed grpcServe %v", err)
		return err
	}

	log.Info("NFD Master stopped serving")
	return nil
}

// getPeerName returns Subject.CommonName from peer TLS certificate
func getPeerName(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("Missing peer data in gRPC context")
	}

	authInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("gRPC peer missing TLS auth info")
	}

	chains := authInfo.State.VerifiedChains
	if len(chains) < 1 {
		return "", errors.New("gRPC peer was not authenticated with a client TLS certificate")
	}
	nodeID := chains[0][0].Subject.CommonName
	if nodeID == "" {
		return "", errors.New("gRPC peer connected with a client TLS cert with no Common Name")
	}

	return nodeID, nil
}

// SetLabels implements gRPC request handling
func (l labeler) SetLabels(c context.Context, r *pb.SetLabelsRequest) (*pb.SetLabelsReply, error) {
	log.Infof("REQUEST Node: %s NFD-version: %s Labels: %s", r.NodeName, r.NfdVersion, r.Labels)

	nodeID, err := getPeerName(c)
	if err != nil {
		log.Errf("Peer error %v", err)
		return &pb.SetLabelsReply{}, err
	}

	if nodeID != r.NodeName {
		err = errors.Errorf("Node name from request [%s] does not match TLS peer name [%s]", r.NodeName, nodeID)
		return &pb.SetLabelsReply{}, err
	}

	for lf, lv := range r.Labels {
		var f []cce.Persistable
		f, err = l.persistenceService.Filter(
			c,
			&NodeFeatureNFD{},
			[]cce.Filter{
				{
					Field: "node_id",
					Value: r.NodeName,
				},
				{
					Field: "nfd_id",
					Value: lf,
				},
			},
		)

		if err != nil {
			log.Errf("Error when filtering DB! %v", err)
			return &pb.SetLabelsReply{}, err
		}

		// persist NFD feature with value
		if len(f) == 0 {
			persisted := NodeFeatureNFD{
				ID:       uuid.NewV4().String(),
				NodeID:   r.NodeName,
				NfdID:    lf,
				NfdValue: lv,
			}

			log.Infof("Creating new entry: %s %s %s %s", persisted.ID, persisted.NodeID, persisted.NfdID,
				persisted.NfdValue)
			if err = l.persistenceService.Create(c, &persisted); err != nil {
				log.Errf("Error creating entity: %v", err)
			}
		} else {
			persisted := NodeFeatureNFD{
				ID:       f[0].GetID(),
				NodeID:   r.NodeName,
				NfdID:    lf,
				NfdValue: lv,
			}
			log.Infof("Updating existing entry: %s %s %s %s", persisted.ID, persisted.NodeID, persisted.NfdID,
				persisted.NfdValue)
			if err = l.persistenceService.BulkUpdate(c, []cce.Persistable{&persisted}); err != nil {
				log.Errf("Error updating entities: %v", err)
			}
		}
	}
	return &pb.SetLabelsReply{}, err
}
