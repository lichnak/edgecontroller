// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"
	"crypto/md5" //nolint:gosec
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"

	"google.golang.org/grpc"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	cce "github.com/open-ness/edgecontroller"
	authpb "github.com/open-ness/edgecontroller/pb/auth"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
	"github.com/open-ness/edgecontroller/uuid"
)

const (
	// SNI is the server name for TLS when connecting to the Controller post-enrollment
	SNI = "controller.openness"
	// EnrollmentSNI is the server name for TLS when connecting to the Controller for enrollment
	EnrollmentSNI = "enroll.controller.openness"

	// This is the gRPC full RPC path (format: /${package}.${service}/${rpc})
	// for the authentication endpoint. The proto is defined here:
	// https://github.com/open-ness/specs/blob/master/schema/pb/auth.proto
	//
	// This path is used to allow Appliances connected (to the EnrollmentSNI)
	// without a valid client certificate to hit the enrollment endpoint to
	// receive a certificate. It is similar to how a REST app may require a
	// session token for API paths other than /login.
	enrollmentMethod = "/openness.auth.AuthService/RequestCredentials"
)

// Server wraps grpc.Server
type Server struct {
	controller *cce.Controller
	grpc       *grpc.Server
}

// NewServer creates a new Server.
func NewServer(controller *cce.Controller, conf *tls.Config) *Server {
	s := &Server{
		controller: controller,
		grpc: grpc.NewServer(
			grpc.Creds(credentials.NewTLS(conf)),
			grpc.UnaryInterceptor(
				func(
					ctx context.Context,
					req interface{},
					info *grpc.UnaryServerInfo,
					handler grpc.UnaryHandler,
				) (resp interface{}, err error) {
					// apply checkAuth middleware
					if err := checkAuth(ctx,
						info.FullMethod); err != nil {
						return nil, err
					}
					return handler(ctx, req)
				},
			),
			grpc.StreamInterceptor(
				func(
					srv interface{},
					ss grpc.ServerStream,
					info *grpc.StreamServerInfo,
					handler grpc.StreamHandler,
				) error {
					// apply checkAuth middleware
					if err := checkAuth(ss.Context(),
						info.FullMethod); err != nil {
						return err
					}
					return handler(srv, ss)
				},
			),
		),
	}

	authpb.RegisterAuthServiceServer(s.grpc, s)
	evapb.RegisterControllerVirtualizationAgentServer(s.grpc, s)

	return s
}

// checkAuth is a middleware, applied inside the unary and stream interceptors,
// to ensure that if the enrollment server config was used (i.e. no client cert
// was provided) that only the enrollment endpoint is authorized.
func checkAuth(ctx context.Context, method string) error {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return fmt.Errorf("expected peer info in gRPC context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "expected peer auth to be TLS, got %T", p.AuthInfo)
	}

	switch tlsInfo.State.ServerName {
	case EnrollmentSNI:
		if method != enrollmentMethod {
			return status.Errorf(codes.PermissionDenied, "unauthorized RPC: %s", method)
		}
		return nil
	case SNI:
		return nil
	default:
		return fmt.Errorf("unexpected server name: %s", tlsInfo.State.ServerName)
	}
}

// Serve wraps grpc.Server.Serve.
func (s *Server) Serve(lis net.Listener) error {
	return s.grpc.Serve(lis)
}

// GracefulStop wraps grpc.Server.GracefulStop.
func (s *Server) GracefulStop() {
	s.grpc.GracefulStop()
}

// Stop wraps grpc.Server.Stop.
func (s *Server) Stop() {
	s.grpc.Stop()
}

// RequestCredentials requests authentication endpoint credentials.
func (s *Server) RequestCredentials(ctx context.Context, id *authpb.Identity) ( // nolint: gocyclo
	*authpb.Credentials,
	error,
) {
	// Parse and validate CSR
	csr := id.GetCsr()
	if csr == "" {
		return nil, status.Error(codes.InvalidArgument, "CSR cannot be empty")
	}
	csrPEM, _ := pem.Decode([]byte(csr))
	if csrPEM == nil {
		return nil, status.Error(codes.InvalidArgument, "unable to decode CSR")
	}
	certReq, err := x509.ParseCertificateRequest(csrPEM.Bytes)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error parsing CSR: %v", err)
	}
	// Validate cert req early. Even though signing will fail if signature is
	// invalid, we are using the pubkey info to determine the node serial and
	// we don't want to allow this to be arbitrarily constructed (within the
	// confines of an ASN1 structure). There is no known attack vector, it is
	// just extreme caution.
	if err = certReq.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error validating CSR: %v", err)
	}

	// Node's identity is base64-encoded (w/o padding) MD5 hash of the public key data
	// gosec: not hashing user input/passwords
	hash := md5.Sum(certReq.RawSubjectPublicKeyInfo) //nolint:gosec
	serial := base64.RawURLEncoding.EncodeToString(hash[:])

	// Verify the Node's pre-approval by public key data
	entities, err := s.controller.PersistenceService.Filter(ctx, &cce.Node{}, []cce.Filter{{
		Field: "serial",
		Value: serial,
	}})
	if err != nil || len(entities) == 0 {
		if err != nil {
			log.Errf("error getting node approval: %v", err)
		}
		return nil, status.Errorf(codes.Unauthenticated, "node %s not approved", serial)
	}
	node := entities[0].(*cce.Node)

	// Sign cert request
	cert, err := s.controller.AuthorityService.SignCSR(
		certReq.Raw,
		&x509.Certificate{
			Subject: pkix.Name{CommonName: node.ID},
		})
	if err != nil {
		log.Errf("Failed to sign CSR: %v", err)
		return nil, status.Error(codes.Internal, "unable to sign CSR")
	}
	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

	// Get signer chain for response
	caChain, err := s.controller.AuthorityService.CAChain()
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to get CA chain")
	}
	if len(caChain) == 0 {
		log.Errf("Failed to get CA chain: CA chain is empty")
		return nil, status.Error(codes.Internal, "CA chain is empty")
	}

	// Encode each certificate in CA chain in PEM
	var chainPEM []string
	for _, caCert := range caChain {
		caPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caCert.Raw,
			},
		)
		chainPEM = append(chainPEM, string(caPEM))
	}

	// Add the root CA to the Node's CA pool
	caPoolPEM := chainPEM[len(chainPEM)-1:]

	// Store Node credentials
	creds := &cce.Credentials{
		ID:          node.ID,
		Certificate: string(certPEM),
	}
	if err = s.controller.PersistenceService.Create(ctx, creds); err != nil {
		log.Errf("Failed to store Node credentials: %v", err)
		return nil, status.Error(codes.Internal, "unable to store credentials")
	}

	// Get the Node's IP address
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "missing peer data from context")
	}
	nodeIP, _, err := net.SplitHostPort(p.Addr.String())
	if nodeIP == "" || err != nil {
		return nil, status.Errorf(codes.Internal, "bad remote address in peer data: %s: %v",
			p.Addr.String(), err)
	}

	// Store the Node's address
	nodeWithTarget := &cce.NodeGRPCTarget{
		ID:         uuid.New(),
		NodeID:     node.ID,
		GRPCTarget: nodeIP,
	}
	if err := s.controller.PersistenceService.Create(ctx, nodeWithTarget); err != nil {
		log.Errf("Failed to store Node address: %v", err)
		return nil, status.Error(codes.Internal, "unable to store node address")
	}
	// Also let the proxy node we have a new client
	cce.RegisterToProxy(ctx, s.controller.PersistenceService, node.ID)

	return &authpb.Credentials{
		Certificate: creds.Certificate,
		CaChain:     chainPEM,
		CaPool:      caPoolPEM,
	}, nil
}

// GetContainerByIP retrieves info of deployed application with IP provided
func (s *Server) GetContainerByIP(ctx context.Context, containerIP *evapb.ContainerIP) (*evapb.ContainerInfo, error) {
	nodeID, err := getNodeID(ctx)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(containerIP.Ip); ip == nil {
		return nil, status.Error(codes.InvalidArgument, "container ip value is not parsable")
	}

	id, err := s.controller.KubernetesClient.GetAppIDByIP(ctx, nodeID, containerIP.Ip)
	if err != nil {
		return nil, status.Error(codes.Internal, "unable to get pod name by ip")
	}

	return &evapb.ContainerInfo{Id: id}, nil
}

// getNodeID extracts the node info from the client TLS certificate. A context
// from a gRPC endpoint must be passed.
func getNodeID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.FailedPrecondition,
			"gRPC call missing peer context")
	}
	authInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", status.Error(codes.FailedPrecondition,
			"gRPC peer missing TLS auth info")
	}
	chains := authInfo.State.VerifiedChains
	if len(chains) < 1 {
		return "", status.Error(codes.Unauthenticated,
			"gRPC peer was not authenticated with a client TLS certificate")
	}
	nodeID := chains[0][0].Subject.CommonName
	if nodeID == "" {
		return "", status.Error(codes.FailedPrecondition,
			"gRPC peer connected with a client TLS cert with no Common Name")
	}

	return nodeID, nil
}
