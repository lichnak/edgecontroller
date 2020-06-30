// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package nfd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/open-ness/common/log"
	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/internal/stubs"
	"github.com/open-ness/edgecontroller/mysql"
	"github.com/open-ness/edgecontroller/nfd-master"
	"github.com/open-ness/edgecontroller/pki"
	"github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"os"
	pb "sigs.k8s.io/node-feature-discovery/pkg/labeler"
	"testing"
	"time"
)

func TestNfdMaster(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "NFD Master test suite")
}

var (
	tempdir string
	ctx     context.Context
	rootCA  *pki.RootCA
)

var dbStub stubs.DBStub
var persStub stubs.PersistenceServiceStub

var _ = BeforeSuite(func() {
	log.SetOutput(GinkgoWriter)

	var err error
	tempdir, err = ioutil.TempDir("", "nfd-master-test")
	Expect(err).NotTo(HaveOccurred())

	rootCA, err = pki.InitRootCA(tempdir)
	Expect(err).NotTo(HaveOccurred())

	nfd.GetDB = func(string) (mysql.CceDB, error) {
		return dbStub, nil
	}

	nfd.GetPersistenceService = func(db mysql.CceDB) cce.PersistenceService {
		return &persStub
	}
})

var _ = AfterSuite(func() {
	os.RemoveAll(tempdir)
})

func createClientTLSCreds(ca *pki.RootCA, clientCN string) credentials.TransportCredentials {

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	cert, err := ca.NewTLSClientCert(key, clientCN)
	Expect(err).NotTo(HaveOccurred())

	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Cert)

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
		}},
		RootCAs: certPool,
	})
}

var _ = Describe("NFD Master Server", func() {
	Describe("Is initialized", func() {
		When("CA certificate file path is invalid", func() {
			It("Returns error", func() {
				nfdSrv := &nfd.ServerNFD{
					CaCertPath: "/invalid/path/cert.pem",
					CaKeyPath:  tempdir + "key.pem",
				}
				err := nfdSrv.ServeGRPC(ctx)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(
					"Failed to load CA certificate: unable to read certificate file: open " +
						"/invalid/path/cert.pem: no such file or directory"))
			})
		})
		When("CA certificate is valid but CA key is invalid", func() {
			It("Returns error", func() {
				nfdSrv := &nfd.ServerNFD{
					CaCertPath: tempdir + "/cert.pem",
					CaKeyPath:  "/invalid/path/key.pem",
				}
				err := nfdSrv.ServeGRPC(ctx)
				Expect(err).Should(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(
					"Failed to load CA key: unable to read key file: open " +
						"/invalid/path/key.pem: no such file or directory"))
			})
		})
		When("SNI is invalid", func() {
			It("Starts successfully but SetLabels request fails", func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				nfdSrv := &nfd.ServerNFD{
					CaCertPath: tempdir + "/cert.pem",
					CaKeyPath:  tempdir + "/key.pem",
					Endpoint:   8082,
					Sni:        "testhost",
				}
				var err error
				go func() {
					err = nfdSrv.ServeGRPC(ctx)
					Expect(err).ShouldNot(HaveOccurred())

				}()

				// wait for server to start
				time.Sleep(1 * time.Second)

				transportCreds := createClientTLSCreds(rootCA, "testnode")
				conn, err := grpc.Dial("localhost:8082", grpc.WithTransportCredentials(transportCreds))
				Expect(err).ShouldNot(HaveOccurred())
				defer conn.Close()

				client := pb.NewLabelerClient(conn)
				req := pb.SetLabelsRequest{NodeName: "testnode"}

				_, err = client.SetLabels(ctx, &req)
				Expect(err.Error()).To(ContainSubstring(
					"authentication handshake failed: x509: certificate is valid for testhost, not localhost"))
			})
		})
	})

	Describe("Is initialized successfully", func() {

		var ctx context.Context
		var cancel context.CancelFunc
		var client pb.LabelerClient
		var conn *grpc.ClientConn

		BeforeEach(func() {
			persStub = stubs.PersistenceServiceStub{}

			ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
			nfdSrv := &nfd.ServerNFD{
				CaCertPath: tempdir + "/cert.pem",
				CaKeyPath:  tempdir + "/key.pem",
				Endpoint:   8082,
				Sni:        "localhost",
			}
			var err error
			go func() {
				err = nfdSrv.ServeGRPC(ctx)
				Expect(err).ShouldNot(HaveOccurred())

			}()

			// wait for server to start
			time.Sleep(200 * time.Millisecond)
			transportCreds := createClientTLSCreds(rootCA, "testnode")
			conn, err = grpc.Dial("localhost:8082", grpc.WithTransportCredentials(transportCreds))
			Expect(err).ShouldNot(HaveOccurred())
			client = pb.NewLabelerClient(conn)
		})

		AfterEach(func() {
			cancel()
			conn.Close()
		})

		When("SetLabels request is received but NodeName does not match TLS CommonName", func() {
			It("Returns error", func() {
				req := pb.SetLabelsRequest{NodeName: "invalidname"}
				_, err := client.SetLabels(ctx, &req)
				Expect(err.Error()).To(ContainSubstring(
					"Node name from request [invalidname] does not match TLS peer name [testnode]"))
			})
		})

		When("SetLabels request is received but TLS peer info does not contain CommonName", func() {
			It("Returns error", func() {

				transportCreds := createClientTLSCreds(rootCA, "")
				conn, err := grpc.Dial("localhost:8082", grpc.WithTransportCredentials(transportCreds))
				Expect(err).ShouldNot(HaveOccurred())
				client = pb.NewLabelerClient(conn)

				req := pb.SetLabelsRequest{NodeName: "testnode"}
				_, err = client.SetLabels(ctx, &req)
				Expect(err.Error()).To(ContainSubstring(
					"gRPC peer connected with a client TLS cert with no Common Name"))
			})
		})

		When("valid SetLabels request is received with empty labels", func() {
			It("Returns no error and does not call persistence service", func() {
				req := pb.SetLabelsRequest{
					NodeName: "testnode",
				}

				_, err := client.SetLabels(ctx, &req)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(persStub.CreateValues).To(HaveLen(0))
				Expect(persStub.FilterValues).To(HaveLen(0))
			})
		})

		When("valid SetLabels request is received with two new labels", func() {
			It("Returns no error and persistence service Filter() and Create() is called two times", func() {
				req := pb.SetLabelsRequest{
					NodeName: "testnode",
					Labels: map[string]string{
						"nfd_id1": "value1",
						"nfd_id2": "value2",
					},
				}

				_, err := client.SetLabels(ctx, &req)

				Expect(err).ShouldNot(HaveOccurred())

				Expect(persStub.FilterValues).To(HaveLen(2))

				order := 0
				if persStub.FilterValues[0][1].Value == "nfd_id2" {
					order = 1
				}

				Expect(persStub.FilterValues[order][0].Field).To(Equal("node_id"))
				Expect(persStub.FilterValues[order][0].Value).To(Equal("testnode"))
				Expect(persStub.FilterValues[order][1].Field).To(Equal("nfd_id"))
				Expect(persStub.FilterValues[order][1].Value).To(Equal("nfd_id1"))

				Expect(persStub.FilterValues[1-order][0].Field).To(Equal("node_id"))
				Expect(persStub.FilterValues[1-order][0].Value).To(Equal("testnode"))
				Expect(persStub.FilterValues[1-order][1].Field).To(Equal("nfd_id"))
				Expect(persStub.FilterValues[1-order][1].Value).To(Equal("nfd_id2"))

				Expect(persStub.CreateValues).To(HaveLen(2))
				Expect(uuid.FromStringOrNil(persStub.CreateValues[0].(*nfd.NodeFeatureNFD).ID)).ToNot(Equal(uuid.Nil))
				Expect(persStub.CreateValues[order].(*nfd.NodeFeatureNFD).NodeID).To(Equal("testnode"))
				Expect(persStub.CreateValues[order].(*nfd.NodeFeatureNFD).NfdID).To(Equal("nfd_id1"))
				Expect(persStub.CreateValues[order].(*nfd.NodeFeatureNFD).NfdValue).To(Equal("value1"))

				Expect(uuid.FromStringOrNil(persStub.CreateValues[1].(*nfd.NodeFeatureNFD).ID)).ToNot(Equal(uuid.Nil))
				Expect(persStub.CreateValues[1-order].(*nfd.NodeFeatureNFD).NodeID).To(Equal("testnode"))
				Expect(persStub.CreateValues[1-order].(*nfd.NodeFeatureNFD).NfdID).To(Equal("nfd_id2"))
				Expect(persStub.CreateValues[1-order].(*nfd.NodeFeatureNFD).NfdValue).To(Equal("value2"))

				Expect(persStub.BulkUpdateValues).To(HaveLen(0))
			})
		})

		When("valid SetLabels request is received with already stored label", func() {
			It("Returns no error and persistence service Filter() and BulkUpdate() is called", func() {
				req := pb.SetLabelsRequest{
					NodeName: "testnode",
					Labels: map[string]string{
						"nfd_id1": "value1",
					},
				}

				entryID := uuid.NewV4().String()
				filterRet := nfd.NodeFeatureNFD{
					ID:       entryID,
					NodeID:   "testnode",
					NfdID:    "nfd_id1",
					NfdValue: "oldval",
				}
				persStub.FilterRet = []cce.Persistable{&filterRet}

				_, err := client.SetLabels(ctx, &req)

				Expect(err).ShouldNot(HaveOccurred())

				Expect(persStub.FilterValues).To(HaveLen(1))
				Expect(persStub.FilterValues[0][0].Field).To(Equal("node_id"))
				Expect(persStub.FilterValues[0][0].Value).To(Equal("testnode"))
				Expect(persStub.FilterValues[0][1].Field).To(Equal("nfd_id"))
				Expect(persStub.FilterValues[0][1].Value).To(Equal("nfd_id1"))

				Expect(persStub.BulkUpdateValues).To(HaveLen(1))
				Expect(persStub.BulkUpdateValues[0][0].(*nfd.NodeFeatureNFD).ID).To(Equal(entryID))
				Expect(persStub.BulkUpdateValues[0][0].(*nfd.NodeFeatureNFD).NodeID).To(Equal("testnode"))
				Expect(persStub.BulkUpdateValues[0][0].(*nfd.NodeFeatureNFD).NfdID).To(Equal("nfd_id1"))
				Expect(persStub.BulkUpdateValues[0][0].(*nfd.NodeFeatureNFD).NfdValue).To(Equal("value1"))

				Expect(persStub.CreateValues).To(HaveLen(0))
			})
		})

		When("valid SetLabels request is received but Filter() returns error", func() {
			It("Returns error and no entry is created/updated", func() {
				req := pb.SetLabelsRequest{
					NodeName: "testnode",
					Labels: map[string]string{
						"nfd_id1": "value1",
					},
				}

				persStub.FilterErr = errors.New("DB filter error")
				_, err := client.SetLabels(ctx, &req)

				Expect(err.Error()).To(ContainSubstring(
					"DB filter error"))

				Expect(persStub.FilterValues).To(HaveLen(1))
				Expect(persStub.CreateValues).To(HaveLen(0))
				Expect(persStub.BulkUpdateValues).To(HaveLen(0))
			})
		})

		When("valid SetLabels request is received but Create() returns error", func() {
			It("Returns error", func() {
				req := pb.SetLabelsRequest{
					NodeName: "testnode",
					Labels: map[string]string{
						"nfd_id1": "value1",
					},
				}

				persStub.CreateErr = errors.New("DB create error")
				_, err := client.SetLabels(ctx, &req)

				Expect(err.Error()).To(ContainSubstring(
					"DB create error"))

				Expect(persStub.FilterValues).To(HaveLen(1))
				Expect(persStub.CreateValues).To(HaveLen(1))
				Expect(persStub.BulkUpdateValues).To(HaveLen(0))
			})
		})

		When("valid SetLabels request is received but BulkUpdate() returns error", func() {
			It("Returns error", func() {
				req := pb.SetLabelsRequest{
					NodeName: "testnode",
					Labels: map[string]string{
						"nfd_id1": "value1",
					},
				}

				filterRet := nfd.NodeFeatureNFD{
					ID:       uuid.NewV4().String(),
					NodeID:   "testnode",
					NfdID:    "nfd_id1",
					NfdValue: "oldval",
				}
				persStub.FilterRet = []cce.Persistable{&filterRet}
				persStub.BulkUpdateErr = errors.New("DB update error")

				_, err := client.SetLabels(ctx, &req)

				Expect(err.Error()).To(ContainSubstring(
					"DB update error"))

				Expect(persStub.FilterValues).To(HaveLen(1))
				Expect(persStub.CreateValues).To(HaveLen(0))
				Expect(persStub.BulkUpdateValues).To(HaveLen(1))
			})
		})
	})
})
