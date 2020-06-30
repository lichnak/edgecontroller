// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cce "github.com/open-ness/edgecontroller"
	authpb "github.com/open-ness/edgecontroller/pb/auth"
)

var _ = Describe("Node Auth Service", func() {
	Describe("RequestCredentials", func() {
		Describe("Success", func() {
			It("Should return auth credentials", func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()

				By("Validating the returned credentials")
				Expect(nodeCfg.creds).ToNot(BeNil())
				Expect(nodeCfg.creds.Certificate).ToNot(BeNil())
				Expect(nodeCfg.creds.CaChain).ToNot(BeEmpty())

				By("Decoding PEM-encoded client certificate")
				certBlock, rest := pem.Decode([]byte(nodeCfg.creds.Certificate))
				Expect(certBlock).ToNot(BeNil())
				Expect(rest).To(BeEmpty())

				By("Parsing the client certificate")
				cert, err := x509.ParseCertificate(certBlock.Bytes)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying certificate was signed with the node's key")
				pubKeyDER, err := x509.MarshalPKIXPublicKey(nodeCfg.key.Public())
				Expect(err).ToNot(HaveOccurred())
				Expect(cert.RawSubjectPublicKeyInfo).To(Equal(pubKeyDER))

				By("Verifying the CN is derived from the public key")
				Expect(cert.Subject.CommonName).To(Equal(nodeCfg.nodeID))

				By("Decoding CA certificates chain to DER")
				var chainDER []byte
				for _, ca := range nodeCfg.creds.CaChain {
					block, _ := pem.Decode([]byte(ca))
					Expect(block).ToNot(BeNil())
					chainDER = append(chainDER, block.Bytes...)
				}

				By("Parsing the CA certificates chain")
				chainCerts, err := x509.ParseCertificates(chainDER)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the certificate was signed by the Controller CA")
				Expect(cert.CheckSignatureFrom(chainCerts[0])).To(Succeed())

				By("Decoding CA certificates pool to DER")
				var poolDER []byte
				for _, ca := range nodeCfg.creds.CaPool {
					block, _ := pem.Decode([]byte(ca))
					Expect(block).ToNot(BeNil())
					poolDER = append(poolDER, block.Bytes...)
				}

				By("Parsing the CA certificates pool")
				poolCerts, err := x509.ParseCertificates(poolDER)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the CA pool contains the Controller CA")
				Expect(poolCerts).To(ContainElement(chainCerts[0]))

				By("Verifying the Node's serial was set")
				resp, err := apiCli.Get("http://127.0.0.1:8080/nodes/" + nodeCfg.nodeID)
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()
				var nodeResp cce.Node
				Expect(json.NewDecoder(resp.Body).Decode(&nodeResp)).To(Succeed())
				Expect(nodeResp.Serial).To(Equal(nodeCfg.serial))
			})
		})
	})

	Describe("Errors", func() {
		It("Should return an error if payload is empty", func() {
			By("Requesting credentials from auth service")
			credentials, err := authSvcCli.RequestCredentials(
				context.TODO(),
				&authpb.Identity{
					Csr: "",
				},
			)
			Expect(err).To(HaveOccurred())
			Expect(credentials).To(BeNil())
		})

		It("Should return an error if payload is invalid", func() {
			By("Requesting credentials from auth service")
			credentials, err := authSvcCli.RequestCredentials(
				context.TODO(),
				&authpb.Identity{
					Csr: "123",
				},
			)
			Expect(err).To(HaveOccurred())
			Expect(credentials).To(BeNil())
		})

		It("Should return a gRPC Unauthenticated error if not pre-approved", func() {
			By("Generating node private key")
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			Expect(err).ToNot(HaveOccurred())

			By("Creating a certificate signing request with private key")
			csrDER, err := x509.CreateCertificateRequest(
				rand.Reader,
				&x509.CertificateRequest{},
				key,
			)
			Expect(err).ToNot(HaveOccurred())

			By("Encoding certificate signing request in PEM")
			csrPEM := pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csrDER,
				})

			By("Requesting credentials from auth service")
			credentials, err := authSvcCli.RequestCredentials(
				context.TODO(),
				&authpb.Identity{
					Csr: string(csrPEM),
				},
			)

			By("Verifying an error occurred")
			Expect(err).To(HaveOccurred())
			Expect(credentials).To(BeNil())

			By("Verifying the error was Unauthenticated")
			st, ok := status.FromError(err)
			Expect(ok).To(BeTrue())
			Expect(st.Code()).To(Equal(codes.Unauthenticated))
		})
	})
})
