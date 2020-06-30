// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package k8s_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cceGRPC "github.com/open-ness/edgecontroller/grpc"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var _ = Describe("Kubernetes Read Metadata Service", func() {
	var (
		cvaSvcCli evapb.ControllerVirtualizationAgentClient
		nodeID    string
		nodeCfg   *nodeConfig
	)

	BeforeEach(func() {
		clearGRPCTargetsTable()
		nodeCfg = createAndRegisterNode()
		nodeID = nodeCfg.nodeID

		block, _ := pem.Decode([]byte(nodeCfg.creds.Certificate))
		if block == nil {
			Fail("failed to parse certificate PEM")
		}

		certBlock, _ := pem.Decode([]byte(nodeCfg.creds.Certificate))
		Expect(certBlock).NotTo(BeNil(), "error decoding certificate in enrollment response")

		x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
		Expect(err).ToNot(HaveOccurred())

		nodeID = x509Cert.Subject.CommonName

		cert := tls.Certificate{Certificate: [][]byte{certBlock.Bytes}, PrivateKey: nodeCfg.key}

		caPool := x509.NewCertPool()
		Expect(caPool.AppendCertsFromPEM(controllerRootPEM)).To(BeTrue(),
			"should load Controller self-signed root into trust pool")

		t := &tls.Config{
			RootCAs:      caPool,
			Certificates: []tls.Certificate{cert},
			ServerName:   cceGRPC.SNI,
			MinVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()

		cvaConn, err := grpc.DialContext(
			ctx,
			fmt.Sprintf("%s:%d", "127.0.0.1", 8081),
			grpc.WithTransportCredentials(credentials.NewTLS(t)),
			grpc.WithBlock())
		Expect(err).ToNot(HaveOccurred(), "Dial failed: %v", err)

		cvaSvcCli = evapb.NewControllerVirtualizationAgentClient(cvaConn)

		// label node with correct id
		execParam := fmt.Sprintf("node-id=%s", nodeID)
		Expect(exec.Command("kubectl",
			"label", "nodes", "minikube", execParam).Run()).To(Succeed())
	})

	AfterEach(func() {
		// un-label node with id
		Expect(exec.Command("kubectl", "label", "nodes", "minikube", "node-id-").Run()).To(Succeed())
		// clean up all k8s deployments
		cmd := exec.Command("kubectl", "delete", "--all", "deployments,pods", "--namespace=default")
		Expect(cmd.Run()).To(Succeed())
	})

	Describe("Get Pod Information By IP", func() {
		var (
			appID = "99459845-422d-4b32-8395-e8f50fd34792"
		)
		Context("Success", func() {
			It("Should return pod information", func() {
				By("Deploying an application to Kubernetes")
				deployApp(nodeID, appID)

				By("Generating IP address of the pod deployed")
				var ip string
				count := 0
				Eventually(func() net.IP {
					count++
					By(fmt.Sprintf("Attempt #%d: Verifying if ip assigned to pod is valid", count))

					out, err := exec.Command("kubectl",
						"get", "pods", "-o=jsonpath='{.items[0].status.podIP}'").Output()
					Expect(err).ToNot(HaveOccurred())

					ip = strings.Trim(string(out), "'")
					return net.ParseIP(ip)
				}, 15*time.Second, 1*time.Second).ShouldNot(BeNil())

				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()

				By(fmt.Sprintf("Requesting container info for pod with ip: %s", ip))
				containerInfo, err := cvaSvcCli.GetContainerByIP(
					ctx,
					&evapb.ContainerIP{
						Ip: ip,
					},
				)
				Expect(err).ToNot(HaveOccurred())
				Expect(containerInfo.Id).To(Equal(appID))
			})
		})
		Context("Error", func() {
			It("Should return an error if request contains no correct IP address", func() {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()

				By("Requesting container info for pod with ip: ''")
				_, err := cvaSvcCli.GetContainerByIP(
					ctx,
					&evapb.ContainerIP{
						Ip: "",
					},
				)
				Expect(err).To(HaveOccurred())
			})

			It("Should return an error if request contains an IP that is not assigned to a pod", func() {
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()

				impossibleIP := "0.0.0.0"
				By("Requesting container info for pod with ip: 0.0.0.0")
				_, err := cvaSvcCli.GetContainerByIP(
					ctx,
					&evapb.ContainerIP{
						Ip: impossibleIP,
					},
				)
				Expect(err).To(MatchError("rpc error: code = Internal desc = unable to get pod name by ip"))
			})
		})
	})
})
