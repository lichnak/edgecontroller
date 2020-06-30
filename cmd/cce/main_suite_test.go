// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package main_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/joho/godotenv"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	cceGRPC "github.com/open-ness/edgecontroller/grpc"
	authpb "github.com/open-ness/edgecontroller/pb/auth"
	"github.com/open-ness/edgecontroller/pki"
	"github.com/open-ness/edgecontroller/swagger"
)

var (
	adminPass string
	dbPass    string

	cmd    *exec.Cmd
	ctrl   *gexec.Session
	node   *gexec.Session
	nodeIn io.WriteCloser

	authSvcCli authpb.AuthServiceClient
	apiCli     *apiClient

	conf     *tls.Config
	telemDir string

	controllerRootPEM []byte
)

var _ = BeforeSuite(func() {
	logger := grpclog.NewLoggerV2(GinkgoWriter, GinkgoWriter, GinkgoWriter)
	grpclog.SetLoggerV2(logger)
	startup()
	initAuthSvcCli()
})

var _ = AfterSuite(func() {
	shutdown()
})

func TestApplicationClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller CE API Suite")
}

func initAuthSvcCli() {
	timeoutCtx, cancel := context.WithTimeout(
		context.Background(), 2*time.Second)
	defer cancel()

	caPool := x509.NewCertPool()
	Expect(caPool.AppendCertsFromPEM(controllerRootPEM)).To(BeTrue(),
		"should load Controller self-signed root into trust pool")
	tlsCreds := credentials.NewClientTLSFromCert(caPool, cceGRPC.EnrollmentSNI)

	conn, err := grpc.DialContext(
		timeoutCtx,
		net.JoinHostPort("127.0.0.1", "8081"),
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithBlock())
	Expect(err).ToNot(HaveOccurred(), "Dial failed: %v", err)

	authSvcCli = authpb.NewAuthServiceClient(conn)
}

func startup() {
	By("Building the controller")
	exe, err := gexec.Build("github.com/open-ness/edgecontroller/cmd/cce")
	Expect(err).ToNot(HaveOccurred(), "Problem building service")

	By("Creating a temp dir for telemetry output files")
	tmpdir, err := ioutil.TempDir(".", "telemetry")
	Expect(err).NotTo(HaveOccurred())
	telemDir, err = filepath.Abs(tmpdir)
	Expect(err).NotTo(HaveOccurred())

	By("Loading environment variables from .env file")
	Expect(godotenv.Load("../../.env")).To(Succeed())

	adminPass = os.Getenv("CCE_ADMIN_PASSWORD")
	Expect(adminPass).ToNot(BeEmpty())

	dbPass = os.Getenv("MYSQL_ROOT_PASSWORD")
	Expect(dbPass).ToNot(BeEmpty())

	By("Starting the controller")
	cmd = exec.Command(exe,
		"-log-level", "debug",
		"-dsn", fmt.Sprintf("root:%s@tcp(:8083)/controller_ce", dbPass),
		"-httpPort", "8080",
		"-grpcPort", "8081",
		"-elaPort", "42101",
		"-evaPort", "42102",
		"-syslogPort", "6514",
		"-statsdPort", "8125",
		"-syslog-path", filepath.Join(telemDir, "syslog.log"),
		"-statsd-path", filepath.Join(telemDir, "statsd.log"),
		"-adminPass", adminPass)
	ctrl, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "Problem starting service")

	By("Reading the Controller self-signed CA from output")
	Eventually(ctrl.Err, 3).Should(gbytes.Say(
		`-----END CERTIFICATE-----`),
		"Service did not print CA cert in time")
	certMatches := regexp.MustCompile(
		`(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----`,
	).FindAll(ctrl.Err.Contents(), -1)
	Expect(certMatches).To(HaveLen(1),
		"Service did not print a single CA cert")
	controllerRootPEM = certMatches[0]
	conf = loadTLSConfig(filepath.Join(".", "certificates", "ca"))

	By("Verifying that the controller started successfully")
	Eventually(ctrl.Err, 3).Should(gbytes.Say(
		"Controller CE ready"),
		"Service did not start in time")

	By("Requesting an authentication token from the controller")
	apiCli = &apiClient{
		Token: authToken(),
	}

	By("Building the node")
	exe, err = gexec.Build(
		"github.com/open-ness/edgecontroller/test/node/grpc")
	Expect(err).ToNot(HaveOccurred(), "Problem building node")

	cmd = exec.Command(exe)
	nodeIn, err = cmd.StdinPipe()
	Expect(err).ToNot(HaveOccurred(), "Problem creating node stdin pipe")

	By("Starting the node")
	node, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "Problem starting node")
}

func shutdown() {
	if ctrl != nil {
		By("Stopping the controller service")
		ctrl.Kill()
	}
	if node != nil {
		By("Stopping the test node")
		node.Kill()
	}
	if nodeIn != nil {
		nodeIn.Close()
	}
	if telemDir != "" {
		By("Cleaning up telemetry output")
		Expect(os.RemoveAll(telemDir)).To(Succeed())
	}
}

func clearGRPCTargetsTable() {
	By("Connecting to the database")
	db, err := sql.Open(
		"mysql",
		fmt.Sprintf("root:%s@tcp(:8083)/controller_ce?multiStatements=true", dbPass))
	Expect(err).ToNot(HaveOccurred())

	defer func() {
		Expect(db.Close()).To(Succeed())
	}()

	By("Pinging the database")
	err = db.Ping()
	Expect(err).ToNot(HaveOccurred())

	timeoutCtx, cancel := context.WithTimeout(
		context.Background(), 2*time.Second)
	defer cancel()

	By("Executing the delete query")
	_, err = db.ExecContext(
		timeoutCtx,
		"DELETE FROM node_grpc_targets")
	Expect(err).ToNot(HaveOccurred())
}

func insertNFDTags(values string) {
	By("Connecting to the database")
	db, err := sql.Open(
		"mysql",
		fmt.Sprintf("root:%s@tcp(:8083)/controller_ce?multiStatements=true", dbPass))
	Expect(err).ToNot(HaveOccurred())

	defer func() {
		Expect(db.Close()).To(Succeed())
	}()

	By("Pinging the database")
	err = db.Ping()
	Expect(err).ToNot(HaveOccurred())

	timeoutCtx, cancel := context.WithTimeout(
		context.Background(), 2*time.Second)
	defer cancel()

	//nolint:gosec
	query := fmt.Sprintf("INSERT INTO nodes_nfd_features (entity) values(%s)", values)
	By(fmt.Sprintf("Executing the insert query: %v", query))
	_, err = db.ExecContext(timeoutCtx, query)
	Expect(err).ToNot(HaveOccurred())
}

func authToken() string {
	payload, err := json.Marshal(
		struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}{"admin", adminPass})
	Expect(err).ToNot(HaveOccurred())

	req, err := http.NewRequest(
		http.MethodPost,
		"http://localhost:8080/auth",
		bytes.NewReader(payload),
	)
	Expect(err).ToNot(HaveOccurred())

	resp, err := new(http.Client).Do(req)
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	Expect(resp.StatusCode).To(Equal(http.StatusCreated))

	var auth struct {
		Token string `json:"token"`
	}
	Expect(json.NewDecoder(resp.Body).Decode(&auth)).To(Succeed())
	Expect(auth.Token).ToNot(BeEmpty())

	return auth.Token
}

type respBody struct {
	ID string
}

func postApps(appType string) (id string) {
	By("Sending a POST /apps request")
	resp, err := apiCli.Post(
		"http://127.0.0.1:8080/apps",
		"application/json",
		strings.NewReader(fmt.Sprintf(`
			{
				"type": "%s",
				"name": "%s app",
				"version": "latest",
				"vendor": "smart edge",
				"description": "my %s app",
				"cores": 4,
				"memory": 1024,
				"ports": [{"port": 80, "protocol": "tcp"}],
				"source": "http://www.test.com/my_%s_app.tar.gz"
			}`, appType, appType, appType, appType)))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 201 Created response")
	Expect(resp.StatusCode).To(Equal(http.StatusCreated))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var rb respBody

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &rb)).To(Succeed())

	return rb.ID
}

func getApp(id string) *swagger.AppDetail {
	By("Sending a GET /apps/{app_id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/apps/%s", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var app swagger.AppDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &app)).To(Succeed())

	return &app
}

func patchNodeDNS(nodeID string) {
	By("Sending a PATCH /nodes/{node_id}/dns request")

	resp, err := apiCli.Patch(
		fmt.Sprintf(
			"http://127.0.0.1:8080/nodes/%s/dns",
			nodeID,
		),
		"application/json",
		strings.NewReader(`
		{
			"name": "Sample DNS configuration",
			"records": {
			  "a": [
				{
					"name": "sample-app1.demosite.com",
					"description": "The domain for my sample app 1",
					"alias": false,
					"values": [
						"192.168.1.5"
				  ]
				},
				{
					"name": "sample-app2.demosite.com",
					"description": "The domain for my sample app 2",
					"alias": false,
					"values": [
					  "192.168.1.9"
				  ]
				}
			  ]
			}
		}`))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	_, err = ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())
}

func patchNodeDNSwithApp(nodeID, appID string) {
	By("Sending a PATCH /nodes/{node_id}/dns request")

	resp, err := apiCli.Patch(
		fmt.Sprintf(
			"http://127.0.0.1:8080/nodes/%s/dns",
			nodeID,
		),
		"application/json",
		strings.NewReader(
			fmt.Sprintf(`
		{
			"name": "Sample DNS configuration",
			"records": {
			  "a": [
				{
					"name": "sample-app1.demosite.com",
					"description": "The domain for my sample app 1",
					"alias": false,
					"values": [
						"192.168.1.5"
				  ]
				},
				{
					"name": "sample-app2.demosite.com",
					"description": "The domain for my sample app 2",
					"alias": true,
					"values": [
					  "%s"
				  ]
				}
			  ]
			}
		}`, appID)))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	_, err = ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())
}

type nodeConfig struct {
	nodeID string
	serial string
	key    *ecdsa.PrivateKey
	creds  *authpb.Credentials
}

func createAndRegisterNode() *nodeConfig {
	By("Generating node private key")
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	Expect(err).ToNot(HaveOccurred())

	By("Creating a CSR with private key")
	csrDER, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{},
		key,
	)
	Expect(err).ToNot(HaveOccurred())

	By("Parsing the CSR")
	certReq, err := x509.ParseCertificateRequest(csrDER)
	Expect(err).ToNot(HaveOccurred())

	By("Encoding the CSR in PEM")
	csrPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrDER,
		})

	By("Pre-approving Node by serial")
	hash := md5.Sum(certReq.RawSubjectPublicKeyInfo) //nolint:gosec
	serial := base64.RawURLEncoding.EncodeToString(hash[:])
	nodeID := postNodesSerial(serial)

	By("Resetting the node")
	Expect(cmd.Process.Signal(syscall.SIGABRT)).To(Succeed(), "Problem resetting node")
	Expect(fmt.Fprintln(nodeIn, nodeID)).To(Equal(len(nodeID) + 1))

	By("Verifying that the node started successfully")
	Eventually(node.Err, 3).Should(gbytes.Say(
		"connecting to port 8081"),
		"Node did not start in time")
	Eventually(node.Err, 3).Should(gbytes.Say(
		"connecting to port 8081"),
		"Node did not start in time")

	By("Requesting credentials from auth service")
	creds, err := authSvcCli.RequestCredentials(
		context.TODO(),
		&authpb.Identity{
			Csr: string(csrPEM),
		},
	)
	Expect(err).ToNot(HaveOccurred())

	return &nodeConfig{
		nodeID: nodeID,
		serial: serial,
		key:    key,
		creds:  creds,
	}
}

func postNodesSerial(serial string) (id string) {
	By("Sending a POST /nodes request")
	resp, err := apiCli.Post(
		"http://127.0.0.1:8080/nodes",
		"application/json",
		strings.NewReader(fmt.Sprintf(`
			{
				"name": "Test Node 1",
				"location": "Localhost port 42101",
				"serial": "%s"
			}`, serial)))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 201 Created response")
	Expect(resp.StatusCode).To(Equal(http.StatusCreated))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var rb respBody

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &rb)).To(Succeed())

	return rb.ID
}

func getNode(id string) *swagger.NodeDetail {
	By("Sending a GET /nodes/{id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeResp swagger.NodeDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeResp)).To(Succeed())

	return &nodeResp
}

func getNodeInterfaces(id string) *swagger.InterfaceList {
	By("Sending a GET /nodes/{id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/interfaces", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeResp swagger.InterfaceList

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeResp)).To(Succeed())

	return &nodeResp
}

func getNodeInterfacePolicy(nodeID, interfaceID string) *swagger.BaseResource {
	By("Sending a GET /nodes/{node_id}/interfaces/{interface_id}/policy request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/interfaces/%s/policy", nodeID, interfaceID))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeResp swagger.BaseResource

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeResp)).To(Succeed())

	return &nodeResp
}

func getNodeApp(nodeID, appID string) *swagger.NodeAppDetail {
	By("Sending a GET /nodes_apps/{id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s", nodeID, appID))

	By("Verifying a 200 OK response")
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeAppResp swagger.NodeAppDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeAppResp)).To(Succeed())

	return &nodeAppResp
}

func getNodeDNS(id string) *swagger.DNSDetail {
	By("Sending a GET /nodes/{node_id}/dns request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/dns", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeDNSConfig swagger.DNSDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeDNSConfig)).To(Succeed())

	return &nodeDNSConfig
}

func getNodeNFD(id string) *swagger.NodeNfdList {
	By(fmt.Sprintf("Sending a GET /nodes/%v/nfd request", id))
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/nfd", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var output swagger.NodeNfdList

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &output)).To(Succeed())

	return &output
}

func postPolicies(policyNames ...string) (id string) {
	var policyName string
	if len(policyNames) == 0 {
		policyName = "policy-1"
	} else {
		policyName = policyNames[0]
	}
	By("Sending a POST /policies request")
	resp, err := apiCli.Post(
		"http://127.0.0.1:8080/policies",
		"application/json",
		strings.NewReader(fmt.Sprintf(`
		{
			"name": "%s",
			"traffic_rules": [{
				"description": "test-rule-1",
				"priority": 1,
				"source": {
					"description": "test-source-1",
					"mac_filter": {
						"mac_addresses": [
							"F0-59-8E-7B-36-8A",
							"23-20-8E-15-89-D1",
							"35-A4-38-73-35-45"
						]
					},
					"ip_filter": {
						"address": "223.1.1.0",
						"mask": 16,
						"begin_port": 2000,
						"end_port": 2012,
						"protocol": "tcp"
					},
					"gtp_filter": {
						"address": "10.6.7.2",
						"mask": 12,
						"imsis": [
							"310150123456789",
							"310150123456790",
							"310150123456791"
						]
					}
				},
				"destination": {
					"description": "test-destination-1",
					"mac_filter": {
						"mac_addresses": [
							"7D-C2-3A-1C-63-D9",
							"E9-6B-D1-D2-1A-6B",
							"C8-32-A9-43-85-55"
						]
					},
					"ip_filter": {
						"address": "64.1.1.0",
						"mask": 16,
						"begin_port": 1000,
						"end_port": 1012,
						"protocol": "tcp"
					},
					"gtp_filter": {
						"address": "108.6.7.2",
						"mask": 4,
						"imsis": [
							"310150123456792",
							"310150123456793",
							"310150123456794"
						]
					}
				},
				"target": {
					"description": "test-target-1",
					"action": "accept",
					"mac_modifier": {
						"mac_address": "C7-5A-E7-98-1B-A3"
					},
					"ip_modifier": {
						"address": "123.2.3.4",
						"port": 1600
					}
				}
			}]
		}`, policyName)))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 201 Created response")
	Expect(resp.StatusCode).To(Equal(http.StatusCreated))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var rb respBody

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &rb)).To(Succeed())

	return rb.ID
}

func getPolicy(id string) *swagger.PolicyDetail {
	By("Sending a GET /policies/{id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/policies/%s", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var policy swagger.PolicyDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &policy)).To(Succeed())

	return &policy
}

func postNodeApps(nodeID, appID string) {
	By("Sending a POST /nodes/{node_id}/apps request")
	resp, err := apiCli.Post(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeID),
		"application/json",
		strings.NewReader(fmt.Sprintf(`
			{
				"id": "%s"
			}`, appID)))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 Created response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))
}

func getNodeApps(nodeID string) *swagger.NodeAppList {
	By("Sending a GET /nodes/{node_id}/apps request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeID),
	)

	By("Verifying a 200 OK response")
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeApps *swagger.NodeAppList

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeApps)).To(Succeed())

	return nodeApps
}

func getNodeAppByID(nodeID, appID string) swagger.NodeAppDetail {
	By("Sending a GET /nodes/{node_id}/apps/{app_id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s", nodeID, appID),
	)

	By("Verifying a 200 OK response")
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var nodeApp swagger.NodeAppDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &nodeApp)).To(Succeed())

	return nodeApp
}

func patchNodesAppsPolicy(
	nodeID string,
	appID string,
	policyID string,
) {
	By("Sending a PATCH /nodes/{node_id}/apps/{app_id}/policy request")
	resp, err := apiCli.Patch(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/policy", nodeID, appID),
		"application/json",
		strings.NewReader(fmt.Sprintf(
			`
			{
				"id": "%s"
			}`, policyID)))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))
}

func loadTLSConfig(dir string) *tls.Config {
	key, err := pki.LoadKey(filepath.Join(dir, "key.pem"))
	Expect(err).NotTo(HaveOccurred())
	cert, err := pki.LoadCertificate(filepath.Join(dir, "cert.pem"))
	Expect(err).NotTo(HaveOccurred())
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  key,
			Leaf:        cert,
		}},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}
}
