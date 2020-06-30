// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package kubeovn_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"syscall"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5" //nolint:gosec
	"crypto/rand"
	"crypto/x509"
	"database/sql"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"k8s.io/client-go/tools/clientcmd"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	_ "github.com/go-sql-driver/mysql" // provides the mysql driver
	cceGRPC "github.com/open-ness/edgecontroller/grpc"
	"github.com/open-ness/edgecontroller/k8s"
	authpb "github.com/open-ness/edgecontroller/pb/auth"
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
	k8sCli     *k8s.Client

	controllerRootPEM []byte
)

var _ = BeforeSuite(func() {
	logger := grpclog.NewLoggerV2(
		GinkgoWriter, GinkgoWriter, GinkgoWriter)
	grpclog.SetLoggerV2(logger)
	startup()
	initAuthSvcCli()
})

var _ = AfterSuite(func() {
	shutdown()
})

func TestApplicationClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Controller CE KubeOVN API Suite")
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

	By("Loading environment variables from .env file")
	Expect(godotenv.Load("../../../.env")).To(Succeed())

	adminPass = os.Getenv("CCE_ADMIN_PASSWORD")
	Expect(adminPass).ToNot(BeEmpty())

	dbPass = os.Getenv("MYSQL_ROOT_PASSWORD")
	Expect(dbPass).ToNot(BeEmpty())

	u, err := user.Current()
	Expect(err).ToNot(HaveOccurred())
	kubeConfig := path.Join(u.HomeDir, ".kube", "config")

	config, err := clientcmd.BuildConfigFromFlags("", kubeConfig)
	Expect(err).ToNot(HaveOccurred())
	cmd = exec.Command(exe,
		"-dsn", fmt.Sprintf("root:%s@tcp(:8083)/controller_ce", dbPass),
		"-httpPort", "8080",
		"-grpcPort", "8081",
		"-elaPort", "42101",
		"-evaPort", "42102",
		"-syslog-path", "./temp_telemetry/syslog.out",
		"-statsd-path", "./temp_telemetry/statsd.out",
		"-adminPass", adminPass,
		"-orchestration-mode", "kubernetes-ovn",
		"-k8s-client-ca-path", config.TLSClientConfig.CAFile,
		"-k8s-client-cert-path", config.TLSClientConfig.CertFile,
		"-k8s-client-key-path", config.TLSClientConfig.KeyFile,
		"-k8s-master-host", config.Host,
		"-k8s-api-path", config.APIPath,
		"-k8s-master-user", config.Username,
	)

	By("Starting the controller in kubernetes-ovn orchestration mode")
	ctrl, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "Problem starting service in kubernetes-ovn orchestration"+
		"mode")

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

	By("Verifying that the controller started successfully")
	Eventually(ctrl.Err, 3).Should(gbytes.Say(
		"Controller CE ready"),
		"Service did not start in time")

	By("Requesting an authentication token from the controller")
	apiCli = &apiClient{
		Token: authToken(),
	}

	By("Initializing Kubernetes client")
	k8sCli = &k8s.Client{
		CAFile:   config.TLSClientConfig.CAFile,
		CertFile: config.TLSClientConfig.CertFile,
		KeyFile:  config.TLSClientConfig.KeyFile,
		Host:     config.Host,
		APIPath:  config.APIPath,
		Username: config.Username,
	}
	err = k8sCli.Ping()
	Expect(err).ToNot(HaveOccurred(), "Problem connecting to kubernetes")

	By("Building the node")
	exe, err = gexec.Build(
		"github.com/open-ness/edgecontroller/test/node/grpc")
	Expect(err).ToNot(HaveOccurred(), "Problem building node")

	cmd = exec.Command(exe,
		"-ela-port", "42101",
		"-eva-port", "42102",
	)
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
	os.RemoveAll("./temp_telemetry")
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

func postKubeOVNPolicies(policyName string) (id string) {
	if policyName == "" {
		policyName = "kubeovn-policy-1"
	}
	By("Sending a POST /kube_ovn/policies request")
	resp, err := apiCli.Post(
		"http://127.0.0.1:8080/kube_ovn/policies",
		"application/json",
		strings.NewReader(fmt.Sprintf(`
		{
			"name": "%s",
			"ingress_rules": [
				{
				"description": "Sample ingress rule.",
				"from": [
					{
					"cidr": "192.168.1.1/24",
					"except": [
						"192.168.1.1/26"
					]
					}
				],
				"ports": [
					{
					"port": 50000,
					"protocol": "tcp"
					}
				]
				}
			],
			"egress_rules": [
				{
				"description": "Sample egress rule.",
				"to": [
					{
					"cidr": "192.168.1.1/24",
					"except": [
						"192.168.1.1/26"
					]
					}
				],
				"ports": [
					{
					"port": 50000,
					"protocol": "tcp"
					}
				]
				}
			]
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

func getKubeOVNPolicy(id string) *swagger.PolicyKubeOVNDetail {
	By("Sending a GET /kube_ovn/policies/{id} request")
	resp, err := apiCli.Get(
		fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s", id))
	Expect(err).ToNot(HaveOccurred())
	defer resp.Body.Close()

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Reading the response body")
	body, err := ioutil.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())

	var policy swagger.PolicyKubeOVNDetail

	By("Unmarshaling the response")
	Expect(json.Unmarshal(body, &policy)).To(Succeed())

	return &policy
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
		"test-node: listening on port: 4210[12]"),
		"Node did not start in time")
	Eventually(node.Err, 3).Should(gbytes.Say(
		"test-node: listening on port: 4210[12]"),
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

func patchNodesAppsKubeOVNPolicy(nodeID string, appID string, policyID string) {
	By("Sending a PATCH /nodes/{node_id}/apps/{app_id}/policy request")
	resp, err := apiCli.Patch(
		fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeID, appID),
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
