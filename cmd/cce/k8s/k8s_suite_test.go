// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package k8s_test

import (
	"bytes"
	"context"
	"io"
	"net"

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
	"syscall"
	"testing"
	"time"

	"github.com/joho/godotenv"
	k8sV1 "k8s.io/api/core/v1"
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
	RunSpecs(t, "Controller CE K8S API Suite")
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
		"-orchestration-mode", "kubernetes",
		"-k8s-client-ca-path", config.TLSClientConfig.CAFile,
		"-k8s-client-cert-path", config.TLSClientConfig.CertFile,
		"-k8s-client-key-path", config.TLSClientConfig.KeyFile,
		"-k8s-master-host", config.Host,
		"-k8s-api-path", config.APIPath,
		"-k8s-master-user", config.Username,
	)

	By("Starting the controller in kubernetes orchestration mode")
	ctrl, err = gexec.Start(cmd, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred(), "Problem starting service in kubernetes orchestration mode")

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
				"cores": 1,
				"memory": 128,
				"source": "http://www.test.com/my_%s_app.tar.gz",
				"ports": [{"port": 80, "protocol": "tcp"}]
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
				"name": "Test-Node-1",
				"location": "Localhost port 42101",
				"serial": "%s",
				"grpc_target": "127.0.0.1:42101"
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

	By("Verifying a 200 OK response")
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	By("Verifying app deployment success")
	count := 0
	Eventually(func() *swagger.NodeAppDetail {
		count++
		By(fmt.Sprintf("Attempt #%d: Verifying if k8s deployment status is deployed", count))
		return getNodeApp(nodeID, appID)
	}, 30*time.Second, 1*time.Second).Should(Equal(
		&swagger.NodeAppDetail{
			NodeAppSummary: swagger.NodeAppSummary{
				ID: appID,
			},
			Status: "deployed",
		},
	))
}

func deployApp(nodeID, appID string) {
	By("Getting the current user")
	u, err := user.Current()
	Expect(err).ToNot(HaveOccurred())

	By("Building path to minikube config file")
	config, err := clientcmd.BuildConfigFromFlags("", path.Join(u.HomeDir, ".kube", "config"))
	Expect(err).ToNot(HaveOccurred())

	By("Initializing kubernetes client")
	k8sCli = &k8s.Client{
		Username: config.Username,
		Host:     config.Host,
		APIPath:  config.APIPath,
		CertFile: config.TLSClientConfig.CertFile,
		KeyFile:  config.TLSClientConfig.KeyFile,
		CAFile:   config.TLSClientConfig.CAFile,
	}
	By("Verifying Kubernetes client can connet to Kubernetes API")
	Expect(k8sCli.Ping()).To(Succeed())

	app := k8s.App{
		ID:     appID,
		Image:  "nginx:1.12", // commonly used public docker container
		Cores:  1,
		Memory: 100,
	}

	// override image pull policy to always pull image
	k8sCli.ImagePullPolicy = k8sV1.PullAlways

	By("Verifying app deployment call to to Kubernetes API successful")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = k8sCli.Deploy(ctx, nodeID, app)
	Expect(err).ToNot(HaveOccurred())

	By("Verifying app start call to Kubernetes API successful")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = k8sCli.Start(ctx, nodeID, appID)
	Expect(err).ToNot(HaveOccurred())

	// revert image pull policy back to default value: never pull
	k8sCli.ImagePullPolicy = k8sV1.PullNever

	By("Verifying app deployment success")
	count := 0
	Eventually(func() k8s.LifecycleStatus {
		count++
		By(fmt.Sprintf("Attempt #%d: Verifying if k8s deployment status is deployed", count))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		status, err := k8sCli.Status(ctx, nodeID, appID)
		Expect(err).ToNot(HaveOccurred())

		return status
	}, 60*time.Second, 1*time.Second).Should(Equal(k8s.Deployed))
}

func getNodeApp(nodeID, appID string) *swagger.NodeAppDetail {
	By("Sending a GET /nodes/{node_id}/apps/{app_id} request")
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
