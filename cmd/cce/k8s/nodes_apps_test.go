// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package k8s_test

import (
	"fmt"
	"github.com/open-ness/edgecontroller/swagger"
	"io/ioutil"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/open-ness/edgecontroller/uuid"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("/nodes/{node_id}/apps for k8s", func() {
	var (
		nodeCfg *nodeConfig
		nodeID  string
		appID   string
	)

	BeforeEach(func() {
		// clean
		clearGRPCTargetsTable()
		nodeCfg = createAndRegisterNode()
		nodeID = nodeCfg.nodeID

		// label node with correct id
		execParam := fmt.Sprintf("node-id=%s", nodeID)
		Expect(exec.Command("kubectl",
			"label", "nodes", "minikube", execParam).Run()).To(Succeed())

		appID = postApps("container")

		// tag docker with app id
		execParam = fmt.Sprintf("%s:%s", appID, "latest")
		cmd := exec.Command("docker", "tag", "nginx:1.12", execParam)
		Expect(cmd.Run()).To(Succeed())
	})

	AfterEach(func() {
		// un-label node
		Expect(exec.Command("kubectl", "label", "nodes", "minikube", "node-id-").Run()).To(Succeed())

		// clean up all k8s deployments
		cmd := exec.Command("kubectl", "delete", "--all", "deployments,pods", "--namespace=default")
		Expect(cmd.Run()).To(Succeed())
		// remove tagged docker image
		execParam := fmt.Sprintf("%s:%s", appID, "latest")
		cmd = exec.Command("docker", "rmi", execParam)
		Expect(cmd.Run()).To(Succeed())
	})

	Describe("POST /nodes/{node_id}/apps", func() {
		DescribeTable("200 OK",
			func() {
				By("Sending a POST /nodes/{node_id}/apps request")
				resp, err := apiCli.Post(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeID),
					"application/json",
					strings.NewReader(fmt.Sprintf(
						`
						{
							"id": "%s"
						}`, appID)))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Reading the response body")
				_, err = ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
			},
			Entry("POST /nodes/{node_id}/apps"),
		)
	})

	Describe("GET /nodes/{node_id}/apps", func() {
		var (
			app2ID string
		)

		BeforeEach(func() {
			postNodeApps(nodeID, appID)

			app2ID = postApps("container")

			execParam := fmt.Sprintf("%s:%s", app2ID, "latest")
			cmd := exec.Command("docker", "tag", "nginx:1.12", execParam)
			Expect(cmd.Run()).To(Succeed())

			postNodeApps(nodeID, app2ID)
		})

		AfterEach(func() {
			execParam := fmt.Sprintf("%s:%s", app2ID, "latest")
			cmd := exec.Command("docker", "rmi", execParam)
			Expect(cmd.Run()).To(Succeed())
		})

		DescribeTable("200 OK",
			func() {
				By("Verifying the 2 created node apps were deployed")
				count := 0
				Eventually(func() *swagger.NodeAppDetail {
					count++
					By(fmt.Sprintf("Attempt #%d: Verifying if k8s deployment status is deployed", count))
					return getNodeApp(nodeID, appID)
				}, 15*time.Second, 1*time.Second).Should(Equal(
					&swagger.NodeAppDetail{
						NodeAppSummary: swagger.NodeAppSummary{
							ID: appID,
						},
						Status: "deployed",
					},
				))

				count = 0
				Eventually(func() *swagger.NodeAppDetail {
					count++
					By(fmt.Sprintf("Attempt #%d: Verifying if k8s deployment status is deployed", count))
					return getNodeApp(nodeID, app2ID)
				}, 15*time.Second, 1*time.Second).Should(Equal(
					&swagger.NodeAppDetail{
						NodeAppSummary: swagger.NodeAppSummary{
							ID: app2ID,
						},
						Status: "deployed",
					},
				))
			},
			Entry("GET /nodes/{node_id}/apps/{app_id}"),
		)
	})

	Describe("GET /nodes/{node_id}/apps/{app_id}", func() {
		BeforeEach(func() {
			postNodeApps(nodeID, appID)
		})

		DescribeTable("200 OK",
			func() {
				nodeAppResp := getNodeApp(nodeID, appID)
				By("Verifying the created node app was deployed")
				Expect(nodeAppResp).To(Equal(
					&swagger.NodeAppDetail{
						NodeAppSummary: swagger.NodeAppSummary{
							ID: appID,
						},
						Status: "deployed",
					},
				))
			},
			Entry("GET /nodes/{node_id}/apps/{app_id}"),
		)

		DescribeTable("404 Not Found",
			func() {
				By("Sending a GET /nodes_apps/{id} request")
				resp, err := apiCli.Get(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeID,
						uuid.New()))

				By("Verifying a 404 Not Found response")
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("GET /nodes/{node_id}/apps/{app_id} with nonexistent ID"),
		)
	})

	Describe("PATCH /nodes/{node_id}/apps/{app_id}", func() {
		BeforeEach(func() {
			postNodeApps(nodeID, appID)
		})

		DescribeTable("200 OK",
			func(reqStr string, expectedNodeAppFull *swagger.NodeAppDetail) {
				By("Sending a PATCH /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Patch(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeID,
						appID,
					),
					"application/json",
					strings.NewReader(reqStr),
				)
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Verifying the node was updated")
				expectedNodeAppFull.NodeAppSummary = swagger.NodeAppSummary{
					ID: appID,
				}
				count := 0
				Eventually(func() *swagger.NodeAppDetail {
					count++
					By(fmt.Sprintf("Attempt #%d: Verifying if k8s deployment status is %s",
						count, expectedNodeAppFull.Status))
					return getNodeApp(nodeID, appID)
				}, 30*time.Second, 1*time.Second).Should(Equal(expectedNodeAppFull))
			},
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id} (command='start')",
				`
				{
					"command": "start"
				}
				`,
				&swagger.NodeAppDetail{
					// due to limitations of minikube support other than linux
					Status: status(),
				},
			),
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id} (command='stop')",
				`
				{
					"command": "stop"
				}
				`,
				&swagger.NodeAppDetail{
					Status: "deployed",
				},
			),
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id} (command='restart')",
				`
				{
					"command": "restart"
				}
				`,
				&swagger.NodeAppDetail{
					// due to limitations of minikube support other than linux
					Status: status(),
				},
			),
		)
	})

	Describe("DELETE /nodes/{node_id}/apps/{app_id}", func() {
		BeforeEach(func() {
			postNodeApps(nodeID, appID)
		})

		DescribeTable("204 No Content",
			func() {
				By("Sending a DELETE /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeID,
						appID))

				By("Verifying a 200 OK response")
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

				By("Verifying the node app was deleted")

				By("Sending a GET /nodes/{node_id}/apps/{app_id} request")
				resp2, err := apiCli.Get(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeID,
						appID))

				By("Verifying a 404 Not Found response")
				Expect(err).ToNot(HaveOccurred())
				defer resp2.Body.Close()
				Expect(resp2.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("DELETE /nodes/{node_id}/apps/{app_id}"),
		)

		DescribeTable("404 Not Found",
			func(id string) {
				By("Sending a DELETE /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeID,
						id))

				By("Verifying a 404 Not Found response")
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"DELETE /nodes/{node_id}/apps/{app_id} with nonexistent ID",
				uuid.New()),
		)
	})
})

func status() string {
	if runtime.GOOS == "linux" {
		return "deployed"
	}
	return "deploying"
}
