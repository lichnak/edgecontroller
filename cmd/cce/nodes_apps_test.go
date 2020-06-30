// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/open-ness/edgecontroller/nfd-master"
	"github.com/open-ness/edgecontroller/swagger"
	"github.com/open-ness/edgecontroller/uuid"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("/nodes/{node_id}/apps", func() {
	var (
		appID string
	)

	BeforeEach(func() {
		clearGRPCTargetsTable()
		appID = postApps("container")
	})

	Describe("POST /nodes/{node_id}/apps", func() {
		DescribeTable("200 OK",
			func() {
				nodeCfg := createAndRegisterNode()

				By("Sending a POST /nodes/{node_id}/apps request")
				resp, err := apiCli.Post(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeCfg.nodeID),
					"application/json",
					strings.NewReader(fmt.Sprintf(
						`
						{
							"id": "%s"
						}
						`, appID)))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))
			},
			Entry(
				"POST /nodes/{node_id}/apps"),
		)

		DescribeTable("500 Internal server error",
			func() {
				nodeCfg := createAndRegisterNode()

				By("Sending a POST /nodes/{node_id}/apps request")

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
								"source": "http://www.test.com/my_%s_app.tar.gz",
								"epafeatures": [{"key": "NFD:test_id", "value": "nfd_val"}]
							}`, "container", "nfd_req", "nfd_req", "container")))
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

				appid := rb.ID

				respPost, err := apiCli.Post(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeCfg.nodeID),
					"application/json",
					strings.NewReader(fmt.Sprintf(
						`
						{
							"id": "%s"
						}
						`, appid)))
				Expect(err).ToNot(HaveOccurred())
				defer respPost.Body.Close()

				By("Verifying a 500 response")
				Expect(respPost.StatusCode).To(Equal(http.StatusInternalServerError))
			},
			Entry(
				"POST /nodes/{node_id}/apps"),
		)

		DescribeTable("200 OK with EPAValidate",
			func() {
				nodeCfg := createAndRegisterNode()

				By("Sending a POST /nodes/{node_id}/apps request")

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
								"source": "http://www.test.com/my_%s_app.tar.gz",
								"epafeatures": [{"key": "NFD:test_id", "value": "nfd_val"}]
							}`, "container", "nfd_req", "nfd_req", "container")))
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

				appid := rb.ID

				By("Executing the delete query")
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

				persisted := nfd.NodeFeatureNFD{
					ID:       uuid.New(),
					NodeID:   nodeCfg.nodeID,
					NfdID:    "test_id",
					NfdValue: "nfd_val",
				}

				bytes, err := json.Marshal(persisted)
				Expect(err).ToNot(HaveOccurred())

				By("Executing the INSERT query with NodeFeatureNFD")
				_, err = db.ExecContext(
					timeoutCtx,
					"INSERT INTO nodes_nfd_features (entity) VALUES (?)",
					bytes)
				Expect(err).ToNot(HaveOccurred())

				respPost, err := apiCli.Post(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeCfg.nodeID),
					"application/json",
					strings.NewReader(fmt.Sprintf(
						`
						{
							"id": "%s"
						}
						`, appid)))
				Expect(err).ToNot(HaveOccurred())
				defer respPost.Body.Close()

				By("Verifying a 200 response")
				Expect(respPost.StatusCode).To(Equal(http.StatusOK))
			},
			Entry(
				"POST /nodes/{node_id}/apps"),
		)

		DescribeTable("400 Bad Request",
			func(req, expectedResp string) {
				nodeCfg := createAndRegisterNode()

				By("Sending a POST /nodes/{node_id}/apps request")
				resp, err := apiCli.Post(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeCfg.nodeID),
					"application/json",
					strings.NewReader(req))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 400 Bad Request response")
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the response body")
				Expect(string(body)).To(Equal(expectedResp))
			},
			Entry(
				"POST /nodes/{node_id}/apps with no request body",
				`
				`,
				"Error unmarshaling json: unexpected end of JSON input"),
			Entry(
				"POST /nodes/{node_id}/apps with invalid JSON",
				`
				id: %s
				`,
				"Error unmarshaling json: invalid character 'i' looking for beginning of value"),
			Entry(
				"POST /nodes/{node_id}/apps without id field",
				fmt.Sprintf(`
				{
					"foobar": "%s"
				}`, uuid.New()),
				"Validation failed: app_id not a valid uuid"),
		)

		DescribeTable("422 Unprocessable Entity",
			func() {
				nodeCfg := createAndRegisterNode()

				By("Sending a POST /nodes/{node_id}/apps request")
				postNodeApps(nodeCfg.nodeID, appID)

				By("Repeating the first POST /nodes/{node_id}/apps request")
				resp, err := apiCli.Post(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps", nodeCfg.nodeID),
					"application/json",
					strings.NewReader(fmt.Sprintf(
						`
						{
							"id": "%s"
						}`, appID)))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 422 response")
				Expect(resp.StatusCode).To(Equal(
					http.StatusUnprocessableEntity))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the response body")
				Expect(string(body)).To(Equal(fmt.Sprintf(
					"duplicate record in nodes_apps detected for node_id %s and "+
						"app_id %s",
					nodeCfg.nodeID,
					appID)))
			},
			Entry("POST /nodes/{node_id}/apps with duplicate node_id and app_id"),
		)
	})

	Describe("GET /nodes/{node_id}/apps", func() {
		var (
			nodeCfg *nodeConfig
			app2ID  string
		)

		BeforeEach(func() {
			nodeCfg = createAndRegisterNode()
			postNodeApps(nodeCfg.nodeID, appID)
			app2ID = postApps("container")
			postNodeApps(nodeCfg.nodeID, app2ID)
		})

		DescribeTable("200 OK",
			func(appIDFilter string) {
				expectedApps := swagger.NodeAppList{
					NodeApps: []swagger.NodeAppSummary{
						{ID: appID},
						{ID: app2ID},
					},
				}

				nodeApps := getNodeApps(nodeCfg.nodeID)

				By("Verifying the created node app(s) were returned")
				Expect(nodeApps.NodeApps).To(HaveLen(2))
				Expect(nodeApps.NodeApps).To(ContainElement(expectedApps.NodeApps[0]))
				Expect(nodeApps.NodeApps).To(ContainElement(expectedApps.NodeApps[1]))
			},
			Entry("GET /nodes/{node_id}/apps", ""),
		)
	})

	Describe("GET /nodes/{node_id}/apps/{id}", func() {
		DescribeTable("200 OK",
			func() {
				nodeCfg := createAndRegisterNode()
				postNodeApps(nodeCfg.nodeID, appID)
				nodeAppResp := getNodeAppByID(nodeCfg.nodeID, appID)

				By("Verifying the created node app was returned")
				Expect(nodeAppResp).To(Equal(
					swagger.NodeAppDetail{
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
				nodeCfg := createAndRegisterNode()
				By("Sending a GET /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Get(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeCfg.nodeID,
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
		DescribeTable("200 OK",
			func(reqStr string, expectedNodeAppResp *swagger.NodeAppDetail) {
				nodeCfg := createAndRegisterNode()
				postNodeApps(nodeCfg.nodeID, appID)

				By("Sending a PATCH /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s", nodeCfg.nodeID, appID),
					"application/json",
					strings.NewReader(reqStr))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Getting the updated node")
				updatedNodeAppResp := getNodeApp(nodeCfg.nodeID, appID)

				By("Verifying the node was updated")
				expectedNodeAppResp.ID = appID
				Expect(updatedNodeAppResp).To(Equal(expectedNodeAppResp))
			},
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id}",
				`
				{
					"command": "start"
				}
				`,
				&swagger.NodeAppDetail{
					Status: "running",
				}),
		)

		DescribeTable("400 Bad Request",
			func(reqStr string, expectedResp string) {
				nodeCfg := createAndRegisterNode()
				postNodeApps(nodeCfg.nodeID, appID)

				By("Sending a PATCH /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s", nodeCfg.nodeID, appID),
					"application/json",
					strings.NewReader(reqStr))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 400 Bad Request")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the response body")
				Expect(string(body)).To(Equal(expectedResp))
			},
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id} without command",
				`
				`,
				"Error unmarshaling json: unexpected end of JSON input"),
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id} with invalid input",
				`
				command: start
				`,
				"Error unmarshaling json: invalid character 'c' looking for beginning of value"),
		)
	})

	Describe("DELETE /nodes/{node_id}/apps/{app_id}", func() {
		DescribeTable("204 No Content",
			func() {
				nodeCfg := createAndRegisterNode()
				postNodeApps(nodeCfg.nodeID, appID)

				By("Sending a DELETE /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeCfg.nodeID, appID))

				By("Verifying a 204 No Content response")
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

				By("Verifying the node app was deleted")

				By("Sending a GET /nodes/{node_id}/apps/{app_id} request")
				resp2, err := apiCli.Get(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeCfg.nodeID, appID))

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
				nodeCfg := createAndRegisterNode()
				resp, err := apiCli.Delete(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeCfg.nodeID, id))

				By("Verifying a 404 Not Found response")
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"DELETE /nodes/{node_id}/apps/{app_id} with nonexistent ID",
				uuid.New()),
		)

		DescribeTable("422 Unprocessable Entity",
			func(resource, expectedResp string) {
				nodeCfg := createAndRegisterNode()
				postNodeApps(nodeCfg.nodeID, appID)

				switch resource {
				case "nodes_apps_traffic_policies":
					patchNodesAppsPolicy(
						nodeCfg.nodeID,
						appID,
						postPolicies())
				}

				By("Sending a DELETE /nodes/{node_id}/apps/{app_id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s",
						nodeCfg.nodeID,
						appID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 422 response")
				Expect(resp.StatusCode).To(Equal(
					http.StatusUnprocessableEntity))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the response body")
				Expect(string(body)).To(Equal(
					fmt.Sprintf(expectedResp, appID)))
			},
			Entry(
				"DELETE /nodes/{node_id}/apps/{app_id} with nodes_apps_traffic_policies record",
				"nodes_apps_traffic_policies",
				"cannot delete app %s: record in use in nodes_apps_traffic_policies",
			),
		)
	})
})
