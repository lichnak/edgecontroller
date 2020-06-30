// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package kubeovn_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/open-ness/edgecontroller/swagger"
	"github.com/open-ness/edgecontroller/uuid"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("/nodes/{node_id}/apps/{app_id}/kube_ovn/policy", func() {
	Describe("PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy", func() {
		DescribeTable("200 OK",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				appID := postApps("container")
				postNodeApps(nodeCfg.nodeID, appID)
				policyID := postKubeOVNPolicies("")

				By("Sending a PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeCfg.nodeID, appID),
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

				By("Checking network policies in kubernetes")
				netpol, err := k8sCli.GetNetworkPolicy(context.TODO(), nodeCfg.nodeID, appID)
				Expect(netpol).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())

				By("Creating a new policy")
				policy2ID := postKubeOVNPolicies("")

				By("Sending a second PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp2, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeCfg.nodeID, appID),
					"application/json",
					strings.NewReader(fmt.Sprintf(
						`
						{
							"id": "%s"
						}`, policy2ID)))
				Expect(err).ToNot(HaveOccurred())
				defer resp2.Body.Close()

				By("Verifying a 200 response")
				Expect(resp2.StatusCode).To(Equal(http.StatusOK))

				By("Checking network policies in kubernetes")
				netpol, err = k8sCli.GetNetworkPolicy(context.TODO(), nodeCfg.nodeID, appID)
				Expect(netpol).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())
			},
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy"),
		)

		DescribeTable("400 Bad Request",
			func(req string) {
				By("Sending a PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy")
				nodeID := uuid.New()
				appID := uuid.New()

				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeID, appID),
					"application/json",
					strings.NewReader(req))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 400 Bad Request response")
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				By("Checking network policies in kubernetes")
				_, err = k8sCli.GetNetworkPolicy(context.TODO(), nodeID, appID)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not found"))
			},
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with invalid payload",
				`"id": "123"`),
		)

		DescribeTable("404 Not Found",
			func(reqType string) {
				By("Sending a PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy")
				var nodeID, appID, policyID string
				switch reqType {
				case "nodeID":
					nodeID = uuid.New()
					appID = uuid.New()
					policyID = uuid.New()
				case "appID":
					clearGRPCTargetsTable()
					nodeCfg := createAndRegisterNode()
					nodeID = nodeCfg.nodeID
					appID = uuid.New()
					policyID = uuid.New()
				case "policyID":
					clearGRPCTargetsTable()
					nodeCfg := createAndRegisterNode()
					nodeID = nodeCfg.nodeID
					appID = postApps("container")
					policyID = uuid.New()
				}

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

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))

				By("Checking network policies in kubernetes")
				_, err = k8sCli.GetNetworkPolicy(context.TODO(), nodeID, appID)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not found"))
			},
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent node ID",
				"nodeID"),
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent app ID",
				"appID"),
			Entry(
				"PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent policy ID",
				"policyID"),
		)
	})

	Describe("GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy", func() {
		DescribeTable("200 OK",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				appID := postApps("container")
				postNodeApps(nodeCfg.nodeID, appID)
				policyID := postKubeOVNPolicies("")
				patchNodesAppsKubeOVNPolicy(nodeCfg.nodeID, appID, policyID)

				By("Sending a GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeCfg.nodeID, appID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				var baseResource swagger.BaseResource

				By("Unmarshaling the response")
				Expect(json.Unmarshal(body, &baseResource)).To(Succeed())

				By("Verifying the created node app traffic policy was returned")
				Expect(baseResource).To(Equal(
					swagger.BaseResource{
						ID: policyID,
					},
				))
			},
			Entry(
				"GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy"),
		)

		DescribeTable("404 Not Found",
			func(reqType string) {
				var nodeID, appID string
				switch reqType {
				case "nodeID":
					nodeID = uuid.New()
					appID = uuid.New()
				case "appID":
					clearGRPCTargetsTable()
					nodeCfg := createAndRegisterNode()
					nodeID = nodeCfg.nodeID
					appID = uuid.New()
				}

				By("Sending a GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeID, appID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent node ID",
				"nodeID"),
			Entry(
				"GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent app ID",
				"appID"),
		)
	})

	Describe("DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy", func() {
		DescribeTable("204 No Content",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				appID := postApps("container")
				postNodeApps(nodeCfg.nodeID, appID)
				policyID := postKubeOVNPolicies("")
				patchNodesAppsKubeOVNPolicy(nodeCfg.nodeID, appID, policyID)

				By("Checking if network policy exists")
				_, err := k8sCli.GetNetworkPolicy(context.TODO(), nodeCfg.nodeID, appID)
				Expect(err).ToNot(HaveOccurred())

				By("Sending a DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeCfg.nodeID, appID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 204 No Content response")
				Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

				By("Checking if network policy exists")
				_, err = k8sCli.GetNetworkPolicy(context.TODO(), nodeCfg.nodeID, appID)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not found"))

				By("Verifying the node app traffic policy was deleted")

				By("Sending a GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp2, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeCfg.nodeID, appID))
				Expect(err).ToNot(HaveOccurred())
				defer resp2.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp2.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy"),
		)

		DescribeTable("404 Not Found",
			func(reqType string) {
				var nodeID, appID string
				switch reqType {
				case "nodeID":
					nodeID = uuid.New()
					appID = uuid.New()
				case "appID":
					clearGRPCTargetsTable()
					nodeCfg := createAndRegisterNode()
					nodeID = nodeCfg.nodeID
					appID = uuid.New()
				case "policy":
					clearGRPCTargetsTable()
					nodeCfg := createAndRegisterNode()
					nodeID = nodeCfg.nodeID
					appID = postApps("container")
				}

				By("Sending a DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/apps/%s/kube_ovn/policy", nodeID, appID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent node ID",
				"nodeID"),
			Entry(
				"DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy with nonexistent app ID",
				"appID"),
			Entry(
				"DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy without policy",
				"policy"),
		)
	})
})
