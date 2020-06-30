// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main_test

import (
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

var _ = Describe("/nodes/{node_id}/dns", func() {
	Describe("PATCH /nodes/{node_id}/dns", func() {
		DescribeTable("200 OK",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				patchNodeDNS(nodeCfg.nodeID)
				appID := postApps("container")
				postNodeApps(nodeCfg.nodeID, appID)
				patchNodeDNSwithApp(nodeCfg.nodeID, appID)
			},
			Entry(
				"PATCH /nodes/{node_id}/dns"),
		)

		DescribeTable("400 Bad Request",
			func(req, expectedResp string) {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				By("Sending a PATCH /nodes/{node_id}/dns request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/dns", nodeCfg.nodeID),
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
				"PATCH /nodes/{node_id}/dns without description of a record",
				fmt.Sprintf(`
				{
					"records": {
						"a": [{"name": "foobar.com", "values": ["%s"]}]
					}
				}`, uuid.New()),
				"DNS call failed mid operation: description cannot be empty"),
			Entry(
				"PATCH /nodes/{node_id}/dns with invalid value for a non-alias record",
				fmt.Sprintf(`
					{
						"records": {
							"a": [{"name": "foobar.com", "description": "foobar", "values": ["%s"]}]
						}
					}`, uuid.New()),
				"DNS call failed mid operation: ips[0] could not be parsed"),
		)
		DescribeTable("501 Not Implemented",
			func(req, expectedResp string) {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				By("Sending a PATCH /nodes/{node_id}/dns request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/dns", nodeCfg.nodeID),
					"application/json",
					strings.NewReader(req))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 501 Not Implemented response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotImplemented))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the response body")
				Expect(string(body)).To(Equal(expectedResp))
			},
			Entry(
				"PATCH /nodes/{node_id}/dns with a forwarder provided",
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
						}
					  ]
					},
					"configurations": {
					  "forwarders" : [
						  {
								"name": "Google DNS",
								"description": "This is the DNS server for Google",
								"value": "8.8.8.8"
						  }
					   ]
					}
				}`),
				"DNS call failed mid operation: received unimplemented field forwarders in request"),
		)
	})

	Describe("GET /nodes/{node_id}/dns", func() {
		DescribeTable("200 OK",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				patchNodeDNS(nodeCfg.nodeID)

				By("Sending a GET /nodes/{node_id}/dns request")
				resp, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/dns", nodeCfg.nodeID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				var nodeDNSConfigs swagger.DNSDetail

				By("Unmarshaling the response")
				Expect(json.Unmarshal(body, &nodeDNSConfigs)).
					To(Succeed())

				By("Verifying the created node <-> DNS configs were returned")
				Expect(nodeDNSConfigs.Records.A).To(ContainElement(
					swagger.DNSARecord{
						Name:        "sample-app1.demosite.com",
						Description: "The domain for my sample app 1",
						Alias:       false,
						Values:      []string{"192.168.1.5"},
					}))
			},
			Entry("GET /nodes/{node_id}/dns"),
		)
		DescribeTable("200 OK",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()

				By("Sending a GET /nodes/{node_id}/dns request")
				resp, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/nodes/%s/dns", nodeCfg.nodeID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				var nodeDNSConfigs swagger.DNSDetail

				By("Unmarshaling the response")
				Expect(json.Unmarshal(body, &nodeDNSConfigs)).
					To(Succeed())

				By("Verifying the created node <-> DNS configs were returned")
				Expect(nodeDNSConfigs).To(Equal(swagger.DNSDetail{
					Records:        swagger.DNSRecords{A: []swagger.DNSARecord{}},
					Configurations: swagger.DNSConfigurations{Forwarders: []swagger.DNSForwarder{}},
				}))
			},
			Entry("GET /nodes/{node_id}/dns"),
		)
	})

	Describe("DELETE /nodes/dns_configs/{id}", func() {
		DescribeTable("204 No Content",
			func() {
				clearGRPCTargetsTable()
				nodeCfg := createAndRegisterNode()
				patchNodeDNS(nodeCfg.nodeID)

				By("Sending a DELETE /nodes/{node_id}/dns request")
				resp, err := apiCli.Delete(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/dns",
						nodeCfg.nodeID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 204 No Content response")
				Expect(resp.StatusCode).To(Equal(http.StatusNoContent))

				By("Verifying the node <-> DNS config was deleted")

				By("Sending a GET /nodes/{node_id}/dns request")
				nodeDNS := getNodeDNS(nodeCfg.nodeID)

				By("Verifying that the response is empty")
				Expect(nodeDNS).To(Equal(&swagger.DNSDetail{
					Records:        swagger.DNSRecords{A: []swagger.DNSARecord{}},
					Configurations: swagger.DNSConfigurations{Forwarders: []swagger.DNSForwarder{}},
				}))
			},
			Entry("DELETE /nodes/{node_id}/dns"),
		)

		DescribeTable("404 Not Found",
			func() {
				By("Sending a DELETE /nodes/{node_id}/dns request")
				resp, err := apiCli.Delete(
					fmt.Sprintf(
						"http://127.0.0.1:8080/nodes/%s/dns",
						uuid.New()))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"DELETE /nodes/{node_id}/dns with nonexistent ID"),
		)
	})
})
