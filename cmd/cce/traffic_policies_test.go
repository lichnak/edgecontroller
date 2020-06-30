// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package main_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/swagger"
	"github.com/open-ness/edgecontroller/uuid"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("/policies", func() {
	Describe("PATCH /policies", func() {
		DescribeTable("201 Created",
			func(req string) {
				By("Sending a PATCH /policies request")
				resp, err := apiCli.Post(
					"http://127.0.0.1:8080/policies",
					"application/json",
					strings.NewReader(req))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 201 response")
				Expect(resp.StatusCode).To(Equal(http.StatusCreated))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				var respBody struct {
					ID string
				}

				By("Unmarshaling the response")
				Expect(json.Unmarshal(body, &respBody)).To(Succeed())

				By("Verifying a UUID was returned")
				Expect(uuid.IsValid(respBody.ID)).To(BeTrue())
			},
			Entry(
				"PATCH /policies",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
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
							"description": "destination1",
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
							"description": "target1",
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
				}`),
		)

		DescribeTable("400 Bad Request",
			func(req, expectedResp string) {
				By("Sending a PATCH /policies request")
				resp, err := apiCli.Post(
					"http://127.0.0.1:8080/policies",
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
			Entry("PATCH /policies without a name",
				`
				{
					"name": ""
				}`,
				"Validation failed: name cannot be empty"),
			Entry("PATCH /policies without rules",
				`
				{
					"name": "policy-1",
					"traffic_rules": []
				}`,
				"Validation failed: rules cannot be empty"),
			Entry("PATCH /policies with rules[0].priority not in [1..65535]",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 65537
					}]
				}`,
				"Validation failed: rules[0].priority must be in [1..65535]"),
			Entry("PATCH /policies without rules[0].source & destination",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1
					}]
				}`,
				"Validation failed: rules[0].source & destination cannot both be empty"),
			Entry("PATCH /policies without rules[0].target",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target cannot be empty"),
			Entry("PATCH /policies without rules[0].source.mac_filter|ip_filter|gtp_filter",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1"
						}
					}]
				}`,
				"Validation failed: rules[0].source.mac_filter|ip_filter|gtp_filter cannot all be nil"),
			Entry("PATCH /policies with invalid rules[0].source.mac_filter.mac_addresses[0]",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": [
									"abc-def"
								]
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.mac_filter.mac_addresses[0] could not be parsed (address abc-def: invalid MAC address)"), //nolint:lll
			Entry("PATCH /policies with invalid rules[0].source.ip_filter.address",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "2234.1.1.0"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.address could not be parsed"),
			Entry("PATCH /policies with rules[0].source.ip_filter.mask not in [0..128]",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 129
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.mask must be in [0..128]"),
			Entry("PATCH /policies with rules[0].source.ip_filter.begin_port not in [0..65535]",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 128,
								"begin_port": 65536
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.begin_port must be in [0..65535]"),
			Entry("PATCH /policies with rules[0].source.ip_filter.end_port not in [0..65535]",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 128,
								"begin_port": 65,
								"end_port": 65536
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.end_port must be in [0..65535]"),
			Entry("PATCH /policies with invalid rules[0].source.ip_filter.protocol",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 128,
								"begin_port": 65,
								"end_port": 65535,
								"protocol": "udtcp"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.protocol must be one of [tcp, udp, icmp, sctp, all]"),
			Entry("PATCH /policies with invalid rules[0].target.action",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "forward"
						}
					}]
				}`,
				"Validation failed: rules[0].target.action must be one of [accept, reject, drop]"),
			Entry("PATCH /policies with invalid rules[0].target.mac_modifier.mac_address",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "accept",
							"mac_modifier": {
								"mac_address": "abc-123"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target.mac_modifier.mac_address could not be parsed (address abc-123: invalid MAC address)"), //nolint:lll
			Entry("PATCH /policies with invalid rules[0].target.ip_modifier.address",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "accept",
							"ip_modifier": {
								"address": "424.2.2.93"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target.ip_modifier.address could not be parsed"),
			Entry("PATCH /policies with rules[0].target.ip_modifier.port not in [1..65535]",
				`
				{
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "accept",
							"ip_modifier": {
								"address": "123.2.3.4",
								"port": 65536
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target.ip_modifier.port must be in [1..65535]"),
		)
	})

	Describe("GET /policies", func() {
		var (
			policyID  string
			policyID2 string
		)

		BeforeEach(func() {
			policyID = postPolicies("policy-1")
			policyID2 = postPolicies("policy-2")
		})

		DescribeTable("200 OK",
			func() {
				By("Sending a GET /policies request")
				resp, err := apiCli.Get(
					"http://127.0.0.1:8080/policies")
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				var policies swagger.PolicyList

				By("Unmarshaling the response")
				Expect(json.Unmarshal(body, &policies)).To(Succeed())

				By("Verifying the 2 created policies were returned")
				Expect(policies.Policies).To(ContainElement(
					swagger.PolicySummary{
						ID:   policyID,
						Name: "policy-1",
					}))
				Expect(policies.Policies).To(ContainElement(
					swagger.PolicySummary{
						ID:   policyID2,
						Name: "policy-2",
					}))
			},
			Entry("GET /policies"),
		)
	})

	Describe("GET /policies/{id}", func() {
		var (
			policyID string
		)

		BeforeEach(func() {
			policyID = postPolicies()
		})

		DescribeTable("200 OK",
			func() {
				policy := getPolicy(policyID)

				By("Verifying the created policy was returned")
				Expect(policy).To(Equal(
					&swagger.PolicyDetail{
						PolicySummary: swagger.PolicySummary{
							ID:   policyID,
							Name: "policy-1",
						},
						Rules: []*cce.TrafficRule{
							{
								Description: "test-rule-1",
								Priority:    1,
								Source: &cce.TrafficSelector{
									Description: "test-source-1",
									MACs: &cce.MACFilter{
										MACAddresses: []string{
											"F0-59-8E-7B-36-8A",
											"23-20-8E-15-89-D1",
											"35-A4-38-73-35-45",
										},
									},
									IP: &cce.IPFilter{
										Address:   "223.1.1.0",
										Mask:      16,
										BeginPort: 2000,
										EndPort:   2012,
										Protocol:  "tcp",
									},
									GTP: &cce.GTPFilter{
										Address: "10.6.7.2",
										Mask:    12,
										IMSIs: []string{
											"310150123456789",
											"310150123456790",
											"310150123456791",
										},
									},
								},
								Destination: &cce.TrafficSelector{
									Description: "test-destination-1",
									MACs: &cce.MACFilter{
										MACAddresses: []string{
											"7D-C2-3A-1C-63-D9",
											"E9-6B-D1-D2-1A-6B",
											"C8-32-A9-43-85-55",
										},
									},
									IP: &cce.IPFilter{
										Address:   "64.1.1.0",
										Mask:      16,
										BeginPort: 1000,
										EndPort:   1012,
										Protocol:  "tcp",
									},
									GTP: &cce.GTPFilter{
										Address: "108.6.7.2",
										Mask:    4,
										IMSIs: []string{
											"310150123456792",
											"310150123456793",
											"310150123456794",
										},
									},
								},
								Target: &cce.TrafficTarget{
									Description: "test-target-1",
									Action:      "accept",
									MAC: &cce.MACModifier{
										MACAddress: "C7-5A-E7-98-1B-A3",
									},
									IP: &cce.IPModifier{
										Address: "123.2.3.4",
										Port:    1600,
									},
								},
							},
						},
					},
				))
			},
			Entry("GET /policies/{id}"),
		)

		DescribeTable("404 Not Found",
			func() {
				By("Sending a GET /policies/{id} request")
				resp, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s",
						uuid.New()))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("GET /policies/{id} with nonexistent ID"),
		)
	})

	Describe("PATCH /policies", func() {
		var (
			policyID string
		)

		BeforeEach(func() {
			policyID = postPolicies()
		})

		DescribeTable("200 Status OK",
			func(reqStr string, expectedPolicy *swagger.PolicyDetail) {
				By("Sending a PATCH /policies/{policy_id} request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s", policyID),
					"application/json",
					strings.NewReader(fmt.Sprintf(reqStr, policyID)))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 Status OK response")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Getting the updated policy")
				updatedPolicy := getPolicy(policyID)

				By("Verifying the policy was updated")
				expectedPolicy.ID = policyID
				Expect(updatedPolicy).To(Equal(expectedPolicy))
			},
			Entry(
				"PATCH /policies",
				`
				{
					"id": "%s",
					"name": "policy-2",
					"traffic_rules": [{
						"description": "test-rule-2",
						"priority": 2,
						"source": {
							"description": "test-source-2",
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
							"description": "test-destination-2",
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
							"description": "test-target-2",
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
				}`,
				&swagger.PolicyDetail{
					PolicySummary: swagger.PolicySummary{
						Name: "policy-2",
					},
					Rules: []*cce.TrafficRule{
						{
							Description: "test-rule-2",
							Priority:    2,
							Source: &cce.TrafficSelector{
								Description: "test-source-2",
								MACs: &cce.MACFilter{
									MACAddresses: []string{
										"F0-59-8E-7B-36-8A",
										"23-20-8E-15-89-D1",
										"35-A4-38-73-35-45",
									},
								},
								IP: &cce.IPFilter{
									Address:   "223.1.1.0",
									Mask:      16,
									BeginPort: 2000,
									EndPort:   2012,
									Protocol:  "tcp",
								},
								GTP: &cce.GTPFilter{
									Address: "10.6.7.2",
									Mask:    12,
									IMSIs: []string{
										"310150123456789",
										"310150123456790",
										"310150123456791",
									},
								},
							},
							Destination: &cce.TrafficSelector{
								Description: "test-destination-2",
								MACs: &cce.MACFilter{
									MACAddresses: []string{
										"7D-C2-3A-1C-63-D9",
										"E9-6B-D1-D2-1A-6B",
										"C8-32-A9-43-85-55",
									},
								},
								IP: &cce.IPFilter{
									Address:   "64.1.1.0",
									Mask:      16,
									BeginPort: 1000,
									EndPort:   1012,
									Protocol:  "tcp",
								},
								GTP: &cce.GTPFilter{
									Address: "108.6.7.2",
									Mask:    4,
									IMSIs: []string{
										"310150123456792",
										"310150123456793",
										"310150123456794",
									},
								},
							},
							Target: &cce.TrafficTarget{
								Description: "test-target-2",
								Action:      "accept",
								MAC: &cce.MACModifier{
									MACAddress: "C7-5A-E7-98-1B-A3",
								},
								IP: &cce.IPModifier{
									Address: "123.2.3.4",
									Port:    1600,
								},
							},
						},
					},
				}),
		)

		DescribeTable("400 Bad Request",
			func(reqStr string, expectedResp string) {
				By("Sending a PATCH /policies/{policy_id} request")
				if strings.Contains(reqStr, "%s") {
					reqStr = fmt.Sprintf(reqStr, policyID)
				}
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s", policyID),
					"application/json",
					strings.NewReader(reqStr))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 400 Bad Request")
				Expect(resp.StatusCode).To(Equal(http.StatusBadRequest))

				By("Reading the response body")
				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the response body")
				Expect(string(body)).To(Equal(expectedResp))
			},
			Entry("PATCH /policies/{policy_id} without name",
				`
					{
						"id": "%s"
					}
				`,
				"Validation failed: name cannot be empty"),
			Entry("PATCH /policies without a name",
				`
				{
					"id": "%s",
					"name": ""
				}`,
				"Validation failed: name cannot be empty"),
			Entry("PATCH /policies without rules",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": []
				}`,
				"Validation failed: rules cannot be empty"),
			Entry("PATCH /policies with rules[0].priority not in [1..65535]",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 65536
					}]
				}`,
				"Validation failed: rules[0].priority must be in [1..65535]"),
			Entry("PATCH /policies without rules[0].source & destination",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1
					}]
				}`,
				"Validation failed: rules[0].source & destination cannot both be empty"),
			Entry("PATCH /policies without rules[0].target",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target cannot be empty"),
			Entry("PATCH /policies without rules[0].source.mac_filter|ip_filter|gtp_filter",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1"
						}
					}]
				}`,
				"Validation failed: rules[0].source.mac_filter|ip_filter|gtp_filter cannot all be nil"),
			Entry("PATCH /policies with invalid rules[0].source.mac_filter.mac_addresses[0]",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": [
									"abc-def"
								]
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.mac_filter.mac_addresses[0] could not be parsed (address abc-def: invalid MAC address)"), //nolint:lll
			Entry("PATCH /policies with invalid rules[0].source.ip_filter.address",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "2234.1.1.0"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.address could not be parsed"),
			Entry("PATCH /policies with rules[0].source.ip_filter.mask not in [0..128]",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 129
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.mask must be in [0..128]"),
			Entry("PATCH /policies with rules[0].source.ip_filter.begin_port not in [0..65535]",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 128,
								"begin_port": 65536
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.begin_port must be in [0..65535]"),
			Entry("PATCH /policies with rules[0].source.ip_filter.end_port not in [0..65535]",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 128,
								"begin_port": 65,
								"end_port": 65537
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.end_port must be in [0..65535]"),
			Entry("PATCH /policies with invalid rules[0].source.ip_filter.protocol",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"ip_filter": {
								"address": "223.1.1.0",
								"mask": 128,
								"begin_port": 65,
								"end_port": 65535,
								"protocol": "udtcp"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].source.ip_filter.protocol must be one of [tcp, udp, icmp, sctp, all]"),
			Entry("PATCH /policies with invalid rules[0].target.action",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "forward"
						}
					}]
				}`,
				"Validation failed: rules[0].target.action must be one of [accept, reject, drop]"),
			Entry("PATCH /policies with invalid rules[0].target.mac_modifier.mac_address",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "accept",
							"mac_modifier": {
								"mac_address": "abc-123"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target.mac_modifier.mac_address could not be parsed (address abc-123: invalid MAC address)"), //nolint:lll
			Entry("PATCH /policies with invalid rules[0].target.ip_modifier.address",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "accept",
							"ip_modifier": {
								"address": "424.2.2.93"
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target.ip_modifier.address could not be parsed"),
			Entry("PATCH /policies with rules[0].target.ip_modifier.port not in [1..65535]",
				`
				{
					"id": "%s",
					"name": "policy-1",
					"traffic_rules": [{
						"description": "rule1",
						"priority": 1,
						"source": {
							"description": "source1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"destination": {
							"description": "destination1",
							"mac_filter": {
								"mac_addresses": []
							}
						},
						"target": {
							"description": "target1",
							"action": "accept",
							"ip_modifier": {
								"address": "123.2.3.4",
								"port": 65537
							}
						}
					}]
				}`,
				"Validation failed: rules[0].target.ip_modifier.port must be in [1..65535]"),
		)
	})

	Describe("DELETE /policies/{id}", func() {
		var (
			policyID string
		)

		BeforeEach(func() {
			policyID = postPolicies()
		})

		DescribeTable("200 OK",
			func() {
				By("Sending a DELETE /policies/{id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s",
						policyID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Verifying the traffic policy was deleted")

				By("Sending a GET /policies/{id} request")
				resp, err = apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s",
						policyID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("DELETE /policies/{id}"),
		)

		DescribeTable("404 Not Found",
			func(id string) {
				By("Sending a DELETE /policies/{id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s",
						id))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"DELETE /policies/{id} with nonexistent ID",
				uuid.New()),
		)

		DescribeTable("422 Unprocessable Entity",
			func(resource, expectedResp string) {
				switch resource {
				case "nodes_apps_traffic_policies":
					clearGRPCTargetsTable()
					nodeCfg := createAndRegisterNode()
					appID := postApps("container")
					postNodeApps(nodeCfg.nodeID, appID)
					policyID = postPolicies()
					patchNodesAppsPolicy(nodeCfg.nodeID, appID, policyID)
				}

				By("Sending a DELETE /policies/{id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/policies/%s",
						policyID))
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
					fmt.Sprintf(expectedResp, policyID)))
			},
			Entry(
				"DELETE /policies/{id} with nodes_apps_traffic_policies record",
				"nodes_apps_traffic_policies",
				"cannot delete traffic_policy_id %s: record in use in nodes_apps_traffic_policies",
			),
		)
	})
})
