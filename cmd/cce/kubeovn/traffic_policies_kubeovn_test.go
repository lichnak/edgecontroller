// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package kubeovn_test

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

var _ = Describe("/kube_ovn/policies", func() {
	Describe("PATCH /kube_ovn/policies", func() {
		DescribeTable("201 Created",
			func(req string) {
				By("Sending a PATCH /kube_ovn/policies request")
				resp, err := apiCli.Post(
					"http://127.0.0.1:8080/kube_ovn/policies",
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
				"PATCH /kube_ovn/policies",
				`
				{
					"name": "Sample Traffic Policy",
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
				}`),
		)
		DescribeTable("400 Bad Request",
			func(req, expectedResp string) {
				By("Sending a patch /kube_ovn/policies request")
				resp, err := apiCli.Post(
					"http://127.0.0.1:8080/kube_ovn/policies",
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
			Entry("PATCH /kube_ovn/policies without a name",
				`
				{
					"name": ""
				}`,
				"Validation failed: name cannot be empty"),
			Entry("PATCH /kube_ovn/policies without rules",
				`
				{
					"name": "kubeovn-policy-1",
					"ingress_rules": [],
					"egress_rules": []
				}`,
				"Validation failed: ingress and egress cannot be empty"),
			Entry("PATCH /kube_ovn/policies with bad port protocol in egress rule",
				`
				{
					"name": "kubeovn-policy-1",
					"ingress_rules": [],
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
								"protocol": "gtp"
							  }
							]
						}
					]
				}`,
				"Validation failed: Egress[0].Ports[0].Not supported protocol: gtp"),
			Entry("PATCH /kube_ovn/policies with bad CIDR in except field in egress rule",
				`
				{
					"name": "kubeovn-policy-1",
					"ingress_rules": [],
					"egress_rules": [
						{
							"description": "Sample egress rule.",
							"to": [
								{
									"cidr": "192.168.1.1/24",
									"except": [
										"192.168.1.1"
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
				}`,
				"Validation failed: Egress[0].To[0].Except[0].Invalid CIDR: invalid CIDR address: 192.168.1.1"),
			Entry("PATCH /kube_ovn/policies with bad CIDR address in ingress rule",
				`
				{
					"name": "kubeovn-policy-1",
					"ingress_rules": [
						{
							"description": "Sample ingress rule.",
							"from": [
								{
									"cidr": "192.168.1.1321/24",
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
					"egress_rules": []
				}`,
				"Validation failed: Ingress[0].From[0].Invalid CIDR: invalid CIDR address: 192.168.1.1321/24"),
		)
	})
	Describe("GET /kube_ovn/policies", func() {
		var (
			policyID  string
			policyID2 string
		)

		BeforeEach(func() {
			policyID = postKubeOVNPolicies("kubeovn-policy-1")
			policyID2 = postKubeOVNPolicies("kubeovn-policy-2")
		})

		DescribeTable("200 OK",
			func() {
				By("Sending a GET /kube_ovn/policies request")
				resp, err := apiCli.Get(
					"http://127.0.0.1:8080/kube_ovn/policies")
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
						Name: "kubeovn-policy-1",
					}))
				Expect(policies.Policies).To(ContainElement(
					swagger.PolicySummary{
						ID:   policyID2,
						Name: "kubeovn-policy-2",
					}))
			},
			Entry("GET /kube_ovn/policies"),
		)
	})

	Describe("GET /kube_ovn/policies/{id}", func() {
		var (
			policyID string
		)

		BeforeEach(func() {
			policyID = postKubeOVNPolicies("kubeovn-policy-1")
		})

		DescribeTable("200 OK",
			func() {
				policy := getKubeOVNPolicy(policyID)

				By("Verifying the created KubeOVN policy was returned")
				Expect(policy).To(Equal(
					&swagger.PolicyKubeOVNDetail{
						PolicySummary: swagger.PolicySummary{
							ID:   policyID,
							Name: "kubeovn-policy-1",
						},
						IngressRules: []*cce.IngressRule{
							{
								Description: "Sample ingress rule.",
								From: []*cce.IPBlock{
									{
										CIDR: "192.168.1.1/24",
										Except: []string{
											"192.168.1.1/26",
										},
									},
								},
								Ports: []*cce.Port{
									{
										Port:     50000,
										Protocol: "tcp",
									},
								},
							},
						},
						EgressRules: []*cce.EgressRule{
							{
								Description: "Sample egress rule.",
								To: []*cce.IPBlock{
									{
										CIDR: "192.168.1.1/24",
										Except: []string{
											"192.168.1.1/26",
										},
									},
								},
								Ports: []*cce.Port{
									{
										Port:     50000,
										Protocol: "tcp",
									},
								},
							},
						},
					}))
			},
			Entry("GET /kube_ovn/policies/{id}"),
		)

		DescribeTable("404 Not Found",
			func() {
				By("Sending a GET /kube_ovn/policies/{id} request")
				resp, err := apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s",
						uuid.New()))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("GET /kube_ovn/policies/{id} with nonexistent ID"),
		)
	})

	Describe("PATCH /kube_ovn/policies/{policy_id}", func() {
		var (
			policyID string
		)

		BeforeEach(func() {
			policyID = postKubeOVNPolicies("kubeovn-policy-1")
		})

		DescribeTable("200 Status OK",
			func(reqStr string, expectedPolicy *swagger.PolicyKubeOVNDetail) {
				By("Sending a PATCH /kube_ovn/policies/{policy_id} request")
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s", policyID),
					"application/json",
					strings.NewReader(fmt.Sprintf(reqStr, policyID)))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 Status OK response")
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Getting the updated policy")
				updatedPolicy := getKubeOVNPolicy(policyID)

				By("Verifying the policy was updated")
				expectedPolicy.ID = policyID
				Expect(updatedPolicy).To(Equal(expectedPolicy))
			},
			Entry(
				"PATCH /kube_ovn/policies/{policy_id}",
				`
				{
					"id": "%s",
					"name": "kubeovn-policy-1",
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
				}`,
				&swagger.PolicyKubeOVNDetail{
					PolicySummary: swagger.PolicySummary{
						ID:   policyID,
						Name: "kubeovn-policy-1",
					},
					IngressRules: []*cce.IngressRule{
						{
							Description: "Sample ingress rule.",
							From: []*cce.IPBlock{
								{
									CIDR: "192.168.1.1/24",
									Except: []string{
										"192.168.1.1/26",
									},
								},
							},
							Ports: []*cce.Port{
								{
									Port:     50000,
									Protocol: "tcp",
								},
							},
						},
					},
					EgressRules: []*cce.EgressRule{
						{
							Description: "Sample egress rule.",
							To: []*cce.IPBlock{
								{
									CIDR: "192.168.1.1/24",
									Except: []string{
										"192.168.1.1/26",
									},
								},
							},
							Ports: []*cce.Port{
								{
									Port:     50000,
									Protocol: "tcp",
								},
							},
						},
					},
				}),
		)

		DescribeTable("400 Bad Request",
			func(reqStr string, expectedResp string) {
				By("Sending a PATCH /kube_ovn/policies/{policy_id} request")
				if strings.Contains(reqStr, "%s") {
					reqStr = fmt.Sprintf(reqStr, policyID)
				}
				resp, err := apiCli.Patch(
					fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s", policyID),
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
			Entry("PATCH /kube_ovn/policies/{policy_id} without name",
				`
				{
					"id": "%s"
				}
				`,
				"Validation failed: name cannot be empty"),
			Entry("PATCH /kube_ovn/policies/{policy_id} without ingress/egress rules",
				`
				{
					"id": "%s",
					"name": "kubeovn-policy-1",
					"ingress_rules": [],
					"egress_rules": []
				}
				`,
				"Validation failed: ingress and egress cannot be empty"),
			Entry("PATCH /kube_ovn/policies/{policy_id} with bad port protocol in egress rule",
				`
				{
					"id": "%s",
					"name": "kubeovn-policy-1",
					"ingress_rules": [],
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
								"protocol": "gtp"
							  }
							]
						}
					]
				}`,
				"Validation failed: Egress[0].Ports[0].Not supported protocol: gtp"),
			Entry("PATCH /kube_ovn/policies/{policy_id} with bad CIDR in except field in egress rule",
				`
				{
					"id": "%s",
					"name": "kubeovn-policy-1",
					"ingress_rules": [],
					"egress_rules": [
						{
							"description": "Sample egress rule.",
							"to": [
								{
									"cidr": "192.168.1.1/24",
									"except": [
										"192.168.1.1"
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
				}`,
				"Validation failed: Egress[0].To[0].Except[0].Invalid CIDR: invalid CIDR address: 192.168.1.1"),
			Entry("PATCH /kube_ovn/policies/{policy_id} with bad CIDR address in ingress rule",
				`
				{
					"id": "%s",
					"name": "kubeovn-policy-1",
					"ingress_rules": [
						{
							"description": "Sample ingress rule.",
							"from": [
								{
									"cidr": "192.168.1.1321/24",
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
					"egress_rules": []
				}`,
				"Validation failed: Ingress[0].From[0].Invalid CIDR: invalid CIDR address: 192.168.1.1321/24"),
		)
	})

	Describe("DELETE /kube_ovn/policies/{id}", func() {
		var (
			policyID string
		)

		BeforeEach(func() {
			policyID = postKubeOVNPolicies("kubeovn-policy-1")
		})

		DescribeTable("200 OK",
			func() {
				By("Sending a DELETE /kube_ovn/policies/{id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s",
						policyID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 200 OK response")
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				By("Verifying the traffic policy was deleted")

				By("Sending a GET /kube_ovn/policies/{id} request")
				resp, err = apiCli.Get(
					fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s",
						policyID))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry("DELETE /kube_ovn/policies/{id}"),
		)

		DescribeTable("404 Not Found",
			func(id string) {
				By("Sending a DELETE /kube_ovn/policies/{id} request")
				resp, err := apiCli.Delete(
					fmt.Sprintf("http://127.0.0.1:8080/kube_ovn/policies/%s",
						id))
				Expect(err).ToNot(HaveOccurred())
				defer resp.Body.Close()

				By("Verifying a 404 Not Found response")
				Expect(resp.StatusCode).To(Equal(http.StatusNotFound))
			},
			Entry(
				"DELETE /kube_ovn/policies/{id} with nonexistent ID",
				uuid.New()),
		)
	})
})
