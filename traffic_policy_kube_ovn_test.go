// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: TrafficPolicyKubeOVN", func() {
	var (
		tp *cce.TrafficPolicyKubeOVN
	)

	BeforeEach(func() {
		tp = &cce.TrafficPolicyKubeOVN{
			ID:   "e9d74c09-d4f6-4615-9f38-b3c177f8ad0c",
			Name: "policy-kube-ovn",
			Ingress: []*cce.IngressRule{
				{
					Description: "Ingress1",
					From: []*cce.IPBlock{
						{
							CIDR:   "1.1.0.0/16",
							Except: []string{"1.1.2.0/24", "1.1.3.0/24"},
						},
					},
					Ports: []*cce.Port{
						{
							Protocol: "tcp",
							Port:     80,
						},
					},
				},
				{
					Description: "Ingress2",
					From: []*cce.IPBlock{
						{
							CIDR:   "2.2.0.0/16",
							Except: []string{"2.2.2.0/24", "2.2.3.0/24"},
						},
					},
					Ports: []*cce.Port{
						{
							Protocol: "udp",
							Port:     80,
						},
					},
				},
			},
			Egress: []*cce.EgressRule{
				{
					Description: "Egress1",
					To: []*cce.IPBlock{
						{
							CIDR:   "3.3.0.0/16",
							Except: []string{"3.3.2.0/24", "3.3.3.0/24"},
						},
					},
					Ports: []*cce.Port{
						{
							Protocol: "tcp",
							Port:     80,
						},
					},
				},
				{
					Description: "Egress2",
					To: []*cce.IPBlock{
						{
							CIDR:   "4.4.0.0/16",
							Except: []string{"4.4.2.0/24", "4.4.3.0/24"},
						},
					},
					Ports: []*cce.Port{
						{
							Protocol: "udp",
							Port:     80,
						},
					},
				},
			},
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "traffic_policies"`, func() {
			Expect(tp.GetTableName()).To(Equal("traffic_policies"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(tp.GetID()).To(Equal("e9d74c09-d4f6-4615-9f38-b3c177f8ad0c"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			tp.SetID("c454f156-b3d0-4e0d-89c2-21dea1c7cbbf")

			By("Getting the updated ID")
			Expect(tp.ID).To(Equal("c454f156-b3d0-4e0d-89c2-21dea1c7cbbf"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			tp.ID = "test"
			Expect(tp.Validate()).To(MatchError("id not a valid UUID"))
		})

		It("Should return an error if name is empty", func() {
			tp.Name = ""
			Expect(tp.Validate()).To(MatchError("name cannot be empty"))
		})

		It("Should return an error if there is no rules", func() {
			tp.Ingress = nil
			tp.Egress = nil
			Expect(tp.Validate()).To(MatchError("ingress and egress cannot be empty"))
		})

		It("Should return an error if CIDR is not valid", func() {
			tp.Ingress[0].From[0].CIDR = "1.1.1.1/33"
			Expect(tp.Validate()).To(MatchError(
				"Ingress[0].From[0].Invalid CIDR: invalid CIDR address: 1.1.1.1/33"))

			tp.Ingress[0].From[0].CIDR = "1.1.0.0/16"
			tp.Egress[0].To[0].CIDR = "1.1.1.1/33"
			Expect(tp.Validate()).To(MatchError(
				"Egress[0].To[0].Invalid CIDR: invalid CIDR address: 1.1.1.1/33"))
		})

		It("Should return an error if except CIDR is not valid", func() {
			tp.Ingress[0].From[0].Except[0] = "1.1.1.1/33"
			Expect(tp.Validate()).To(MatchError(
				"Ingress[0].From[0].Except[0].Invalid CIDR: invalid CIDR address: 1.1.1.1/33"))

			tp.Ingress[0].From[0].Except[0] = "1.1.1.0/24"
			tp.Egress[0].To[0].Except[0] = "1.1.1.1/33"
			Expect(tp.Validate()).To(MatchError(
				"Egress[0].To[0].Except[0].Invalid CIDR: invalid CIDR address: 1.1.1.1/33"))
		})

		It("Should return an error if except CIDR is the same as CIDR", func() {
			tp.Ingress[0].From[0].Except[0] = "1.1.0.0/16"
			Expect(tp.Validate()).To(MatchError(
				"Ingress[0].From[0].Except[0].CIDR(1.1.0.0/16) is the same as CIDR(1.1.0.0/16)"))

			tp.Ingress[0].From[0].Except[0] = "1.1.1.0/24"
			tp.Egress[0].To[0].Except[0] = "3.3.0.0/16"
			Expect(tp.Validate()).To(MatchError(
				"Egress[0].To[0].Except[0].CIDR(3.3.0.0/16) is the same as CIDR(3.3.0.0/16)"))
		})

		It("Should return an error if except CIDR is not a subset of CIDR", func() {
			tp.Ingress[0].From[0].Except[0] = "1.2.2.0/24"
			Expect(tp.Validate()).To(MatchError(
				"Ingress[0].From[0].Except[0].CIDR(1.2.2.0/24) is not in CIDR(1.1.0.0/16)"))

			tp.Ingress[0].From[0].Except[0] = "1.1.1.0/24"
			tp.Egress[0].To[0].Except[0] = "3.4.4.0/24"
			Expect(tp.Validate()).To(MatchError(
				"Egress[0].To[0].Except[0].CIDR(3.4.4.0/24) is not in CIDR(3.3.0.0/16)"))
		})

		It("Should return an error if except CIDR mask is not valid", func() {
			tp.Ingress[0].From[0].Except[0] = "1.1.0.0/15"
			Expect(tp.Validate()).To(MatchError(
				"Ingress[0].From[0].Except[0].CIDR(1.1.0.0/15) mask is invalid"))

			tp.Ingress[0].From[0].Except[0] = "1.1.1.0/24"
			tp.Egress[0].To[0].Except[0] = "3.3.0.0/15"
			Expect(tp.Validate()).To(MatchError(
				"Egress[0].To[0].Except[0].CIDR(3.3.0.0/15) mask is invalid"))
		})

		It("Should return success if the rules are correct", func() {
			Expect(tp.Validate()).To(Succeed())
		})
	})
	Describe("String", func() {
		It("Should return the string value", func() {
			fmt.Println(tp)
			Expect(tp.String()).To(Equal(strings.TrimSpace(`
TrafficPolicyKubeOVN[
	ID: e9d74c09-d4f6-4615-9f38-b3c177f8ad0c,
	Name: policy-kube-ovn,
	Ingress: [
		IngressRule[
			Description: Ingress1,
			From: [
				IPBlock[
					CIDR: 1.1.0.0/16,
					Except:	[
						1.1.2.0/24
						1.1.3.0/24
					]
				]
			],
			Ports: [
				Port[
					Port: 80,
					Protocol: tcp
				]
			]
		]
		IngressRule[
			Description: Ingress2,
			From: [
				IPBlock[
					CIDR: 2.2.0.0/16,
					Except:	[
						2.2.2.0/24
						2.2.3.0/24
					]
				]
			],
			Ports: [
				Port[
					Port: 80,
					Protocol: udp
				]
			]
		]
	], 
	Egress: [
		EgressRule[
			Description: Egress1,
			To: [
				IPBlock[
					CIDR: 3.3.0.0/16,
					Except:	[
						3.3.2.0/24
						3.3.3.0/24
					]
				]
			],
			Ports: [
				Port[
					Port: 80,
					Protocol: tcp
				]
			]
		]
		EgressRule[
			Description: Egress2,
			To: [
				IPBlock[
					CIDR: 4.4.0.0/16,
					Except:	[
						4.4.2.0/24
						4.4.3.0/24
					]
				]
			],
			Ports: [
				Port[
					Port: 80,
					Protocol: udp
				]
			]
		]
	]
]`,
			)))
		})
	})

	Describe("ToK8s", func() {
		It("Should convert traffic policy to network policy", func() {
			netpol := tp.ToK8s()

			Expect(netpol.Spec.Ingress).To(HaveLen(2))

			Expect(netpol.Spec.Ingress[0].Ports).To(HaveLen(1))
			Expect(netpol.Spec.Ingress[0].Ports[0].Port.IntValue()).To(Equal(80))
			Expect(*(netpol.Spec.Ingress[0].Ports[0].Protocol)).To(BeEquivalentTo("TCP"))
			Expect(netpol.Spec.Ingress[0].From).To(HaveLen(1))
			Expect(netpol.Spec.Ingress[0].From[0].IPBlock.CIDR).To(Equal("1.1.0.0/16"))
			Expect(netpol.Spec.Ingress[0].From[0].IPBlock.Except).To(HaveLen(2))
			Expect(netpol.Spec.Ingress[0].From[0].IPBlock.Except[0]).To(Equal("1.1.2.0/24"))
			Expect(netpol.Spec.Ingress[0].From[0].IPBlock.Except[1]).To(Equal("1.1.3.0/24"))

			Expect(netpol.Spec.Ingress[1].Ports).To(HaveLen(1))
			Expect(netpol.Spec.Ingress[1].Ports[0].Port.IntValue()).To(Equal(80))
			Expect(*(netpol.Spec.Ingress[1].Ports[0].Protocol)).To(BeEquivalentTo("UDP"))
			Expect(netpol.Spec.Ingress[1].From).To(HaveLen(1))
			Expect(netpol.Spec.Ingress[1].From[0].IPBlock.CIDR).To(Equal("2.2.0.0/16"))
			Expect(netpol.Spec.Ingress[1].From[0].IPBlock.Except).To(HaveLen(2))
			Expect(netpol.Spec.Ingress[1].From[0].IPBlock.Except[0]).To(Equal("2.2.2.0/24"))
			Expect(netpol.Spec.Ingress[1].From[0].IPBlock.Except[1]).To(Equal("2.2.3.0/24"))

			Expect(netpol.Spec.Egress).To(HaveLen(2))

			Expect(netpol.Spec.Egress[0].Ports).To(HaveLen(1))
			Expect(netpol.Spec.Egress[0].Ports[0].Port.IntValue()).To(Equal(80))
			Expect(*(netpol.Spec.Egress[0].Ports[0].Protocol)).To(BeEquivalentTo("TCP"))
			Expect(netpol.Spec.Egress[0].To).To(HaveLen(1))
			Expect(netpol.Spec.Egress[0].To[0].IPBlock.CIDR).To(Equal("3.3.0.0/16"))
			Expect(netpol.Spec.Egress[0].To[0].IPBlock.Except).To(HaveLen(2))
			Expect(netpol.Spec.Egress[0].To[0].IPBlock.Except[0]).To(Equal("3.3.2.0/24"))
			Expect(netpol.Spec.Egress[0].To[0].IPBlock.Except[1]).To(Equal("3.3.3.0/24"))

			Expect(netpol.Spec.Egress[1].Ports).To(HaveLen(1))
			Expect(netpol.Spec.Egress[1].Ports[0].Port.IntValue()).To(Equal(80))
			Expect(*(netpol.Spec.Egress[1].Ports[0].Protocol)).To(BeEquivalentTo("UDP"))
			Expect(netpol.Spec.Egress[1].To).To(HaveLen(1))
			Expect(netpol.Spec.Egress[1].To[0].IPBlock.CIDR).To(Equal("4.4.0.0/16"))
			Expect(netpol.Spec.Egress[1].To[0].IPBlock.Except).To(HaveLen(2))
			Expect(netpol.Spec.Egress[1].To[0].IPBlock.Except[0]).To(Equal("4.4.2.0/24"))
			Expect(netpol.Spec.Egress[1].To[0].IPBlock.Except[1]).To(Equal("4.4.3.0/24"))
		})
	})
})
