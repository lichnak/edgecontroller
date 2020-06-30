// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Join Entities: NodeAppTrafficPolicy", func() {
	var (
		natp *cce.NodeAppTrafficPolicy
	)

	BeforeEach(func() {
		natp = &cce.NodeAppTrafficPolicy{
			ID:              "a2243693-4fcb-4b80-a914-3c3662424abd",
			NodeAppID:       "7a41f67a-086a-4ec2-a980-5db97d9c9f4e",
			TrafficPolicyID: "9d740cee-035f-4076-847c-d1c80cdf19db",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "nodes_apps_traffic_policies"`, func() {
			Expect(natp.GetTableName()).To(Equal(
				"nodes_apps_traffic_policies"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(natp.GetID()).To(Equal(
				"a2243693-4fcb-4b80-a914-3c3662424abd"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			natp.SetID("456")

			By("Getting the updated ID")
			Expect(natp.ID).To(Equal("456"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			natp.ID = "123"
			Expect(natp.Validate()).To(MatchError("id not a valid uuid"))
		})

		It("Should return an error if NodeAppID is not a "+
			"UUID", func() {
			natp.NodeAppID = "123"
			Expect(natp.Validate()).To(MatchError(
				"nodes_apps_id not a valid uuid"))
		})

		It("Should return an error if TrafficPolicyID is not a UUID", func() {
			natp.TrafficPolicyID = "123"
			Expect(natp.Validate()).To(MatchError(
				"traffic_policy_id not a valid uuid"))
		})
	})

	Describe("FilterFields", func() {
		It("Should return the filterable fields", func() {
			Expect(natp.FilterFields()).To(Equal([]string{
				"nodes_apps_id",
				"traffic_policy_id",
			}))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(natp.String()).To(Equal(strings.TrimSpace(`
NodeAppTrafficPolicy[
    ID: a2243693-4fcb-4b80-a914-3c3662424abd
    NodeAppID: 7a41f67a-086a-4ec2-a980-5db97d9c9f4e
    TrafficPolicyID: 9d740cee-035f-4076-847c-d1c80cdf19db
]`,
			)))
		})
	})
})
