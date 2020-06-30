// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Join Entities: NodeApp", func() {
	var (
		na *cce.NodeApp
	)

	BeforeEach(func() {
		na = &cce.NodeApp{
			ID:     "7a41f67a-086a-4ec2-a980-5db97d9c9f4e",
			NodeID: "48606c73-3905-47e0-864f-14bc7466f5bb",
			AppID:  "efcece3c-6b58-4993-8d45-bde6239d4baa",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "nodes_apps"`, func() {
			Expect(na.GetTableName()).To(Equal("nodes_apps"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(na.GetID()).To(Equal(
				"7a41f67a-086a-4ec2-a980-5db97d9c9f4e"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			na.SetID("456")

			By("Getting the updated ID")
			Expect(na.ID).To(Equal("456"))
		})
	})

	Describe("GetNodeID", func() {
		It("Should return the node ID", func() {
			Expect(na.GetNodeID()).To(Equal(
				"48606c73-3905-47e0-864f-14bc7466f5bb"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			na.ID = "123"
			Expect(na.Validate()).To(MatchError("id not a valid uuid"))
		})

		It("Should return an error if NodeID is not a UUID", func() {
			na.NodeID = "123"
			Expect(na.Validate()).To(MatchError("node_id not a valid uuid"))
		})

		It("Should return an error if AppID is not a UUID", func() {
			na.AppID = "123"
			Expect(na.Validate()).To(MatchError(
				"app_id not a valid uuid"))
		})
	})

	Describe("FilterFields", func() {
		It("Should return the filterable fields", func() {
			Expect(na.FilterFields()).To(Equal([]string{
				"node_id",
				"app_id",
			}))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(na.String()).To(Equal(strings.TrimSpace(`
NodeApp[
    ID: 7a41f67a-086a-4ec2-a980-5db97d9c9f4e
    NodeID: 48606c73-3905-47e0-864f-14bc7466f5bb
    AppID: efcece3c-6b58-4993-8d45-bde6239d4baa
]`,
			)))
		})
	})
})
