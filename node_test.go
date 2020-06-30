// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: Node", func() {
	var (
		node *cce.Node
	)

	BeforeEach(func() {
		node = &cce.Node{
			ID:       "48606c73-3905-47e0-864f-14bc7466f5bb",
			Name:     "test-node",
			Location: "test-location",
			Serial:   "test-serial",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "nodes"`, func() {
			Expect(node.GetTableName()).To(Equal("nodes"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(node.GetID()).To(Equal(
				"48606c73-3905-47e0-864f-14bc7466f5bb"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			node.SetID("456")

			By("Getting the updated ID")
			Expect(node.ID).To(Equal("456"))
		})
	})

	Describe("GetNodeID", func() {
		It("Should return the node ID", func() {
			Expect(node.GetNodeID()).To(Equal(
				"48606c73-3905-47e0-864f-14bc7466f5bb"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			node.ID = "123"
			Expect(node.Validate()).To(MatchError("id not a valid uuid"))
		})

		It("Should return an error if Name is empty", func() {
			node.Name = ""
			Expect(node.Validate()).To(MatchError("name cannot be empty"))
		})

		It("Should return an error if Location is empty", func() {
			node.Location = ""
			Expect(node.Validate()).To(MatchError("location cannot be empty"))
		})

		It("Should return an error if Serial is empty", func() {
			node.Serial = ""
			Expect(node.Validate()).To(MatchError("serial cannot be empty"))
		})
	})

	Describe("FilterFields", func() {
		It("Should return the filterable fields", func() {
			Expect(node.FilterFields()).To(Equal([]string{
				"serial",
			}))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(node.String()).To(Equal(strings.TrimSpace(`
Node[
    ID: 48606c73-3905-47e0-864f-14bc7466f5bb
    Name: test-node
    Location: test-location
    Serial: test-serial
]`,
			)))
		})
	})
})
