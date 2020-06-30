// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: NodeGRPCTarget", func() {
	var (
		target *cce.NodeGRPCTarget
	)

	BeforeEach(func() {
		target = &cce.NodeGRPCTarget{
			ID:         "ca0fa495-1020-405b-a78c-9a1884349078",
			NodeID:     "48606c73-3905-47e0-864f-14bc7466f5bb",
			GRPCTarget: "127.0.0.1",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "node_grpc_targets"`, func() {
			Expect(target.GetTableName()).To(Equal("node_grpc_targets"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(target.GetID()).To(Equal(
				"ca0fa495-1020-405b-a78c-9a1884349078"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			target.SetID("456")

			By("Getting the updated ID")
			Expect(target.ID).To(Equal("456"))
		})
	})

	Describe("GetNodeID", func() {
		It("Should return the target ID", func() {
			Expect(target.GetNodeID()).To(Equal(
				"48606c73-3905-47e0-864f-14bc7466f5bb"))
		})
	})

	Describe("FilterFields", func() {
		It("Should return the filterable fields", func() {
			Expect(target.FilterFields()).To(Equal([]string{
				"node_id",
			}))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(target.String()).To(Equal(strings.TrimSpace(`
NodeGRPCTarget[
    ID: ca0fa495-1020-405b-a78c-9a1884349078
    NodeID: 48606c73-3905-47e0-864f-14bc7466f5bb
    GRPCTarget: 127.0.0.1
]`,
			)))
		})
	})
})
