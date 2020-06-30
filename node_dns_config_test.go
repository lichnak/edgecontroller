// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Join Entities: NodeDNSConfig", func() {
	var (
		ncfg *cce.NodeDNSConfig
	)

	BeforeEach(func() {
		ncfg = &cce.NodeDNSConfig{
			ID:          "6c7eacb8-7b95-4541-940c-aa18a6204645",
			NodeID:      "48606c73-3905-47e0-864f-14bc7466f5bb",
			DNSConfigID: "84c1f7b9-53e7-408e-9223-deab73befc54",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "nodes_dns_configs"`, func() {
			Expect(ncfg.GetTableName()).To(Equal("nodes_dns_configs"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(ncfg.GetID()).To(Equal(
				"6c7eacb8-7b95-4541-940c-aa18a6204645"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			ncfg.SetID("456")

			By("Getting the updated ID")
			Expect(ncfg.ID).To(Equal("456"))
		})
	})

	Describe("GetNodeID", func() {
		It("Should return the node ID", func() {
			Expect(ncfg.GetNodeID()).To(Equal(
				"48606c73-3905-47e0-864f-14bc7466f5bb"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			ncfg.ID = "123"
			Expect(ncfg.Validate()).To(MatchError("id not a valid uuid"))
		})

		It("Should return an error if NodeID is not a UUID", func() {
			ncfg.NodeID = "123"
			Expect(ncfg.Validate()).To(MatchError("node_id not a valid uuid"))
		})

		It("Should return an error if DNSConfigID is not a UUID", func() {
			ncfg.DNSConfigID = "123"
			Expect(ncfg.Validate()).To(MatchError(
				"dns_config_id not a valid uuid"))
		})
	})

	Describe("FilterFields", func() {
		It("Should return the filterable fields", func() {
			Expect(ncfg.FilterFields()).To(Equal([]string{
				"node_id",
				"dns_config_id",
			}))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(ncfg.String()).To(Equal(strings.TrimSpace(`
NodeDNSConfig[
    ID: 6c7eacb8-7b95-4541-940c-aa18a6204645
    NodeID: 48606c73-3905-47e0-864f-14bc7466f5bb
    DNSConfigID: 84c1f7b9-53e7-408e-9223-deab73befc54
]`,
			)))
		})
	})
})
