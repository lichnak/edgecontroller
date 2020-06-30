// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: DNSConfigAppAlias", func() {
	var (
		cfgAlias *cce.DNSConfigAppAlias
	)

	BeforeEach(func() {
		cfgAlias = &cce.DNSConfigAppAlias{
			ID:          "8066699a-e81d-4d1f-b860-3ff836c0409f",
			DNSConfigID: "84c1f7b9-53e7-408e-9223-deab73befc54",
			Name:        "test-dns-config-app-alias",
			Description: "test-description",
			AppID:       "efcece3c-6b58-4993-8d45-bde6239d4baa",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "dns_configs_app_aliases"`, func() {
			Expect(cfgAlias.GetTableName()).To(Equal(
				"dns_configs_app_aliases"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(cfgAlias.GetID()).To(Equal(
				"8066699a-e81d-4d1f-b860-3ff836c0409f"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			cfgAlias.SetID("456")

			By("Getting the updated ID")
			Expect(cfgAlias.ID).To(Equal("456"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			cfgAlias.ID = "123"
			Expect(cfgAlias.Validate()).To(MatchError("id not a valid uuid"))
		})

		It("Should return an error if DNSConfigID is not a UUID", func() {
			cfgAlias.DNSConfigID = "123"
			Expect(cfgAlias.Validate()).To(MatchError(
				"dns_config_id not a valid uuid"))
		})

		It("Should return an error if Name is empty", func() {
			cfgAlias.Name = ""
			Expect(cfgAlias.Validate()).To(MatchError("name cannot be empty"))
		})

		It("Should return an error if Description is empty", func() {
			cfgAlias.Description = ""
			Expect(cfgAlias.Validate()).To(MatchError(
				"description cannot be empty"))
		})

		It("Should return an error if AppID is not a UUID", func() {
			cfgAlias.AppID = "123"
			Expect(cfgAlias.Validate()).To(MatchError(
				"app_id not a valid uuid"))
		})
	})

	Describe("FilterFields", func() {
		It("Should return the filterable fields", func() {
			Expect(cfgAlias.FilterFields()).To(Equal([]string{
				"dns_config_id",
				"app_id",
			}))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(cfgAlias.String()).To(Equal(strings.TrimSpace(`
DNSConfigAppAlias[
    ID: 8066699a-e81d-4d1f-b860-3ff836c0409f
    DNSConfigID: 84c1f7b9-53e7-408e-9223-deab73befc54
    AppID: efcece3c-6b58-4993-8d45-bde6239d4baa
]`,
			)))
		})
	})
})
