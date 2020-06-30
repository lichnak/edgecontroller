// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: DNSConfig", func() {
	var (
		cfg *cce.DNSConfig
	)

	BeforeEach(func() {
		cfg = &cce.DNSConfig{
			ID:   "84c1f7b9-53e7-408e-9223-deab73befc54",
			Name: "Configuration: CHOC Hospital MECs",
			ARecords: []*cce.DNSARecord{
				{
					Name:        "patient-checkin.choc.org",
					Description: "Patient Check-in Dashboard",
					IPs: []string{
						"172.16.55.43",
						"172.16.55.44",
					},
				},
			},
			Forwarders: []*cce.DNSForwarder{
				{
					Name:        "Google DNS #1",
					Description: "Google's DNS servers (primary)",
					IP:          "8.8.8.8",
				},
				{
					Name:        "Cloudflare DNS #1",
					Description: "Cloudflare's DNS servers (backup)",
					IP:          "1.1.1.1",
				},
			},
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "dns_configs"`, func() {
			Expect(cfg.GetTableName()).To(Equal("dns_configs"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(cfg.GetID()).To(Equal(
				"84c1f7b9-53e7-408e-9223-deab73befc54"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			cfg.SetID("456")

			By("Getting the updated ID")
			Expect(cfg.ID).To(Equal("456"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			cfg.ID = "123"
			Expect(cfg.Validate()).To(MatchError("id not a valid uuid"))
		})

		It("Should return an error if Name is empty", func() {
			cfg.Name = ""
			Expect(cfg.Validate()).To(MatchError("name cannot be empty"))
		})

		It("Should return an error if ARecords and Forwarders are both"+
			"empty", func() {
			cfg.ARecords = nil
			cfg.Forwarders = nil
			Expect(cfg.Validate()).To(MatchError(
				"a_records|forwarders cannot both be empty"))
		})

		It("Should return an error if ARecords.Name is empty", func() {
			cfg.ARecords[0].Name = ""
			Expect(cfg.Validate()).To(MatchError(
				"a_records[0].name cannot be empty"))
		})

		It("Should return an error if ARecords.Description is empty", func() {
			cfg.ARecords[0].Description = ""
			Expect(cfg.Validate()).To(MatchError(
				"a_records[0].description cannot be empty"))
		})

		It("Should return an error if ARecords.IPs is empty", func() {
			cfg.ARecords[0].IPs = nil
			Expect(cfg.Validate()).To(MatchError(
				"a_records[0].ips cannot be empty"))
		})

		It("Should return an error if ARecords.IPs contains an empty IP "+
			"address", func() {
			cfg.ARecords[0].IPs[0] = ""
			Expect(cfg.Validate()).To(MatchError(
				"a_records[0].ips[0] cannot be empty"))
		})

		It("Should return an error if ARecords.IPs contains an invalid IP "+
			"address", func() {
			cfg.ARecords[0].IPs[0] = "abc"
			Expect(cfg.Validate()).To(MatchError(
				"a_records[0].ips[0] could not be parsed"))
		})

		It("Should return an error if ARecords.IPs contains a zero IP "+
			"address", func() {
			cfg.ARecords[0].IPs[0] = "0.0.0.0"
			Expect(cfg.Validate()).To(MatchError(
				"a_records[0].ips[0] cannot be zero"))
		})

		It("Should return an error if Forwarders.Name is empty", func() {
			cfg.Forwarders[0].Name = ""
			Expect(cfg.Validate()).To(MatchError(
				"forwarders[0].name cannot be empty"))
		})

		It("Should return an error if Forwarders.Description is empty", func() {
			cfg.Forwarders[0].Description = ""
			Expect(cfg.Validate()).To(MatchError(
				"forwarders[0].description cannot be empty"))
		})

		It("Should return an error if Forwarders.IP is empty", func() {
			cfg.Forwarders[0].IP = ""
			Expect(cfg.Validate()).To(MatchError(
				"forwarders[0].ip cannot be empty"))
		})

		It("Should return an error if Forwarders.IP is invalid", func() {
			cfg.Forwarders[0].IP = "abc"
			Expect(cfg.Validate()).To(MatchError(
				"forwarders[0].ip could not be parsed"))
		})

		It("Should return an error if Forwarders.IP is zero", func() {
			cfg.Forwarders[0].IP = "0.0.0.0"
			Expect(cfg.Validate()).To(MatchError(
				"forwarders[0].ip cannot be zero"))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(cfg.String()).To(Equal(strings.TrimSpace(`
DNSConfig[
    ID: 84c1f7b9-53e7-408e-9223-deab73befc54
    Name: Configuration: CHOC Hospital MECs
    ARecords: [
        DNSARecord[
            Name: patient-checkin.choc.org
            Description: Patient Check-in Dashboard
            IPs: [
                172.16.55.43
                172.16.55.44
            ]
        ]
    ]
    Forwarders: [
        DNSForwarder[
            Name: Google DNS #1
            Description: Google's DNS servers (primary)
            IP: 8.8.8.8
        ]
        DNSForwarder[
            Name: Cloudflare DNS #1
            Description: Cloudflare's DNS servers (backup)
            IP: 1.1.1.1
        ]
    ]
]`,
			)))
		})
	})
})
