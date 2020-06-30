// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("DNS Service Client", func() {
	Describe("SetA", func() {
		Describe("Success", func() {
			It("Should set A records", func() {
				By("Setting A records")
				Expect(dnsSvcCli.SetA(ctx, &cce.DNSARecord{
					Name:        "patient-checkin.choc.org",
					Description: "Patient Check-in Dashboard",
					IPs: []string{
						"app-70233300-C0B4-4315-BAAF-8C4BAF953611",
					},
				})).To(Succeed())
			})
		})

		Describe("Errors", func() {})
	})

	Describe("DeleteA", func() {
		Describe("Success", func() {
			It("Should delete A records", func() {
				By("Deleting A records")
				Expect(dnsSvcCli.DeleteA(ctx, &cce.DNSARecord{
					Name:        "patient-checkin.choc.org",
					Description: "Patient Check-in Dashboard",
					IPs: []string{
						"app-70233300-C0B4-4315-BAAF-8C4BAF953611",
					},
				})).To(Succeed())
			})
		})

		Describe("Errors", func() {})
	})

	Describe("SetForwarders", func() {
		Describe("Success", func() {
			It("Should set forwarders", func() {
				By("Setting forwarders")
				Expect(dnsSvcCli.SetForwarders(ctx, []*cce.DNSForwarder{
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
				})).To(Succeed())
			})
		})

		Describe("Errors", func() {})
	})

	Describe("DeleteForwarders", func() {
		Describe("Success", func() {
			It("Should delete forwarders", func() {
				By("Deleting forwarders")
				Expect(dnsSvcCli.DeleteForwarders(ctx, []*cce.DNSForwarder{
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
				})).To(Succeed())
			})
		})

		Describe("Errors", func() {})
	})
})
