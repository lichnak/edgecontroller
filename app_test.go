// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce_test

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
)

var _ = Describe("Entities: App", func() {
	var (
		app *cce.App
	)

	BeforeEach(func() {
		app = &cce.App{
			ID:          "efcece3c-6b58-4993-8d45-bde6239d4baa",
			Type:        "container",
			Name:        "test-container-app",
			Vendor:      "test-vendor",
			Description: "test-description",
			Version:     "latest",
			Cores:       4,
			Memory:      1024,
			Ports: []cce.PortProto{
				{Port: 80, Protocol: "tcp"},
				{Port: 443, Protocol: "tcp"},
			},
			Source: "https://path/to/file.zip",
		}
	})

	Describe("GetTableName", func() {
		It(`Should return "apps"`, func() {
			Expect(app.GetTableName()).To(Equal("apps"))
		})
	})

	Describe("GetID", func() {
		It("Should return the ID", func() {
			Expect(app.GetID()).To(Equal(
				"efcece3c-6b58-4993-8d45-bde6239d4baa"))
		})
	})

	Describe("SetID", func() {
		It("Should set and return the updated ID", func() {
			By("Setting the ID")
			app.SetID("456")

			By("Getting the updated ID")
			Expect(app.ID).To(Equal("456"))
		})
	})

	Describe("Validate", func() {
		It("Should return an error if ID is not a UUID", func() {
			app.ID = "123"
			Expect(app.Validate()).To(MatchError("id not a valid uuid"))
		})

		It(`Should return an error if Type is not "container" or "vm"`, func() {
			app.Type = "foo"
			Expect(app.Validate()).To(MatchError(
				`type must be either "container" or "vm"`))
		})

		It("Should return an error if Name is empty", func() {
			app.Name = ""
			Expect(app.Validate()).To(MatchError("name cannot be empty"))
		})

		It("Should return an error if Version is empty", func() {
			app.Version = ""
			Expect(app.Validate()).To(MatchError("version cannot be empty"))
		})

		It("Should return an error if Vendor is empty", func() {
			app.Vendor = ""
			Expect(app.Validate()).To(MatchError("vendor cannot be empty"))
		})

		It("Should return an error if Cores is < 1", func() {
			app.Cores = 0
			Expect(app.Validate()).To(MatchError("cores must be in [1..8]"))
		})

		It("Should return an error if Cores is > 8", func() {
			app.Cores = 9
			Expect(app.Validate()).To(MatchError("cores must be in [1..8]"))
		})

		It("Should return an error if Memory is < 1", func() {
			app.Memory = 0
			Expect(app.Validate()).To(MatchError(
				"memory must be in [1..16384]"))
		})

		It("Should return an error if Memory is > 16384", func() {
			app.Memory = 16385
			Expect(app.Validate()).To(MatchError(
				"memory must be in [1..16384]"))
		})

		It("Should return an error if Ports (port) is invalid", func() {
			app.Ports[0].Port = 99999
			Expect(app.Validate()).To(MatchError(
				"port must be in [1..65535]"))
		})

		It("Should return an error if Ports (protocol) is invalid", func() {
			app.Ports[0].Protocol = "protocolthatdoesnotexist"
			Expect(app.Validate()).To(MatchError(
				"protocol must be tcp, udp, sctp, icmp or all"))
		})

		It("Should return an error if Source is empty", func() {
			app.Source = ""
			Expect(app.Validate()).To(MatchError("source cannot be empty"))
		})

		It("Should return an error if Source is an invalid HTTP URI", func() {
			app.Source = "invalid.url"
			Expect(app.Validate()).To(MatchError("source cannot be parsed as a URI"))
		})
	})

	Describe("String", func() {
		It("Should return the string value", func() {
			Expect(app.String()).To(Equal(strings.TrimSpace(`
App[
    ID: efcece3c-6b58-4993-8d45-bde6239d4baa
    Name: test-container-app
    Version: latest
    Vendor: test-vendor
    Description: test-description
    Cores: 4
    Memory: 1024
    Ports: [80/tcp 443/tcp]
    Source: https://path/to/file.zip
    EPAFeatures: []
]`,
			)))
		})
	})
})
