// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/uuid"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = Describe("Network Interface Service Client", func() {
	BeforeEach(func() {
		By("Resetting the interfaces")
		err := interfaceSvcCli.BulkUpdate(
			ctx,
			[]*cce.NetworkInterface{
				{
					ID:          "if0",
					Description: "interface0",
					Driver:      "kernel",
					Type:        "none",
					MACAddress:  "mac0",
					VLAN:        0,
					Zones:       nil,
				},
				{
					ID:          "if1",
					Description: "interface1",
					Driver:      "kernel",
					Type:        "none",
					MACAddress:  "mac1",
					VLAN:        1,
					Zones:       nil,
				},
				{
					ID:          "if2",
					Description: "interface2",
					Driver:      "kernel",
					Type:        "none",
					MACAddress:  "mac2",
					VLAN:        2,
					Zones:       nil,
				},
				{
					ID:          "if3",
					Description: "interface3",
					Driver:      "kernel",
					Type:        "none",
					MACAddress:  "mac3",
					VLAN:        3,
					Zones:       nil,
				},
			},
		)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("GetAll", func() {
		Describe("Success", func() {
			It("Should get all interfaces", func() {
				By("Getting all interfaces")
				nis, err := interfaceSvcCli.GetAll(ctx)

				By("Verifying the response contains all four interfaces")
				Expect(err).ToNot(HaveOccurred())
				Expect(nis).To(Equal(
					[]*cce.NetworkInterface{
						{
							ID:                "if0",
							Description:       "interface0",
							Driver:            "kernel",
							Type:              "none",
							MACAddress:        "mac0",
							VLAN:              0,
							Zones:             nil,
							FallbackInterface: "",
						},
						{
							ID:                "if1",
							Description:       "interface1",
							Driver:            "kernel",
							Type:              "none",
							MACAddress:        "mac1",
							VLAN:              1,
							Zones:             nil,
							FallbackInterface: "",
						},
						{
							ID:                "if2",
							Description:       "interface2",
							Driver:            "kernel",
							Type:              "none",
							MACAddress:        "mac2",
							VLAN:              2,
							Zones:             nil,
							FallbackInterface: "",
						},
						{
							ID:                "if3",
							Description:       "interface3",
							Driver:            "kernel",
							Type:              "none",
							MACAddress:        "mac3",
							VLAN:              3,
							Zones:             nil,
							FallbackInterface: "",
						},
					},
				))
			})
		})

		Describe("Errors", func() {})
	})

	Describe("Get", func() {
		Describe("Success", func() {
			It("Should get interfaces", func() {
				By("Getting the first interface")
				ni0, err := interfaceSvcCli.Get(ctx, "if0")

				By("Verifying the response")
				Expect(err).ToNot(HaveOccurred())
				Expect(ni0).To(Equal(
					&cce.NetworkInterface{
						ID:          "if0",
						Description: "interface0",
						Driver:      "kernel",
						Type:        "none",
						MACAddress:  "mac0",
						VLAN:        0,
						Zones:       nil,
					},
				))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the interface does not "+
				"exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				noIF, err := interfaceSvcCli.Get(ctx, badID)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred(),
					"Expected error but got interface: %v", noIF)
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Interface %s not found", badID)))
			})
		})
	})

	Describe("Update", func() {
		Describe("Success", func() {
			It("Should update interfaces", func() {
				By("Updating the third network interface")
				err := interfaceSvcCli.Update(
					ctx,
					&cce.NetworkInterface{
						ID:          "if2",
						Description: "interface2",
						Driver:      "userspace",
						Type:        "bidirectional",
						MACAddress:  "mac2",
						VLAN:        2,
						Zones:       nil,
					},
				)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Getting the updated interface")
				ni2, err := interfaceSvcCli.Get(ctx, "if2")

				By("Verifying the response matches the updated interface")
				Expect(err).ToNot(HaveOccurred())
				Expect(ni2).To(Equal(
					&cce.NetworkInterface{
						ID:          "if2",
						Description: "interface2",
						Driver:      "userspace",
						Type:        "bidirectional",
						MACAddress:  "mac2",
						VLAN:        2,
						Zones:       nil,
					},
				))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the ID does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				err := interfaceSvcCli.Update(ctx,
					&cce.NetworkInterface{ID: badID})

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Interface %s not found", badID)))
			})
		})
	})

	Describe("BulkUpdate", func() {
		Describe("Success", func() {
			It("Should bulk update interfaces", func() {
				By("Bulk updating the second and fourth network interfaces")
				err := interfaceSvcCli.BulkUpdate(
					ctx,
					[]*cce.NetworkInterface{
						{
							ID:          "if0",
							Description: "interface0",
							Driver:      "kernel",
							Type:        "none",
							MACAddress:  "mac0",
							VLAN:        0,
							Zones:       nil,
						},
						{
							ID:          "if1",
							Description: "interface1",
							Driver:      "userspace",
							Type:        "upstream",
							MACAddress:  "mac1",
							VLAN:        1,
							Zones:       nil,
						},
						{
							ID:          "if2",
							Description: "interface2",
							Driver:      "kernel",
							Type:        "none",
							MACAddress:  "mac2",
							VLAN:        2,
							Zones:       nil,
						},
						{
							ID:          "if3",
							Description: "interface3",
							Driver:      "userspace",
							Type:        "downstream",
							MACAddress:  "mac3",
							VLAN:        3,
							Zones:       nil,
						},
					},
				)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Getting the second interface")
				ni1, err := interfaceSvcCli.Get(ctx, "if1")

				By("Verifying the response matches the updated interface")
				Expect(err).ToNot(HaveOccurred())
				Expect(ni1).To(Equal(
					&cce.NetworkInterface{
						ID:          "if1",
						Description: "interface1",
						Driver:      "userspace",
						Type:        "upstream",
						MACAddress:  "mac1",
						VLAN:        1,
						Zones:       nil,
					},
				))

				By("Getting the fourth interface")
				ni3, err := interfaceSvcCli.Get(ctx, "if3")

				By("Verifying the response matches the updated interface")
				Expect(err).ToNot(HaveOccurred())
				Expect(ni3).To(Equal(
					&cce.NetworkInterface{
						ID:          "if3",
						Description: "interface3",
						Driver:      "userspace",
						Type:        "downstream",
						MACAddress:  "mac3",
						VLAN:        3,
						Zones:       nil,
					},
				))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the ID does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				err := interfaceSvcCli.BulkUpdate(
					ctx,
					[]*cce.NetworkInterface{
						{ID: badID},
					},
				)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Interface %s not found", badID)))
			})

			It("Should return an error if not all interfaces are sent in the request", func() {
				By("Not passing all interfaces")
				err := interfaceSvcCli.BulkUpdate(
					ctx,
					[]*cce.NetworkInterface{
						{
							ID:          "if0",
							Description: "interface0",
							Driver:      "kernel",
							Type:        "none",
							MACAddress:  "mac0",
							VLAN:        0,
							Zones:       nil,
						},
					},
				)

				By("Verifying a FailedPrecondition response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.FailedPrecondition,
						"Network Interface if1 missing from request")))
			})
		})
	})
})
