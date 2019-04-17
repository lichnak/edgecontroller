// Copyright 2019 Smart-Edge.com, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package clients_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/smartedgemec/controller-ce/pb"
	"github.com/smartedgemec/controller-ce/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = Describe("Network Interface Service", func() {
	BeforeEach(func() {
		By("Resetting the interfaces")
		err := interfaceSvcCli.BulkUpdate(
			ctx,
			&pb.NetworkInterfaces{
				NetworkInterfaces: []*pb.NetworkInterface{
					{
						Id:          "if0",
						Description: "interface0",
						Driver:      pb.NetworkInterface_KERNEL,
						Type:        pb.NetworkInterface_NONE,
						MacAddress:  "mac0",
						Vlan:        0,
						Zones:       nil,
					},
					{
						Id:          "if1",
						Description: "interface1",
						Driver:      pb.NetworkInterface_KERNEL,
						Type:        pb.NetworkInterface_NONE,
						MacAddress:  "mac1",
						Vlan:        1,
						Zones:       nil,
					},
					{
						Id:          "if2",
						Description: "interface2",
						Driver:      pb.NetworkInterface_KERNEL,
						Type:        pb.NetworkInterface_NONE,
						MacAddress:  "mac2",
						Vlan:        2,
						Zones:       nil,
					},
					{
						Id:          "if3",
						Description: "interface3",
						Driver:      pb.NetworkInterface_KERNEL,
						Type:        pb.NetworkInterface_NONE,
						MacAddress:  "mac3",
						Vlan:        3,
						Zones:       nil,
					},
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
				Expect(nis.NetworkInterfaces).To(Equal(
					[]*pb.NetworkInterface{
						{
							Id:                   "if0",
							Description:          "interface0",
							Driver:               pb.NetworkInterface_KERNEL,
							Type:                 pb.NetworkInterface_NONE,
							MacAddress:           "mac0",
							Vlan:                 0,
							Zones:                nil,
							FallbackInterface:    "",
							XXX_NoUnkeyedLiteral: *new(struct{}),
							XXX_unrecognized:     nil,
							XXX_sizecache:        0,
						},
						{
							Id:                   "if1",
							Description:          "interface1",
							Driver:               pb.NetworkInterface_KERNEL,
							Type:                 pb.NetworkInterface_NONE,
							MacAddress:           "mac1",
							Vlan:                 1,
							Zones:                nil,
							FallbackInterface:    "",
							XXX_NoUnkeyedLiteral: *new(struct{}),
							XXX_unrecognized:     nil,
							XXX_sizecache:        0,
						},
						{
							Id:                   "if2",
							Description:          "interface2",
							Driver:               pb.NetworkInterface_KERNEL,
							Type:                 pb.NetworkInterface_NONE,
							MacAddress:           "mac2",
							Vlan:                 2,
							Zones:                nil,
							FallbackInterface:    "",
							XXX_NoUnkeyedLiteral: *new(struct{}),
							XXX_unrecognized:     nil,
							XXX_sizecache:        0,
						},
						{
							Id:                   "if3",
							Description:          "interface3",
							Driver:               pb.NetworkInterface_KERNEL,
							Type:                 pb.NetworkInterface_NONE,
							MacAddress:           "mac3",
							Vlan:                 3,
							Zones:                nil,
							FallbackInterface:    "",
							XXX_NoUnkeyedLiteral: *new(struct{}),
							XXX_unrecognized:     nil,
							XXX_sizecache:        0,
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
					&pb.NetworkInterface{
						Id:          "if0",
						Description: "interface0",
						Driver:      pb.NetworkInterface_KERNEL,
						Type:        pb.NetworkInterface_NONE,
						MacAddress:  "mac0",
						Vlan:        0,
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
				noVNF, err := interfaceSvcCli.Get(ctx, badID)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred(),
					"Expected error but got app: %v", noVNF)
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
					&pb.NetworkInterface{
						Id:          "if2",
						Description: "interface2",
						Driver:      pb.NetworkInterface_USERSPACE,
						Type:        pb.NetworkInterface_BIDIRECTIONAL,
						MacAddress:  "mac2",
						Vlan:        2,
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
					&pb.NetworkInterface{
						Id:          "if2",
						Description: "interface2",
						Driver:      pb.NetworkInterface_USERSPACE,
						Type:        pb.NetworkInterface_BIDIRECTIONAL,
						MacAddress:  "mac2",
						Vlan:        2,
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
					&pb.NetworkInterface{Id: badID})

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
					&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{
								Id:          "if1",
								Description: "interface1",
								Driver:      pb.NetworkInterface_USERSPACE,
								Type:        pb.NetworkInterface_UPSTREAM,
								MacAddress:  "mac1",
								Vlan:        1,
								Zones:       nil,
							},
							{
								Id:          "if3",
								Description: "interface3",
								Driver:      pb.NetworkInterface_USERSPACE,
								Type:        pb.NetworkInterface_DOWNSTREAM,
								MacAddress:  "mac3",
								Vlan:        3,
								Zones:       nil,
							},
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
					&pb.NetworkInterface{
						Id:          "if1",
						Description: "interface1",
						Driver:      pb.NetworkInterface_USERSPACE,
						Type:        pb.NetworkInterface_UPSTREAM,
						MacAddress:  "mac1",
						Vlan:        1,
						Zones:       nil,
					},
				))

				By("Getting the fourth interface")
				ni3, err := interfaceSvcCli.Get(ctx, "if3")

				By("Verifying the response matches the updated interface")
				Expect(err).ToNot(HaveOccurred())
				Expect(ni3).To(Equal(
					&pb.NetworkInterface{
						Id:          "if3",
						Description: "interface3",
						Driver:      pb.NetworkInterface_USERSPACE,
						Type:        pb.NetworkInterface_DOWNSTREAM,
						MacAddress:  "mac3",
						Vlan:        3,
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
					&pb.NetworkInterfaces{
						NetworkInterfaces: []*pb.NetworkInterface{
							{Id: badID},
						},
					},
				)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Interface %s not found", badID)))
			})
		})
	})
})