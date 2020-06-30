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

var _ = Describe("Network Interface Policy Service Client", func() {
	Describe("Set", func() {
		Describe("Success", func() {
			It("Should set the traffic policy", func() {
				By("Updating if2's traffic policy")
				err := interfacePolicySvcCli.Set(
					ctx,
					"if2",
					&cce.TrafficPolicy{
						ID: uuid.New(),
						Rules: []*cce.TrafficRule{
							{
								Description: "updated_rule",
								Priority:    0,
								Source: &cce.TrafficSelector{
									Description: "updated_source",
									MACs: &cce.MACFilter{
										MACAddresses: []string{
											"updated_source_mac_0",
											"updated_source_mac_1",
										},
									},
								},
								Destination: &cce.TrafficSelector{
									Description: "updated_destination",
									MACs: &cce.MACFilter{
										MACAddresses: []string{
											"updated_dest_mac_0",
											"updated_dest_mac_1",
										},
									},
								},
								Target: &cce.TrafficTarget{
									Description: "updated_target",
									Action:      "accept",
									MAC: &cce.MACModifier{
										MACAddress: "updated_target_mac",
									},
									IP: &cce.IPModifier{
										Address: "127.0.0.1",
										Port:    9999,
									},
								},
							},
						},
					},
				)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the ID does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				err := interfacePolicySvcCli.Set(ctx, badID, &cce.TrafficPolicy{
					ID: uuid.New(),
				})

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Interface %s not found", badID)))
			})
		})
	})

	Describe("Delete", func() {
		Describe("Success", func() {
			It("Should delete the traffic policy", func() {
				By("Deleting the traffic policy")
				err := interfacePolicySvcCli.Delete(ctx, "if2")

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the interface ID does not exist", func() {
				By("Passing a nonexistent interface ID")
				badID := uuid.New()
				err := interfacePolicySvcCli.Delete(ctx, badID)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Interface %s not found", badID)))
			})
		})
	})
})
