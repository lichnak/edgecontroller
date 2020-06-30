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

var _ = Describe("Application Policy Service Client", func() {
	var (
		appID           string
		trafficPolicyID string
	)

	BeforeEach(func() {
		var err error

		By("Generating new IDs")
		appID = uuid.New()
		trafficPolicyID = uuid.New()

		By("Deploying an application")
		err = appDeploySvcCli.Deploy(
			ctx,
			&cce.App{
				ID:          appID,
				Type:        "container",
				Name:        "test_container_app",
				Vendor:      "test_vendor",
				Description: "test container app",
				Version:     "latest",
				Cores:       4,
				Memory:      4096,
				Ports:       []cce.PortProto{{Port: 80, Protocol: "tcp"}},
				Source:      "https://path/to/file.zip",
			})
		Expect(err).ToNot(HaveOccurred())
		Expect(appID).ToNot(BeNil())
	})

	Describe("Set", func() {
		Describe("Success", func() {
			It("Should set the traffic policy", func() {
				By("Updating the traffic policy")
				err := appPolicySvcCli.Set(
					ctx,
					appID,
					&cce.TrafficPolicy{
						ID: trafficPolicyID,
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
			It("Should return an error if the app ID does not exist", func() {
				By("Passing a nonexistent app ID")
				badID := uuid.New()
				err := appPolicySvcCli.Set(ctx, badID, &cce.TrafficPolicy{
					ID: trafficPolicyID,
				})

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Application %s not found", badID)))
			})
		})
	})

	Describe("Delete", func() {
		Describe("Success", func() {
			It("Should delete the traffic policy", func() {
				By("Deleting the traffic policy")
				err := appPolicySvcCli.Delete(ctx, appID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the app ID does not exist", func() {
				By("Passing a nonexistent app ID")
				badID := uuid.New()
				err := appPolicySvcCli.Delete(ctx, badID)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Application %s not found", badID)))
			})
		})
	})
})
