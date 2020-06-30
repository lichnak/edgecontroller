// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"github.com/open-ness/edgecontroller/uuid"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ = Describe("Network Zone Service Client", func() {
	var (
		zoneID  string
		zone2ID string
	)

	BeforeEach(func() {
		var err error

		By("Generating new IDs")
		zoneID = uuid.New()
		zone2ID = uuid.New()

		By("Creating a new zone")
		zone := &elapb.NetworkZone{
			Id:          zoneID,
			Description: "test_network_zone",
		}
		err = zoneSvcCli.Create(ctx, zone)
		Expect(err).ToNot(HaveOccurred())

		By("Creating a second zone")
		zone2 := &elapb.NetworkZone{
			Id:          zone2ID,
			Description: "test_network_zone_2",
		}
		err = zoneSvcCli.Create(ctx, zone2)
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Create", func() {
		Describe("Success", func() {
			It("Should create new zones", func() {
				By("Verifying the responses are IDs")
				Expect(zoneID).ToNot(BeNil())
				Expect(zone2ID).ToNot(BeNil())
			})
		})

		Describe("Errors", func() {})
	})

	Describe("Update", func() {
		Describe("Success", func() {
			It("Should update an existing zone", func() {
				By("Updating the first zone")
				err := zoneSvcCli.Update(
					ctx,
					&elapb.NetworkZone{
						Id:          zoneID,
						Description: "test_updated_network_zone",
					},
				)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Getting the updated zone")
				zone, err := zoneSvcCli.Get(ctx, zoneID)

				By("Verifying the response matches the updated zone")
				Expect(err).ToNot(HaveOccurred())
				Expect(zone).To(Equal(
					&elapb.NetworkZone{
						Id:          zoneID,
						Description: "test_updated_network_zone",
					},
				))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the ID does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				err := zoneSvcCli.Update(ctx, &elapb.NetworkZone{Id: badID})

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Zone %s not found", badID)))
			})
		})
	})

	Describe("BulkUpdate", func() {
		Describe("Success", func() {
			It("Should bulk update zones", func() {
				By("Bulk updating the two zones")
				err := zoneSvcCli.BulkUpdate(
					ctx,
					&elapb.NetworkZones{
						NetworkZones: []*elapb.NetworkZone{
							{
								Id:          zoneID,
								Description: "test_updated_network_zone",
							},
							{
								Id:          zone2ID,
								Description: "test_updated_network_zone_2",
							},
						},
					},
				)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Getting the first zone")
				zone, err := zoneSvcCli.Get(ctx, zoneID)

				By("Verifying the response matches the updated zone")
				Expect(err).ToNot(HaveOccurred())
				Expect(zone).To(Equal(
					&elapb.NetworkZone{
						Id:          zoneID,
						Description: "test_updated_network_zone",
					},
				))

				By("Getting the second zone")
				zone2, err := zoneSvcCli.Get(ctx, zone2ID)

				By("Verifying the response matches the updated zone")
				Expect(err).ToNot(HaveOccurred())
				Expect(zone2).To(Equal(
					&elapb.NetworkZone{
						Id:          zone2ID,
						Description: "test_updated_network_zone_2",
					},
				))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the ID does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				err := zoneSvcCli.BulkUpdate(
					ctx,
					&elapb.NetworkZones{
						NetworkZones: []*elapb.NetworkZone{
							{Id: badID},
						},
					},
				)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Zone %s not found", badID)))
			})
		})
	})

	Describe("GetAll", func() {
		Describe("Success", func() {
			It("Should get all zones", func() {
				By("Getting all zones")
				zones, err := zoneSvcCli.GetAll(ctx)

				By("Verifying the response includes the two zones")
				Expect(err).ToNot(HaveOccurred())
				Expect(len(zones.NetworkZones)).To(BeNumerically(">=", 2))
				Expect(zones.NetworkZones).To(ContainElement(
					&elapb.NetworkZone{
						Id:          zoneID,
						Description: "test_network_zone",
					},
				))
				Expect(zones.NetworkZones).To(ContainElement(
					&elapb.NetworkZone{
						Id:          zone2ID,
						Description: "test_network_zone_2",
					},
				))
			})
		})

		Describe("Errors", func() {})
	})

	Describe("Get", func() {
		Describe("Success", func() {
			It("Should get zones", func() {
				By("Getting the first zone")
				zone, err := zoneSvcCli.Get(ctx, zoneID)

				By("Verifying the response matches the first zone")
				Expect(err).ToNot(HaveOccurred())
				Expect(zone).To(Equal(
					&elapb.NetworkZone{
						Id:          zoneID,
						Description: "test_network_zone",
					},
				))

				By("Getting the secone zone")
				zone2, err := zoneSvcCli.Get(ctx, zone2ID)

				By("Verifying the response matches the second zone")
				Expect(err).ToNot(HaveOccurred())
				Expect(zone2).To(Equal(
					&elapb.NetworkZone{
						Id:          zone2ID,
						Description: "test_network_zone_2",
					},
				))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the zone does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				noZone, err := zoneSvcCli.Get(ctx, badID)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred(),
					"Expected error but got zone: %v", noZone)
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Zone %s not found", badID)))
			})
		})
	})

	Describe("Delete", func() {
		Describe("Success", func() {
			It("Should delete zones", func() {
				By("Deleting the first zone")
				err := zoneSvcCli.Delete(ctx, zoneID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the zone was deleted")
				_, err = zoneSvcCli.Get(ctx, zoneID)
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Zone %s not found", zoneID)))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the zone does not exist", func() {
				By("Passing a nonexistent ID")
				badID := uuid.New()
				noZone, err := zoneSvcCli.Get(ctx, badID)

				By("Verifying a NotFound response")
				Expect(err).To(HaveOccurred(),
					"Expected error but got zone: %v", noZone)
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.NotFound,
						"Network Zone %s not found", badID)))
			})
		})
	})
})
