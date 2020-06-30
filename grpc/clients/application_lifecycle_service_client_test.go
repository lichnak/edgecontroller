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

var _ = Describe("Application Lifecycle Service Client", func() {
	var (
		containerAppID string
		vmAppID        string
	)

	BeforeEach(func() {
		var err error

		By("Generating new IDs")
		containerAppID = uuid.New()
		vmAppID = uuid.New()

		By("Deploying a container application")
		err = appDeploySvcCli.Deploy(
			ctx,
			&cce.App{
				ID:          containerAppID,
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

		By("Deploying a VM application")
		err = appDeploySvcCli.Deploy(
			ctx,
			&cce.App{
				ID:          vmAppID,
				Type:        "vm",
				Name:        "test_vm_app",
				Vendor:      "test_vendor",
				Description: "test vm app",
				Version:     "latest",
				Cores:       4,
				Memory:      4096,
				Ports:       []cce.PortProto{{Port: 80, Protocol: "tcp"}},
				Source:      "https://path/to/file.zip",
			})
		Expect(err).ToNot(HaveOccurred())
	})

	Describe("Start", func() {
		Describe("Success", func() {
			It("Should start container applications", func() {
				By("Starting the container application")
				err := appLifeSvcCli.Start(ctx, containerAppID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the container application is started")
				status, err := appLifeSvcCli.GetStatus(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(Equal(cce.Running))
			})

			It("Should start VM applications", func() {
				By("Starting the VM application")
				err := appLifeSvcCli.Start(ctx, vmAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the VM application is started")
				status, err := appLifeSvcCli.GetStatus(ctx, vmAppID)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(Equal(cce.Running))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the application is already "+
				"running", func() {
				By("Starting the container application")
				err := appLifeSvcCli.Start(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Attempting to start the container application again")
				err = appLifeSvcCli.Start(ctx, containerAppID)

				By("Verifying a FailedPrecondition response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.FailedPrecondition,
						"Application %s not stopped or ready", containerAppID)))
			})
		})
	})

	Describe("Restart", func() {
		Describe("Success", func() {
			It("Should restart container applications", func() {
				By("Starting the container application")
				err := appLifeSvcCli.Start(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Restarting the container application")
				err = appLifeSvcCli.Restart(ctx, containerAppID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the container application is restarted")
				status, err := appLifeSvcCli.GetStatus(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(Equal(cce.Running))
			})

			It("Should restart VM applications", func() {
				By("Starting the VM application")
				err := appLifeSvcCli.Start(ctx, vmAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Restarting the VM application")
				err = appLifeSvcCli.Restart(ctx, vmAppID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the VM application is restarted")
				status, err := appLifeSvcCli.GetStatus(ctx, vmAppID)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(Equal(cce.Running))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the application is not "+
				"running", func() {
				By("Attempting to restart the container application")
				err := appLifeSvcCli.Restart(ctx, containerAppID)

				By("Verifying a FailedPrecondition response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.FailedPrecondition,
						"Application %s not running", containerAppID)))
			})
		})
	})

	Describe("Stop", func() {
		Describe("Success", func() {
			It("Should stop container applications", func() {
				By("Starting the container application")
				err := appLifeSvcCli.Start(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Stopping the container application")
				err = appLifeSvcCli.Stop(ctx, containerAppID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the container application is stopped")
				status, err := appLifeSvcCli.GetStatus(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(Equal(cce.Stopped))
			})

			It("Should stop VM applications", func() {
				By("Starting the VM application")
				err := appLifeSvcCli.Start(ctx, vmAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Stopping the VM application")
				err = appLifeSvcCli.Stop(ctx, vmAppID)

				By("Verifying a success response")
				Expect(err).ToNot(HaveOccurred())

				By("Verifying the VM application is stopped")
				status, err := appLifeSvcCli.GetStatus(ctx, vmAppID)
				Expect(err).ToNot(HaveOccurred())
				Expect(status).To(Equal(cce.Stopped))
			})
		})

		Describe("Errors", func() {
			It("Should return an error if the application is already "+
				"stopped", func() {
				By("Starting the container application")
				err := appLifeSvcCli.Start(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Stopping the container application")
				err = appLifeSvcCli.Stop(ctx, containerAppID)
				Expect(err).ToNot(HaveOccurred())

				By("Attempting to stop the container application again")
				err = appLifeSvcCli.Stop(ctx, containerAppID)

				By("Verifying a FailedPrecondition response")
				Expect(err).To(HaveOccurred())
				Expect(errors.Cause(err)).To(Equal(
					status.Errorf(codes.FailedPrecondition,
						"Application %s not running", containerAppID)))

			})
		})
	})
})
