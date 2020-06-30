// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients_test

import (
	"context"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gclients "github.com/open-ness/edgecontroller/grpc/clients"
	ctrlgmock "github.com/open-ness/edgecontroller/mock/controller/grpc"
	nodegmock "github.com/open-ness/edgecontroller/mock/node/grpc"
)

var (
	ctx             = context.Background()
	mockNode        = nodegmock.NewMockNode()
	appDeploySvcCli = &gclients.ApplicationDeploymentServiceClient{
		PBCli: &ctrlgmock.MockPBApplicationDeploymentServiceClient{
			MockNode: mockNode,
		},
	}
	appLifeSvcCli = &gclients.ApplicationLifecycleServiceClient{
		PBCli: &ctrlgmock.MockPBApplicationLifecycleServiceClient{
			MockNode: mockNode,
		},
	}
	appPolicySvcCli = &gclients.ApplicationPolicyServiceClient{
		PBCli: &ctrlgmock.MockPBApplicationPolicyServiceClient{
			MockNode: mockNode,
		},
	}
	interfaceSvcCli = &gclients.InterfaceServiceClient{
		PBCli: &ctrlgmock.MockPBInterfaceServiceClient{
			MockNode: mockNode,
		},
	}
	zoneSvcCli = &gclients.ZoneServiceClient{
		PBCli: &ctrlgmock.MockPBZoneServiceClient{
			MockNode: mockNode,
		},
	}
	interfacePolicySvcCli = &gclients.InterfacePolicyServiceClient{
		PBCli: &ctrlgmock.MockPBInterfacePolicyServiceClient{
			MockNode: mockNode,
		},
	}
	dnsSvcCli = &gclients.DNSServiceClient{
		PBCli: &ctrlgmock.MockPBDNSServiceClient{
			MockNode: mockNode,
		},
	}
)

func TestApplicationClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "gRPC Clients Suite")
}
