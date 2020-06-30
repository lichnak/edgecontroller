// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
)

// MockNode provides a mock node gRPC server.
type MockNode struct {
	AppDeploySvc evapb.ApplicationDeploymentServiceServer
	AppLifeSvc   evapb.ApplicationLifecycleServiceServer
	AppPolicySvc elapb.ApplicationPolicyServiceServer
	DNSSvc       elapb.DNSServiceServer
	InterfaceSvc elapb.InterfaceServiceServer
	IfPolicySvc  elapb.InterfacePolicyServiceServer
	ZoneSvc      elapb.ZoneServiceServer
}

// NewMockNode creates a new MockNode with node services initialized.
// AppDeploySvc and AppLifeSvc are combined into appDeployLifeService.
func NewMockNode() *MockNode {
	var (
		appDeployLifeSvc = newAppDeployLifeService()
		appPolicySvc     = newAppPolicyService(appDeployLifeSvc)
		dnsSvc           = newDNSService()
		interfaceSvc     = newInterfaceService()
		ifPolicySvc      = newInterfacePolicyService(interfaceSvc)
		zoneSvc          = &zoneService{}
	)

	appDeployLifeSvc.appPolicyService = appPolicySvc

	return &MockNode{
		AppDeploySvc: appDeployLifeSvc,
		AppLifeSvc:   appDeployLifeSvc,
		AppPolicySvc: appPolicySvc,
		InterfaceSvc: interfaceSvc,
		IfPolicySvc:  ifPolicySvc,
		ZoneSvc:      zoneSvc,
		DNSSvc:       dnsSvc,
	}
}

// Reset resets the state of the mock node.
func (mn *MockNode) Reset() {
	mn.AppDeploySvc.(*appDeployLifeService).reset()
	mn.AppPolicySvc.(*appPolicyService).reset()
	mn.InterfaceSvc.(*interfaceService).reset()
	mn.IfPolicySvc.(*interfacePolicyService).reset()
	mn.ZoneSvc.(*zoneService).reset()
	mn.DNSSvc.(*dnsService).reset()
}
