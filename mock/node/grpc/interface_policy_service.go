// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type interfacePolicyService struct {
	// map of interface ID to traffic policy
	policies map[string]*elapb.TrafficPolicy

	// reference to interface server
	interfaceService *interfaceService
}

func newInterfacePolicyService(
	interfaceService *interfaceService,
) *interfacePolicyService {
	return &interfacePolicyService{
		policies:         make(map[string]*elapb.TrafficPolicy),
		interfaceService: interfaceService,
	}
}

func (s *interfacePolicyService) reset() {
	s.policies = make(map[string]*elapb.TrafficPolicy)
}

func (s *interfacePolicyService) Set(
	ctx context.Context,
	policy *elapb.TrafficPolicy,
) (*empty.Empty, error) {
	if s.interfaceService.find(policy.Id) == nil {
		return nil, status.Errorf(
			codes.NotFound, "Network Interface %s not found", policy.Id)
	}

	s.policies[policy.Id] = policy

	return &empty.Empty{}, nil
}

func (s *interfacePolicyService) Get(
	ctx context.Context,
	id *elapb.InterfaceID,
) (*elapb.TrafficPolicy, error) {
	if s.policies[id.Id] == nil {
		return nil, status.Errorf(
			codes.NotFound, "Network Interface %s not found", id.Id)
	}

	return s.policies[id.Id], nil
}
