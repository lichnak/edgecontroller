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

type appPolicyService struct {
	// map of application ID to traffic policy
	policies map[string]*elapb.TrafficPolicy

	// reference to application server
	appSvc *appDeployLifeService
}

func newAppPolicyService(
	appSvc *appDeployLifeService,
) *appPolicyService {
	return &appPolicyService{
		policies: make(map[string]*elapb.TrafficPolicy),
		appSvc:   appSvc,
	}
}

func (s *appPolicyService) reset() {
	s.policies = make(map[string]*elapb.TrafficPolicy)
}

func (s *appPolicyService) Set(
	ctx context.Context,
	policy *elapb.TrafficPolicy,
) (*empty.Empty, error) {
	if s.appSvc.find(policy.Id) == nil {
		return nil, status.Errorf(
			codes.NotFound, "Application %s not found", policy.Id)
	}

	s.policies[policy.Id] = policy

	return &empty.Empty{}, nil
}
