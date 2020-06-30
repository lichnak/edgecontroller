// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type appDeployLifeService struct {
	// maps of application ID to application
	containerApps map[string]*evapb.Application
	vmApps        map[string]*evapb.Application

	// reference to policy server
	appPolicyService *appPolicyService
}

func newAppDeployLifeService() *appDeployLifeService {
	return &appDeployLifeService{
		containerApps: make(map[string]*evapb.Application),
		vmApps:        make(map[string]*evapb.Application),
	}
}

func (s *appDeployLifeService) reset() {
	s.containerApps = make(map[string]*evapb.Application)
	s.vmApps = make(map[string]*evapb.Application)
}

func (s *appDeployLifeService) DeployContainer(
	ctx context.Context,
	containerApp *evapb.Application,
) (*empty.Empty, error) {
	s.containerApps[containerApp.Id] = containerApp
	containerApp.Status = evapb.LifecycleStatus_READY

	return &empty.Empty{}, nil
}

func (s *appDeployLifeService) DeployVM(
	ctx context.Context,
	vmApp *evapb.Application,
) (*empty.Empty, error) {
	s.vmApps[vmApp.Id] = vmApp
	vmApp.Status = evapb.LifecycleStatus_READY

	return &empty.Empty{}, nil
}

func (s *appDeployLifeService) GetStatus(
	ctx context.Context,
	id *evapb.ApplicationID,
) (*evapb.LifecycleStatus, error) {
	if containerApp, ok := s.containerApps[id.Id]; ok {
		return &evapb.LifecycleStatus{
			Status: containerApp.Status,
		}, nil
	}

	if vmApp, ok := s.vmApps[id.Id]; ok {
		return &evapb.LifecycleStatus{
			Status: vmApp.Status,
		}, nil
	}

	return nil, status.Errorf(codes.NotFound, "Application %s not found", id.Id)
}

func (s *appDeployLifeService) Redeploy(
	ctx context.Context,
	app *evapb.Application,
) (*empty.Empty, error) {
	if oldApp, ok := s.containerApps[app.Id]; ok {
		app.Status = oldApp.Status
		s.containerApps[app.Id] = app
		return &empty.Empty{}, nil
	}

	if oldApp, ok := s.vmApps[app.Id]; ok {
		app.Status = oldApp.Status
		s.vmApps[app.Id] = app
		return &empty.Empty{}, nil
	}

	return nil, status.Errorf(
		codes.NotFound, "Application %s not found", app.Id)
}

func (s *appDeployLifeService) Undeploy(
	ctx context.Context,
	id *evapb.ApplicationID,
) (*empty.Empty, error) {
	var policyExists bool
	if _, policyExists = s.appPolicyService.policies[id.Id]; policyExists {
		delete(s.appPolicyService.policies, id.Id)
		policyExists = true
	}

	if _, ok := s.containerApps[id.Id]; ok {
		delete(s.containerApps, id.Id)
		return &empty.Empty{}, nil
	}

	if _, ok := s.vmApps[id.Id]; ok {
		delete(s.vmApps, id.Id)
		return &empty.Empty{}, nil
	}

	if policyExists {
		return nil, status.Errorf(codes.DataLoss,
			"Application %s not found but had a policy!", id.Id)
	}

	return nil, status.Errorf(codes.NotFound, "Application %s not found", id.Id)
}

func (s *appDeployLifeService) Start(
	ctx context.Context,
	cmd *evapb.LifecycleCommand,
) (*empty.Empty, error) {
	app := s.find(cmd.Id)

	if app != nil {
		switch app.Status {
		case evapb.LifecycleStatus_READY:
		case evapb.LifecycleStatus_STOPPED:
		default:
			return nil, status.Errorf(
				codes.FailedPrecondition, "Application %s not stopped or ready",
				cmd.Id)
		}

		app.Status = evapb.LifecycleStatus_RUNNING
		return &empty.Empty{}, nil
	}

	return nil, status.Errorf(
		codes.NotFound, "Application %s not found", cmd.Id)
}

func (s *appDeployLifeService) Stop(
	ctx context.Context,
	cmd *evapb.LifecycleCommand,
) (*empty.Empty, error) {
	app := s.find(cmd.Id)

	if app != nil {
		if app.Status != evapb.LifecycleStatus_RUNNING {
			return nil, status.Errorf(
				codes.FailedPrecondition, "Application %s not running", cmd.Id)
		}

		app.Status = evapb.LifecycleStatus_STOPPED
		return &empty.Empty{}, nil
	}

	return nil, status.Errorf(
		codes.NotFound, "Application %s not found", cmd.Id)
}

func (s *appDeployLifeService) Restart(
	ctx context.Context,
	cmd *evapb.LifecycleCommand,
) (*empty.Empty, error) {
	app := s.find(cmd.Id)

	if app != nil {
		if app.Status != evapb.LifecycleStatus_RUNNING {
			return nil, status.Errorf(
				codes.FailedPrecondition, "Application %s not running", cmd.Id)
		}

		return &empty.Empty{}, nil
	}

	return nil, status.Errorf(
		codes.NotFound, "Application %s not found", cmd.Id)
}

func (s *appDeployLifeService) find(id string) *evapb.Application {
	if containerApp, ok := s.containerApps[id]; ok {
		return containerApp
	}

	if vmApp, ok := s.vmApps[id]; ok {
		return vmApp
	}

	return nil
}
