// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	gmock "github.com/open-ness/edgecontroller/mock/node/grpc"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
	"google.golang.org/grpc"
)

// MockPBApplicationDeploymentServiceClient delegates to a MockNode.
type MockPBApplicationDeploymentServiceClient struct {
	MockNode *gmock.MockNode
}

// DeployContainer delegates to a MockNode.
func (c *MockPBApplicationDeploymentServiceClient) DeployContainer(
	ctx context.Context,
	in *evapb.Application,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppDeploySvc.DeployContainer(ctx, in)
}

// DeployVM delegates to a MockNode.
func (c *MockPBApplicationDeploymentServiceClient) DeployVM(
	ctx context.Context,
	in *evapb.Application,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppDeploySvc.DeployVM(ctx, in)
}

// Redeploy delegates to a MockNode.
func (c *MockPBApplicationDeploymentServiceClient) Redeploy(
	ctx context.Context,
	in *evapb.Application,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppDeploySvc.Redeploy(ctx, in)
}

// Undeploy delegates to a MockNode.
func (c *MockPBApplicationDeploymentServiceClient) Undeploy(
	ctx context.Context,
	in *evapb.ApplicationID,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppDeploySvc.Undeploy(ctx, in)
}
