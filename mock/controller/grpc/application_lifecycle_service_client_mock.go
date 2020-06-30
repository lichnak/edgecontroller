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

// MockPBApplicationLifecycleServiceClient delegates to a MockNode.
type MockPBApplicationLifecycleServiceClient struct {
	MockNode *gmock.MockNode
}

// Start delegates to a MockNode.
func (c *MockPBApplicationLifecycleServiceClient) Start(
	ctx context.Context,
	in *evapb.LifecycleCommand,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppLifeSvc.Start(ctx, in)
}

// Stop delegates to a MockNode.
func (c *MockPBApplicationLifecycleServiceClient) Stop(
	ctx context.Context,
	in *evapb.LifecycleCommand,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppLifeSvc.Stop(ctx, in)
}

// Restart delegates to a MockNode.
func (c *MockPBApplicationLifecycleServiceClient) Restart(
	ctx context.Context,
	in *evapb.LifecycleCommand,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppLifeSvc.Restart(ctx, in)
}

// GetStatus delegates to a MockNode.
func (c *MockPBApplicationLifecycleServiceClient) GetStatus(
	ctx context.Context,
	in *evapb.ApplicationID,
	opts ...grpc.CallOption,
) (*evapb.LifecycleStatus, error) {
	return c.MockNode.AppLifeSvc.GetStatus(ctx, in)
}
