// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	gmock "github.com/open-ness/edgecontroller/mock/node/grpc"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"google.golang.org/grpc"
)

// MockPBInterfaceServiceClient delegates to a MockNode.
type MockPBInterfaceServiceClient struct {
	MockNode *gmock.MockNode
}

// Update delegates to a MockNode.
func (c *MockPBInterfaceServiceClient) Update(
	ctx context.Context,
	in *elapb.NetworkInterface,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.InterfaceSvc.Update(ctx, in)
}

// BulkUpdate delegates to a MockNode.
func (c *MockPBInterfaceServiceClient) BulkUpdate(
	ctx context.Context,
	in *elapb.NetworkInterfaces,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.InterfaceSvc.BulkUpdate(ctx, in)
}

// GetAll delegates to a MockNode.
func (c *MockPBInterfaceServiceClient) GetAll(
	ctx context.Context,
	in *empty.Empty,
	opts ...grpc.CallOption,
) (*elapb.NetworkInterfaces, error) {
	return c.MockNode.InterfaceSvc.GetAll(ctx, in)
}

// Get delegates to a MockNode.
func (c *MockPBInterfaceServiceClient) Get(
	ctx context.Context,
	in *elapb.InterfaceID,
	opts ...grpc.CallOption,
) (*elapb.NetworkInterface, error) {
	return c.MockNode.InterfaceSvc.Get(ctx, in)
}
