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

// MockPBInterfacePolicyServiceClient delegates to a MockNode.
type MockPBInterfacePolicyServiceClient struct {
	MockNode *gmock.MockNode
}

// Set delegates to a MockNode.
func (c *MockPBInterfacePolicyServiceClient) Set(
	ctx context.Context,
	in *elapb.TrafficPolicy,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.IfPolicySvc.Set(ctx, in)
}
