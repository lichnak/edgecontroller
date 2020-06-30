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

// MockPBApplicationPolicyServiceClient delegates to a MockNode.
type MockPBApplicationPolicyServiceClient struct {
	MockNode *gmock.MockNode
}

// Set delegates to a MockNode.
func (c *MockPBApplicationPolicyServiceClient) Set(
	ctx context.Context,
	in *elapb.TrafficPolicy,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.AppPolicySvc.Set(ctx, in)
}
