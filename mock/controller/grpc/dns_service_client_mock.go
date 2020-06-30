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

// MockPBDNSServiceClient delegates to a MockNode.
type MockPBDNSServiceClient struct {
	MockNode *gmock.MockNode
}

// SetA delegates to a MockNode.
func (c *MockPBDNSServiceClient) SetA(
	ctx context.Context,
	in *elapb.DNSARecordSet,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.DNSSvc.SetA(ctx, in)
}

// DeleteA delegates to a MockNode.
func (c *MockPBDNSServiceClient) DeleteA(
	ctx context.Context,
	in *elapb.DNSARecordSet,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.DNSSvc.DeleteA(ctx, in)
}

// SetForwarders delegates to a MockNode.
func (c *MockPBDNSServiceClient) SetForwarders(
	ctx context.Context,
	in *elapb.DNSForwarders,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.DNSSvc.SetForwarders(ctx, in)
}

// DeleteForwarders delegates to a MockNode.
func (c *MockPBDNSServiceClient) DeleteForwarders(
	ctx context.Context,
	in *elapb.DNSForwarders,
	opts ...grpc.CallOption,
) (*empty.Empty, error) {
	return c.MockNode.DNSSvc.DeleteForwarders(ctx, in)
}
