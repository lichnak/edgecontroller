// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients

import (
	"context"

	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/grpc"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	"github.com/pkg/errors"
)

// InterfacePolicyServiceClient wraps the PB client.
type InterfacePolicyServiceClient struct {
	PBCli elapb.InterfacePolicyServiceClient
}

// NewInterfacePolicyServiceClient creates a new client.
func NewInterfacePolicyServiceClient(
	conn *grpc.ClientConn,
) *InterfacePolicyServiceClient {
	return &InterfacePolicyServiceClient{
		conn.NewInterfacePolicyServiceClient(),
	}
}

// Set sets the traffic policy.
func (c *InterfacePolicyServiceClient) Set(
	ctx context.Context,
	interfaceID string,
	interfacePolicy *cce.TrafficPolicy,
) error {
	_, err := c.PBCli.Set(
		ctx,
		toPBTrafficPolicy(interfaceID, interfacePolicy))

	if err != nil {
		return errors.Wrap(err, "error setting interface policy")
	}

	return nil
}

// Delete deletes an interface's traffic policy. This resets it to the default policy.
func (c *InterfacePolicyServiceClient) Delete(
	ctx context.Context,
	appID string,
) error {
	if err := c.Set(ctx, appID, nil); err != nil {
		return errors.Wrap(err, "error deleting interface policy")
	}

	return nil
}
