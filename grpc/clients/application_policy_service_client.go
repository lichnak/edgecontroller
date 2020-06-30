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

// ApplicationPolicyServiceClient wraps the PB client.
type ApplicationPolicyServiceClient struct {
	PBCli elapb.ApplicationPolicyServiceClient
}

// NewApplicationPolicyServiceClient creates a new client.
func NewApplicationPolicyServiceClient(
	conn *grpc.ClientConn,
) *ApplicationPolicyServiceClient {
	return &ApplicationPolicyServiceClient{
		conn.NewApplicationPolicyServiceClient(),
	}
}

// Set sets an app's traffic policy.
func (c *ApplicationPolicyServiceClient) Set(
	ctx context.Context,
	appID string,
	policy *cce.TrafficPolicy,
) error {
	_, err := c.PBCli.Set(
		ctx,
		toPBTrafficPolicy(appID, policy))

	if err != nil {
		return errors.Wrap(err, "error setting application policy")
	}

	return nil
}

// Delete deletes an app's traffic policy. This resets it to the default policy.
func (c *ApplicationPolicyServiceClient) Delete(
	ctx context.Context,
	appID string,
) error {
	if err := c.Set(ctx, appID, nil); err != nil {
		return errors.Wrap(err, "error deleting application policy")
	}

	return nil
}
