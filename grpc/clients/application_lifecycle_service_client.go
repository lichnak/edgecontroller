// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package clients

import (
	"context"

	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/grpc"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
	"github.com/pkg/errors"
)

// ApplicationLifecycleServiceClient wraps the PB client.
type ApplicationLifecycleServiceClient struct {
	PBCli evapb.ApplicationLifecycleServiceClient
}

// NewApplicationLifecycleServiceClient creates a new client.
func NewApplicationLifecycleServiceClient(
	conn *grpc.ClientConn,
) *ApplicationLifecycleServiceClient {
	return &ApplicationLifecycleServiceClient{
		conn.NewApplicationLifecycleServiceClient(),
	}
}

// Start starts a stopped application.
func (c *ApplicationLifecycleServiceClient) Start(
	ctx context.Context,
	id string,
) error {
	_, err := c.PBCli.Start(
		ctx,
		&evapb.LifecycleCommand{
			Id:  id,
			Cmd: evapb.LifecycleCommand_START,
		})

	if err != nil {
		return errors.Wrap(err, "error starting application")
	}

	return nil
}

// Stop stops a running application.
func (c *ApplicationLifecycleServiceClient) Stop(
	ctx context.Context,
	id string,
) error {
	_, err := c.PBCli.Stop(
		ctx,
		&evapb.LifecycleCommand{
			Id:  id,
			Cmd: evapb.LifecycleCommand_STOP,
		})

	if err != nil {
		return errors.Wrap(err, "error stopping application")
	}

	return nil
}

// Restart restarts a running application.
func (c *ApplicationLifecycleServiceClient) Restart(
	ctx context.Context,
	id string,
) error {
	_, err := c.PBCli.Restart(
		ctx,
		&evapb.LifecycleCommand{
			Id:  id,
			Cmd: evapb.LifecycleCommand_RESTART,
		})

	if err != nil {
		return errors.Wrap(err, "error restarting application")
	}

	return nil
}

// GetStatus retrieves an application's status.
func (c *ApplicationLifecycleServiceClient) GetStatus(
	ctx context.Context,
	id string,
) (cce.LifecycleStatus, error) {
	pbStatus, err := c.PBCli.GetStatus(
		ctx,
		&evapb.ApplicationID{Id: id})

	if err != nil {
		return cce.Unknown, errors.Wrap(err, "error retrieving application")
	}

	return fromPBLifecycleStatus(pbStatus), nil
}
