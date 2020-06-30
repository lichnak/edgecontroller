// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package grpc

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	logger "github.com/open-ness/common/log"
	elapb "github.com/open-ness/edgecontroller/pb/ela"
	evapb "github.com/open-ness/edgecontroller/pb/eva"
)

var log = logger.DefaultLogger.WithField("pkg", "grpc")

// ClientConn wraps grpc.ClientConn
type ClientConn struct {
	conn *grpc.ClientConn
}

// Dial dials the remote server.
func Dial(ctx context.Context, target string, conf *tls.Config, opts ...grpc.DialOption) (*ClientConn, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if conf != nil {
		opts = append(opts, grpc.WithTransportCredentials(
			credentials.NewTLS(conf)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	conn, err := grpc.DialContext(ctx, target, opts...)
	if err != nil {
		return nil, errors.Wrapf(err, "dial %s failed", target)
	}

	return &ClientConn{conn}, nil
}

// Close wraps grpc.Close()
func (c *ClientConn) Close() error {
	return c.conn.Close()
}

// NewApplicationDeploymentServiceClient wraps the pb function.
func (c *ClientConn) NewApplicationDeploymentServiceClient() evapb.ApplicationDeploymentServiceClient {
	return evapb.NewApplicationDeploymentServiceClient(c.conn)
}

// NewApplicationLifecycleServiceClient wraps the pb function.
func (c *ClientConn) NewApplicationLifecycleServiceClient() evapb.ApplicationLifecycleServiceClient {
	return evapb.NewApplicationLifecycleServiceClient(c.conn)
}

// NewApplicationPolicyServiceClient wraps the pb function.
func (c *ClientConn) NewApplicationPolicyServiceClient() elapb.ApplicationPolicyServiceClient {
	return elapb.NewApplicationPolicyServiceClient(c.conn)
}

// NewInterfaceServiceClient wraps the pb function.
func (c *ClientConn) NewInterfaceServiceClient() elapb.InterfaceServiceClient {
	return elapb.NewInterfaceServiceClient(c.conn)
}

// NewInterfacePolicyServiceClient wraps the pb function.
func (c *ClientConn) NewInterfacePolicyServiceClient() elapb.InterfacePolicyServiceClient {
	return elapb.NewInterfacePolicyServiceClient(c.conn)
}

// NewZoneServiceClient wraps the pb function.
func (c *ClientConn) NewZoneServiceClient() elapb.ZoneServiceClient {
	return elapb.NewZoneServiceClient(c.conn)
}

// NewDNSServiceClient wraps the pb function.
func (c *ClientConn) NewDNSServiceClient() elapb.DNSServiceClient {
	return elapb.NewDNSServiceClient(c.conn)
}
