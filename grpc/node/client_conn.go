// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package node

import (
	"context"
	"crypto/tls"

	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/grpc"
	gclients "github.com/open-ness/edgecontroller/grpc/clients"
	ggrpc "google.golang.org/grpc"
)

// ClientConn wraps a Node and provides a Connect() method to create wrapped gRPC clients.
type ClientConn struct {
	Addr string
	Port string
	TLS  *tls.Config

	conn *grpc.ClientConn

	AppDeploySvcCli   *gclients.ApplicationDeploymentServiceClient
	AppLifeSvcCli     *gclients.ApplicationLifecycleServiceClient
	AppPolicySvcCli   *gclients.ApplicationPolicyServiceClient
	IfacePolicySvcCli *gclients.InterfacePolicyServiceClient
	IfaceSvcCli       *gclients.InterfaceServiceClient
	DNSSvcCli         *gclients.DNSServiceClient
	ZoneSvcCli        *gclients.ZoneServiceClient
}

// Connect connects to a node via grpc.Dial.
func (cc *ClientConn) Connect(ctx context.Context) error {
	var err error

	if cc.Port == "42102" { // XXX use the actual variable with this!
		// OP-1742: ContextDialler not supported by Gateway
		//nolint:staticcheck
		cc.conn, err = grpc.Dial(ctx, cc.Addr, cc.TLS,
			ggrpc.WithDialer(cce.PrefaceLis.DialEva))

		// EVA
		cc.AppDeploySvcCli = gclients.NewApplicationDeploymentServiceClient(cc.conn)
		cc.AppLifeSvcCli = gclients.NewApplicationLifecycleServiceClient(cc.conn)
	} else {
		// OP-1742: ContextDialler not supported by Gateway
		//nolint:staticcheck
		cc.conn, err = grpc.Dial(ctx, cc.Addr, cc.TLS,
			ggrpc.WithDialer(cce.PrefaceLis.DialEla))

		// ELA
		cc.AppPolicySvcCli = gclients.NewApplicationPolicyServiceClient(cc.conn)
		cc.IfacePolicySvcCli = gclients.NewInterfacePolicyServiceClient(cc.conn)
		cc.DNSSvcCli = gclients.NewDNSServiceClient(cc.conn)
		cc.IfaceSvcCli = gclients.NewInterfaceServiceClient(cc.conn)

		cc.ZoneSvcCli = gclients.NewZoneServiceClient(cc.conn) // XXX unimplemented?
	}

	return err
}

func (cc *ClientConn) Disconnect() {
	cc.conn.Close()
}
