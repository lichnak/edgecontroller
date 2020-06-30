// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"
	"crypto/tls"
	"fmt"

	cce "github.com/open-ness/edgecontroller"
	"github.com/open-ness/edgecontroller/grpc/node"
	"github.com/open-ness/edgecontroller/k8s"
	"github.com/pkg/errors"
)

const (
	defaultELAPort = "42101"
	defaultEVAPort = "42102"
)

func connectNode(
	ctx context.Context,
	ps cce.PersistenceService,
	e cce.NodeEntity,
	port string,
	conf *tls.Config,
) (*node.ClientConn, error) {
	targets, err := ps.Filter(
		ctx,
		&cce.NodeGRPCTarget{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: e.GetNodeID(),
			},
		})
	if err != nil {
		return nil, errors.Wrapf(err, "could not fetch gRPC target from DB")
	}
	// sanity check since we are about to access targets[0]
	if len(targets) != 1 {
		return nil, fmt.Errorf("filter returned %v", targets)
	}

	target := targets[0].(*cce.NodeGRPCTarget)
	addr := target.GRPCTarget
	if conf != nil {
		conf = conf.Clone()
		conf.ServerName = e.GetNodeID()
	}

	log.Debugf("connectNode(%v): connecting to %v", e.GetNodeID(), target)

	nodeCC := node.ClientConn{Addr: addr, Port: port, TLS: conf}
	if err := nodeCC.Connect(ctx); err != nil {
		log.Noticef("Could not connect to node: %v", err)
		return nil, errors.Wrap(err, "could not connect to node")
	}
	log.Debugf("Connection to node %s established: %s", e.GetNodeID(), addr)

	return &nodeCC, nil
}

func disconnectNode(nodeCC *node.ClientConn) {
	log.Debugf("Disconnecting %v", nodeCC)
	nodeCC.Disconnect()
}

func getController(ctx context.Context) *cce.Controller {
	return ctx.Value(contextKey("controller")).(*cce.Controller)
}

func toK8SApp(app *cce.App) k8s.App {
	var ports []*k8s.PortProto
	for _, port := range app.Ports {
		ports = append(ports, &k8s.PortProto{
			Port:     int32(port.Port),
			Protocol: port.Protocol,
		})
	}

	return k8s.App{
		ID:     app.ID,
		Image:  app.ID + ":latest",
		Cores:  app.Cores,
		Memory: app.Memory,
		Ports:  ports,
	}
}
