// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"

	cce "github.com/open-ness/edgecontroller"
)

func handleGetNodes(
	ctx context.Context,
	ps cce.PersistenceService,
	e cce.Persistable,
) (cce.RespEntity, error) {
	ctrl := getController(ctx)
	nodePort := ctrl.ELAPort
	if nodePort == "" {
		nodePort = defaultELAPort
	}

	nodeCC, err := connectNode(ctx, ps, e.(*cce.Node), nodePort, ctrl.EdgeNodeCreds)

	if err != nil {
		return nil, err
	}
	defer disconnectNode(nodeCC)

	nis, err := nodeCC.IfaceSvcCli.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	return &cce.NodeResp{
		Node:              *e.(*cce.Node),
		NetworkInterfaces: nis,
	}, nil
}

func handleGetNodesApps(ctx context.Context, ps cce.PersistenceService, e cce.Persistable) (cce.RespEntity, error) {
	ctrl := getController(ctx)
	nodePort := ctrl.EVAPort
	if nodePort == "" {
		nodePort = defaultEVAPort
	}

	nodeCC, err := connectNode(ctx, ps, e.(*cce.NodeApp), nodePort, ctrl.EdgeNodeCreds)
	if err != nil {
		return nil, err
	}
	defer disconnectNode(nodeCC)

	s, err := nodeCC.AppLifeSvcCli.GetStatus(ctx, e.(*cce.NodeApp).AppID)
	if err != nil {
		return nil, err
	}

	if ctrl.OrchestrationMode == cce.OrchestrationModeNative {
		return &cce.NodeAppResp{
			NodeApp: *e.(*cce.NodeApp),
			Status:  s.String(),
		}, nil
	}

	// Kubernetes status
	// For Unknown, Deploying and Error return immediately
	switch s {
	case cce.Unknown, cce.Deploying, cce.Error:
		return &cce.NodeAppResp{
			NodeApp: *e.(*cce.NodeApp),
			Status:  s.String(),
		}, nil
	}

	k8sStatus, err := ctrl.KubernetesClient.Status(ctx, e.(*cce.NodeApp).NodeID, e.(*cce.NodeApp).AppID)
	if err != nil {
		return nil, err
	}

	return &cce.NodeAppResp{
		NodeApp: *e.(*cce.NodeApp),
		Status:  string(k8sStatus),
	}, nil
}
