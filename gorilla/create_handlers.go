// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"
	"fmt"

	cce "github.com/open-ness/edgecontroller"
)

func handleCreateNodesApps(ctx context.Context, ps cce.PersistenceService, e cce.Persistable) error {
	app, err := ps.Read(ctx, e.(*cce.NodeApp).AppID, &cce.App{})
	if err != nil {
		return fmt.Errorf("Error fetching app from DB: %v", err)
	}

	log.Debugf("Loaded app %s\n%+v", app.GetID(), app)

	ctrl := getController(ctx)
	nodePort := ctrl.EVAPort
	if nodePort == "" {
		nodePort = defaultEVAPort
	}
	nodeCC, err := connectNode(ctx, ps, e.(*cce.NodeApp), nodePort, ctrl.EdgeNodeCreds)
	if err != nil {
		return fmt.Errorf("Error connecting to node: %v", err)
	}
	defer disconnectNode(nodeCC)

	if err := nodeCC.AppDeploySvcCli.Deploy(ctx, app.(*cce.App)); err != nil {
		return err
	}

	if ctrl.OrchestrationMode == cce.OrchestrationModeKubernetes ||
		ctrl.OrchestrationMode == cce.OrchestrationModeKubernetesOVN {
		err := ctrl.KubernetesClient.Deploy(
			ctx,
			e.(*cce.NodeApp).GetNodeID(),
			toK8SApp(app.(*cce.App)))
		if err != nil {
			return err
		}
	}

	log.Infof("App %s deployed to node", app.GetID())

	return nil
}

func handleCreateNodesDNSConfigs(
	ctx context.Context,
	ps cce.PersistenceService,
	e cce.Persistable,
) error {
	dnsConfig, err := ps.Read(ctx, e.(*cce.NodeDNSConfig).DNSConfigID, &cce.DNSConfig{})
	if err != nil {
		return err
	}
	log.Debugf("Loaded DNS Config %s\n%+v", dnsConfig.GetID(), dnsConfig)

	ctrl := getController(ctx)
	nodePort := ctrl.ELAPort
	if nodePort == "" {
		nodePort = defaultELAPort
	}
	nodeCC, err := connectNode(ctx, ps, e.(*cce.NodeDNSConfig), nodePort, ctrl.EdgeNodeCreds)
	if err != nil {
		return err
	}
	defer disconnectNode(nodeCC)

	for _, aRecord := range dnsConfig.(*cce.DNSConfig).ARecords {
		if err := nodeCC.DNSSvcCli.SetA(ctx, aRecord); err != nil {
			return err
		}
	}

	return nodeCC.DNSSvcCli.SetForwarders(ctx, dnsConfig.(*cce.DNSConfig).Forwarders)
}

func handleCreateNodesDNSConfigsWithAliases(
	ctx context.Context,
	ps cce.PersistenceService,
	nodeDNS cce.Persistable,
	dnsConfig cce.Persistable,
	dnsAliases []cce.Persistable,
) error {
	ctrl := getController(ctx)
	nodePort := ctrl.ELAPort
	if nodePort == "" {
		nodePort = defaultELAPort
	}
	nodeCC, err := connectNode(ctx, ps, nodeDNS.(*cce.NodeDNSConfig), nodePort, ctrl.EdgeNodeCreds)
	if err != nil {
		return err
	}
	defer disconnectNode(nodeCC)

	for _, alias := range dnsAliases {
		record := &cce.DNSARecord{
			Name:        alias.(*cce.DNSConfigAppAlias).AppID,
			Description: alias.(*cce.DNSConfigAppAlias).Description,
			IPs:         []string{alias.(*cce.DNSConfigAppAlias).AppID},
		}

		if err := nodeCC.DNSSvcCli.SetA(ctx, record); err != nil {
			return err
		}
	}

	for _, aRecord := range dnsConfig.(*cce.DNSConfig).ARecords {
		if err := nodeCC.DNSSvcCli.SetA(ctx, aRecord); err != nil {
			return err
		}
	}

	if len(dnsConfig.(*cce.DNSConfig).Forwarders) != 0 {
		if err := nodeCC.DNSSvcCli.SetForwarders(ctx, dnsConfig.(*cce.DNSConfig).Forwarders); err != nil {
			return err
		}
	}

	return nil
}
