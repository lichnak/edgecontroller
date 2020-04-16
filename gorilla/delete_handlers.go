// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package gorilla

import (
	"context"

	cce "github.com/otcshare/edgecontroller"
	"github.com/pkg/errors"
)

func handleDeleteNodesApps(ctx context.Context, ps cce.PersistenceService, e cce.Persistable) error {
	app, err := ps.Read(
		ctx,
		e.(*cce.NodeApp).AppID,
		&cce.App{})
	if err != nil {
		return err
	}

	ctrl := getController(ctx)
	nodePort := ctrl.EVAPort
	if nodePort == "" {
		nodePort = defaultEVAPort
	}
	nodeCC, err := connectNode(ctx, ps, e.(*cce.NodeApp), nodePort, ctrl.EdgeNodeCreds)
	if err != nil {
		return err
	}
	defer disconnectNode(nodeCC)

	// if kubernetes un-deploy application
	if ctrl.OrchestrationMode == cce.OrchestrationModeKubernetes ||
		ctrl.OrchestrationMode == cce.OrchestrationModeKubernetesOVN {
		if err = ctrl.KubernetesClient.Undeploy(
			ctx,
			e.(*cce.NodeApp).NodeID,
			e.(*cce.NodeApp).AppID,
		); err != nil {
			return err
		}
	}

	err = nodeCC.AppDeploySvcCli.Undeploy(ctx, app.GetID())

	return err
}

func handleDeleteNodesDNSConfigs(
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

	for _, aRecord := range dnsConfig.(*cce.DNSConfig).ARecords {
		if err := nodeCC.DNSSvcCli.DeleteA(ctx, aRecord); err != nil {
			return err
		}
	}

	return nodeCC.DNSSvcCli.DeleteForwarders(ctx, dnsConfig.(*cce.DNSConfig).Forwarders)
}

func handleDeleteNodesDNSConfigsWithAliases(
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

		if err := nodeCC.DNSSvcCli.DeleteA(ctx, record); err != nil {
			return err
		}
	}

	for _, aRecord := range dnsConfig.(*cce.DNSConfig).ARecords {
		if err := nodeCC.DNSSvcCli.DeleteA(ctx, aRecord); err != nil {
			return err
		}
	}

	if len(dnsConfig.(*cce.DNSConfig).Forwarders) != 0 {
		if err := nodeCC.DNSSvcCli.DeleteForwarders(ctx, dnsConfig.(*cce.DNSConfig).Forwarders); err != nil {
			return err
		}
	}

	return nil
}

func handleForcedDeleteNodesDNSConfigs(ctx context.Context, ctrl *cce.Controller, nodeID string) error {
	var persistedNode []cce.Persistable
	var err error

	// Filter nodes_dns_config to get the ID
	if persistedNode, err = ctrl.PersistenceService.Filter(
		ctx,
		&cce.NodeDNSConfig{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: nodeID,
			},
		},
	); err != nil {
		log.Errf("Error obtaining nodes_dns_configs: %v", err)
		return err
	}

	if len(persistedNode) < 1 {
		return nil
	}

	log.Errf("Deleting dns: %v", persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID)

	persistedConfig, err := ctrl.PersistenceService.Read(
		ctx,
		persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID,
		&cce.DNSConfig{},
	)
	if err != nil {
		log.Errf("Error fetching node_dns_config: %v", err)
		return err
	}

	// Fetch the DNS aliases from persistence
	persistedAliases, err := ctrl.PersistenceService.Filter(
		ctx,
		&cce.DNSConfigAppAlias{},
		[]cce.Filter{
			{Field: "dns_config_id", Value: persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID},
		},
	)
	if err != nil {
		log.Errf("Error fetching dns aliases: %v", err)
		return err
	}

	_, err = ctrl.PersistenceService.Delete(
		ctx,
		persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID,
		&cce.NodeDNSConfig{},
	)
	if err != nil {
		log.Errf("Error deleting node_dns_config: %v", err)
		return err
	}

	// Delete the association from persistence
	if _, err = ctrl.PersistenceService.Delete(
		ctx, persistedNode[0].GetID(), persistedNode[0],
	); err != nil {
		log.Errf("Error deleting association: %v", err)
		return err
	}

	// Delete the aliases from persistence
	for _, alias := range persistedAliases {
		if _, err = ctrl.PersistenceService.Delete(ctx, alias.GetID(), alias); err != nil {
			log.Errf("Error deleting aliases: %v", err)
			return err
		}
	}

	// Delete the config from persistence
	if _, err = ctrl.PersistenceService.Delete(ctx, persistedConfig.GetID(), persistedConfig); err != nil {
		log.Errf("Error deleting DNS config: %v", err)
		return err
	}

	return nil
}

func handleForceDeleteNodesApps(ctx context.Context, ctrl *cce.Controller, nodeID string) error {
	var persistedNode []cce.Persistable
	var err error

	// Filter node apps
	if persistedNode, err = ctrl.PersistenceService.Filter(
		ctx,
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: nodeID,
			},
		},
	); err != nil {
		log.Errf("Error obtaining apps: %v", err)
		return err
	}

	for _, app := range persistedNode {
		// Filter nodes_apps_traffic_policies to get the ID
		nodeAppPolicies, err := ctrl.PersistenceService.Filter(
			ctx,
			&cce.NodeAppTrafficPolicy{},
			[]cce.Filter{
				{
					Field: "nodes_apps_id",
					Value: app.GetID(),
				},
			})
		if err != nil {
			log.Errf("Error reading nodes_apps_traffic_policies: %v", err)
			return err
		}

		// Delete policies
		var ok bool
		for _, policy := range nodeAppPolicies {
			ok, err = ctrl.PersistenceService.Delete(ctx, policy.GetID(), &cce.NodeAppTrafficPolicy{})
			if err != nil {
				log.Errf("Error deleting from nodes_apps_traffic_policies: %v", err)
				return err
			}
			if !ok {
				log.Err("Did not delete 1 record from nodes_apps_traffic_policies")
				return err
			}
		}

		log.Infof("Deleting app: %v", app.GetID())
		// Delete app info on the controller
		_, err = ctrl.PersistenceService.Delete(ctx, app.GetID(), &cce.NodeApp{})
		if err != nil {
			log.Errf("Error deleting app: %v", err)
			return err
		}
	}

	return nil
}

func handleForceDeleteNodesInterfacePolicy(ctx context.Context, ctrl *cce.Controller, nodeID string) error {
	var persistedPolicy []cce.Persistable
	var err error

	// Filter node apps
	if persistedPolicy, err = ctrl.PersistenceService.Filter(
		ctx,
		&cce.NodeInterfaceTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: nodeID,
			},
		},
	); err != nil {
		log.Errf("Error obtaining apps: %v", err)
		return err
	}

	for _, policy := range persistedPolicy {
		ok, err := ctrl.PersistenceService.Delete(ctx, policy.GetID(), policy)
		if err != nil {
			log.Errf("Error deleting from nodes_interfaces_traffic_policies: %v", err)
			return err
		}
		if !ok {
			log.Err("Did not delete 1 record from nodes_interfaces_traffic_policies")
			return err
		}
	}

	return nil
}

func handleDeleteNode(ctx context.Context, ctrl *cce.Controller, nodeID string) error {
	// Check that we can delete the entity
	if statusCode, err := checkDBDeleteNodes(ctx, ctrl.PersistenceService, nodeID); err != nil {
		log.Errf("Error running DB logic: %v, %v", err, statusCode)
		return err
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(ctx, nodeID, &cce.Node{})
	if err != nil {
		log.Errf("Error reading entity: %v", err)
		return err
	}
	if persisted == nil {
		err = errors.New("No node found for node ID: " + nodeID)
		return err
	}

	var ok bool
	ok, err = ctrl.PersistenceService.Delete(ctx, nodeID, &cce.Node{})
	if err != nil {
		return err
	}

	// we just fetched the entity, so if !ok then something went wrong
	if !ok {
		return errors.New("Fetched entity could not be used")
	}
	return nil
}
