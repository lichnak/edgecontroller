// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"
	"fmt"
	"net/http"

	cce "github.com/open-ness/edgecontroller"
)

func checkDBCreateNodesApps(
	ctx context.Context,
	ps cce.PersistenceService,
	e cce.Persistable,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: e.(*cce.NodeApp).NodeID,
			},
			{
				Field: "app_id",
				Value: e.(*cce.NodeApp).AppID,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) != 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"duplicate record in %s detected for node_id %s and app_id %s",
			e.(*cce.NodeApp).GetTableName(),
			e.(*cce.NodeApp).NodeID,
			e.(*cce.NodeApp).AppID)
	}

	return 0, nil
}

func checkDBCreateDNSConfigsAppAliases(
	ctx context.Context,
	ps cce.PersistenceService,
	e cce.Persistable,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.DNSConfigAppAlias{},
		[]cce.Filter{
			{
				Field: "dns_config_id",
				Value: e.(*cce.DNSConfigAppAlias).DNSConfigID,
			},
			{
				Field: "app_id",
				Value: e.(*cce.DNSConfigAppAlias).AppID,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) != 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"duplicate record in %s detected for dns_config_id %s and app_id %s",
			e.(*cce.DNSConfigAppAlias).GetTableName(),
			e.(*cce.DNSConfigAppAlias).DNSConfigID,
			e.(*cce.DNSConfigAppAlias).AppID)
	}

	return 0, nil
}

func checkDBCreateNodesDNSConfigs(
	ctx context.Context,
	ps cce.PersistenceService,
	e cce.Persistable,
) (statusCode int, err error) {
	var es []cce.Persistable

	// the nodes_dns_configs table has a unique constraint on node_id so we don't filter on dns_config_id
	if es, err = ps.Filter(
		ctx,
		&cce.NodeDNSConfig{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: e.(*cce.NodeDNSConfig).NodeID,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) != 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"duplicate record in %s detected for node_id %s",
			e.(*cce.NodeDNSConfig).GetTableName(),
			e.(*cce.NodeDNSConfig).NodeID)
	}

	return 0, nil
}
