// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"
	"fmt"
	"net/http"

	cce "github.com/open-ness/edgecontroller"
)

func checkDBDeleteNodes(
	ctx context.Context,
	ps cce.PersistenceService,
	id string,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete node_id %s: record in use in nodes_apps",
			id)
	}

	if es, err = ps.Filter(
		ctx,
		&cce.NodeDNSConfig{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete node_id %s: record in use in nodes_dns_configs",
			id)
	}

	return 0, nil
}

func checkDBDeleteApps(
	ctx context.Context,
	ps cce.PersistenceService,
	id string,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.DNSConfigAppAlias{},
		[]cce.Filter{
			{
				Field: "app_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete app_id %s: record in use in dns_configs_app_aliases",
			id)
	}

	if es, err = ps.Filter(
		ctx,
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "app_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete app_id %s: record in use in nodes_apps",
			id)
	}

	return 0, nil
}

func checkDBDeleteNodesApps(
	ctx context.Context,
	ps cce.PersistenceService,
	id string,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete node_app_id %s: record in use in nodes_apps_traffic_policies",
			id)
	}

	return 0, nil
}

func checkDBDeleteTrafficPolicies(
	ctx context.Context,
	ps cce.PersistenceService,
	id string,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "traffic_policy_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete traffic_policy_id %s: record in use in "+
				"nodes_apps_traffic_policies",
			id)
	}

	return 0, nil
}

func checkDBDeleteDNSConfigs(
	ctx context.Context,
	ps cce.PersistenceService,
	id string,
) (statusCode int, err error) {
	var es []cce.Persistable

	if es, err = ps.Filter(
		ctx,
		&cce.DNSConfigAppAlias{},
		[]cce.Filter{
			{
				Field: "dns_config_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete dns_config_id %s: record in use in "+
				"dns_configs_app_aliases",
			id)
	}

	if es, err = ps.Filter(
		ctx,
		&cce.NodeDNSConfig{},
		[]cce.Filter{
			{
				Field: "dns_config_id",
				Value: id,
			},
		},
	); err != nil {
		return http.StatusInternalServerError, err
	}

	if len(es) > 0 {
		return http.StatusUnprocessableEntity, fmt.Errorf(
			"cannot delete dns_config_id %s: record in use in "+
				"nodes_dns_configs",
			id)
	}

	return 0, nil
}
