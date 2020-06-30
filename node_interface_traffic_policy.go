// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// TODO: Entire project: Rename all instance of `network_interface` to `interface`
// TODO: Entire project: Rename all instance of `network_interfaces` to `interfaces`
// TODO: Entire project: Rename all instance of `traffic_policy` to `policy`
// TODO: Entire project: Rename all instance of `traffic_policies` to `policies`
// TODO: Entire project: Rename all instance of `NetworkInterface` to `Interface`
// TODO: Entire project: Rename all instance of `NetworkInterfaces` to `Interfaces`
// TODO: Entire project: Rename all instance of `TrafficPolicy` to `Policy`
// TODO: Entire project: Rename all instance of `TrafficPolicies` to `Policies`

// NodeInterfaceTrafficPolicy represents an association between a
// NodeInterface and a TrafficPolicy.
type NodeInterfaceTrafficPolicy struct {
	ID                 string `json:"id"`
	NodeID             string `json:"node_id"`
	NetworkInterfaceID string `json:"network_interface_id"`
	TrafficPolicyID    string `json:"traffic_policy_id"`
}

// GetTableName returns the name of the persistence table.
func (*NodeInterfaceTrafficPolicy) GetTableName() string {
	return "nodes_network_interfaces_traffic_policies"
}

// GetID gets the ID.
func (n_i_tp *NodeInterfaceTrafficPolicy) GetID() string {
	return n_i_tp.ID
}

// SetID sets the ID.
func (n_i_tp *NodeInterfaceTrafficPolicy) SetID(id string) {
	n_i_tp.ID = id
}

// Validate validates the model.
func (n_i_tp *NodeInterfaceTrafficPolicy) Validate() error {
	if !uuid.IsValid(n_i_tp.ID) {
		return errors.New("id not a valid uuid")
	}
	if !uuid.IsValid(n_i_tp.NodeID) {
		return errors.New("node_id not a valid uuid")
	}
	if !uuid.IsValid(n_i_tp.NetworkInterfaceID) {
		return errors.New("network_interface_id not a valid uuid")
	}
	if !uuid.IsValid(n_i_tp.TrafficPolicyID) {
		return errors.New("traffic_policy_id not a valid uuid")
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*NodeInterfaceTrafficPolicy) FilterFields() []string {
	return []string{
		"node_id",
		"network_interface_id",
		"traffic_policy_id",
	}
}

func (n_i_tp *NodeInterfaceTrafficPolicy) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
NodeInterfaceTrafficPolicy[
	ID: %s
	NodeID: %s
    NetworkInterfaceID: %s
    TrafficPolicyID: %s
]`),
		n_i_tp.ID,
		n_i_tp.NodeID,
		n_i_tp.NetworkInterfaceID,
		n_i_tp.TrafficPolicyID)
}
