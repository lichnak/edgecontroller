// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// NodeAppTrafficPolicy represents an association between a
// NodeApp and a TrafficPolicy.
type NodeAppTrafficPolicy struct {
	ID              string `json:"id"`
	NodeAppID       string `json:"nodes_apps_id"`
	TrafficPolicyID string `json:"traffic_policy_id"`
}

// GetTableName returns the name of the persistence table.
func (*NodeAppTrafficPolicy) GetTableName() string {
	return "nodes_apps_traffic_policies"
}

// GetID gets the ID.
func (n_a_tp *NodeAppTrafficPolicy) GetID() string {
	return n_a_tp.ID
}

// SetID sets the ID.
func (n_a_tp *NodeAppTrafficPolicy) SetID(id string) {
	n_a_tp.ID = id
}

// Validate validates the model.
func (n_a_tp *NodeAppTrafficPolicy) Validate() error {
	if !uuid.IsValid(n_a_tp.ID) {
		return errors.New("id not a valid uuid")
	}
	if !uuid.IsValid(n_a_tp.NodeAppID) {
		return errors.New("nodes_apps_id not a valid uuid")
	}
	if !uuid.IsValid(n_a_tp.TrafficPolicyID) {
		return errors.New("traffic_policy_id not a valid uuid")
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*NodeAppTrafficPolicy) FilterFields() []string {
	return []string{
		"nodes_apps_id",
		"traffic_policy_id",
	}
}

func (n_a_tp *NodeAppTrafficPolicy) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
NodeAppTrafficPolicy[
    ID: %s
    NodeAppID: %s
    TrafficPolicyID: %s
]`),
		n_a_tp.ID,
		n_a_tp.NodeAppID,
		n_a_tp.TrafficPolicyID)
}
