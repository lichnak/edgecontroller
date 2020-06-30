// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// NodeDNSConfig represents an association between a Node and a DNSConfig.
type NodeDNSConfig struct {
	ID          string `json:"id"`
	NodeID      string `json:"node_id"`
	DNSConfigID string `json:"dns_config_id"`
}

// GetTableName returns the name of the persistence table.
func (*NodeDNSConfig) GetTableName() string {
	return "nodes_dns_configs"
}

// GetID gets the ID.
func (n_cfg *NodeDNSConfig) GetID() string {
	return n_cfg.ID
}

// SetID sets the ID.
func (n_cfg *NodeDNSConfig) SetID(id string) {
	n_cfg.ID = id
}

// GetNodeID gets the node ID.
func (n_cfg *NodeDNSConfig) GetNodeID() string {
	return n_cfg.NodeID
}

// Validate validates the model.
func (n_cfg *NodeDNSConfig) Validate() error {
	if !uuid.IsValid(n_cfg.ID) {
		return errors.New("id not a valid uuid")
	}
	if !uuid.IsValid(n_cfg.NodeID) {
		return errors.New("node_id not a valid uuid")
	}
	if !uuid.IsValid(n_cfg.DNSConfigID) {
		return errors.New("dns_config_id not a valid uuid")
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*NodeDNSConfig) FilterFields() []string {
	return []string{
		"node_id",
		"dns_config_id",
	}
}

func (n_cfg *NodeDNSConfig) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
NodeDNSConfig[
    ID: %s
    NodeID: %s
    DNSConfigID: %s
]`),
		n_cfg.ID,
		n_cfg.NodeID,
		n_cfg.DNSConfigID)
}
