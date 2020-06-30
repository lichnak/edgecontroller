// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// Node is a node (aka appliance or device).
type Node struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Location string `json:"location"`
	Serial   string `json:"serial"`
}

// NodeReq is a Node request.
type NodeReq struct {
	Node
	NetworkInterfaces []*NetworkInterface             `json:"network_interfaces"`
	TrafficPolicies   []NetworkInterfaceTrafficPolicy `json:"traffic_policies"`
}

// NodeResp is a Node response.
// TODO add a String() method and test for this struct.
type NodeResp struct {
	Node
	NetworkInterfaces []*NetworkInterface `json:"network_interfaces"`
}

// NetworkInterface is a NetworkInterface.
// TODO add a String() method for this struct.
type NetworkInterface struct {
	ID                string   `json:"id"`
	Description       string   `json:"description"`
	Driver            string   `json:"driver"`
	Type              string   `json:"type"`
	MACAddress        string   `json:"mac_address"`
	VLAN              int      `json:"vlan"`
	Zones             []string `json:"zones"`
	FallbackInterface string   `json:"fallback_interface"`
}

// NetworkInterfaceTrafficPolicy specifies the traffic policy for a network interface.
type NetworkInterfaceTrafficPolicy struct {
	NetworkInterfaceID string `json:"network_interface_id"`
	TrafficPolicyID    string `json:"traffic_policy_id"`
}

// GetTableName returns the name of the persistence table.
func (*Node) GetTableName() string {
	return "nodes"
}

// GetID gets the ID.
func (n *Node) GetID() string {
	return n.ID
}

// SetID sets the ID.
func (n *Node) SetID(id string) {
	n.ID = id
}

// GetNodeID gets the node ID.
func (n *Node) GetNodeID() string {
	return n.ID
}

// Validate validates the model.
func (n *Node) Validate() error {
	if !uuid.IsValid(n.ID) {
		return errors.New("id not a valid uuid")
	}
	if n.Name == "" {
		return errors.New("name cannot be empty")
	}
	if n.Location == "" {
		return errors.New("location cannot be empty")
	}
	if n.Serial == "" {
		return errors.New("serial cannot be empty")
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*Node) FilterFields() []string {
	return []string{
		"serial",
	}
}

func (n *Node) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
Node[
    ID: %s
    Name: %s
    Location: %s
    Serial: %s
]`),
		n.ID,
		n.Name,
		n.Location,
		n.Serial)
}

// Validate validates the request model.
// TODO add a test for this method.
func (nr *NodeReq) Validate() error {
	if err := nr.Node.Validate(); err != nil {
		return err
	}
	for i, ni := range nr.NetworkInterfaces {
		if ni.ID == "" {
			return fmt.Errorf("network_interfaces[%d].id cannot be empty", i)
		}
		switch ni.Driver {
		case "kernel", "userspace":
		default:
			return fmt.Errorf("network_interfaces[%d].driver must be one of [kernel, userspace]", i)
		}
		switch ni.Type {
		case "none", "upstream", "downstream", "bidirectional", "breakout":
		default:
			return fmt.Errorf("network_interfaces[%d].type must be one of [none, upstream, downstream, "+
				"bidirectional, breakout]", i)
		}
		if ni.VLAN < 0 || ni.VLAN > 255 {
			return fmt.Errorf("network_interfaces[%d].vlan must be in [0..255]", i)
		}
	}
	for i, tp := range nr.TrafficPolicies {
		if !uuid.IsValid(tp.TrafficPolicyID) {
			return fmt.Errorf("traffic_policies[%d].traffic_policy_id not a valid uuid", i)
		}
	}

	return nil
}

// GetTableName returns the name of the persistence table.
func (nr *NodeReq) GetTableName() string {
	return nr.Node.GetTableName()
}
