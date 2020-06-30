// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package swagger

import (
	cce "github.com/open-ness/edgecontroller"
)

// PolicySummary is a summary of an application traffic policy or interface traffic policy.
type PolicySummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PolicyDetail is a detailed representation of the traffic policy.
type PolicyDetail struct {
	PolicySummary
	Rules []*cce.TrafficRule `json:"traffic_rules"`
}

// PolicyKubeOVNDetail is a detailed representation of the traffic policy for KubeOVN implementation.
type PolicyKubeOVNDetail struct {
	PolicySummary
	IngressRules []*cce.IngressRule `json:"ingress_rules"`
	EgressRules  []*cce.EgressRule  `json:"egress_rules"`
}

// PolicyList is a list representation of traffic policies.
type PolicyList struct {
	Policies []PolicySummary `json:"policies"`
}
