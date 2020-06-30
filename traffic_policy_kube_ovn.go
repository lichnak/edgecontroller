// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"

	coreV1 "k8s.io/api/core/v1"
	networkingV1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TrafficPolicyKubeOVN is an application or interface traffic policy.
type TrafficPolicyKubeOVN struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Ingress []*IngressRule `json:"ingress_rules"`
	Egress  []*EgressRule  `json:"egress_rules"`
}

// GetTableName returns the name of the persistence table.
func (*TrafficPolicyKubeOVN) GetTableName() string {
	return "traffic_policies"
}

// GetID gets the ID.
func (tp *TrafficPolicyKubeOVN) GetID() string {
	return tp.ID
}

// SetID sets the ID.
func (tp *TrafficPolicyKubeOVN) SetID(id string) {
	tp.ID = id
}

// Validate validates the model.
func (tp *TrafficPolicyKubeOVN) Validate() error {
	if !uuid.IsValid(tp.ID) {
		return errors.New("id not a valid UUID")
	}

	if tp.Name == "" {
		return errors.New("name cannot be empty")
	}

	if len(tp.Ingress) == 0 && len(tp.Egress) == 0 {
		return errors.New("ingress and egress cannot be empty")
	}

	for i, rule := range tp.Ingress {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("Ingress[%d].%s", i, err.Error())
		}
	}
	for i, rule := range tp.Egress {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("Egress[%d].%s", i, err.Error())
		}
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*TrafficPolicyKubeOVN) FilterFields() []string {
	return []string{}
}

func (tp *TrafficPolicyKubeOVN) String() string {
	var ingress, egress string

	for i, rule := range tp.Ingress {
		ingress += rule.String()
		if i < len(tp.Ingress)-1 {
			ingress += "\n		"
		}
	}

	for i, rule := range tp.Egress {
		egress += rule.String()
		if i < len(tp.Egress)-1 {
			egress += "\n		"
		}
	}

	return fmt.Sprintf(strings.TrimSpace(`
TrafficPolicyKubeOVN[
	ID: %s,
	Name: %s,
	Ingress: [
		%s
	], 
	Egress: [
		%s
	]
]`),
		tp.ID,
		tp.Name,
		ingress,
		egress)
}

// IngressRule is the model for a ingress rule.
type IngressRule struct {
	Description string     `json:"description"`
	From        []*IPBlock `json:"from"`
	Ports       []*Port    `json:"ports"`
}

// Validate validates the model.
func (ir *IngressRule) Validate() error {
	for i, block := range ir.From {
		if err := block.Validate(); err != nil {
			return fmt.Errorf("From[%d].%s", i, err.Error())
		}
	}

	for i, port := range ir.Ports {
		if err := port.Validate(); err != nil {
			return fmt.Errorf("Ports[%d].%s", i, err.Error())
		}
	}

	return nil
}

func (ir *IngressRule) String() string {
	var from, ports string
	for i, block := range ir.From {
		from += block.String()
		if i < len(ir.From)-1 {
			from += "\n				"
		}
	}
	for i, port := range ir.Ports {
		ports += port.String()
		if i < len(ir.Ports)-1 {
			ports += "\n				"
		}
	}
	return fmt.Sprintf(strings.TrimSpace(`
		IngressRule[
			Description: %s,
			From: [
				%s
			],
			Ports: [
				%s
			]
		]`),
		ir.Description,
		from,
		ports)
}

// EgressRule is the model for a egress rule.
type EgressRule struct {
	Description string     `json:"description"`
	To          []*IPBlock `json:"to"`
	Ports       []*Port    `json:"ports"`
}

// Validate validates the model.
func (er *EgressRule) Validate() error {
	for i, block := range er.To {
		if err := block.Validate(); err != nil {
			return fmt.Errorf("To[%d].%s", i, err.Error())
		}
	}

	for i, port := range er.Ports {
		if err := port.Validate(); err != nil {
			return fmt.Errorf("Ports[%d].%s", i, err.Error())
		}
	}

	return nil
}

func (er *EgressRule) String() string {
	var to, ports string
	for i, block := range er.To {
		to += block.String()
		if i < len(er.To)-1 {
			to += "\n				"
		}
	}
	for i, port := range er.Ports {
		ports += port.String()
		if i < len(er.Ports)-1 {
			ports += "\n				"
		}
	}
	return fmt.Sprintf(strings.TrimSpace(`
		EgressRule[
			Description: %s,
			To: [
				%s
			],
			Ports: [
				%s
			]
		]`),
		er.Description,
		to,
		ports)
}

// IPBlock is the model for a ip block.
type IPBlock struct {
	CIDR   string   `json:"cidr"`
	Except []string `json:"except"`
}

// Validate validates the model.
func (ipb *IPBlock) Validate() error {
	_, n, err := net.ParseCIDR(ipb.CIDR)
	if err != nil {
		return fmt.Errorf("Invalid CIDR: %s", err.Error())
	}

	for i, exceptCIDR := range ipb.Except {
		exceptIP, exceptNet, err := net.ParseCIDR(exceptCIDR)
		if err != nil {
			return fmt.Errorf("Except[%d].Invalid CIDR: %s", i, err.Error())
		}

		if exceptNet.String() == n.String() {
			return fmt.Errorf("Except[%d].CIDR(%s) is the same as CIDR(%s)", i, exceptCIDR, ipb.CIDR)
		}

		if !n.IP.Equal(exceptIP.Mask(n.Mask)) {
			return fmt.Errorf("Except[%d].CIDR(%s) is not in CIDR(%s)", i, exceptCIDR, ipb.CIDR)
		}

		eS, _ := exceptNet.Mask.Size()
		nS, _ := n.Mask.Size()
		if eS <= nS {
			return fmt.Errorf("Except[%d].CIDR(%s) mask is invalid", i, exceptCIDR)
		}
	}

	return nil
}

func (ipb *IPBlock) String() string {
	var except string
	for i, e := range ipb.Except {
		except += e
		if i < len(ipb.Except)-1 {
			except += "\n						"
		}
	}
	return fmt.Sprintf(strings.TrimSpace(`
				IPBlock[
					CIDR: %s,
					Except:	[
						%s
					]
				]`),
		ipb.CIDR,
		except)
}

// Port is the model for a port.
type Port struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
}

// Validate validates the model.
func (p *Port) Validate() error {
	if p.Protocol != "tcp" && p.Protocol != "udp" && p.Protocol != "sctp" {
		return fmt.Errorf("Not supported protocol: %s", p.Protocol)
	}

	return nil
}

func (p *Port) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
				Port[
					Port: %d,
					Protocol: %s
				]`),
		p.Port,
		p.Protocol)
}

// ToK8s converts traffic policy into Kubernetes' NetworkPolicy
func (tp *TrafficPolicyKubeOVN) ToK8s() *networkingV1.NetworkPolicy {
	np := &networkingV1.NetworkPolicy{
		Spec: networkingV1.NetworkPolicySpec{},
	}

	is := []networkingV1.NetworkPolicyIngressRule{}
	for _, ingress := range tp.Ingress {
		is = append(is, ingress.ToK8s())
	}

	es := []networkingV1.NetworkPolicyEgressRule{}
	for _, egress := range tp.Egress {
		es = append(es, egress.ToK8s())
	}

	policyTypes := []networkingV1.PolicyType{}
	if len(es) > 0 {
		np.Spec.Egress = es
		policyTypes = append(policyTypes, "Egress")
	}

	if len(is) > 0 {
		np.Spec.Ingress = is
		policyTypes = append(policyTypes, "Ingress")
	}

	np.Spec.PolicyTypes = policyTypes

	return np
}

// ToK8s converts port into Kubernetes' port
func (p *Port) ToK8s() networkingV1.NetworkPolicyPort {
	k8sProtocol := func(protocol string) coreV1.Protocol {
		switch protocol {
		case "udp", "UDP":
			return coreV1.ProtocolUDP
		case "sctp", "SCTP":
			return coreV1.ProtocolSCTP
		default:
			return coreV1.ProtocolTCP
		}
	}

	protocol := k8sProtocol(p.Protocol)
	intstrPort := intstr.FromInt(int(p.Port))

	return networkingV1.NetworkPolicyPort{
		Protocol: &protocol,
		Port:     &intstrPort,
	}
}

// ToK8s converts IPBlock into Kubernetes' Peer
func (ipb *IPBlock) ToK8s() networkingV1.NetworkPolicyPeer {
	excepts := []string{}
	excepts = append(excepts, ipb.Except...)
	return networkingV1.NetworkPolicyPeer{
		IPBlock: &networkingV1.IPBlock{
			CIDR:   ipb.CIDR,
			Except: excepts,
		},
	}
}

// ToK8s converts ingress rule into Kubernetes' ingress rule
func (ir *IngressRule) ToK8s() networkingV1.NetworkPolicyIngressRule {
	ingress := networkingV1.NetworkPolicyIngressRule{}

	for _, port := range ir.Ports {
		ingress.Ports = append(ingress.Ports, port.ToK8s())
	}

	for _, from := range ir.From {
		ingress.From = append(ingress.From, from.ToK8s())
	}

	return ingress
}

// ToK8s converts egress rule into Kubernetes' egress rule
func (er *EgressRule) ToK8s() networkingV1.NetworkPolicyEgressRule {
	egress := networkingV1.NetworkPolicyEgressRule{}

	for _, port := range er.Ports {
		egress.Ports = append(egress.Ports, port.ToK8s())
	}

	for _, to := range er.To {
		egress.To = append(egress.To, to.ToK8s())
	}

	return egress
}
