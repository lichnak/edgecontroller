// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// TrafficPolicy is an application or interface traffic policy.
type TrafficPolicy struct {
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Rules []*TrafficRule `json:"traffic_rules"`
}

// GetTableName returns the name of the persistence table.
func (*TrafficPolicy) GetTableName() string {
	return "traffic_policies"
}

// GetID gets the ID.
func (tp *TrafficPolicy) GetID() string {
	return tp.ID
}

// SetID sets the ID.
func (tp *TrafficPolicy) SetID(id string) {
	tp.ID = id
}

// Validate validates the model.
func (tp *TrafficPolicy) Validate() error {
	if !uuid.IsValid(tp.ID) {
		return errors.New("id not a valid uuid")
	}
	if tp.Name == "" {
		return errors.New("name cannot be empty")
	}
	if len(tp.Rules) == 0 {
		return errors.New("rules cannot be empty")
	}
	for i, rule := range tp.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rules[%d].%s", i, err.Error())
		}
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*TrafficPolicy) FilterFields() []string {
	return []string{}
}

func (tp *TrafficPolicy) String() string {
	rules := ""

	for i, rule := range tp.Rules {
		rules += rule.String()
		if i < len(tp.Rules)-1 {
			rules += "\n        "
		}
	}

	return fmt.Sprintf(strings.TrimSpace(`
TrafficPolicy[
	ID: %s,
	Name: %s,
    Rules: [
        %s
    ]
]`),
		tp.ID,
		tp.Name,
		rules)
}

// TrafficRule is the model for a traffic rule.
type TrafficRule struct {
	Description string           `json:"description"`
	Priority    int              `json:"priority"`
	Source      *TrafficSelector `json:"source"`
	Destination *TrafficSelector `json:"destination"`
	Target      *TrafficTarget   `json:"target"`
}

// Validate validates the model.
func (tr *TrafficRule) Validate() error {
	if tr.Priority < 1 || tr.Priority > 65535 {
		return errors.New("priority must be in [1..65535]")
	}
	if tr.Source == nil && tr.Destination == nil {
		return errors.New("source & destination cannot both be empty")
	}
	if tr.Source != nil {
		if err := tr.Source.Validate(); err != nil {
			return fmt.Errorf("source.%s", err.Error())
		}
	}
	if tr.Destination != nil {
		if err := tr.Destination.Validate(); err != nil {
			return fmt.Errorf("destination.%s", err.Error())
		}
	}
	if tr.Target == nil {
		return errors.New("target cannot be empty")
	}
	if err := tr.Target.Validate(); err != nil {
		return fmt.Errorf("target.%s", err.Error())
	}

	return nil
}

func (tr *TrafficRule) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
        TrafficRule[
            Description: %s
            Priority: %d
            Source: %s
            Destination: %s
            Target: %s
        ]`),
		tr.Description,
		tr.Priority,
		tr.Source,
		tr.Destination,
		tr.Target)
}

// TrafficSelector is the model for a traffic selector.
type TrafficSelector struct {
	Description string     `json:"description"`
	MACs        *MACFilter `json:"mac_filter"`
	IP          *IPFilter  `json:"ip_filter"`
	GTP         *GTPFilter `json:"gtp_filter"`
}

// Validate validates the model.
func (ts *TrafficSelector) Validate() error {
	if ts.MACs == nil && ts.IP == nil && ts.GTP == nil {
		return errors.New("mac_filter|ip_filter|gtp_filter cannot all be nil")
	}
	if ts.MACs != nil {
		if err := ts.MACs.Validate(); err != nil {
			return fmt.Errorf("mac_filter.%s", err.Error())
		}
	}
	if ts.IP != nil {
		if err := ts.IP.Validate(); err != nil {
			return fmt.Errorf("ip_filter.%s", err.Error())
		}
	}
	if ts.GTP != nil {
		if err := ts.GTP.Validate(); err != nil {
			return fmt.Errorf("gtp_filter.%s", err.Error())
		}
	}

	return nil
}

func (ts *TrafficSelector) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
            TrafficSelector[
                Description: %s
                MACs: %s
                IP: %s
                GTP: %s
            ]`),
		ts.Description,
		ts.MACs,
		ts.IP,
		ts.GTP)
}

// TrafficTarget is the model for a traffic target.
type TrafficTarget struct {
	Description string       `json:"description"`
	Action      string       `json:"action"`
	MAC         *MACModifier `json:"mac_modifier"`
	IP          *IPModifier  `json:"ip_modifier"`
}

// Validate validates the model.
func (tt *TrafficTarget) Validate() error {
	switch tt.Action {
	case "accept", "reject", "drop":
	default:
		return errors.New("action must be one of [accept, reject, drop]")
	}
	if tt.MAC != nil {
		if err := tt.MAC.Validate(); err != nil {
			return fmt.Errorf("mac_modifier.%s", err.Error())
		}
	}
	if tt.IP != nil {
		if err := tt.IP.Validate(); err != nil {
			return fmt.Errorf("ip_modifier.%s", err.Error())
		}
	}

	return nil
}

func (tt *TrafficTarget) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
            TrafficTarget[
                Description: %s
                Action: %s
                MAC: %s
                IP: %s
            ]`),
		tt.Description,
		tt.Action,
		tt.MAC,
		tt.IP)
}

// MACFilter is the model for a MAC filter.
type MACFilter struct {
	MACAddresses []string `json:"mac_addresses"`
}

// Validate validates the model.
func (f *MACFilter) Validate() error {
	for i, mac := range f.MACAddresses {
		if _, err := net.ParseMAC(mac); err != nil {
			return fmt.Errorf("mac_addresses[%d] could not be parsed (%s)",
				i, err.Error())
		}
	}

	return nil
}

func (f *MACFilter) String() string {
	macs := ""

	for i, mac := range f.MACAddresses {
		macs += mac
		if i < len(f.MACAddresses)-1 {
			macs += "\n                        "
		}
	}

	return fmt.Sprintf(strings.TrimSpace(`
                MACFilter[
                    MACAddresses: [
                        %s
                    ]
                ]`),
		macs)
}

// IPFilter is the model for an IP filter.
type IPFilter struct {
	Address   string `json:"address"`
	Mask      int    `json:"mask"`
	BeginPort int    `json:"begin_port"`
	EndPort   int    `json:"end_port"`
	Protocol  string `json:"protocol"`
}

// Validate validates the model.
func (f *IPFilter) Validate() error {
	if net.ParseIP(f.Address) == nil {
		return errors.New("address could not be parsed")
	}
	if f.Mask < 0 || f.Mask > 128 {
		return errors.New("mask must be in [0..128]")
	}
	if f.BeginPort < 0 || f.BeginPort > 65535 {
		return errors.New("begin_port must be in [0..65535]")
	}
	if f.EndPort < 0 || f.EndPort > 65535 {
		return errors.New("end_port must be in [0..65535]")
	}
	if f.BeginPort > f.EndPort {
		return errors.New("begin_port must be <= end_port")
	}
	switch f.Protocol {
	case "tcp", "udp", "icmp", "sctp", "all":
	default:
		return errors.New("protocol must be one of [tcp, udp, icmp, sctp, all]")
	}

	return nil
}

func (f *IPFilter) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
                IPFilter[
                    Address: %s
                    Mask: %d
                    BeginPort: %d
                    EndPort: %d
                    Protocol: %s
                ]`),
		f.Address,
		f.Mask,
		f.BeginPort,
		f.EndPort,
		f.Protocol)
}

// GTPFilter is the model for a GTP filter.
type GTPFilter struct {
	Address string   `json:"address"`
	Mask    int      `json:"mask"`
	IMSIs   []string `json:"imsis"`
}

// Validate validates the model.
func (f *GTPFilter) Validate() error {
	if f.Address == "" {
		return errors.New("address cannot be empty")
	}
	if net.ParseIP(f.Address) == nil {
		return errors.New("address could not be parsed")
	}
	if f.Mask < 0 || f.Mask > 128 {
		return errors.New("mask must be in [0..128]")
	}
	for i, imsi := range f.IMSIs {
		if _, err := strconv.ParseInt(imsi, 10, 64); err != nil {
			return fmt.Errorf("imsis[%d] must be 14 or 15 digits", i)
		}
		switch len(imsi) {
		case 14, 15:
		default:
			return fmt.Errorf("imsis[%d] must be 14 or 15 digits", i)
		}
	}

	return nil
}

func (f *GTPFilter) String() string {
	imsis := ""

	for i, imsi := range f.IMSIs {
		imsis += imsi
		if i < len(f.IMSIs)-1 {
			imsis += "\n                        "
		}
	}

	return fmt.Sprintf(strings.TrimSpace(`
                GTPFilter[
                    Address: %s
                    Mask: %d
                    IMSIs: [
                        %s
                    ]
                ]`),
		f.Address,
		f.Mask,
		imsis)
}

// MACModifier is the model for a MAC modifier.
type MACModifier struct {
	MACAddress string `json:"mac_address"`
}

// Validate validates the model.
func (m *MACModifier) Validate() error {
	if _, err := net.ParseMAC(m.MACAddress); err != nil {
		return fmt.Errorf("mac_address could not be parsed (%s)", err.Error())
	}

	return nil
}

func (m *MACModifier) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
                MACModifier[
                    MACAddress: %s
                ]`),
		m.MACAddress)
}

// IPModifier is the model for an IP modifier.
type IPModifier struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// Validate validates the model.
func (m *IPModifier) Validate() error {
	if net.ParseIP(m.Address) == nil {
		return errors.New("address could not be parsed")
	}
	if m.Port < 1 || m.Port > 65535 {
		return errors.New("port must be in [1..65535]")
	}

	return nil
}

func (m *IPModifier) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
                IPModifier[
                    Address: %s
                    Port: %d
                ]`),
		m.Address,
		m.Port)
}
