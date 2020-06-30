// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// DNSConfig is a DNS configuration.
type DNSConfig struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	ARecords   []*DNSARecord   `json:"a_records"`
	Forwarders []*DNSForwarder `json:"forwarders"`
}

// GetTableName returns the name of the persistence table.
func (cfg *DNSConfig) GetTableName() string {
	return "dns_configs"
}

// GetID gets the ID.
func (cfg *DNSConfig) GetID() string {
	return cfg.ID
}

// SetID sets the ID.
func (cfg *DNSConfig) SetID(id string) {
	cfg.ID = id
}

// Validate validates the model.
func (cfg *DNSConfig) Validate() error {
	if !uuid.IsValid(cfg.ID) {
		return errors.New("id not a valid uuid")
	}
	if cfg.Name == "" {
		return errors.New("name cannot be empty")
	}
	if len(cfg.ARecords) == 0 && len(cfg.Forwarders) == 0 {
		return errors.New("a_records|forwarders cannot both be empty")
	}
	for i, aRecord := range cfg.ARecords {
		if err := aRecord.Validate(); err != nil {
			return fmt.Errorf("a_records[%d].%s", i, err.Error())
		}
	}
	for i, forwarder := range cfg.Forwarders {
		if err := forwarder.Validate(); err != nil {
			return fmt.Errorf("forwarders[%d].%s", i, err.Error())
		}
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*DNSConfig) FilterFields() []string {
	return []string{}
}

func (cfg *DNSConfig) String() string {
	records := ""

	for i, record := range cfg.ARecords {
		records += record.String()
		if i < len(cfg.ARecords)-1 {
			records += "\n        "
		}
	}

	forwarders := ""

	for i, forwarder := range cfg.Forwarders {
		forwarders += forwarder.String()
		if i < len(cfg.Forwarders)-1 {
			forwarders += "\n        "
		}
	}

	return fmt.Sprintf(strings.TrimSpace(`
DNSConfig[
    ID: %s
    Name: %s
    ARecords: [
        %s
    ]
    Forwarders: [
        %s
    ]
]`),
		cfg.ID,
		cfg.Name,
		records,
		forwarders)
}

// DNSARecord is a DNS A record.
type DNSARecord struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IPs         []string `json:"ips"`
}

// Validate validates the model.
func (r *DNSARecord) Validate() error {
	if r.Name == "" {
		return errors.New("name cannot be empty")
	}
	if r.Description == "" {
		return errors.New("description cannot be empty")
	}
	if len(r.IPs) == 0 {
		return errors.New("ips cannot be empty")
	}
	for i, ip := range r.IPs {
		if ip == "" {
			return fmt.Errorf("ips[%d] cannot be empty", i)
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("ips[%d] could not be parsed", i)
		}
		if net.ParseIP(ip).IsUnspecified() {
			return fmt.Errorf("ips[%d] cannot be zero", i)
		}
	}

	return nil
}

func (r *DNSARecord) String() string {
	ips := ""

	for i, ip := range r.IPs {
		ips += ip
		if i < len(r.IPs)-1 {
			ips += "\n                "
		}
	}

	return fmt.Sprintf(strings.TrimSpace(`
        DNSARecord[
            Name: %s
            Description: %s
            IPs: [
                %s
            ]
        ]`),
		r.Name,
		r.Description,
		ips)
}

// DNSForwarder is a DNS forwarder.
type DNSForwarder struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	IP          string `json:"ip"`
}

// Validate validates the model.
func (f *DNSForwarder) Validate() error {
	if f.Name == "" {
		return errors.New("name cannot be empty")
	}
	if f.Description == "" {
		return errors.New("description cannot be empty")
	}
	if f.IP == "" {
		return fmt.Errorf("ip cannot be empty")
	}
	if net.ParseIP(f.IP) == nil {
		return fmt.Errorf("ip could not be parsed")
	}
	if net.ParseIP(f.IP).IsUnspecified() {
		return fmt.Errorf("ip cannot be zero")
	}

	return nil
}

func (f *DNSForwarder) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
        DNSForwarder[
            Name: %s
            Description: %s
            IP: %s
        ]`),
		f.Name,
		f.Description,
		f.IP)
}
