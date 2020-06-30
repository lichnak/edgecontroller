// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// DNSConfigAppAlias represents an association between a DNSConfig and an AppID.
type DNSConfigAppAlias struct {
	ID          string `json:"id"`
	DNSConfigID string `json:"dns_config_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	AppID       string `json:"app_id"`
}

// GetTableName returns the name of the persistence table.
func (*DNSConfigAppAlias) GetTableName() string {
	return "dns_configs_app_aliases"
}

// GetID gets the ID.
func (cfg_alias *DNSConfigAppAlias) GetID() string {
	return cfg_alias.ID
}

// SetID sets the ID.
func (cfg_alias *DNSConfigAppAlias) SetID(id string) {
	cfg_alias.ID = id
}

// Validate validates the model.
func (cfg_alias *DNSConfigAppAlias) Validate() error {
	if !uuid.IsValid(cfg_alias.ID) {
		return errors.New("id not a valid uuid")
	}
	if !uuid.IsValid(cfg_alias.DNSConfigID) {
		return errors.New("dns_config_id not a valid uuid")
	}
	if cfg_alias.Name == "" {
		return errors.New("name cannot be empty")
	}
	if cfg_alias.Description == "" {
		return errors.New("description cannot be empty")
	}
	if !uuid.IsValid(cfg_alias.AppID) {
		return errors.New("app_id not a valid uuid")
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*DNSConfigAppAlias) FilterFields() []string {
	return []string{
		"dns_config_id",
		"app_id",
	}
}

func (cfg_alias *DNSConfigAppAlias) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
DNSConfigAppAlias[
    ID: %s
    DNSConfigID: %s
    AppID: %s
]`),
		cfg_alias.ID,
		cfg_alias.DNSConfigID,
		cfg_alias.AppID)
}
