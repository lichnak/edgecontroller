// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package cce

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/open-ness/edgecontroller/uuid"
)

// App is an application.
type App struct {
	ID          string       `json:"id"`
	Type        string       `json:"type"`
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Vendor      string       `json:"vendor"`
	Description string       `json:"description"`
	Cores       int          `json:"cores"`
	Memory      int          `json:"memory"` // in MB
	Ports       []PortProto  `json:"ports,omitempty"`
	Source      string       `json:"source"`
	EPAFeatures []EPAFeature `json:"epafeatures,omitempty"`
}

// PortProto is a port and protocol combination. It is typically used to represent the ports and protocols that an
// application is listening on and needs exposed.
type PortProto struct {
	Port     uint32 `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

func (pp PortProto) String() string {
	return fmt.Sprintf("%d/%s", pp.Port, pp.Protocol)
}

// EPAFeature is a key-value pair used to represent
// Enhanced Platform Awareness feature settings
type EPAFeature struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// GetTableName returns the name of the persistence table.
func (*App) GetTableName() string {
	return "apps"
}

// GetID gets the ID.
func (app *App) GetID() string {
	return app.ID
}

// SetID sets the ID.
func (app *App) SetID(id string) {
	app.ID = id
}

// Validate validates the model.
func (app *App) Validate() error { // nolint: gocyclo
	if !uuid.IsValid(app.ID) {
		return errors.New("id not a valid uuid")
	}
	if app.Type != "container" && app.Type != "vm" {
		return errors.New(`type must be either "container" or "vm"`)
	}
	if app.Name == "" {
		return errors.New("name cannot be empty")
	}
	if app.Vendor == "" {
		return errors.New("vendor cannot be empty")
	}
	if app.Version == "" {
		return errors.New("version cannot be empty")
	}
	if app.Cores < 1 || app.Cores > MaxCores {
		return fmt.Errorf("cores must be in [1..%d]", MaxCores)
	}
	if app.Memory < 1 || app.Memory > MaxMemory {
		return fmt.Errorf("memory must be in [1..%d]", MaxMemory)
	}
	for _, pp := range app.Ports {
		switch pp.Protocol {
		case "tcp", "udp", "icmp", "sctp", "all":
		case "":
			if pp.Port == 0 {
				continue // permit empty / no setting
			}
		default:
			return fmt.Errorf("protocol must be tcp, udp, sctp, icmp or all")
		}
		if pp.Port < 1 || pp.Port > MaxPort {
			return fmt.Errorf("port must be in [1..%d]", MaxPort)
		}
	}
	if app.Source == "" {
		return errors.New("source cannot be empty")
	}
	if _, err := url.ParseRequestURI(app.Source); err != nil {
		return errors.New("source cannot be parsed as a URI")
	}

	return nil
}

// FilterFields returns the filterable fields for this model.
func (*App) FilterFields() []string {
	return []string{}
}

func (app *App) String() string {
	return fmt.Sprintf(strings.TrimSpace(`
App[
    ID: %s
    Name: %s
    Version: %s
    Vendor: %s
    Description: %s
    Cores: %d
    Memory: %d
    Ports: %s
    Source: %s
    EPAFeatures: %s
]`),
		app.ID,
		app.Name,
		app.Version,
		app.Vendor,
		app.Description,
		app.Cores,
		app.Memory,
		app.Ports,
		app.Source,
		app.EPAFeatures)
}

// EPAValidate returns error if provided nodeFeatures do not fulfill app.EPAFeatures
func (app *App) EPAValidate(nodeFeatures map[string]string) error {
	for _, epaFeature := range app.EPAFeatures {
		if epaFeature.Key == "" || epaFeature.Value == "" || len(epaFeature.Key) < 4 {
			continue
		}

		nfdPrefix := strings.ToLower(epaFeature.Key[:4])
		epaKey := epaFeature.Key[4:]
		if nfdPrefix != "nfd:" || len(epaKey) == 0 {
			continue
		}

		if nodeFeatureVal, ok := nodeFeatures[epaKey]; ok {
			if nodeFeatureVal != epaFeature.Value {
				return fmt.Errorf("EPA Feature [%s] value required: [%s] provided by node: [%s] ", epaKey,
					epaFeature.Value, nodeFeatureVal)
			}
		} else {
			return fmt.Errorf("Missing EPA Feature: [%s] required by app", epaKey)
		}
	}
	return nil
}
