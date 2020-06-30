// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package swagger

import (
	cce "github.com/open-ness/edgecontroller"
)

// AppSummary is a summary representation of the app.
type AppSummary struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
}

// AppDetail is a detailed representation of the app.
type AppDetail struct {
	AppSummary
	Cores       int              `json:"cores"`
	Memory      int              `json:"memory"`
	Ports       []cce.PortProto  `json:"ports"`
	Source      string           `json:"source"`
	EPAFeatures []cce.EPAFeature `json:"epafeatures,omitempty"`
}

// AppList is a list representation of apps.
type AppList struct {
	Apps []AppSummary `json:"apps"`
}
