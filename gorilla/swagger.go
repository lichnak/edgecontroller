// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

package gorilla

// TODO: Update schema to include all returned response codes
// 			Known missing from schema:
//				400 StatusBadRequest
//				422 StatusUnprocessableEntity (checkDBDeleteNodesApps, etc.)
//				500 StatusInternalServerError
//				look for others...

// TODO: for any status codes added, add unit tests.

// TODO: rename all instances of swagger to OpenAPI or OAS. Include file names, etc.
// TODO: rename `swag` prefix from methods. Extraneous after revisions completed.

// TODO: Remove nolint when possible and address the issues

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	cce "github.com/otcshare/edgecontroller"
	"github.com/otcshare/edgecontroller/nfd-master"
	"github.com/otcshare/edgecontroller/swagger"
	"github.com/otcshare/edgecontroller/uuid"
)

// The following handlers are compliant to our published Swagger (OpenAPI 3.0) schema.

// Used for GET /nodes endpoint
func (g *Gorilla) swagGETNodes(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence
	persisted, err := ctrl.PersistenceService.ReadAll(r.Context(), &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	nodes := swagger.NodeList{Nodes: []swagger.NodeSummary{}}
	for _, n := range persisted {
		node := swagger.NodeSummary{
			ID:       n.(*cce.Node).ID,
			Name:     n.(*cce.Node).Name,
			Location: n.(*cce.Node).Location,
			Serial:   n.(*cce.Node).Serial,
		}
		nodes.Nodes = append(nodes.Nodes, node)
	}

	// Marshal the response object to JSON
	nodesJSON, err := json.Marshal(nodes)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(nodesJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for POST /nodes endpoint
func (g *Gorilla) swagPOSTNodes(w http.ResponseWriter, r *http.Request) {
	g.nodesHandler.create(w, r)
}

// Used for GET /nodes/{node_id} endpoint
func (g *Gorilla) swagGETNodeByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Construct the response object
	node := swagger.NodeDetail{
		NodeSummary: swagger.NodeSummary{
			ID:       persisted.(*cce.Node).ID,
			Name:     persisted.(*cce.Node).Name,
			Location: persisted.(*cce.Node).Location,
			Serial:   persisted.(*cce.Node).Serial,
		},
	}

	// Marshal the response object to JSON
	nodeJSON, err := json.Marshal(node)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(nodeJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id} endpoint
func (g *Gorilla) swagPATCHNodeByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	node := swagger.NodeDetail{}
	if err := json.Unmarshal(body, &node); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Convert it to a persistable object
	persisted := cce.Node{
		ID:       mux.Vars(r)["node_id"],
		Name:     node.Name,
		Location: node.Location,
		Serial:   node.Serial,
	}

	// Validate the object
	if err := persisted.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", persisted, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Persist the object
	if err := ctrl.PersistenceService.BulkUpdate(r.Context(), []cce.Persistable{&persisted}); err != nil {
		log.Errf("Error updating entities: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /nodes/{node_id} endpoint
// and DELETE /nodes/{node_id}?force=true endpoint
func (g *Gorilla) swagDELETENodeByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Check if query contains force parameter
	forceQuery := r.URL.Query()["force"]

	forced := false

	var err error

	// Parse query force parameter
	if len(forceQuery) > 0 {
		forced, err = strconv.ParseBool(forceQuery[0])
		if err != nil {
			log.Errf("Wrong query parameter: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	if forced {
		if err = handleForcedDeleteNodesDNSConfigs(r.Context(), ctrl, mux.Vars(r)["node_id"]); err != nil {
			log.Errf("Error force-deleting node's DNS: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err = handleForceDeleteNodesApps(r.Context(), ctrl, mux.Vars(r)["node_id"]); err != nil {
			log.Errf("Error force-deleting node's apps: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err = handleForceDeleteNodesInterfacePolicy(r.Context(), ctrl, mux.Vars(r)["node_id"]); err != nil {
			log.Errf("Error force-deleting node's interface policies: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	if err = handleDeleteNode(r.Context(), ctrl, mux.Vars(r)["node_id"]); err != nil {
		log.Errf("Error deleting node: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}
}

// Used for GET /apps endpoint
func (g *Gorilla) swagGETApps(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence
	persisted, err := ctrl.PersistenceService.ReadAll(r.Context(), &cce.App{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	apps := swagger.AppList{Apps: []swagger.AppSummary{}}
	for _, a := range persisted {
		app := swagger.AppSummary{
			ID:          a.(*cce.App).ID,
			Type:        a.(*cce.App).Type,
			Name:        a.(*cce.App).Name,
			Version:     a.(*cce.App).Version,
			Vendor:      a.(*cce.App).Vendor,
			Description: a.(*cce.App).Description,
		}
		apps.Apps = append(apps.Apps, app)
	}

	// Marshal the response object to JSON
	appsJSON, err := json.Marshal(apps)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(appsJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for POST /apps endpoint
func (g *Gorilla) swagPOSTApps(w http.ResponseWriter, r *http.Request) {
	g.appsHandler.create(w, r)
}

// Used for GET /apps/{app_id} endpoint
func (g *Gorilla) swagGETAppByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["app_id"], &cce.App{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Construct the response object
	app := swagger.AppDetail{
		AppSummary: swagger.AppSummary{
			ID:          persisted.(*cce.App).ID,
			Type:        persisted.(*cce.App).Type,
			Name:        persisted.(*cce.App).Name,
			Version:     persisted.(*cce.App).Version,
			Vendor:      persisted.(*cce.App).Vendor,
			Description: persisted.(*cce.App).Description,
		},
		Cores:       persisted.(*cce.App).Cores,
		Memory:      persisted.(*cce.App).Memory,
		Source:      persisted.(*cce.App).Source,
		Ports:       persisted.(*cce.App).Ports,
		EPAFeatures: persisted.(*cce.App).EPAFeatures,
	}

	// Marshal the response object to JSON
	appJSON, err := json.Marshal(app)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(appJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /apps/{app_id} endpoint
func (g *Gorilla) swagPATCHAppByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	app := swagger.AppDetail{}
	if err := json.Unmarshal(body, &app); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Convert it to a persistable object
	persisted := cce.App{
		ID:          app.ID,
		Type:        app.Type,
		Name:        app.Name,
		Version:     app.Version,
		Vendor:      app.Vendor,
		Description: app.Description,
		Cores:       app.Cores,
		Memory:      app.Memory,
		Source:      app.Source,
		Ports:       app.Ports,
		EPAFeatures: app.EPAFeatures,
	}

	// Validate the object
	if err := persisted.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", persisted, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Persist the object
	if err := ctrl.PersistenceService.BulkUpdate(r.Context(), []cce.Persistable{&persisted}); err != nil {
		log.Errf("Error updating entities: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /apps/{app_id} endpoint
func (g *Gorilla) swagDELETEAppByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Check that we can delete the entity
	if statusCode, err := checkDBDeleteApps(r.Context(), ctrl.PersistenceService, mux.Vars(r)["app_id"]); err != nil {
		log.Errf("Error running DB logic: %v", err)
		w.WriteHeader(statusCode)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["app_id"], &cce.App{})
	if err != nil {
		log.Errf("Error reading entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ok, err := ctrl.PersistenceService.Delete(r.Context(), mux.Vars(r)["app_id"], &cce.App{})
	if err != nil {
		log.Errf("Error deleting entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// we just fetched the entity, so if !ok then something went wrong
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for GET /policies endpoint
func (g *Gorilla) swagGETPolicies(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence
	persisted, err := ctrl.PersistenceService.ReadAll(r.Context(), &cce.TrafficPolicy{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	policies := swagger.PolicyList{Policies: []swagger.PolicySummary{}}
	for _, a := range persisted {
		policy := swagger.PolicySummary{
			ID:   a.(*cce.TrafficPolicy).ID,
			Name: a.(*cce.TrafficPolicy).Name,
		}
		policies.Policies = append(policies.Policies, policy)
	}

	// Marshal the response object to JSON
	policiesJSON, err := json.Marshal(policies)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(policiesJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for POST /policies endpoint
func (g *Gorilla) swagPOSTPolicies(w http.ResponseWriter, r *http.Request) {
	g.trafficPoliciesHandler.create(w, r)
}

// Used for GET /policies/{policy_id} endpoint
func (g *Gorilla) swagGETPolicyByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["policy_id"], &cce.TrafficPolicy{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Construct the response object
	policy := swagger.PolicyDetail{
		PolicySummary: swagger.PolicySummary{
			ID:   persisted.(*cce.TrafficPolicy).ID,
			Name: persisted.(*cce.TrafficPolicy).Name,
		},
		Rules: persisted.(*cce.TrafficPolicy).Rules,
	}

	// Marshal the response object to JSON
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(policyJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /policies/{policy_id} endpoint
func (g *Gorilla) swagPATCHPolicyByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	policy := swagger.PolicyDetail{}
	if err := json.Unmarshal(body, &policy); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Convert it to a persistable object
	persisted := cce.TrafficPolicy{
		ID:    policy.ID,
		Name:  policy.Name,
		Rules: policy.Rules,
	}

	// Validate the object
	if err := persisted.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", persisted, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Persist the object
	if err := ctrl.PersistenceService.BulkUpdate(r.Context(), []cce.Persistable{&persisted}); err != nil {
		log.Errf("Error updating entities: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /policies/{policy_id}
func (g *Gorilla) swagDELETEPolicyByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Check that we can delete the entity
	if statusCode, err := checkDBDeleteTrafficPolicies(
		r.Context(),
		ctrl.PersistenceService,
		mux.Vars(r)["policy_id"]); err != nil {
		log.Errf("Error running DB logic: %v", err)
		w.WriteHeader(statusCode)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["policy_id"], &cce.TrafficPolicy{})
	if err != nil {
		log.Errf("Error reading entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ok, err := ctrl.PersistenceService.Delete(r.Context(), mux.Vars(r)["policy_id"], &cce.TrafficPolicy{})
	if err != nil {
		log.Errf("Error deleting entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// we just fetched the entity, so if !ok then something went wrong
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for GET /kube_ovn/policies endpoints
func (g *Gorilla) swagGETKubeOVNPolicies(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence
	persisted, err := ctrl.PersistenceService.ReadAll(r.Context(), &cce.TrafficPolicyKubeOVN{})
	if err != nil {
		log.Errf("Failed to fetch the nodes from persistence: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	policies := swagger.PolicyList{Policies: []swagger.PolicySummary{}}
	for _, a := range persisted {
		policy := swagger.PolicySummary{
			ID:   a.(*cce.TrafficPolicyKubeOVN).ID,
			Name: a.(*cce.TrafficPolicyKubeOVN).Name,
		}
		policies.Policies = append(policies.Policies, policy)
	}

	// Marshal the response object to JSON
	policiesJSON, err := json.Marshal(policies)
	if err != nil {
		log.Errf("Failed to marshal the response object to JSON: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(policiesJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for POST /kube_ovn/policies endpoint
func (g *Gorilla) swagPOSTKubeOVNPolicies(w http.ResponseWriter, r *http.Request) {
	g.trafficPoliciesKubeOVNHandler.create(w, r)
}

// Used for GET /policies/{policy_id} endpoint
func (g *Gorilla) swagGETKubeOVNPolicyByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["policy_id"], &cce.TrafficPolicyKubeOVN{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Construct the response object
	policy := swagger.PolicyKubeOVNDetail{
		PolicySummary: swagger.PolicySummary{
			ID:   persisted.(*cce.TrafficPolicyKubeOVN).ID,
			Name: persisted.(*cce.TrafficPolicyKubeOVN).Name,
		},
		IngressRules: persisted.(*cce.TrafficPolicyKubeOVN).Ingress,
		EgressRules:  persisted.(*cce.TrafficPolicyKubeOVN).Egress,
	}

	// Marshal the response object to JSON
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(policyJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /kube_ovn/policies/{policy_id} endpoint
func (g *Gorilla) swagPATCHKubeOVNPolicyByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	policy := swagger.PolicyKubeOVNDetail{}
	if err := json.Unmarshal(body, &policy); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Convert it to a persistable object
	persisted := cce.TrafficPolicyKubeOVN{
		ID:      policy.ID,
		Name:    policy.Name,
		Ingress: policy.IngressRules,
		Egress:  policy.EgressRules,
	}

	// Validate the object
	if err := persisted.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", persisted, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Persist the object
	if err := ctrl.PersistenceService.BulkUpdate(r.Context(), []cce.Persistable{&persisted}); err != nil {
		log.Errf("Error updating entities: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /kube_ovn/policies/{policy_id}
func (g *Gorilla) swagDELETEKubeOVNPolicyByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Check that we can delete the entity
	if statusCode, err := checkDBDeleteTrafficPolicies(
		r.Context(),
		ctrl.PersistenceService,
		mux.Vars(r)["policy_id"]); err != nil {
		log.Errf("Error running DB logic: %v", err)
		w.WriteHeader(statusCode)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["policy_id"], &cce.TrafficPolicyKubeOVN{})
	if err != nil {
		log.Errf("Error reading entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	ok, err := ctrl.PersistenceService.Delete(r.Context(), mux.Vars(r)["policy_id"], &cce.TrafficPolicyKubeOVN{})
	if err != nil {
		log.Errf("Error deleting entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// we just fetched the entity, so if !ok then something went wrong
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for GET /nodes/{node_id}/dns endpoint
func (g *Gorilla) swagGETNodeDNS(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Construct the response object
	dns := swagger.DNSDetail{
		Records:        swagger.DNSRecords{A: []swagger.DNSARecord{}},
		Configurations: swagger.DNSConfigurations{Forwarders: []swagger.DNSForwarder{}},
	}

	// Fetch the entity from persistence
	persistedNode, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeDNSConfig{},
		[]cce.Filter{{Field: "node_id", Value: mux.Vars(r)["node_id"]}},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(persistedNode) != 0 {
		// Fetch the DNS config from persistence
		var persistedConfig cce.Persistable
		persistedConfig, err = ctrl.PersistenceService.Read(
			r.Context(),
			persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID,
			&cce.DNSConfig{},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Fetch the DNS aliases from persistence
		var persistedAliases []cce.Persistable
		persistedAliases, err = ctrl.PersistenceService.Filter(
			r.Context(),
			&cce.DNSConfigAppAlias{},
			[]cce.Filter{
				{Field: "dns_config_id", Value: persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Construct the response object
		dns = swagger.DNSDetail{
			DNSSummary: swagger.DNSSummary{
				ID:   persistedConfig.(*cce.DNSConfig).ID,
				Name: persistedConfig.(*cce.DNSConfig).Name,
			},
		}

		// Add the IP based A records to the response
		for _, record := range persistedConfig.(*cce.DNSConfig).ARecords {
			rec := swagger.DNSARecord{
				Name:        record.Name,
				Description: record.Description,
				Alias:       false,
				Values:      record.IPs,
			}
			dns.Records.A = append(dns.Records.A, rec)
		}

		// Add the alias based A records to the response
		for _, record := range persistedAliases {
			rec := swagger.DNSARecord{
				Name:        record.(*cce.DNSConfigAppAlias).Name,
				Description: record.(*cce.DNSConfigAppAlias).Description,
				Alias:       true,
				Values:      []string{record.(*cce.DNSConfigAppAlias).AppID},
			}
			dns.Records.A = append(dns.Records.A, rec)
		}

		// Add the forwarders to the response
		for _, forwarder := range persistedConfig.(*cce.DNSConfig).Forwarders {
			fwdr := swagger.DNSForwarder{
				Name:        forwarder.Name,
				Description: forwarder.Description,
				Value:       forwarder.IP,
			}
			dns.Configurations.Forwarders = append(dns.Configurations.Forwarders, fwdr)
		}
	}

	// Marshal the response object to JSON
	dnsJSON, err := json.Marshal(dns)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(dnsJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id}/dns endpoint
func (g *Gorilla) swagPATCHNodeDNS(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Delete the old persisted data
	if err := g.swagDNSDeleteHelper(w, r); err != nil {
		_, err = w.Write([]byte(fmt.Sprintf("DNS call failed mid operation: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Create the new requested data
	if err := g.swagDNSCreateHelper(w, r); err != nil {
		_, err = w.Write([]byte(fmt.Sprintf("DNS call failed mid operation: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}
}

// Used for DELETE /nodes/{node_id}/dns endpoint
func (g *Gorilla) swagDELETENodeDNS(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Delete the old persisted data
	if err := g.swagDNSDeleteHelper(w, r); err != nil {
		_, err = w.Write([]byte(fmt.Sprintf("DNS call failed mid operation: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (g *Gorilla) swagDNSCreateHelper(w http.ResponseWriter, r *http.Request) error { //nolint:gocyclo
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the requested DNS configurations
	requested := swagger.DNSDetail{}
	if err := json.Unmarshal(body, &requested); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return err
	}

	if len(requested.Configurations.Forwarders) != 0 {
		log.Err("Received unimplemented field forwarders in request")
		w.WriteHeader(http.StatusNotImplemented)
		return fmt.Errorf("received unimplemented field forwarders in request")
	}

	// Create the new persistable entity for the DNS config
	newConfig := &cce.DNSConfig{
		ID:   uuid.New(),
		Name: requested.Name,
	}

	// Create the new persistable association
	nodeDNS := &cce.NodeDNSConfig{
		ID:          uuid.New(),
		NodeID:      mux.Vars(r)["node_id"],
		DNSConfigID: newConfig.ID,
	}

	// Create the new persistable entity for the DNS aliases
	var newAliases []cce.Persistable

	// Construct the persistable entities
	for _, req := range requested.Records.A {
		switch {
		case req.Alias && len(req.Values) != 0:
			record := cce.DNSConfigAppAlias{
				ID:          uuid.New(),
				DNSConfigID: newConfig.ID,
				Name:        req.Name,
				Description: req.Description,
				AppID:       req.Values[0],
			}
			if err := record.Validate(); err != nil {
				log.Errf("Error creating DNS config aliases: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return err
			}
			newAliases = append(newAliases, &record)
		case !req.Alias:
			record := &cce.DNSARecord{
				Name:        req.Name,
				Description: req.Description,
				IPs:         req.Values,
			}
			if err := record.Validate(); err != nil {
				log.Errf("Error creating DNS config non-aliases: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return err
			}
			newConfig.ARecords = append(newConfig.ARecords, record)
		}
	}
	for _, req := range requested.Configurations.Forwarders {
		config := &cce.DNSForwarder{
			Name:        req.Name,
			Description: req.Description,
			IP:          req.Value,
		}
		if err := config.Validate(); err != nil {
			log.Errf("Error creating DNS config forwarders: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return err
		}
		newConfig.Forwarders = append(newConfig.Forwarders, config)
	}

	// Create the DNS config and aliases from the node
	if err := handleCreateNodesDNSConfigsWithAliases(
		r.Context(), ctrl.PersistenceService, nodeDNS, newConfig, newAliases,
	); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	// Create the config in persistence
	if err := ctrl.PersistenceService.Create(r.Context(), newConfig); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	// Create the aliases in persistence
	for _, alias := range newAliases {
		if err := ctrl.PersistenceService.Create(r.Context(), alias); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}
	}

	// Create the association in persistence
	if err := ctrl.PersistenceService.Create(r.Context(), nodeDNS); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	return nil
}

func (g *Gorilla) swagDNSDeleteHelper(w http.ResponseWriter, r *http.Request) error {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence
	persistedNode, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeDNSConfig{},
		[]cce.Filter{{Field: "node_id", Value: mux.Vars(r)["node_id"]}},
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	// If there's persisted DNS data, delete it from the node and from persistence
	if len(persistedNode) != 0 {
		// Fetch the DNS config from persistence
		persistedConfig, err := ctrl.PersistenceService.Read(
			r.Context(),
			persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID,
			&cce.DNSConfig{},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

		// Fetch the DNS aliases from persistence
		persistedAliases, err := ctrl.PersistenceService.Filter(
			r.Context(),
			&cce.DNSConfigAppAlias{},
			[]cce.Filter{
				{Field: "dns_config_id", Value: persistedNode[0].(*cce.NodeDNSConfig).DNSConfigID},
			},
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

		// Delete the DNS config and aliases from the node
		if err := handleDeleteNodesDNSConfigsWithAliases(
			r.Context(), ctrl.PersistenceService, persistedNode[0], persistedConfig, persistedAliases,
		); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

		// Delete the association from persistence
		if _, err := ctrl.PersistenceService.Delete(
			r.Context(), persistedNode[0].GetID(), persistedNode[0],
		); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

		// Delete the aliases from persistence
		for _, alias := range persistedAliases {
			if _, err := ctrl.PersistenceService.Delete(r.Context(), alias.GetID(), alias); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return err
			}
		}

		// Delete the config from persistence
		if _, err := ctrl.PersistenceService.Delete(r.Context(), persistedConfig.GetID(), persistedConfig); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return err
		}

	}
	return nil
}

// Used for GET /nodes/{node_id}/interfaces endpoint
func (g *Gorilla) swagGETInterfaces(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Get the data from the remote entity
	response, err := handleGetNodes(r.Context(), ctrl.PersistenceService, persisted)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	ifaces := swagger.InterfaceList{Interfaces: []swagger.InterfaceSummary{}}
	for _, res := range response.(*cce.NodeResp).NetworkInterfaces {
		iface := swagger.InterfaceSummary{
			ID:                res.ID,
			Description:       res.Description,
			Driver:            res.Driver,
			Type:              res.Type,
			MACAddress:        res.MACAddress,
			VLAN:              res.VLAN,
			Zones:             res.Zones,
			FallbackInterface: res.FallbackInterface,
		}
		ifaces.Interfaces = append(ifaces.Interfaces, iface)
	}

	// Marshal the response object to JSON
	ifacesJSON, err := json.Marshal(ifaces)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(ifacesJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id}/interfaces endpoint
func (g *Gorilla) swagPATCHInterfaces(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	ifaces := swagger.InterfaceList{}
	if err := json.Unmarshal(body, &ifaces); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Convert it to a persistable object
	requested := cce.NodeReq{
		Node:              *persisted.(*cce.Node),
		NetworkInterfaces: []*cce.NetworkInterface{},
	}

	for _, iface := range ifaces.Interfaces {
		p := &cce.NetworkInterface{
			ID:                iface.ID,
			Description:       iface.Description,
			Driver:            iface.Driver,
			Type:              iface.Type,
			MACAddress:        iface.MACAddress,
			VLAN:              iface.VLAN,
			Zones:             iface.Zones,
			FallbackInterface: iface.FallbackInterface,
		}
		requested.NetworkInterfaces = append(requested.NetworkInterfaces, p)
	}

	// Validate the object
	if err = requested.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", requested, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	code, err := handleUpdateNodes(r.Context(), ctrl.PersistenceService, &requested)
	switch {
	case code != 0:
		log.Errf("Error updating remote entities: %v", err)
		w.WriteHeader(code)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Persist the object
	if err := ctrl.PersistenceService.BulkUpdate(r.Context(), []cce.Persistable{&requested}); err != nil {
		log.Errf("Error updating entities: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for GET /nodes/{node_id}/interfaces/{interface_id} endpoint
func (g *Gorilla) swagGETInterfaceByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Get the data from the remote entity
	response, err := handleGetNodes(r.Context(), ctrl.PersistenceService, persisted)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	iface := swagger.InterfaceDetail{}
	for _, res := range response.(*cce.NodeResp).NetworkInterfaces {
		if res.ID == mux.Vars(r)["interface_id"] {
			iface = swagger.InterfaceDetail{
				InterfaceSummary: swagger.InterfaceSummary{
					ID:                res.ID,
					Description:       res.Description,
					Driver:            res.Driver,
					Type:              res.Type,
					MACAddress:        res.MACAddress,
					VLAN:              res.VLAN,
					Zones:             res.Zones,
					FallbackInterface: res.FallbackInterface,
				},
			}
		}
	}

	// If its not set, then it's not found
	if iface.ID == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Marshal the response object to JSON
	ifaceJSON, err := json.Marshal(iface)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(ifaceJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for GET /nodes/{node_id}/interfaces/{interface_id}/policy endpoint
func (g *Gorilla) swagGETNodeInterfacePolicy(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Construct the response object
	baseResource := swagger.BaseResource{}

	// Filter nodes_network_interfaces_traffic_policies to get the traffic_policy_id
	nodeIFacePolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeInterfaceTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "network_interface_id", // db field slightly different
				Value: mux.Vars(r)["interface_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering nodes_network_interfaces_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeIFacePolicies) != 0 {
		baseResource = swagger.BaseResource{
			ID: nodeIFacePolicies[0].(*cce.NodeInterfaceTrafficPolicy).TrafficPolicyID,
		}
	}

	// Marshal the response object to JSON
	baseResourceJSON, err := json.Marshal(baseResource)
	if err != nil {
		log.Errf("Error marshaling response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(baseResourceJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id}/interfaces/{interface_id}/policy endpoint
func (g *Gorilla) swagPATCHNodeInterfacePolicy(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	var baseResource swagger.BaseResource
	if err := json.Unmarshal(body, &baseResource); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Fetch the nodes from persistence and check if it's there
	node, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if node == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// TODO: Verify the interface ID is valid

	// Query traffic_policies to verify the baseResourceID is valid
	policy, err := ctrl.PersistenceService.Read(r.Context(), baseResource.ID, &cce.TrafficPolicy{})
	if err != nil {
		log.Errf("Error reading traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if policy == nil {
		w.WriteHeader(http.StatusNotFound)
		_, err = w.Write([]byte(fmt.Sprintf("traffic policy %s not found", baseResource.ID)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Construct the update object to dial to the node
	requested := cce.NodeReq{
		Node: cce.Node{
			ID: mux.Vars(r)["node_id"],
		},
		TrafficPolicies: []cce.NetworkInterfaceTrafficPolicy{
			{
				NetworkInterfaceID: mux.Vars(r)["interface_id"],
				TrafficPolicyID:    baseResource.ID,
			},
		},
	}

	// Update the remote node
	code, err := handleUpdateNodes(r.Context(), ctrl.PersistenceService, &requested)
	switch {
	case code != 0:
		log.Errf("Error updating remote entities: %v", err)
		w.WriteHeader(code)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Filter nodes_interfaces_traffic_policies to see if a record already exists
	nodeIfacePolicy, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeInterfaceTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "network_interface_id",
				Value: mux.Vars(r)["interface_id"],
			},
		})
	if err != nil {
		log.Errf("Error reading nodes_interfaces_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If it exists, delete it
	if len(nodeIfacePolicy) == 1 {
		ok, err := ctrl.PersistenceService.Delete(
			r.Context(),
			nodeIfacePolicy[0].GetID(),
			&cce.NodeInterfaceTrafficPolicy{},
		)
		if err != nil {
			log.Errf("Error deleting from nodes_interfaces_traffic_policies: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !ok {
			log.Err("Did not delete 1 record from nodes_interfaces_traffic_policies")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Convert the base resource to a persistable object
	persisted := cce.NodeInterfaceTrafficPolicy{
		ID:                 uuid.New(),
		NodeID:             mux.Vars(r)["node_id"],
		NetworkInterfaceID: mux.Vars(r)["interface_id"],
		TrafficPolicyID:    baseResource.ID,
	}

	// Persist the object
	if err := ctrl.PersistenceService.Create(r.Context(), &persisted); err != nil {
		log.Errf("Error creating entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /nodes/{node_id}/interfaces/{interface_id}/policy endpoint
func (g *Gorilla) swagDELETENodeInterfacePolicy(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence and check if it's there
	node, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if node == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// TODO: Verify the interface ID is valid

	// Construct the update object to dial to the node
	requested := cce.NodeReq{
		Node: cce.Node{
			ID: mux.Vars(r)["node_id"],
		},
		TrafficPolicies: []cce.NetworkInterfaceTrafficPolicy{
			{
				NetworkInterfaceID: mux.Vars(r)["interface_id"],
				TrafficPolicyID:    "", // set no policy
			},
		},
	}

	// Update the remote node
	code, err := handleUpdateNodes(r.Context(), ctrl.PersistenceService, &requested)
	switch {
	case code != 0:
		log.Errf("Error updating remote entities: %v", err)
		w.WriteHeader(code)
		_, err = w.Write([]byte(err.Error()))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Filter nodes_interfaces_traffic_policies to see if a record already exists
	nodeIfacePolicy, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeInterfaceTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "network_interface_id",
				Value: mux.Vars(r)["interface_id"],
			},
		})
	if err != nil {
		log.Errf("Error reading nodes_interfaces_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If it exists, delete it
	if len(nodeIfacePolicy) == 1 {
		ok, err := ctrl.PersistenceService.Delete(
			r.Context(),
			nodeIfacePolicy[0].GetID(),
			&cce.NodeInterfaceTrafficPolicy{},
		)
		if err != nil {
			log.Errf("Error deleting from nodes_interfaces_traffic_policies: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !ok {
			log.Err("Did not delete 1 record from nodes_interfaces_traffic_policies")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// Query the DB to get the NFD features for a node. Return in a map form.
func getNfdFeatures(ctx context.Context, nodeID string) (map[string]string, error) {
	ctrl := ctx.Value(contextKey("controller")).(*cce.Controller)
	// Fetch the NFD features for node from persistence
	persistedNodeNFD, err := ctrl.PersistenceService.Filter(
		ctx,
		&nfd.NodeFeatureNFD{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: nodeID,
			},
		},
	)
	if err != nil {
		log.Errf("Error when retrieving NFD features for node %s from database: %v",
			nodeID, err)
		return nil, err
	}

	// Convert persisted node NFD features to plain map
	features := make(map[string]string)
	for _, f := range persistedNodeNFD {
		nfd := f.(*nfd.NodeFeatureNFD)
		features[nfd.NfdID] = nfd.NfdValue
	}

	return features, nil
}

// Used for GET /nodes/{node_id}/apps endpoint
func (g *Gorilla) swagGETNodeApps(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the nodes from persistence and check if it's there
	node, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if node == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Construct the response object
	nodeApps := swagger.NodeAppList{NodeApps: []swagger.NodeAppSummary{}}

	// Filter nodes_apps to get the node_app_id
	persisted, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	for _, a := range persisted {
		nodeApps.NodeApps = append(nodeApps.NodeApps, swagger.NodeAppSummary{
			ID: a.(*cce.NodeApp).AppID,
		})
	}

	// Marshal the response object to JSON
	nodeAppsJSON, err := json.Marshal(nodeApps)
	if err != nil {
		log.Errf("Error marshaling response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(nodeAppsJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// TODO: Change /nodes/{node_id}/apps POST -> PATCH
//			- Ensure the UI is in sync when changed.

// Used for POST /nodes/{node_id}/apps endpoint
func (g *Gorilla) swagPOSTNodeApp(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	var baseResource swagger.BaseResource
	if err := json.Unmarshal(body, &baseResource); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Error unmarshaling json: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: baseResource.ID,
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) != 0 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, err = w.Write([]byte(fmt.Sprintf(
			"duplicate record in nodes_apps detected for node_id %s and app_id %s",
			mux.Vars(r)["node_id"], baseResource.ID,
		)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err := ctrl.PersistenceService.Read(r.Context(), mux.Vars(r)["node_id"], &cce.Node{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Construct the create object to dial to the node app
	nodeApp := cce.NodeApp{
		ID:     uuid.New(),
		NodeID: mux.Vars(r)["node_id"],
		AppID:  baseResource.ID,
	}

	// Validate the object
	if err = nodeApp.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", nodeApp, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	persisted, err = ctrl.PersistenceService.Read(r.Context(), baseResource.ID, &cce.App{})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if persisted == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// EPA validation
	features, err := getNfdFeatures(r.Context(), mux.Vars(r)["node_id"])
	if err != nil {
		log.Errf("swagPOSTNodeApp(): getNfdFeatures() failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: %v\n", err)
		return
	}
	err = persisted.(*cce.App).EPAValidate(features)
	if err != nil {
		log.Errf("Unable to deploy app [%s] on node [%s]: %v", nodeApp.AppID, mux.Vars(r)["node_id"], err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create the remote node app
	err = handleCreateNodesApps(r.Context(), ctrl.PersistenceService, &nodeApp)
	if err != nil {
		log.Errf("Error creating node app: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error: %v", err)
		return
	}

	// Persist the object
	if err := ctrl.PersistenceService.Create(r.Context(), &nodeApp); err != nil {
		log.Errf("Error creating entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for GET /nodes/{node_id}/apps/{app_id} endpoint
func (g *Gorilla) swagGETNodeAppsByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create the remote node app
	response, err := handleGetNodesApps(r.Context(), ctrl.PersistenceService, nodeApps[0])
	if err != nil {
		log.Errf("Error creating node app: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	nodeAppDetail := swagger.NodeAppDetail{
		NodeAppSummary: swagger.NodeAppSummary{
			ID: nodeApps[0].(*cce.NodeApp).AppID,
		},
		Status: response.(*cce.NodeAppResp).Status,
	}

	// Marshal the response object to JSON
	nodeAppDetailJSON, err := json.Marshal(nodeAppDetail)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(nodeAppDetailJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id}/apps/{app_id} endpoint
func (g *Gorilla) swagPATCHNodeAppsByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	nodeAppDetail := swagger.NodeAppDetail{}
	if err := json.Unmarshal(body, &nodeAppDetail); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Error unmarshaling json: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Fetch the entity from persistence and check if it's there
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Convert it to a persistable object
	requested := cce.NodeAppReq{
		NodeApp: *nodeApps[0].(*cce.NodeApp),
		Cmd:     nodeAppDetail.Command,
	}

	// Validate the object
	if err = requested.Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", requested, err)
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err)))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	code, err := handleUpdateNodesApps(r.Context(), ctrl.PersistenceService, &requested)
	switch {
	case code != 0:
		log.Errf("Error updating remote entities: %v", err)
		w.WriteHeader(code)
		_, err = w.Write([]byte("error updating remote entity"))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}
}

// Used for DELETE /nodes/{node_id}/apps/{app_id} endpoint
func (g *Gorilla) swagDELETENodeAppByID(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Fetch the entity from persistence and check if it's there
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Check that we can delete the entity
	var statusCode int
	if statusCode, err = checkDBDeleteNodesApps(
		r.Context(), ctrl.PersistenceService, nodeApps[0].(*cce.NodeApp).ID,
	); err != nil {
		log.Errf("Error running DB logic: %v", err)
		w.WriteHeader(statusCode)
		_, err = w.Write([]byte(
			fmt.Sprintf("cannot delete app %s: record in use in nodes_apps_traffic_policies", mux.Vars(r)["app_id"])))
		if err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	// Delete the app from the node
	if err = handleDeleteNodesApps(
		r.Context(), ctrl.PersistenceService, nodeApps[0],
	); err != nil {
		log.Errf("Error making remote call: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete the resource
	ok, err := ctrl.PersistenceService.Delete(r.Context(), nodeApps[0].(*cce.NodeApp).ID, &cce.NodeApp{})
	if err != nil {
		log.Errf("Error deleting entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Used for GET /nodes/{node_id}/apps/{app_id}/policy endpoint
func (g *Gorilla) swagGETNodeAppPolicy(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Filter nodes_apps_traffic_policies to get the traffic_policy_id
	nodeAppTrafficPolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: nodeApps[0].GetID(),
			},
		})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeAppTrafficPolicies) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeAppTrafficPolicies) > 1 {
		log.Errf("Filter nodes_apps_traffic_policies returned %d records", len(nodeAppTrafficPolicies))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	baseResource := swagger.BaseResource{
		ID: nodeAppTrafficPolicies[0].(*cce.NodeAppTrafficPolicy).TrafficPolicyID,
	}

	// Marshal the response object to JSON
	baseResourceJSON, err := json.Marshal(baseResource)
	if err != nil {
		log.Errf("Error marshaling response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(baseResourceJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id}/apps/{app_id}/policy endpoint
func (g *Gorilla) swagPATCHNodeAppPolicy(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	var baseResource swagger.BaseResource
	if err := json.Unmarshal(body, &baseResource); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Query traffic_policies to verify the baseResourceID is valid
	policy, err := ctrl.PersistenceService.Read(r.Context(), baseResource.ID, &cce.TrafficPolicy{})
	if err != nil {
		log.Errf("Error reading traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if policy == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Connect to node
	nodePort := ctrl.ELAPort
	if nodePort == "" {
		nodePort = defaultELAPort
	}
	nodeCC, err := connectNode(
		r.Context(),
		ctrl.PersistenceService,
		nodeApps[0].(*cce.NodeApp),
		nodePort,
		ctrl.EdgeNodeCreds)
	if err != nil {
		log.Errf("Error connecting to node: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Make gRPC call to node to set the policy
	if err = nodeCC.AppPolicySvcCli.Set(
		r.Context(),
		nodeApps[0].(*cce.NodeApp).AppID,
		policy.(*cce.TrafficPolicy),
	); err != nil {
		log.Errf("Error setting policy: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Filter nodes_apps_traffic_policies to see if a record already exists
	nodeAppPolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: nodeApps[0].GetID(),
			},
		})
	if err != nil {
		log.Errf("Error reading nodes_apps_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If it exists, delete it
	if len(nodeAppPolicies) == 1 {
		ok, err := ctrl.PersistenceService.Delete(r.Context(), nodeAppPolicies[0].GetID(), &cce.NodeAppTrafficPolicy{})
		if err != nil {
			log.Errf("Error deleting from nodes_apps_traffic_policies: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !ok {
			log.Err("Did not delete 1 record from nodes_apps_traffic_policies")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Convert the base resource to a persistable object
	persisted := cce.NodeAppTrafficPolicy{
		ID:              uuid.New(),
		NodeAppID:       nodeApps[0].GetID(),
		TrafficPolicyID: baseResource.ID,
	}

	// Persist the object
	if err := ctrl.PersistenceService.Create(r.Context(), &persisted); err != nil {
		log.Errf("Error creating entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /nodes/{node_id}/apps/{app_id}/policy endpoint
func (g *Gorilla) swagDELETENodeAppPolicy(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Filter nodes_apps_traffic_policies to get the ID
	nodeAppPolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: nodeApps[0].GetID(),
			},
		})
	if err != nil {
		log.Errf("Error reading nodes_apps_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Connect to node
	nodePort := ctrl.ELAPort
	if nodePort == "" {
		nodePort = defaultELAPort
	}
	nodeCC, err := connectNode(
		r.Context(),
		ctrl.PersistenceService,
		nodeApps[0].(*cce.NodeApp),
		nodePort,
		ctrl.EdgeNodeCreds)
	if err != nil {
		log.Errf("Error connecting to node: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Make gRPC call to node to delete the policy
	if err = nodeCC.AppPolicySvcCli.Delete(
		r.Context(),
		nodeApps[0].(*cce.NodeApp).AppID,
	); err != nil {
		log.Errf("Error deleting policy: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete the resource
	ok, err := ctrl.PersistenceService.Delete(r.Context(), nodeAppPolicies[0].GetID(), &cce.NodeAppTrafficPolicy{})
	if err != nil {
		log.Errf("Error deleting from nodes_apps_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ok {
		log.Err("Did not delete 1 record from nodes_apps_traffic_policies")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Used for GET /nodes/{node_id}/apps/{app_id}/kube_ovn/policy endpoint
func (g *Gorilla) swagGETNodeAppKubeOVNPolicy(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Filter nodes_apps_traffic_policies to get the traffic_policy_id
	nodeAppTrafficPolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: nodeApps[0].GetID(),
			},
		})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeAppTrafficPolicies) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeAppTrafficPolicies) > 1 {
		log.Errf("Filter nodes_apps_traffic_policies returned %d records", len(nodeAppTrafficPolicies))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Construct the response object
	baseResource := swagger.BaseResource{
		ID: nodeAppTrafficPolicies[0].(*cce.NodeAppTrafficPolicy).TrafficPolicyID,
	}

	// Marshal the response object to JSON
	baseResourceJSON, err := json.Marshal(baseResource)
	if err != nil {
		log.Errf("Error marshaling response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err = w.Write(baseResourceJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}

// Used for PATCH /nodes/{node_id}/apps/{app_id}/kube_ovn/policy endpoint
func (g *Gorilla) swagPATCHNodeAppKubeOVNPolicy(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	// Unmarshal the payload
	var baseResource swagger.BaseResource
	if err := json.Unmarshal(body, &baseResource); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Query traffic_policies to verify the baseResourceID is valid
	policy, err := ctrl.PersistenceService.Read(r.Context(), baseResource.ID, &cce.TrafficPolicyKubeOVN{})
	if err != nil {
		log.Errf("Error reading traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if policy == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Try delete network policy for app
	_ = ctrl.KubernetesClient.DeleteNetworkPolicy(r.Context(), nodeApps[0].(*cce.NodeApp).NodeID,
		nodeApps[0].(*cce.NodeApp).AppID)

	// Apply new network policy for app
	if err = ctrl.KubernetesClient.ApplyNetworkPolicy(r.Context(), nodeApps[0].(*cce.NodeApp).NodeID,
		nodeApps[0].(*cce.NodeApp).AppID, policy.(*cce.TrafficPolicyKubeOVN).ToK8s(),
	); err != nil {
		log.Errf("Error setting policy: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Filter nodes_apps_traffic_policies to see if a record already exists
	nodeAppPolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: nodeApps[0].GetID(),
			},
		})
	if err != nil {
		log.Errf("Error reading nodes_apps_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If it exists, delete it
	if len(nodeAppPolicies) == 1 {
		ok, err := ctrl.PersistenceService.Delete(r.Context(), nodeAppPolicies[0].GetID(), &cce.NodeAppTrafficPolicy{})
		if err != nil {
			log.Errf("Error deleting from nodes_apps_traffic_policies: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !ok {
			log.Err("Did not delete 1 record from nodes_apps_traffic_policies")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	// Convert the base resource to a persistable object
	persisted := cce.NodeAppTrafficPolicy{
		ID:              uuid.New(),
		NodeAppID:       nodeApps[0].GetID(),
		TrafficPolicyID: baseResource.ID,
	}

	// Persist the object
	if err := ctrl.PersistenceService.Create(r.Context(), &persisted); err != nil {
		log.Errf("Error creating entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// Used for DELETE /nodes/{node_id}/apps/{app_id}/kube_ovn/policy endpoint
func (g *Gorilla) swagDELETENodeAppKubeOVNPolicy(w http.ResponseWriter, r *http.Request) {
	// Load the controller to access the persistence and the payload
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)

	// Filter nodes_apps to get the node_app_id
	nodeApps, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeApp{},
		[]cce.Filter{
			{
				Field: "node_id",
				Value: mux.Vars(r)["node_id"],
			},
			{
				Field: "app_id",
				Value: mux.Vars(r)["app_id"],
			},
		})
	if err != nil {
		log.Errf("Error filtering node_apps: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(nodeApps) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(nodeApps) > 1 {
		log.Errf("Filter node_apps returned %d records", len(nodeApps))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Filter nodes_apps_traffic_policies to get the ID
	nodeAppPolicies, err := ctrl.PersistenceService.Filter(
		r.Context(),
		&cce.NodeAppTrafficPolicy{},
		[]cce.Filter{
			{
				Field: "nodes_apps_id",
				Value: nodeApps[0].GetID(),
			},
		})
	if err != nil {
		log.Errf("Error reading nodes_apps_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Make gRPC call to node to delete the policy
	if err = ctrl.KubernetesClient.DeleteNetworkPolicy(
		r.Context(), nodeApps[0].(*cce.NodeApp).NodeID, nodeApps[0].(*cce.NodeApp).AppID,
	); err != nil {
		log.Errf("Error deleting policy: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete the resource
	ok, err := ctrl.PersistenceService.Delete(r.Context(), nodeAppPolicies[0].GetID(), &cce.NodeAppTrafficPolicy{})
	if err != nil {
		log.Errf("Error deleting from nodes_apps_traffic_policies: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !ok {
		log.Err("Did not delete 1 record from nodes_apps_traffic_policies")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Return the NFD tags of a node in a Json form to the remote caller
func (g *Gorilla) swagGETNodeNFDTags(w http.ResponseWriter, r *http.Request) {
	nodeID := mux.Vars(r)["node_id"]

	// Convert persisted node NFD features to NodeNfdList
	features, err := getNfdFeatures(r.Context(), nodeID)
	if err != nil {
		log.Errf("swagGETNodeNFDTags(): getNfdFeatures() failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: %v\n", err)
		return
	}
	nodeNfds := swagger.NodeNfdList{}
	for k, v := range features {
		nodeNfdTag := swagger.NodeNfdTag{ID: k, Value: v}
		nodeNfds.List = append(nodeNfds.List, nodeNfdTag)
	}
	nfdJSON, err := json.Marshal(nodeNfds)
	if err != nil {
		log.Errf("Error %v marshaling the NFD features into JSON for node %v", err, nodeID)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error: %v\n", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(nfdJSON); err != nil {
		log.Errf("Error writing response: %v", err)
	}
	fmt.Fprintf(w, "\n")
}
