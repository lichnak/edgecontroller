// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/gorilla/mux"
	logger "github.com/open-ness/common/log"
	cce "github.com/open-ness/edgecontroller"
)

var log = logger.DefaultLogger.WithField("pkg", "gorilla")

// Gorilla wraps the gorilla router and application routes.
type Gorilla struct {
	// router
	router *mux.Router

	// TODO: Check if these handlers are still necessary
	// entity routes handlers
	nodesHandler                  *handler
	appsHandler                   *handler
	trafficPoliciesHandler        *handler
	trafficPoliciesKubeOVNHandler *handler
	dnsConfigsHandler             *handler

	// join routes handlers
	dnsConfigsAppAliasesHandler *handler
	nodesDNSConfigsHandler      *handler
	nodesAppsHandler            *handler
}

// NewGorilla creates a new Gorilla.
func NewGorilla( //nolint:gocyclo
	controller *cce.Controller,
) *Gorilla {
	g := &Gorilla{
		// router
		router: mux.NewRouter(),

		// entity routes handlers
		nodesHandler: &handler{
			model:    &cce.Node{},
			reqModel: &cce.NodeReq{},

			checkDBDelete: checkDBDeleteNodes,

			handleGet:    handleGetNodes,
			handleUpdate: handleUpdateNodes,
		},
		appsHandler: &handler{
			model:         &cce.App{},
			checkDBDelete: checkDBDeleteApps,
		},
		trafficPoliciesHandler: &handler{
			model:         &cce.TrafficPolicy{},
			checkDBDelete: checkDBDeleteTrafficPolicies,
		},
		trafficPoliciesKubeOVNHandler: &handler{
			model:         &cce.TrafficPolicyKubeOVN{},
			checkDBDelete: checkDBDeleteTrafficPolicies,
		},
		dnsConfigsHandler: &handler{
			model:         &cce.DNSConfig{},
			checkDBDelete: checkDBDeleteDNSConfigs,
		},

		// join routes handlers
		dnsConfigsAppAliasesHandler: &handler{
			model:         &cce.DNSConfigAppAlias{},
			checkDBCreate: checkDBCreateDNSConfigsAppAliases,
		},
		nodesAppsHandler: &handler{
			model:    &cce.NodeApp{},
			reqModel: &cce.NodeAppReq{},

			checkDBCreate: checkDBCreateNodesApps,
			checkDBDelete: checkDBDeleteNodesApps,

			handleCreate: handleCreateNodesApps,
			handleGet:    handleGetNodesApps,
			handleUpdate: handleUpdateNodesApps,
			handleDelete: handleDeleteNodesApps,
		},
		nodesDNSConfigsHandler: &handler{
			model: &cce.NodeDNSConfig{},

			checkDBCreate: checkDBCreateNodesDNSConfigs,

			handleCreate: handleCreateNodesDNSConfigs,
			handleDelete: handleDeleteNodesDNSConfigs,
		},
	}

	nativePoliciesHandlers := map[string]http.HandlerFunc{
		"GET      /policies":             g.swagGETPolicies,
		"POST     /policies":             g.swagPOSTPolicies,
		"GET      /policies/{policy_id}": g.swagGETPolicyByID,
		"PATCH    /policies/{policy_id}": g.swagPATCHPolicyByID,
		"DELETE   /policies/{policy_id}": g.swagDELETEPolicyByID,

		"GET      /nodes/{node_id}/interfaces/{interface_id}/policy": g.swagGETNodeInterfacePolicy,
		"PATCH    /nodes/{node_id}/interfaces/{interface_id}/policy": g.swagPATCHNodeInterfacePolicy,
		"DELETE   /nodes/{node_id}/interfaces/{interface_id}/policy": g.swagDELETENodeInterfacePolicy,

		"GET      /nodes/{node_id}/apps/{app_id}/policy": g.swagGETNodeAppPolicy,
		"PATCH    /nodes/{node_id}/apps/{app_id}/policy": g.swagPATCHNodeAppPolicy,
		"DELETE   /nodes/{node_id}/apps/{app_id}/policy": g.swagDELETENodeAppPolicy,
	}

	kubeOVNPoliciesHandlers := map[string]http.HandlerFunc{
		"GET      /kube_ovn/policies":             g.swagGETKubeOVNPolicies,
		"POST     /kube_ovn/policies":             g.swagPOSTKubeOVNPolicies,
		"GET      /kube_ovn/policies/{policy_id}": g.swagGETKubeOVNPolicyByID,
		"PATCH    /kube_ovn/policies/{policy_id}": g.swagPATCHKubeOVNPolicyByID,
		"DELETE   /kube_ovn/policies/{policy_id}": g.swagDELETEKubeOVNPolicyByID,

		"GET      /nodes/{node_id}/apps/{app_id}/kube_ovn/policy": g.swagGETNodeAppKubeOVNPolicy,
		"PATCH    /nodes/{node_id}/apps/{app_id}/kube_ovn/policy": g.swagPATCHNodeAppKubeOVNPolicy,
		"DELETE   /nodes/{node_id}/apps/{app_id}/kube_ovn/policy": g.swagDELETENodeAppKubeOVNPolicy,
	}

	routes := map[string]http.HandlerFunc{
		"POST     /auth": authenticate,

		"GET      /nodes":           g.swagGETNodes,
		"POST     /nodes":           g.swagPOSTNodes,
		"GET      /nodes/{node_id}": g.swagGETNodeByID,
		"PATCH    /nodes/{node_id}": g.swagPATCHNodeByID,
		"DELETE   /nodes/{node_id}": g.swagDELETENodeByID,

		"GET      /apps":          g.swagGETApps,
		"POST     /apps":          g.swagPOSTApps,
		"GET      /apps/{app_id}": g.swagGETAppByID,
		"PATCH    /apps/{app_id}": g.swagPATCHAppByID,
		"DELETE   /apps/{app_id}": g.swagDELETEAppByID,

		"GET      /nodes/{node_id}/dns": g.swagGETNodeDNS,
		"PATCH    /nodes/{node_id}/dns": g.swagPATCHNodeDNS,
		"DELETE   /nodes/{node_id}/dns": g.swagDELETENodeDNS,

		"GET      /nodes/{node_id}/interfaces":                g.swagGETInterfaces,
		"PATCH    /nodes/{node_id}/interfaces":                g.swagPATCHInterfaces,
		"GET      /nodes/{node_id}/interfaces/{interface_id}": g.swagGETInterfaceByID,

		"GET      /nodes/{node_id}/apps":          g.swagGETNodeApps,
		"POST     /nodes/{node_id}/apps":          g.swagPOSTNodeApp,
		"GET      /nodes/{node_id}/apps/{app_id}": g.swagGETNodeAppsByID,
		"PATCH    /nodes/{node_id}/apps/{app_id}": g.swagPATCHNodeAppsByID,
		"DELETE   /nodes/{node_id}/apps/{app_id}": g.swagDELETENodeAppByID,

		"GET      /nodes/{node_id}/nfd": g.swagGETNodeNFDTags,
	}

	if controller.OrchestrationMode == cce.OrchestrationModeKubernetesOVN {
		for k, v := range kubeOVNPoliciesHandlers {
			routes[k] = v
		}
	} else {
		for k, v := range nativePoliciesHandlers {
			routes[k] = v
		}
	}

	for endpoint, handlerFunc := range routes {
		split := strings.Fields(endpoint)
		g.router.HandleFunc(split[1], handlerFunc).Methods(split[0])
	}

	// Catch panics
	g.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if r := recover(); r != nil {
					log.Critf("Recovered in handler func: %q\nStack trace:\n%s",
						r, string(debug.Stack()))
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	})

	// Limit size of all request payloads to prevent resource starvation
	g.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, cce.MaxBodySize)
			next.ServeHTTP(w, r)
		})
	})

	// Set a timeout on all requests to prevent resource starvation
	g.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), cce.MaxHTTPRequestTime)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Inject the controller
	g.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(
				r.Context(),
				contextKey("controller"),
				controller)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	// Require auth token for all endpoints except POST /auth
	g.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.RequestURI == "/auth" {
				next.ServeHTTP(w, r)
			} else {
				requireAuthHandler(next).ServeHTTP(w, r)
			}
		})
	})

	// Read and inject the body for POST and PATCH requests
	g.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST", "PATCH":
				body, err := ioutil.ReadAll(r.Body)
				if err != nil {
					log.Errf("Error reading body: %v", err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				ctx := context.WithValue(r.Context(), contextKey("body"), body)

				// Scrub for the body payload for potentially sensitive authentication data
				// (this only affects logging, not the actual request body)
				// TODO: Log the JSON payload here but with the password field scrubbed
				if r.URL.Path == "/auth" {
					body = []byte("***** REDACTED *****")
				}

				log.Debugf("Injected body: %s", string(body))
				next.ServeHTTP(w, r.WithContext(ctx))
			default:
				next.ServeHTTP(w, r)
			}
		})
	})

	return g
}

type contextKey string

func (c contextKey) String() string {
	return "controller-ce context key " + string(c)
}

// ServeHTTP wraps mux.ServeHTTP.
func (g *Gorilla) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	g.router.ServeHTTP(w, req)
}
