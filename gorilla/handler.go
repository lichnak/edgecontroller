// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package gorilla

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	cce "github.com/open-ness/edgecontroller"
	uuid "github.com/satori/go.uuid"
)

type handler struct {
	model    cce.Persistable
	reqModel cce.ReqEntity

	// these funcs provide db constraint (unique/foreign key) checks
	checkDBCreate func(
		context.Context,
		cce.PersistenceService,
		cce.Persistable,
	) (statusCode int, err error)
	checkDBDelete func(
		ctx context.Context,
		ps cce.PersistenceService,
		id string,
	) (statusCode int, err error)

	// these funcs provide application logic
	handleCreate func(
		context.Context,
		cce.PersistenceService,
		cce.Persistable,
	) error
	handleGet func(
		context.Context,
		cce.PersistenceService,
		cce.Persistable,
	) (cce.RespEntity, error)
	handleUpdate func(
		context.Context,
		cce.PersistenceService,
		cce.Validatable,
	) (statusCode int, err error)
	handleDelete func(
		context.Context,
		cce.PersistenceService,
		cce.Persistable,
	) error
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) { //nolint:gocyclo
	ctrl := r.Context().Value(contextKey("controller")).(*cce.Controller)
	body := r.Context().Value(contextKey("body")).([]byte)

	p := reflect.New(reflect.ValueOf(h.model).Elem().Type()).Interface().(cce.Persistable)
	if err := json.Unmarshal(body, p); err != nil {
		log.Errf("Error unmarshaling json: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if p.GetID() != "" {
		w.WriteHeader(http.StatusBadRequest)

		if _, err := w.Write([]byte("Validation failed: id cannot be specified in POST request")); err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	p.SetID(uuid.NewV4().String())

	if err := p.(cce.Validatable).Validate(); err != nil {
		log.Debugf("Validation failed for %#v: %v", p, err)
		w.WriteHeader(http.StatusBadRequest)
		if _, err = w.Write([]byte(fmt.Sprintf("Validation failed: %v", err))); err != nil {
			log.Errf("Error writing response: %v", err)
		}
		return
	}

	if h.checkDBCreate != nil {
		if statusCode, err := h.checkDBCreate(r.Context(), ctrl.PersistenceService, p); err != nil {
			log.Errf("Error checking DB create: %v", err)
			w.WriteHeader(statusCode)
			_, err = w.Write([]byte(err.Error()))
			if err != nil {
				log.Errf("Error writing response: %v", err)
			}
			return
		}
	}

	if h.handleCreate != nil {
		if err := h.handleCreate(r.Context(), ctrl.PersistenceService, p); err != nil {
			log.Errf("Error handling create logic: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(err.Error()))
			if err != nil {
				log.Errf("Error writing response: %v", err)
			}
			return
		}
	}

	if err := ctrl.PersistenceService.Create(r.Context(), p); err != nil {
		log.Errf("Error creating entity: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header()["Content-Type"] = []string{"application/json"}
	w.WriteHeader(http.StatusCreated)

	if _, err := w.Write([]byte(fmt.Sprintf(`{"id":"%s"}`, p.GetID()))); err != nil {
		log.Errf("Error writing response: %v", err)
	}
}
