// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2020 Intel Corporation

package stubs

import (
	"context"
	"database/sql"
	cce "github.com/open-ness/edgecontroller"
)

type DBStub struct {
	PingError error
}

func (d DBStub) Ping() error {
	return d.PingError
}

func (d DBStub) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	return nil, nil
}

func (d DBStub) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	return nil, nil
}

type PersistenceServiceStub struct {
	CreateErr        error
	CreateValues     []cce.Persistable
	Ctr              int
	FilterErr        error
	FilterValues     [][]cce.Filter
	FilterRet        []cce.Persistable
	BulkUpdateErr    error
	BulkUpdateValues [][]cce.Persistable
}

func (ps *PersistenceServiceStub) Create(c context.Context, p cce.Persistable) error {
	ps.CreateValues = append(ps.CreateValues, p)
	return ps.CreateErr
}

func (ps *PersistenceServiceStub) Read(context.Context, string, cce.Persistable) (cce.Persistable, error) {
	return nil, nil
}

func (ps *PersistenceServiceStub) Filter(c context.Context, fb cce.Filterable, f []cce.Filter) ([]cce.Persistable,
	error) {
	ps.FilterValues = append(ps.FilterValues, f)
	return ps.FilterRet, ps.FilterErr
}

func (ps *PersistenceServiceStub) ReadAll(context.Context, cce.Persistable) ([]cce.Persistable, error) {
	return nil, nil
}

func (ps *PersistenceServiceStub) BulkUpdate(c context.Context, p []cce.Persistable) error {
	ps.BulkUpdateValues = append(ps.BulkUpdateValues, p)
	return ps.BulkUpdateErr
}

func (ps *PersistenceServiceStub) Delete(context.Context, string, cce.Persistable) (bool, error) {
	return false, nil
}
