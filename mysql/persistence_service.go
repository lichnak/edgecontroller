// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019 Intel Corporation

package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	_ "github.com/go-sql-driver/mysql" // provides the mysql driver
	cce "github.com/open-ness/edgecontroller"
	"github.com/pkg/errors"
)

type CceDB interface {
	Ping() error
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

// PersistenceService implements cce.PersistenceService.
type PersistenceService struct {
	DB CceDB
}

// Create persists a resource.
func (s *PersistenceService) Create(
	ctx context.Context,
	e cce.Persistable,
) error {
	// Create a timeout context for a DB operation
	ctx, cancel := context.WithTimeout(ctx, cce.MaxDBRequestTime)
	defer cancel()

	bytes, err := json.Marshal(e)
	if err != nil {
		return errors.Wrap(err, "error marshaling")
	}

	_, err = s.DB.ExecContext(
		ctx,
		// gosec: Table name is not based on user input
		fmt.Sprintf( //nolint:gosec
			`INSERT INTO %s (entity) VALUES (?)`, e.GetTableName()),
		bytes)
	if err != nil {
		return errors.Wrap(err, "error inserting record")
	}

	return nil
}

// Read retrieves a single resource of the given type by ID.
func (s *PersistenceService) Read(
	ctx context.Context,
	id string,
	zv cce.Persistable,
) (e cce.Persistable, err error) {
	// Create a timeout context for a DB operation
	ctx, cancel := context.WithTimeout(ctx, cce.MaxDBRequestTime)
	defer cancel()

	rows, err := s.DB.QueryContext(
		ctx,
		// gosec: Table name is not based on user input
		fmt.Sprintf( //nolint:gosec
			`SELECT entity
             FROM %s
             WHERE id = ?`, zv.GetTableName()),
		id)
	if err != nil {
		return nil, errors.Wrap(err, "error running query")
	}

	if !rows.Next() {
		return nil, nil
	}

	if e, err = s.scan(rows, zv); err != nil {
		return nil, err
	}

	return e, nil
}

// Filter retrieves a collection of resources of the given type using a set of
// filters.
func (s *PersistenceService) Filter(
	ctx context.Context,
	zv cce.Filterable,
	fs []cce.Filter,
) (es []cce.Persistable, err error) {
	// Create a timeout context for a DB operation
	ctx, cancel := context.WithTimeout(ctx, cce.MaxDBRequestTime)
	defer cancel()

	// gosec: Table name is not based on user input
	q := fmt.Sprintf("SELECT entity FROM %s", zv.GetTableName()) //nolint:gosec

	ffs := zv.FilterFields()
	sort.Strings(ffs)

	var (
		fields []string
		params []interface{}
	)
	for _, f := range fs {
		// gosec: Only whitelisted filters are allowed to be injected into
		// the SQL query
		allowed := false
		for _, allowedField := range ffs {
			if f.Field == allowedField {
				allowed = true
			}
			if allowedField >= f.Field {
				break
			}
		}
		if !allowed {
			return nil, errors.Errorf("disallowed filter field %q", f.Field)
		}
		fields = append(fields, fmt.Sprintf("%s = ?", f.Field))
		params = append(params, f.Value)
	}
	if len(params) > 0 {
		q += " WHERE " + strings.Join(fields, " AND ") //nolint:gosec
	}

	rows, err := s.DB.QueryContext(
		ctx, q, params...)
	if err != nil {
		return nil, errors.Wrap(err, "error running query")
	}

	for rows.Next() {
		e, err := s.scan(rows, zv)
		if err != nil {
			return nil, err
		}

		es = append(es, e)
	}

	return
}

// ReadAll retrieves all resources of the given type.
func (s *PersistenceService) ReadAll(
	ctx context.Context,
	zv cce.Persistable,
) (es []cce.Persistable, err error) {
	// Create a timeout context for a DB operation
	ctx, cancel := context.WithTimeout(ctx, cce.MaxDBRequestTime)
	defer cancel()

	rows, err := s.DB.QueryContext(
		ctx,
		// gosec: Table name is not based on user input
		fmt.Sprintf( //nolint:gosec
			"SELECT entity FROM %s", zv.GetTableName()))
	if err != nil {
		return nil, errors.Wrap(err, "error running query")
	}

	for rows.Next() {
		e, err := s.scan(rows, zv)
		if err != nil {
			return nil, err
		}

		es = append(es, e)
	}

	return
}

func (s *PersistenceService) scan(
	rows *sql.Rows,
	zv cce.Persistable,
) (cce.Persistable, error) {
	var bytes []byte
	if err := rows.Scan(&bytes); err != nil {
		return nil, errors.Wrap(err, "error scanning row")
	}

	e := reflect.New(reflect.ValueOf(zv).Elem().Type()).Interface().(cce.Persistable)
	if err := json.Unmarshal(bytes, e); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling")
	}

	return e, nil
}

// BulkUpdate updates multiple resources.
func (s *PersistenceService) BulkUpdate(
	ctx context.Context,
	es []cce.Persistable,
) error {
	// Create a timeout context for a DB operation
	ctx, cancel := context.WithTimeout(ctx, cce.MaxDBRequestTime)
	defer cancel()

	for _, e := range es {
		bytes, err := json.Marshal(e)
		if err != nil {
			return errors.Wrap(err, "error marshaling")
		}

		_, err = s.DB.ExecContext(
			ctx,
			// gosec: Table name is not based on user input
			fmt.Sprintf( //nolint:gosec
				`UPDATE %s
                 SET entity = ?
                 WHERE id = JSON_EXTRACT(?, "$.id")`,
				e.GetTableName()),
			bytes, bytes)
		if err != nil {
			return errors.Wrap(err, "error updating record")
		}
	}

	return nil
}

// Delete deletes a resource of the given type.
func (s *PersistenceService) Delete(
	ctx context.Context,
	id string,
	zv cce.Persistable,
) (ok bool, err error) {
	// Create a timeout context for a DB operation
	ctx, cancel := context.WithTimeout(ctx, cce.MaxDBRequestTime)
	defer cancel()

	result, err := s.DB.ExecContext(
		ctx,
		// gosec: Table name is not based on user input
		fmt.Sprintf( //nolint:gosec
			`DELETE
             FROM %s
             WHERE id = ?`, zv.GetTableName()),
		id)
	if err != nil {
		return false, errors.Wrap(err, "error deleting record")
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, errors.Wrap(err, "error getting rows affected")
	}

	if rows != 1 {
		return false, nil
	}

	return true, nil
}
