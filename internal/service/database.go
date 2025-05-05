package service

import (
	"context"
	"database/sql"
)

// Database implements the database operations.
// TODO: Move the database code here.
type Database struct {
	db *sql.DB
}

func NewDatabase(db *sql.DB) *Database {
	return &Database{db: db}
}

func (d *Database) SystemsDataGet(ctx context.Context, systemId, path string) (data interface{}, ok bool, err error) {
	return nil, false, nil

}

func (d *Database) SystemsDataPut(ctx context.Context, systemId, path string, data interface{}) error {

	return nil
}
func (d *Database) SystemsDataDelete(ctx context.Context, systemId, path string) error {
	return nil
}
