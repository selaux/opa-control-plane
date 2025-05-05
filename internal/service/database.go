package service

import (
	"context"
	"database/sql"
	"encoding/json"
)

// Database implements the database operations.
// TODO: Move more database code here.
type Database struct {
	db *sql.DB
}

func (d *Database) Init(db *sql.DB) {
	d.db = db
}

func (d *Database) SystemsDataGet(ctx context.Context, systemId, path string) (interface{}, bool, error) {
	rows, err := d.db.Query(`SELECT
	data
FROM
	systems_data
WHERE system_id = ? AND path = ?`, systemId, path)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, false, nil
	}

	var bs []byte
	if err := rows.Scan(&bs); err != nil {
		return nil, false, err
	}

	var data interface{}
	if err := json.Unmarshal(bs, &data); err != nil {
		return nil, false, err
	}

	return data, true, nil
}

func (d *Database) SystemsDataPut(ctx context.Context, systemId, path string, data interface{}) error {
	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`INSERT OR REPLACE INTO systems_data (system_id, path, data) VALUES (?, ?, ?)`, systemId, path, bs)
	return err
}

func (d *Database) SystemsDataDelete(ctx context.Context, systemId, path string) error {
	_, err := d.db.Exec(`DELETE FROM systems_data WHERE system_id = ? AND path = ?`, systemId, path)
	return err
}
