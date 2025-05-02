package sqlsync

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
)

// SQLDataSynchronizer is a struct that implements the Synchronizer interface for bundle files stored in SQL database.
// It is expected that the caller will handle concurrency and parallelism. The Synchronizer is not thread-safe. It
// dumps files stored in SQL database into a directory used by the builder package to construct a bundle.
type SQLDataSynchronizer struct {
	path   string
	db     *sql.DB
	system string
}

func NewSQLDataSynchronizer(path string, db *sql.DB, system string) *SQLDataSynchronizer {
	return &SQLDataSynchronizer{path: path, db: db, system: system}
}

func (s *SQLDataSynchronizer) Execute(ctx context.Context) error {
	err := os.MkdirAll(s.path, 0755)
	if err != nil {
		return err
	}

	rows, err := s.db.Query(`SELECT
	path,
	data
FROM
	systems_data
WHERE
	system_id = ?`, s.system)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var pathInBundle string
		var data []byte
		if err := rows.Scan(&pathInBundle, &data); err != nil {
			return err
		}

		path := filepath.Join(s.path, pathInBundle)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		if err := os.WriteFile(path, data, 0644); err != nil {
			return err
		}
	}

	return nil
}
