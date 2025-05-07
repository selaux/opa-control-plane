package sqlsync

import (
	"context"
	"os"
	"path/filepath"
)

// SQLDataSynchronizer is a struct that implements the Synchronizer interface for bundle files stored in SQL database.
// It is expected that the caller will handle concurrency and parallelism. The Synchronizer is not thread-safe. It
// dumps files stored in SQL database into a directory used by the builder package to construct a bundle.
type SQLDataSynchronizer struct {
	path  string
	query func(string) (DataCursor, error)
	id    string
}

type Database interface {
	QueryLibraryData(string) (DataCursor, error)
	QuerySystemData(string) (DataCursor, error)
}

// TODO: Move this to database package with Data struct.
type DataCursor interface {
	Close() error
	Next() bool
	Value() (Data, error)
}

type Data struct {
	Path string
	Data []byte
}

func NewSQLLibraryDataSynchronizer(path string, db Database, id string) *SQLDataSynchronizer {
	return &SQLDataSynchronizer{path: path, query: db.QueryLibraryData, id: id}
}

func NewSQLSystemDataSynchronizer(path string, db Database, id string) *SQLDataSynchronizer {
	return &SQLDataSynchronizer{path: path, query: db.QuerySystemData, id: id}
}

func (s *SQLDataSynchronizer) Execute(ctx context.Context) error {
	err := os.MkdirAll(s.path, 0755)
	if err != nil {
		return err
	}

	cursor, err := s.query(s.id)
	if err != nil {
		return err
	}
	defer cursor.Close()
	for cursor.Next() {
		data, err := cursor.Value()
		if err != nil {
			return err
		}
		path := filepath.Join(s.path, data.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}

		if err := os.WriteFile(path, data.Data, 0644); err != nil {
			return err
		}
	}

	return nil
}
