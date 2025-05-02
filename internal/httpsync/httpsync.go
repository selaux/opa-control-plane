package httpsync

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// HttpDataSynchronizer is a struct that implements the Synchronizer interface for downloading JSON from HTTP endpoints.
type HttpDataSynchronizer struct {
	path string // The path where the data will be saved
	url  string
	// TODO: Add more fields if needed, such as headers, authentication, etc.
}

func New(path string, url string) *HttpDataSynchronizer {
	return &HttpDataSynchronizer{path: path, url: url}
}

func (s *HttpDataSynchronizer) Execute(ctx context.Context) error {
	err := os.MkdirAll(filepath.Dir(s.path), 0755)
	if err != nil {
		return err
	}

	f, err := os.Create(s.path)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := http.Get(s.url)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}
