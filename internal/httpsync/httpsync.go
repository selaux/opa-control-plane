package httpsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/tsandall/lighthouse/internal/config"
)

// HttpDataSynchronizer is a struct that implements the Synchronizer interface for downloading JSON from HTTP endpoints.
type HttpDataSynchronizer struct {
	path        string // The path where the data will be saved
	url         string
	credentials *config.SecretRef
}

func New(path string, url string, credentials *config.SecretRef) *HttpDataSynchronizer {
	return &HttpDataSynchronizer{path: path, url: url, credentials: credentials}
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

	req, err := http.NewRequest("GET", s.url, nil)
	if err != nil {
		return err
	}

	err = setAuthHeaders(ctx, s.credentials, req)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (s *HttpDataSynchronizer) Close(ctx context.Context) {
	// No resources to close for HTTP synchronizer
}

func setAuthHeaders(ctx context.Context, credentials *config.SecretRef, req *http.Request) error {
	if credentials == nil {
		return nil
	}

	secret, err := credentials.Resolve()
	if err != nil {
		return err
	}

	value, err := secret.Get(ctx)
	if err != nil {
		return err
	}

	switch value["type"] {
	case "basic_auth":
		username, _ := value["username"].(string)
		password, _ := value["password"].(string)
		req.SetBasicAuth(username, password)
	case "token":
		token, _ := value["token"].(string)
		req.Header.Set("Authorization", "Bearer "+token)
	default:
		return fmt.Errorf("unsupported authentication type: %v", value["type"])
	}

	return nil
}
