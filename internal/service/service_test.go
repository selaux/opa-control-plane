package service_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/internal/service"
)

func TestUnconfiguredSecretHandling(t *testing.T) {

	bs := []byte(fmt.Sprintf(`{
		bundles: {
			test_bundle: {
				object_storage: {
					filesystem: {
						path: %q
					}
				},
				requirements: [
					{source: test_src}
				]
			}
		},
		sources: {
			test_src: {
				git: {
					repo: https://example.com/repo.git,  # doesn't matter
					credentials: test_creds,
					reference: refs/heads/main,
				}
			}
		},
		secrets: {
			test_creds: {}  # not configured
		}
	}`, filepath.Join(t.TempDir(), "bundles")))

	log := logging.NewLogger(logging.Config{Level: logging.LevelDebug})

	config, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	svc := service.New().
		WithConfig(config).
		WithPersistenceDir(filepath.Join(t.TempDir(), "data")).
		WithSingleShot(true).
		WithLogger(log)

	err = svc.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	report := svc.Report()

	status := report.Bundles["test_bundle"]

	if status.State != service.BuildStateSyncFailed {
		t.Fatal("expected sync failure state")
	} else if status.Message != `source "test_src": git synchronizer: https://example.com/repo.git: secret "test_creds" is not configured` {
		t.Fatal("unexpected status message")
	}
}
