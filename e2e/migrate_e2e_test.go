//go:build migration_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/tsandall/lighthouse/cmd/backtest"
	"github.com/tsandall/lighthouse/cmd/migrate"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/service"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
	"github.com/tsandall/lighthouse/internal/util"
	"github.com/tsandall/lighthouse/libraries"
	"golang.org/x/sync/errgroup"
)

func TestEnvoy21(t *testing.T) {

	var styraURL = os.Getenv("STYRA_URL")
	if styraURL == "" {
		log.Fatal("STYRA_URL environment variable is not set")
	}

	var styraToken = os.Getenv("STYRA_TOKEN")
	if styraToken == "" {
		log.Fatal("STYRA_TOKEN environment variable is not set")
	}

	var styraEnvoySystemId = os.Getenv("STYRA_ENVOY_SYSTEM_ID")
	if styraEnvoySystemId == "" {
		log.Fatal("STYRA_ENVOY_SYSTEM_ID environment variable is not set")
	}

	mock, s3TS := testS3Service(t, "test")

	var secretsConfig = `{
		secrets: {
			libraries/envoy/git: {
				type: http_basic_auth,
				password: $GITHUB_PASSWORD,
				username: $GITHUB_USERNAME,
			},
		},
	}`

	var storageConfig = fmt.Sprintf(`{
		systems: {
			Envoy App: {
				object_storage: {
					aws: {
						url: %q,
						bucket: test,
						region: mock-region,
						key: bundle.tar.gz,
					},
				},
			},
		},
	}`, s3TS.URL)

	files := map[string]string{
		"config.d/1-secrets.yaml": string(secretsConfig),
		"config.d/2-storage.yaml": string(storageConfig),
	}

	tempfs.WithTempFS(t, files, func(t *testing.T, dir string) {

		f, err := os.Create(filepath.Join(dir, "config.d", "0-config.yaml"))
		if err != nil {
			t.Fatal(err)
		}

		err = migrate.Run(migrate.Options{
			URL:      styraURL,
			Token:    styraToken,
			SystemId: styraEnvoySystemId,
			Prune:    true,
			Output:   f,
		})
		if err != nil {
			t.Fatal(err)
		}

		merged, err := config.Merge([]string{filepath.Join(dir, "config.d")})
		if err != nil {
			t.Fatal(err)
		}

		svc := service.New().
			WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
			WithConfig(merged).
			WithPersistenceDir(filepath.Join(dir, "data"))

		var g errgroup.Group
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		g.Go(func() error {
			return svc.Run(ctx)
		})

		for {
			time.Sleep(time.Millisecond * 100)
			var obj *gofakes3.Object
			var err error
			for obj == nil && (err == nil || gofakes3.HasErrorCode(err, gofakes3.ErrNoSuchKey)) {
				obj, err = mock.GetObject("test", "bundle.tar.gz", nil)
				time.Sleep(time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			break
		}

		buf := bytes.NewBuffer(nil)

		if err := backtest.Run(backtest.Options{
			ConfigFile:   []string{filepath.Join(dir, "config.d")},
			URL:          styraURL,
			Token:        styraToken,
			NumDecisions: 100,
			Output:       buf,
		}); err != nil {
			t.Fatal(err)
		}

		var r backtest.Report
		if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
			t.Fatal(err)
		}

		if r.Systems["Envoy App"].Status != "passed" {
			t.Fatalf("expected Envoy App system to be successful, got: %s", r.Systems["Envoy App"].Status)
		}
	})

}

func testS3Service(t *testing.T, bucket string) (*s3mem.Backend, *httptest.Server) {
	mock := s3mem.New()
	mock.CreateBucket(bucket)
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	t.Cleanup(ts.Close)
	return mock, ts
}
