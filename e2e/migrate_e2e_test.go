//go:build migration_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"text/template"
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

func TestMigration(t *testing.T) {
	var styraURL = os.Getenv("STYRA_URL")
	if styraURL == "" {
		log.Fatal("STYRA_URL environment variable is not set")
	}

	var styraToken = os.Getenv("STYRA_TOKEN")
	if styraToken == "" {
		log.Fatal("STYRA_TOKEN environment variable is not set")
	}

	cases := []struct {
		name            string
		systemName      string
		systemIdEnvName string
		extraConfigs    map[string]string
		policyType      string // used to filter decisions for backtest
		datasources     bool   // indicates whether to include datasource content in migration
	}{
		{
			name:            "envoy21",
			systemName:      "Envoy App",
			systemIdEnvName: "STYRA_ENVOY_SYSTEM_ID",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/envoy/git: {
							type: http_basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					systems: {
						Envoy App: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			name:            "kubernetes2-validating",
			systemName:      "Banteng cluster",
			systemIdEnvName: "STYRA_KUBERNETES_SYSTEM_ID",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/test/git: {
							type: http_basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					systems: {
						Banteng cluster: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			policyType: "validating",
		},
		{
			name:            "kubernetes2-mutating",
			systemName:      "Banteng cluster",
			systemIdEnvName: "STYRA_KUBERNETES_SYSTEM_ID",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/test/git: {
							type: http_basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					systems: {
						Banteng cluster: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			policyType: "mutating",
		},
		{
			name:            "custom system with push datasource",
			systemName:      "Custom app",
			systemIdEnvName: "STYRA_CUSTOM_SYSTEM_ID",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/custom_snippets/git: {
							type: http_basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
						systems/a8318943a5814712a69adcb2d9f76976/git: {
							type: http_basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					systems: {
						Custom app: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
			datasources: true,
		},
		{
			name:            "istio10",
			systemName:      "Istio App",
			systemIdEnvName: "STYRA_ISTIO_SYSTEM_ID",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					systems: {
						Istio App: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
		{
			// NOTE(tsandall): policies depend on two datasources however system
			// does not have any decisions that exercise that part of the
			// policy, so we are not enabling datasource content migration here.
			name:            "kong-gateway10",
			systemName:      "Kong Gateway - prod",
			systemIdEnvName: "STYRA_KONG_GATEWAY_SYSTEM_ID",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					systems: {
						Kong Gateway - prod: {
							object_storage: {
								aws: {
									url: {{ .URL }},
									bucket: test,
									region: mock-region,
									key: bundle.tar.gz,
								},
							},
						},
					},
				}`,
			},
		},
	}

	type templateParams struct {
		URL string
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			systemId := os.Getenv(tc.systemIdEnvName)
			if systemId == "" {
				log.Fatalf("%v environment variable is not set", tc.systemIdEnvName)
			}

			mock, s3TS := testS3Service(t, "test")

			files := make(map[string]string)
			var params templateParams
			params.URL = s3TS.URL

			for name, content := range tc.extraConfigs {
				tmpl, err := template.New(name).Parse(content)
				if err != nil {
					t.Fatal(err)
				}

				buf := bytes.NewBuffer(nil)
				if err := tmpl.Execute(buf, params); err != nil {
					t.Fatal(err)
				}

				files[name] = buf.String()
			}

			tempfs.WithTempFS(t, files, func(t *testing.T, dir string) {

				t.Logf("Root directory: %v", dir)

				f, err := os.Create(filepath.Join(dir, "config.d", "0-config.yaml"))
				if err != nil {
					t.Fatal(err)
				}

				err = migrate.Run(migrate.Options{
					URL:         styraURL,
					Token:       styraToken,
					SystemId:    systemId,
					Prune:       true,
					Datasources: tc.datasources,
					Output:      f,
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
					ConfigFile:           []string{filepath.Join(dir, "config.d")},
					URL:                  styraURL,
					Token:                styraToken,
					NumDecisions:         100,
					PolicyType:           tc.policyType,
					MaxEvalTimeInflation: 100,
					Output:               buf,
				}); err != nil {
					t.Fatal(err)
				}

				var r backtest.Report
				if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
					t.Fatal(err)
				}

				if r.Systems[tc.systemName].Status != "passed" {
					t.Fatalf("expected %q system to be successful, got: %s", tc.systemName, r.Systems[tc.systemName].Status)
				}

			})
		})
	}
}

func testS3Service(t *testing.T, bucket string) (*s3mem.Backend, *httptest.Server) {
	mock := s3mem.New()
	mock.CreateBucket(bucket)
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	t.Cleanup(ts.Close)
	return mock, ts
}
