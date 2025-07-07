//go:build migration_e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/styrainc/lighthouse/cmd/backtest"
	"github.com/styrainc/lighthouse/cmd/migrate"
	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/internal/service"
	"github.com/styrainc/lighthouse/internal/test/tempfs"
	"github.com/styrainc/lighthouse/internal/util"
	"github.com/styrainc/lighthouse/libraries"
	"golang.org/x/sync/errgroup"
)

func TestMigration(t *testing.T) {

	// Set mock AWS credentials to avoid IMDS errors.
	os.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	os.Setenv("AWS_REGION", "us-east-1")

	cases := []struct {
		name              string
		styraURL          string
		systemId          string
		styraTokenEnvName string // default STYRA_TOKEN
		systemName        string
		extraConfigs      map[string]string
		policyType        string // used to filter decisions for backtest
		datasources       bool   // indicates whether to include datasource content in migration
	}{
		{
			name:       "envoy21",
			styraURL:   "https://expo.styra.com",
			systemId:   "f89b1de32c4a4252ac19db97c007f8d4",
			systemName: "Envoy App",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/envoy/git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
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
			name:              "envoy1",
			styraURL:          "https://kurt.styra.com",
			systemId:          "cbbf33aeb9ce44349bc3faad43060ae0",
			systemName:        "envoy-v1-e2e-test",
			styraTokenEnvName: "STYRA_TOKEN_3",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						envoy-v1-e2e-test: {
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
			name:              "kubernetes1",
			styraURL:          "https://test.styra.com",
			systemId:          "ace44151df234247ab59e9177d02c9cc",
			styraTokenEnvName: "STYRA_TOKEN_2",
			systemName:        "torin-k8s-v1-test",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						torin-k8s-v1-test: {
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
			name:       "kubernetes2-validating",
			styraURL:   "https://expo.styra.com",
			systemId:   "b470325746e3417e86301b564113b29b",
			systemName: "Banteng cluster",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/test/git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
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
			name:       "kubernetes2-mutating",
			styraURL:   "https://expo.styra.com",
			systemId:   "b470325746e3417e86301b564113b29b",
			systemName: "Banteng cluster",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/test/git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
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
			name:       "custom system with push datasource",
			styraURL:   "https://expo.styra.com",
			systemId:   "a8318943a5814712a69adcb2d9f76976",
			systemName: "Custom app",
			extraConfigs: map[string]string{
				"config.d/1-secrets.yaml": `{
					secrets: {
						libraries/custom_snippets/git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
						systems/a8318943a5814712a69adcb2d9f76976/git: {
							type: basic_auth,
							password: $GITHUB_PASSWORD,
							username: $GITHUB_USERNAME,
						},
					},
				}`,
				"config.d/2-storage.yaml": `{
					bundles: {
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
			name:       "istio10",
			styraURL:   "https://expo.styra.com",
			systemId:   "a3dd4c8155ae43a794b6e5b7a53cdd60",
			systemName: "Istio App",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
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
			name:       "kuma10",
			styraURL:   "https://expo.styra.com",
			systemId:   "d1c66f8ca33749b9b27b2d2ac1151bc1",
			systemName: "Kuma",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						Kuma: {
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
			name:       "kong-gateway10",
			styraURL:   "https://expo.styra.com",
			systemId:   "ef6321e7461a4035b8638f73951fa0c4",
			systemName: "Kong Gateway - prod",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
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
		{
			name:       "terraform20",
			styraURL:   "https://expo.styra.com",
			systemId:   "c600dddb333c48b7b67616564e7b8726",
			systemName: "Terraform - GCP",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						Terraform - GCP: {
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
			name:              "http pull datasources",
			styraURL:          "https://test.styra.com",
			styraTokenEnvName: "STYRA_TOKEN_2",
			systemId:          "c765ce3ea0e14751b88e3530f9d3c8ac",
			systemName:        "torin-pull-test-2",
			extraConfigs: map[string]string{
				"config.d/2-storage.yaml": `{
					bundles: {
						"torin-pull-test-2": {
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

			if tc.styraTokenEnvName == "" {
				tc.styraTokenEnvName = "STYRA_TOKEN"
			}

			styraToken := os.Getenv(tc.styraTokenEnvName)
			if styraToken == "" {
				t.Fatalf("%v environment variable is not set", tc.styraTokenEnvName)
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
					URL:         tc.styraURL,
					Token:       styraToken,
					SystemId:    tc.systemId,
					Prune:       true,
					Datasources: tc.datasources,
					EmbedFiles:  true,
					Output:      f,
				})
				if err != nil {
					t.Fatal(err)
				}

				merged, err := config.Merge([]string{filepath.Join(dir, "config.d")}, true)
				if err != nil {
					t.Fatal(err)
				}

				svc := service.New().
					WithBuiltinFS(util.NewEscapeFS(libraries.FS)).
					WithConfig(merged).
					WithPersistenceDir(filepath.Join(dir, "data")).
					WithLogger(logging.NewLogger(logging.Config{Level: logging.LevelDebug}))

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

				maxEvalTimeInflation := 100
				if v := os.Getenv("BACKTEST_MAX_EVAL_TIME_INFLATION"); v != "" {
					n, err := strconv.Atoi(v)
					if err != nil {
						t.Fatal(err)
					}
					maxEvalTimeInflation = n
				}

				if err := backtest.Run(backtest.Options{
					ConfigFile:           []string{filepath.Join(dir, "config.d")},
					URL:                  tc.styraURL,
					Token:                styraToken,
					NumDecisions:         100,
					PolicyType:           tc.policyType,
					MaxEvalTimeInflation: maxEvalTimeInflation,
					Output:               buf,
				}); err != nil {
					t.Fatal(err)
				}

				var r backtest.Report
				if err := json.Unmarshal(buf.Bytes(), &r); err != nil {
					t.Fatal(err)
				}

				if r.Systems[tc.systemName].Status != "passed" {
					t.Logf("Dumping output:\n%v", string(buf.Bytes()))
					t.Fatalf("expected %q system to be successful", tc.systemName)
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
