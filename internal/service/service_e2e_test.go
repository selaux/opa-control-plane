package service_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/tsandall/lighthouse/internal/service"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

func TestService(t *testing.T) {
	tests := []struct {
		note            string
		config          string
		fileParameters  map[string]string
		gitFiles        map[string]string
		datasourceFiles map[string]string
		expectedRego    map[string]string
		expectedData    string
	}{
		{
			note: "TestFromConfigWithGit",
			config: `{
		systems: {
			TestSystem: {
				git: {
					repo: {{ .RemoteGitDir }},
					reference: refs/heads/master,
					path: "app/",
				},
				object_storage: {
					aws: {
						url: {{ .S3URL }},
						bucket: test,
						key: bundle.tar.gz,
						region: mock-region,
					}
				},
				datasources: [
					{
						name: "datasource1",
						path: "datasource1",
						type: "http",
						config: {
							url: {{ .HTTPURL }}/datasource1
						}
					}
				],
				files: {
					"foo.rego": {{ .FooRego }}
				}
			}
		},
		libraries: {
			TestLibrary: {
				git: {
					repo: {{ .RemoteGitDir }},
					reference: refs/heads/master,
					path: "lib/",
				},
				datasources: [
				{
						name: "datasource2",
						path: "datasource2",
						type: "http",
						config: {
							url: {{ .HTTPURL }}/datasource2
						}
					}
				],
				files: {
					"bar.rego": {{ .BarRego }}
				}
			}
		}
	}`,
			fileParameters: map[string]string{
				"AppRego": "package app\np := data.lib.q",
				"LibRego": "package lib\nq := data.lib.s",
				"FooRego": "package foo",
				"BarRego": "package lib\ns := true",
			},
			gitFiles: map[string]string{
				"app/app.rego": "AppRego",
				"lib/lib.rego": "LibRego",
			},
			datasourceFiles: map[string]string{
				"/datasource1": `{"key": "value1"}`,
				"/datasource2": `{"key": "value2"}`,
			},
			expectedRego: map[string]string{
				"foo.rego": "FooRego",
				"app.rego": "AppRego",
				"lib.rego": "LibRego",
				"bar.rego": "BarRego",
			},
			expectedData: `{
				"datasource1": {"key": "value1"},
				"datasource2": {"key": "value2"}
			}`,
		},
		{
			note: "TestFromConfigWithoutGit",
			config: `{
		systems: {
			TestSystem: {
				object_storage: {
					aws: {
						url: {{ .S3URL }},
						bucket: test,
						key: bundle.tar.gz,
						region: mock-region,
					}
				},
				datasources: [
					{
						name: "datasource1",
						path: "datasource1",
						type: "http",
						config: {
							url: {{ .HTTPURL }}/datasource1
						}
					}
				],
				files: {
					"app/app.rego": {{ .AppRego }},
					"foo.rego": {{ .FooRego }}
				}
			}
		},
		libraries: {
			TestLibrary: {
				datasources: [
				{
						name: "datasource2",
						path: "datasource2",
						type: "http",
						config: {
							url: {{ .HTTPURL }}/datasource2
						}
					}
				],
				files: {
					"bar.rego": {{ .BarRego }},
					"lib/lib.rego": {{ .LibRego }}
				}
			}
		}
	}`,
			fileParameters: map[string]string{
				"AppRego": "package app\np := data.lib.q",
				"FooRego": "package foo",
				"BarRego": "package lib\ns := true",
				"LibRego": "package lib\nq := data.lib.s",
			},
			datasourceFiles: map[string]string{
				"/datasource1": `{"key": "value1"}`,
				"/datasource2": `{"key": "value2"}`,
			},
			expectedRego: map[string]string{
				"foo.rego":     "FooRego",
				"app/app.rego": "AppRego",
				"lib/lib.rego": "LibRego",
				"bar.rego":     "BarRego",
			},
			expectedData: `{
				"datasource1": {"key": "value1"},
				"datasource2": {"key": "value2"}
			}`,
		},
		{
			note: "TestFromConfigWithRequirements",
			config: `{
		systems: {
			TestSystem: {
				object_storage: {
					aws: {
						url: {{ .S3URL }},
						bucket: test,
						key: bundle.tar.gz,
						region: mock-region,
					}
				},
				files: {
					"app.rego": {{ .AppRego }}
				},
				requirements: [{library: TestLibrary}]
			}
		},
		libraries: {
			TestLibrary: {
				files: {
					"main.rego": {{ .LibRego }}
				}
			}
		}
	}`,
			fileParameters: map[string]string{
				"AppRego": "package app\np := 7",
				"LibRego": "package main\nmain := data.app.p",
			},
			expectedRego: map[string]string{
				"app.rego":  "AppRego",
				"main.rego": "LibRego",
			},
		},
		{
			note: "TestFromConfigWithStacks",
			config: `{
		systems: {
			TestSystem: {
				labels: {
					app: payments,
					env: production
				},
				object_storage: {
					aws: {
						url: {{ .S3URL }},
						bucket: test,
						key: bundle.tar.gz,
						region: mock-region,
					}
				},
				files: {
					"app.rego": {{ .AppRego }}
				},
				requirements: [
					{library: TestLibConflicts}
				]
			}
		},
		libraries: {
			TestLib: {
				files: {
					"stacks/foo/foo.rego": {{ .LibRego }}
				}
			},
			TestLibConflicts: {
				files: {
					"main.rego": {{ .MainRego }}
				}
			}
		},
		stacks: {
			TestStack: {
				selector: {
					env: [production]
				},
				source: {
					library: TestLib
				}
			}
		}
	}`,
			fileParameters: map[string]string{
				"AppRego": "package app\np := 7",
				"LibRego": "package stacks.foo\np := 8",
				"MainRego": `
		package main

		main := x if {
			x := stack_result
			x >= data.app.p
		} else := x {
			x := data.app.p
		}

		stack_result := max([x | x := data.stacks[_].p])
	`,
			},
			expectedRego: map[string]string{
				"app.rego":            "AppRego",
				"stacks/foo/foo.rego": "LibRego",
				"main.rego":           "MainRego",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.note, func(t *testing.T) {

			rootDir, _, err := tempfs.MakeTempFS("", test.note, nil)
			if err != nil {
				t.Fatal(err)
			}

			t.Log("Root Directory:", rootDir)

			// Setup git files if any

			remoteGitDir := path.Join(rootDir, "remote-git")

			if len(test.gitFiles) > 0 {
				for name, content := range test.gitFiles {
					if s, ok := test.fileParameters[content]; ok {
						content = s
					}

					if err := os.MkdirAll(path.Dir(path.Join(remoteGitDir, name)), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path.Join(remoteGitDir, name), []byte(content), 0644); err != nil {
						t.Fatal(err)
					}
				}

				repo, err := git.PlainInit(remoteGitDir, false)
				if err != nil {
					t.Fatal(err)
				}

				w, err := repo.Worktree()
				if err != nil {
					t.Fatal(err)
				}

				for name := range test.gitFiles {
					if _, err := w.Add(name); err != nil {
						t.Fatal(err)
					}
				}

				if _, err := w.Commit("Initial commit", &git.CommitOptions{Author: &object.Signature{}}); err != nil {
					t.Fatal(err)
				}
			}

			// Create a mock S3 service with a test bucket and a mock HTTP service to serve the datasource.

			mock, s3TS := testS3Service(t, "test")
			httpTS := testHTTPDataServer(t, test.datasourceFiles)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			configPath := path.Join(rootDir, "config.yaml")
			persistenceDir := path.Join(rootDir, "data")

			tmpl, err := template.New("config").Parse(test.config)
			if err != nil {
				t.Fatal(err)
			}

			buf := bytes.NewBuffer(nil)
			parameters := map[string]interface{}{
				"RemoteGitDir": remoteGitDir,
				"S3URL":        s3TS.URL,
				"HTTPURL":      httpTS.URL,
			}
			for k, v := range test.fileParameters {
				parameters[k] = base64.StdEncoding.EncodeToString([]byte(v))
			}
			err = tmpl.Execute(buf, parameters)
			if err != nil {
				t.Fatal(err)
			}

			err = os.WriteFile(configPath, buf.Bytes(), 0644)
			if err != nil {
				t.Fatal(err)
			}

			svc := service.New().WithConfigFile(configPath).WithPersistenceDir(persistenceDir)

			doneCh := make(chan error)

			go func() {
				doneCh <- svc.Run(ctx)
			}()

			for {
				obj, err := mock.GetObject("test", "bundle.tar.gz", nil)

				if err != nil {
					if gofakes3.HasErrorCode(err, gofakes3.ErrNoSuchKey) {
						time.Sleep(time.Millisecond)
						continue
					}
					t.Fatal(err)
				}

				b, err := bundle.NewReader(obj.Contents).Read()
				if err != nil {
					t.Fatal(err)
				}

				if len(test.expectedRego) != len(b.Modules) {
					t.Fatalf("expected %v modules but got %v", len(test.expectedRego), len(b.Modules))
				}

				got := map[string]string{}
				for _, mf := range b.Modules {
					got[strings.TrimPrefix(mf.Path, "/")] = string(mf.Raw)
				}

				for k := range test.expectedRego {
					rego := test.expectedRego[k]
					if s, ok := test.fileParameters[rego]; ok {
						rego = s
					}
					if rego != got[k] {
						t.Fatalf("exp:\n%v\n\ngot:\n%v", test.expectedRego[k], got[k])
					}
				}

				var expectedData interface{}

				if test.expectedData != "" {
					if err := json.Unmarshal([]byte(test.expectedData), &expectedData); err != nil {
						t.Fatalf("failed to unmarshal expected data: %v", err)
					}
				} else {
					expectedData = map[string]interface{}{}
				}

				if !reflect.DeepEqual(b.Data, expectedData) {
					t.Fatalf("expected data to be %v but got %v", expectedData, b.Data)
				}

				break
			}

			cancel()
			err = <-doneCh
			if err != nil {
				t.Fatal(err)
			}
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

func testHTTPDataServer(t *testing.T, files map[string]string) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		content, ok := files[r.URL.Path]
		if !ok {
			http.Error(w, "file not found", http.StatusNotFound)
			return
		}

		_, err := w.Write([]byte(content))
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}
