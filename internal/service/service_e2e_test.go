package service_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/tsandall/lighthouse/internal/service"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// TestCases is a struct that holds a slice of test cases in a YAML file.
type TestCases struct {
	Cases []TestCase `yaml:"cases"`
}

type TestCase struct {
	Note               string            `yaml:"note"`
	Config             string            `yaml:"config"`
	ContentParameters  map[string]string `yaml:"content_parameters"`
	GitFiles           map[string]string `yaml:"git_files"`
	HTTPEndpoints      map[string]string `yaml:"http_endpoints"`
	ExpectedFilesystem []string          `yaml:"expected_filesystem"`
	ExpectedBundle     ExpectedBundle    `yaml:"expected_bundle"`
}

type ExpectedBundle struct {
	Rego map[string]string `yaml:"rego"`
	Data string            `yaml:"data"`
}

func TestService(t *testing.T) {

	for _, test := range loadTestCases(t).Cases {
		t.Run(test.Note, func(t *testing.T) {
			tempfs.WithTempFS(t, nil, func(t *testing.T, rootDir string) {

				t.Log("Root Directory:", rootDir)

				// Setup git files if any

				remoteGitDir := path.Join(rootDir, "remote-git")
				if len(test.GitFiles) > 0 {
					for name, content := range test.GitFiles {
						content = formatTemplate(t, content, test.ContentParameters)

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

					for name := range test.GitFiles {
						if _, err := w.Add(name); err != nil {
							t.Fatal(err)
						}
					}

					if _, err := w.Commit("Initial commit", &git.CommitOptions{Author: &object.Signature{}}); err != nil {
						t.Fatal(err)
					}
				}

				// Create a mock S3 service with a test bucket and a mock HTTP service to serve the datasource.

				for name, content := range test.HTTPEndpoints {
					test.HTTPEndpoints[name] = formatTemplate(t, content, test.ContentParameters)
				}

				mock, s3TS := testS3Service(t, "test")
				httpTS := testHTTPDataServer(t, test.HTTPEndpoints)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				configPath := path.Join(rootDir, "config.yaml")
				persistenceDir := path.Join(rootDir, "data")

				parameters := map[string]string{
					"git_url":  remoteGitDir,
					"s3_url":   s3TS.URL,
					"http_url": httpTS.URL,
				}
				for k, v := range test.ContentParameters {
					parameters[k] = v
				}

				s := formatTemplate(t, test.Config, parameters)

				err := os.WriteFile(configPath, []byte(s), 0644)
				if err != nil {
					t.Fatal(err)
				}

				var g errgroup.Group
				g.Go(func() error {
					return service.New().WithConfigFile(configPath).WithPersistenceDir(persistenceDir).Run(ctx)
				})

				for {
					obj, err := mock.GetObject("test", "bundle.tar.gz", nil)

					if err != nil {
						if gofakes3.HasErrorCode(err, gofakes3.ErrNoSuchKey) {
							time.Sleep(time.Millisecond)
							continue
						}
						t.Fatal(err)
					}

					// Check the filesystem layout used to construct the bundle.

					var files []string
					err = filepath.Walk(persistenceDir, func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return err
						}
						if info.IsDir() {
							return nil
						}

						path = strings.TrimPrefix(path, persistenceDir)

						// Filter out the git hidden directories and database file constructed.

						switch slashPath := filepath.ToSlash(path); {
						case strings.Contains(slashPath, "/.git/"):
						case slashPath == "/sqlite.db":
						default:
							files = append(files, path)
						}

						return nil
					})
					if err != nil {
						t.Fatal(err)
					}

					if !reflect.DeepEqual(files, test.ExpectedFilesystem) {
						t.Fatalf("expected files on disk: %v, got: %v", test.ExpectedFilesystem, files)
					}

					// Check the bundle contents.

					b, err := bundle.NewReader(obj.Contents).Read()
					if err != nil {
						t.Fatal(err)
					}

					if len(test.ExpectedBundle.Rego) != len(b.Modules) {
						t.Fatalf("expected %v modules but got %v", len(test.ExpectedBundle.Rego), len(b.Modules))
					}

					got := map[string]string{}
					for _, mf := range b.Modules {
						got[strings.TrimPrefix(mf.Path, "/")] = string(mf.Raw)
					}

					for k := range test.ExpectedBundle.Rego {
						rego := formatTemplate(t, test.ExpectedBundle.Rego[k], test.ContentParameters)
						if rego != got[k] {
							t.Fatalf("exp:\n%v\n\ngot:\n%v", rego, got[k])
						}
					}

					var expectedData interface{}

					if test.ExpectedBundle.Data != "" {
						data := formatTemplate(t, test.ExpectedBundle.Data, test.ContentParameters)

						if err := json.Unmarshal([]byte(data), &expectedData); err != nil {
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
				err = g.Wait()
				if err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func formatTemplate(t *testing.T, templateStr string, contentParameters map[string]string) string {
	buf := bytes.NewBuffer(nil)
	parameters := map[string]interface{}{}
	for k, v := range contentParameters {
		parameters[k] = v
	}

	funcs := template.FuncMap{
		"base64encode": func(s string) (string, error) {
			return base64.StdEncoding.EncodeToString([]byte(s)), nil
		},
	}

	tmpl, err := template.New("data").Funcs(funcs).Parse(templateStr)
	if err != nil {
		t.Fatal(err)
	}

	err = tmpl.Execute(buf, parameters)
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func loadTestCases(t *testing.T) TestCases {
	var testCases TestCases

	err := filepath.Walk("testdata/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var cases TestCases
		err = yaml.Unmarshal(data, &cases)
		if err != nil {
			return err
		}

		testCases.Cases = append(testCases.Cases, cases.Cases...)
		return nil

	})

	if err != nil {
		t.Fatal(err)
	}

	return testCases
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
