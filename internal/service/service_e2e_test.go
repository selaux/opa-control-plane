package service_test

import (
	"bytes"
	"context"
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

func TestFromConfigWithGit(t *testing.T) {

	rootDir, _, err := tempfs.MakeTempFS("", "lighthouse_e2e_w_git", map[string]string{
		"remote-git/app/app.rego": "package app\np := data.lib.q",
		"remote-git/lib/lib.rego": "package lib\nq := data.lib.s",
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Root Directory:", rootDir)

	remoteGitDir := path.Join(rootDir, "remote-git")

	repo, err := git.PlainInit(remoteGitDir, false)
	if err != nil {
		t.Fatal(err)
	}

	w, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Add("app/app.rego"); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Add("lib/lib.rego"); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Commit("Initial commit", &git.CommitOptions{Author: &object.Signature{}}); err != nil {
		t.Fatal(err)
	}

	// Create a mock S3 service with a test bucket and a mock HTTP service to serve the datasource.

	mock, s3TS := testS3Service(t, "test")
	httpTS := testHTTPDataServer(t, map[string]string{
		"/datasource1": `{"key": "value1"}`,
		"/datasource2": `{"key": "value2"}`,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configPath := path.Join(rootDir, "config.yaml")
	persistenceDir := path.Join(rootDir, "data")

	tmpl, err := template.New("config").Parse(`{
		systems: {
			TestSystem: {
				git: {
					repo: {{ .RemoteGitDir }},
					reference: refs/heads/master,
					path: "app/",
				},
				object_storage: {
					aws: {
						url: {{ .MockS3URL }},
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
							url: {{ .MockHTTPURL }}/datasource1
						}
					}
				],
				files: {
					"foo.rego": "cGFja2FnZSBmb28="
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
							url: {{ .MockHTTPURL }}/datasource2
						}
					}
				],
				files: {
					"bar.rego": "cGFja2FnZSBsaWIKcyA6PSB0cnVl"
				}
			}
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	err = tmpl.Execute(buf, struct {
		RemoteGitDir    string
		MockS3URL       string
		MockHTTPURL     string
		TestFileContent string
	}{
		RemoteGitDir: remoteGitDir,
		MockS3URL:    s3TS.URL,
		MockHTTPURL:  httpTS.URL,
	})
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

		expectedRego := map[string]string{
			"foo.rego":     "package foo",
			"app/app.rego": "package app\np := data.lib.q",
			"lib/lib.rego": "package lib\nq := data.lib.s",
			"bar.rego":     "package lib\ns := true",
		}
		expectedData := map[string]interface{}{
			"datasource1": map[string]interface{}{
				"key": "value1",
			},
			"datasource2": map[string]interface{}{
				"key": "value2",
			},
		}

		if len(expectedRego) != len(b.Modules) {
			t.Fatalf("expected %v modules but got %v", len(expectedRego), len(b.Modules))
		}

		got := map[string]string{}
		for _, mf := range b.Modules {
			got[strings.TrimPrefix(mf.Path, "/")] = string(mf.Raw)
		}

		for k := range expectedRego {
			if expectedRego[k] != got[k] {
				t.Fatalf("exp:\n%v\n\ngot:\n%v", expectedRego[k], got[k])
			}
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
}

func TestFromConfigWithouthGit(t *testing.T) {
	rootDir, _, err := tempfs.MakeTempFS("", "lighthouse_e2e_wo_git", nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Root Directory:", rootDir)

	// Create a mock S3 service with a test bucket and a mock HTTP service to serve the datasource.
	mock, s3TS := testS3Service(t, "test")
	httpTS := testHTTPDataServer(t, map[string]string{
		"/datasource1": `{"key": "value1"}`,
		"/datasource2": `{"key": "value2"}`,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configPath := path.Join(rootDir, "config.yaml")
	persistenceDir := path.Join(rootDir, "data")

	tmpl, err := template.New("config").Parse(`{
		systems: {
			TestSystem: {
				object_storage: {
					aws: {
						url: {{ .MockS3URL }},
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
							url: {{ .MockHTTPURL }}/datasource1
						}
					}
				],
				files: {
					"app/app.rego": "cGFja2FnZSBhcHAKcCA6PSBkYXRhLmxpYi5x",
					"foo.rego": "cGFja2FnZSBmb28="
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
							url: {{ .MockHTTPURL }}/datasource2
						}
					}
				],
				files: {
					"bar.rego": "cGFja2FnZSBsaWIKcyA6PSB0cnVl",
					"lib/lib.rego": "cGFja2FnZSBsaWIKcSA6PSBkYXRhLmxpYi5z"
				}
			}
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	err = tmpl.Execute(buf, struct {
		MockS3URL       string
		MockHTTPURL     string
		TestFileContent string
	}{
		MockS3URL:   s3TS.URL,
		MockHTTPURL: httpTS.URL,
	})
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

		expectedRego := map[string]string{
			"foo.rego":     "package foo",
			"app/app.rego": "package app\np := data.lib.q",
			"lib/lib.rego": "package lib\nq := data.lib.s",
			"bar.rego":     "package lib\ns := true",
		}
		expectedData := map[string]interface{}{
			"datasource1": map[string]interface{}{
				"key": "value1",
			},
			"datasource2": map[string]interface{}{
				"key": "value2",
			},
		}

		if len(expectedRego) != len(b.Modules) {
			t.Fatalf("expected %v modules but got %v", len(expectedRego), len(b.Modules))
		}

		got := map[string]string{}
		for _, mf := range b.Modules {
			got[strings.TrimPrefix(mf.Path, "/")] = string(mf.Raw)
		}

		for k := range expectedRego {
			if expectedRego[k] != got[k] {
				t.Fatalf("exp:\n%v\n\ngot:\n%v", expectedRego[k], got[k])
			}
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
