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

// TODO(tsandall): update e2e tests to handle
// non-git backed systems

func TestFromConfig(t *testing.T) {

	rootDir, _, err := tempfs.MakeTempFS("", "lighthouse_e2e", nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Root Directory:", rootDir)

	remoteGitDir := path.Join(rootDir, "remote-git")

	repo, err := git.PlainInit(remoteGitDir, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, x := range []string{"app", "lib"} {
		if err := os.Mkdir(path.Join(remoteGitDir, x), 0755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(path.Join(remoteGitDir, "app/app.rego"), []byte("package app\np := data.lib.q"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path.Join(remoteGitDir, "lib/lib.rego"), []byte("package lib\nq := data.lib.s"), 0644); err != nil {
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

	// Create a mock S3 service with a test bucket.

	mock := s3mem.New()
	mock.CreateBucket("test")
	s3TS := httptest.NewServer(gofakes3.New(mock).Server())
	defer s3TS.Close()

	t.Log("Test S3 URL:", s3TS.URL)

	// Create a mock HTTP service to serve the datasource.
	httpTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var content []byte
		if r.URL.Path == "/datasource1" {
			content = []byte(`{"key": "value1"}`)
		} else {
			content = []byte(`{"key": "value2"}`)
		}
		_, err := w.Write(content)
		if err != nil {
			http.Error(w, "failed to write response", http.StatusInternalServerError)
		}
	}))
	defer httpTS.Close()

	t.Log("Test HTTP URL:", httpTS.URL)

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

	if err := os.Mkdir(persistenceDir, 0755); err != nil {
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
