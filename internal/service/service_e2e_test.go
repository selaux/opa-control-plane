package service_test

import (
	"bytes"
	"context"
	"html/template"
	"net/http/httptest"
	"os"
	"path"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	_ "github.com/go-git/go-git/v5/plumbing/object"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/tsandall/lighthouse/internal/service"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

// TODO(tsandall): update e2e tests to handle
// non-git backed systems
// libraries

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

	if err := os.WriteFile(path.Join(remoteGitDir, "lib/lib.rego"), []byte("package lib\nq := 7"), 0644); err != nil {
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
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	defer ts.Close()

	t.Log("Test S3 URL:", ts.URL)

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
				}
			}
		},
		libraries: {
			TestLibrary: {
				git: {
					repo: {{ .RemoteGitDir }},
					reference: refs/heads/master,
					path: "lib/",
				}
			}
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	err = tmpl.Execute(buf, struct {
		RemoteGitDir string
		MockS3URL    string
	}{
		RemoteGitDir: remoteGitDir,
		MockS3URL:    ts.URL,
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

	doneCh := make(chan struct{})

	go func() {
		if err := svc.Run(ctx); err != nil {
			t.Fatal(err)
		}

		doneCh <- struct{}{}
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

		exp := []string{
			"package app\np := data.lib.q",
			"package lib\nq := 7",
		}

		if len(exp) != len(b.Modules) {
			t.Fatalf("expected %v modules but got %v", len(exp), len(b.Modules))
		}

		for i := range exp {
			if exp[i] != string(b.Modules[i].Raw) {
				t.Fatalf("exp:\n%v\n\ngot:\n%v", exp[i], string(b.Modules[i].Raw))
			}
		}

		break
	}

	cancel()
	_ = <-doneCh

}
