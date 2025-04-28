package builder_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/opa/bundle"

	"github.com/tsandall/lighthouse/internal/builder"
)

func TestBuilder(t *testing.T) {

	cases := []struct {
		note        string
		systemFiles map[string]string
		libFiles    []map[string]string
		exp         map[string]string
	}{
		{
			note: "trivial case",
			systemFiles: map[string]string{
				"x/x.rego": `package x

				p := 7`,
			},
		},
	}

	for _, tc := range cases {

		allFiles := map[string]string{}
		for f, src := range tc.systemFiles {
			allFiles[filepath.Join("system", f)] = src
		}

		withTempFS(allFiles, func(root string) {

			buf := bytes.NewBuffer(nil)

			b := builder.New().
				WithSystemSpec(&builder.SystemSpec{Repo: filepath.Join(root, "system")}).
				WithOutput(buf)

			err := b.Build(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			bundle, err := bundle.NewReader(buf).Read()
			if err != nil {
				log.Fatal(err)
			}

			for _, mf := range bundle.Modules {
				fmt.Println(string(mf.Raw))
			}

		})

	}

}

/* copied from https://github.com/open-policy-agent/opa/blob/main/v1/util/test/tempfs.go */

func withTempFS(files map[string]string, f func(string)) {
	rootDir, cleanup, err := MakeTempFS("", "lighthouse_test", files)
	if err != nil {
		panic(err)
	}
	defer cleanup()
	f(rootDir)
}

// MakeTempFS creates a temporary directory structure for test purposes rooted at root.
// If root is empty, the dir is created in the default system temp location.
// If the creation fails, cleanup is nil and the caller does not have to invoke it. If
// creation succeeds, the caller should invoke cleanup when they are done.
func MakeTempFS(root, prefix string, files map[string]string) (rootDir string, cleanup func(), err error) {

	rootDir, err = os.MkdirTemp(root, prefix)

	if err != nil {
		return "", nil, err
	}

	cleanup = func() {
		os.RemoveAll(rootDir)
	}

	skipCleanup := false

	// Cleanup unless flag is unset. It will be unset if we succeed.
	defer func() {
		if !skipCleanup {
			cleanup()
		}
	}()

	for path, content := range files {
		dirname, filename := filepath.Split(path)
		dirPath := filepath.Join(rootDir, dirname)
		if err := os.MkdirAll(dirPath, 0777); err != nil {
			return "", nil, err
		}

		f, err := os.Create(filepath.Join(dirPath, filename))
		if err != nil {
			return "", nil, err
		}

		if _, err := f.WriteString(content); err != nil {
			return "", nil, err
		}
	}

	skipCleanup = true

	return rootDir, cleanup, nil
}
