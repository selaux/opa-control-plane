package builder_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
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
				"/x/x.rego": `package x
				p := 7`,
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := 7`,
			},
		},
		{
			note: "library deps",
			systemFiles: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			libFiles: []map[string]string{{
				"lib0.rego": `package lib0
				q := data.lib2.r`,
			}, {
				"libUnused.rego": `package libUnused
				s := 42`,
			}, {
				"lib2.rego": `package lib2
				r := 42`,
			}},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
				"/lib0.rego": `package lib0
				q := data.lib2.r`,
				"/lib2.rego": `package lib2
				r := 42`,
			},
		},
	}

	for _, tc := range cases {

		allFiles := map[string]string{}
		for f, src := range tc.systemFiles {
			allFiles[filepath.Join("system", f)] = trimLeadingWhitespace(src)
		}

		for i, srcs := range tc.libFiles {
			for f, src := range srcs {
				allFiles[filepath.Join(fmt.Sprintf("lib%d", i), f)] = trimLeadingWhitespace(src)
			}
		}

		for f, src := range tc.exp {
			tc.exp[f] = trimLeadingWhitespace(src)
		}

		withTempFS(allFiles, func(root string) {

			buf := bytes.NewBuffer(nil)

			var libSpecs []*builder.LibrarySpec

			for i := range tc.libFiles {
				libSpecs = append(libSpecs, &builder.LibrarySpec{
					Repo:  filepath.Join(root, fmt.Sprintf("lib%d", i)),
					Roots: []ast.Ref{ast.MustParseRef(fmt.Sprintf("data.lib%d", i))},
				})
			}

			b := builder.New().
				WithSystemSpec(&builder.SystemSpec{Repo: filepath.Join(root, "system")}).
				WithLibrarySpecs(libSpecs).
				WithOutput(buf)

			err := b.Build(context.Background())
			if err != nil {
				t.Fatal(err)
			}

			bundle, err := bundle.NewReader(buf).Read()
			if err != nil {
				log.Fatal(err)
			}

			fileMap := map[string]string{}

			for _, mf := range bundle.Modules {
				fileMap[mf.Path] = string(mf.Raw)
			}

			if len(fileMap) != len(tc.exp) {
				t.Fatalf("expected %d files, got %d", len(tc.exp), len(fileMap))
			}

			for path, src := range tc.exp {
				if fileMap[path] != src {
					t.Fatalf("expected %q, got %q", src, fileMap[path])
				}
			}

		})

	}

}

func trimLeadingWhitespace(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, " \t")
	}
	return strings.Join(lines, "\n")
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
