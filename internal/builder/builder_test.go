package builder_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"

	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

func TestBuilder(t *testing.T) {

	cases := []struct {
		note        string
		systemFiles map[string]string
		libFiles    []map[string]string
		fileFiles   map[string]string
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
		{
			note: "extra files (root)",
			systemFiles: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			fileFiles: map[string]string{
				"foo/file0.rego": `package file0
				f := 42`,
				"data.json": `{"c":3}`,
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
				"/foo/file0.rego": `package file0
				f := 42`,
				"/data.json": `{"c":3}`,
			},
		},
		{
			note: "extra files (non-root)",
			systemFiles: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			fileFiles: map[string]string{
				"foo/file0.rego": `package file0
				f := 42`,
				"bar/data.json": `{"a": 1, "b": 2}`,
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
				"/foo/file0.rego": `package file0
				f := 42`,
				"/data.json": `{"bar":{"a":1,"b":2}}`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(b *testing.T) {
			allFiles := map[string]string{}
			for f, src := range tc.systemFiles {
				allFiles[filepath.Join("system", f)] = trimLeadingWhitespace(src)
			}

			for i, srcs := range tc.libFiles {
				for f, src := range srcs {
					allFiles[filepath.Join(fmt.Sprintf("lib%d", i), f)] = trimLeadingWhitespace(src)
				}
			}

			for f, src := range tc.fileFiles {
				allFiles[filepath.Join("extra", f)] = trimLeadingWhitespace(src)
			}

			for f, src := range tc.exp {
				tc.exp[f] = trimLeadingWhitespace(src)
			}

			tempfs.WithTempFS(allFiles, func(root string) {

				buf := bytes.NewBuffer(nil)

				var libSpecs []*builder.LibrarySpec

				for i := range tc.libFiles {
					libSpecs = append(libSpecs, &builder.LibrarySpec{
						Repo:  filepath.Join(root, fmt.Sprintf("lib%d", i)),
						Roots: []ast.Ref{ast.MustParseRef(fmt.Sprintf("data.lib%d", i))},
					})
				}

				var fileSpecs []*builder.FileSpec
				if len(tc.fileFiles) > 0 {
					fileSpecs = append(fileSpecs, &builder.FileSpec{Path: filepath.Join(root, "extra")})
				}

				b := builder.New().
					WithSystemSpec(&builder.SystemSpec{Repo: filepath.Join(root, "system")}).
					WithLibrarySpecs(libSpecs).
					WithFileSpecs(fileSpecs).
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

				if len(bundle.Data) > 0 {
					data, _ := json.Marshal(bundle.Data)
					fileMap["/data.json"] = string(data)
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
