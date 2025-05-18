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

	"github.com/open-policy-agent/opa/bundle"

	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

func TestBuilder(t *testing.T) {

	type libSpecMock struct {
		Repo  map[string]string
		Files map[string]string
	}

	cases := []struct {
		note               string
		systemRepo         map[string]string
		systemFiles        map[string]string
		systemRequirements []string
		libs               []libSpecMock
		exp                map[string]string
	}{
		{
			note: "trivial case",
			systemRepo: map[string]string{
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
			systemRepo: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			libs: []libSpecMock{{
				Repo: map[string]string{"lib0.rego": `package lib0
				q := data.lib2.r`},
			}, {
				Repo: map[string]string{"libUnused.rego": `package libUnused
				s := 42`},
			}, {
				Repo: map[string]string{"lib2.rego": `package lib2
				r := 42`},
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
			note: "system files: root",
			systemRepo: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			systemFiles: map[string]string{
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
			note: "system files: non-root",
			systemRepo: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			systemFiles: map[string]string{
				"foo/file0.rego": `package file0
				f := 42`,
				"bar/data.json":     `{"a": 1, "b": 2}`,
				"baz/bar/data.json": `{"c": 3, "d": 4}`,
				"qux/data.json":     `[1,2]`,
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
				"/foo/file0.rego": `package file0
				f := 42`,
				"/data.json": `{"bar":{"a":1,"b":2},"baz":{"bar":{"c":3,"d":4}},"qux":[1,2]}`,
			},
		},
		{
			note: "library files",
			systemRepo: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
			},
			libs: []libSpecMock{
				{Files: map[string]string{"z.rego": "package lib0\nq := data.lib1.r"}},
				{Files: map[string]string{"DONOTINCLUDE.rego": "package lib999\nq := data.lib1.r"}},
				{Files: map[string]string{"w.rego": "package lib1\nr := 7"}},
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := data.lib0.q`,
				"/z.rego": "package lib0\nq := data.lib1.r",
				"/w.rego": "package lib1\nr := 7",
			},
		},
		{
			note: "requirements",
			systemRepo: map[string]string{
				"/x/x.rego": "package x\np := 7",
			},
			systemRequirements: []string{"lib0"},
			libs: []libSpecMock{
				{Files: map[string]string{
					"main.rego": "package main\nmain := data.x.p",
				}},
			},
			exp: map[string]string{
				"/x/x.rego":  "package x\np := 7",
				"/main.rego": "package main\nmain := data.x.p",
			},
		},
		{
			note: "nested refs",
			systemRepo: map[string]string{
				"x.rego": `
					package x
					p := f([data.lib.r])[_]  # parses as ref(call(...), var(_))
				`,
			},
			libs: []libSpecMock{{
				Repo: map[string]string{"y.rego": `
					package lib

					r := 7`},
			}},
			exp: map[string]string{
				"/x.rego": `
					package x
					p := f([data.lib.r])[_]  # parses as ref(call(...), var(_))
				`,
				"/y.rego": `
					package lib

					r := 7`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(b *testing.T) {
			allFiles := map[string]string{}
			for f, src := range tc.systemRepo {
				allFiles[filepath.Join("system", f)] = trimLeadingWhitespace(src)
			}

			for i, mock := range tc.libs {
				for f, src := range mock.Repo {
					allFiles[filepath.Join(fmt.Sprintf("lib%d", i), f)] = trimLeadingWhitespace(src)
				}
				for f, src := range mock.Files {
					allFiles[filepath.Join(fmt.Sprintf("lib%dFiles", i), f)] = trimLeadingWhitespace(src)
				}
			}

			for f, src := range tc.systemFiles {
				allFiles[filepath.Join("systemFiles", f)] = trimLeadingWhitespace(src)
			}

			for f, src := range tc.exp {
				tc.exp[f] = trimLeadingWhitespace(src)
			}

			tempfs.WithTempFS(allFiles, func(root string) {

				buf := bytes.NewBuffer(nil)

				var libSpecs []*builder.LibrarySpec

				for i := range tc.libs {
					ls := &builder.LibrarySpec{}
					if len(tc.libs[i].Repo) > 0 {
						ls.RepoDir = filepath.Join(root, fmt.Sprintf("lib%d", i))
					}
					if len(tc.libs[i].Files) > 0 {
						ls.FileDir = filepath.Join(root, fmt.Sprintf("lib%dFiles", i))
					}
					libSpecs = append(libSpecs, ls)
				}

				ss := &builder.SystemSpec{}

				if len(tc.systemRepo) > 0 {
					ss.RepoDir = filepath.Join(root, "system")
				}

				if len(tc.systemFiles) > 0 {
					ss.FileDir = filepath.Join(root, "systemFiles")
				}

				for _, req := range tc.systemRequirements {
					ss.Requirements = append(ss.Requirements, config.Requirement{Library: &req})
				}

				b := builder.New().
					WithSystemSpec(ss).
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

				if len(bundle.Data) > 0 {
					data, _ := json.Marshal(bundle.Data)
					fileMap["/data.json"] = string(data)
				}

				if len(fileMap) != len(tc.exp) {
					for k, v := range fileMap {
						t.Logf("Got %v:\n%v", k, v)
					}
					t.Fatalf("expected %d files, got %d", len(tc.exp), len(fileMap))
				}

				for path, src := range tc.exp {
					if fileMap[path] != src {
						for k, v := range fileMap {
							t.Logf("Got %v:\n%v", k, v)
						}
						t.Fatalf("Expected %v:\n%v", path, src)
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
