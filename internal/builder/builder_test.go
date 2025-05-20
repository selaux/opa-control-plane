package builder_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/bundle"

	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

func TestBuilder(t *testing.T) {

	type sourceMock struct {
		name         string
		files        map[string]string
		requirements []string
	}

	cases := []struct {
		note     string
		sources  []sourceMock
		exp      map[string]string
		expError error
	}{
		{
			note: "no requirements",
			sources: []sourceMock{
				{
					files: map[string]string{
						"/x/x.rego": `package x
						p := 7`,
						"/x/y/data.json": `{"A": 7}`,
					},
				},
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				p := 7`,
				"/data.json": `{"x":{"y":{"A":7}}}`,
			},
		},
		{
			note: "multiple requirements",
			sources: []sourceMock{
				{
					files: map[string]string{
						"/x/x.rego": `package x
						import rego.v1
						p if data.lib1.q`,
					},
					requirements: []string{"lib1"},
				},
				{
					files: map[string]string{
						"/lib1.rego": `package lib1
						import rego.v1
						q if data.lib2.r`,
					},
					requirements: []string{"lib2"},
					name:         "lib1",
				},
				{
					files: map[string]string{
						"/lib2.rego": `package lib2
						import rego.v1
						r if input.x > 7`,
					},
					name: "lib2",
				},
				{
					// this source should not show up
					files: map[string]string{
						"/lib3.rego": `package lib3`,
					},
					name: "lib3",
				},
			},
			exp: map[string]string{
				"/x/x.rego": `package x
				import rego.v1
				p if data.lib1.q`,
				"/lib1.rego": `package lib1
				import rego.v1
				q if data.lib2.r`,
				"/lib2.rego": `package lib2
				import rego.v1
				r if input.x > 7`,
			},
		},
		{
			note: "package conflict: same",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []string{"lib2"},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						// add another file that generates a conflict error
						"lib2_other.rego": `package x

						r := 7`,
					},
				},
			},
			expError: fmt.Errorf(`package x in "system" conflicts with package x in "lib2"`),
		},
		{
			note: "package conflict: prefix",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []string{"lib2"},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						// add another file that generates a conflict error
						"lib2_other.rego": `package x.y.z

						r := 7`,
					},
				},
			},
			expError: fmt.Errorf(`package x in "system" conflicts with package x.y.z in "lib2"`),
		},
		{
			note: "package conflict: prefix (reverse)",
			sources: []sourceMock{
				{
					name: "system",
					files: map[string]string{
						"x.rego": `package x.y
						p := data.lib1.q`,
					},
					requirements: []string{"lib1"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
					requirements: []string{"lib2"},
				},
				{
					name: "lib2",
					files: map[string]string{
						"lib2.rego": `package lib2
						q := 7`,
						// add another file that generates a conflict error
						"lib2_other.rego": `package x

						r := 7`,
					},
				},
			},
			expError: fmt.Errorf(`package x.y in "system" conflicts with package x in "lib2"`),
		},
		{
			note: "missing library",
			sources: []sourceMock{
				{
					files: map[string]string{
						"x.rego": `package x
						p := data.lib1.q`,
					},
					requirements: []string{"libX"},
				},
				{
					name: "lib1",
					files: map[string]string{
						"lib1.rego": `package lib1
						p := data.lib1.q`,
					},
				},
			},
			expError: fmt.Errorf("missing library \"libX\""),
		},
	}

	for _, tc := range cases {
		t.Run(tc.note, func(b *testing.T) {
			allFiles := map[string]string{}

			for i, src := range tc.sources {
				for k, v := range src.files {
					allFiles[fmt.Sprintf("src%d/%v", i, k)] = trimLeadingWhitespace(v)
				}
			}

			for f, src := range tc.exp {
				tc.exp[f] = trimLeadingWhitespace(src)
			}

			tempfs.WithTempFS(t, allFiles, func(t *testing.T, root string) {

				buf := bytes.NewBuffer(nil)

				var srcs []*builder.Source
				for i, src := range tc.sources {
					var rs []config.Requirement
					for i := range src.requirements {
						rs = append(rs, config.Requirement{Library: &src.requirements[i]})
					}
					srcs = append(srcs, &builder.Source{
						Name:         src.name,
						Dirs:         []builder.Dir{{Path: fmt.Sprintf("%v/src%d", root, i)}},
						Requirements: rs,
					})
				}
				b := builder.New().
					WithSources(srcs).
					WithOutput(buf)

				err := b.Build(context.Background())
				if err != nil {
					if tc.expError != nil {
						if err.Error() == tc.expError.Error() {
							return
						}
						t.Fatalf("Got: %v\nExpected: %v", err, tc.expError)
					} else {
						t.Fatal(err)
					}
				} else if tc.expError != nil {
					t.Fatalf("Build succeeded but expected error: %v", tc.expError)
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
