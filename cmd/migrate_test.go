package cmd

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/tsandall/lighthouse/internal/config"
)

func TestLibraryPackageIndex(t *testing.T) {

	index := newLibraryPackageIndex()

	for _, add := range []struct {
		pkg string
		lib string
	}{
		{"libraries/foo/bar", "foo"},
		{"libraries/foo/baz", "foo"},
		{"libraries/qux/corge", "qux"},
	} {
		index.Add(add.pkg, add.lib)
	}

	for i, tc := range []struct {
		path string
		exp  map[string]struct{}
	}{
		{"libraries", map[string]struct{}{"foo": {}, "qux": {}}},
		{"libraries/foo", map[string]struct{}{"foo": {}}},
		{"libraries/foo/bar", map[string]struct{}{"foo": {}}},
		{"libraries/foo/bar/baz", map[string]struct{}{"foo": {}}},
		{"libraries/qux", map[string]struct{}{"qux": {}}},
		{"libraries/qux/corge", map[string]struct{}{"qux": {}}},
		{"libraries/qux/corge/grault", map[string]struct{}{"qux": {}}},
		{"doesnotexist", map[string]struct{}{}},
		{"does/not/exist", map[string]struct{}{}},
		{"libraries/doesnotexist", map[string]struct{}{}},
		{"libraries/foo/doesnotexist", map[string]struct{}{}},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := index.Lookup(tc.path)
			if !reflect.DeepEqual(result, tc.exp) {
				t.Fatal("path:", tc.path, "got:", result, "want:", tc.exp)
			}
		})
	}
}

func TestBaseLibIndex(t *testing.T) {

	cases := []struct {
		path string
		lib  string
	}{
		{path: "global", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes/envoy:2.1", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes/envoy:2.1/conflicts", lib: "template.envoy:2.1-conflicts"},
		{path: "global/systemtypes/envoy:2.1/conflicts/entry", lib: "template.envoy:2.1-conflicts"},
		{path: "application", lib: "template.envoy:2.1-entrypoint-application"},
		{path: "system/log", lib: "template.envoy:2.1-entrypoint-log"},
		{path: "system/authz", lib: "template.envoy:2.1-entrypoint-authz"},
		{path: "main", lib: "template.envoy:2.1-entrypoint-main"},
	}

	for _, tc := range cases {
		got := baseLibPackageIndex["template.envoy:2.1"].Lookup(tc.path)
		exp := map[string]struct{}{}
		exp[tc.lib] = struct{}{}
		if !reflect.DeepEqual(exp, got) {
			t.Fatalf("expected %v but got %v", tc.lib, got)
		}
	}
}

func TestPruneConfig(t *testing.T) {

	root, err := config.Parse(bytes.NewBufferString(`{
		systems: {
			sys1: {
				requirements: [{library: lib1}],
				git: {credentials: sec1},
				labels: {foo: bar}
			}
		},
		stacks: {
			stack1: {
				selector: {foo: [bar]},
				requirements: [{library: lib2}]
			},
			stack2: {
				selector: {
					DONOTMATCH: []
				},
				requirements: [{library: lib3}, {library: libUNUSED3}]
			}
		},
		libraries: {
			lib1: {
				requirements: [{library: lib3}],
				git: {credentials: sec2}
			},
			lib2: {
				requirements: [{library: lib4}],
				git: {credentials: sec3}
			},
			lib3: {
				git: {credentials: sec4}
			},
			lib4: {
				git: {credentials: sec5}
			},
			libUNUSED1: {
				git: {credentials: sec6},
				requirements: [{library: libUNUSED2}]
			},
			libUNUSED2: {
				git: {credentials: sec7},
			},
			libUNUSED3: {
			}
		},
		secrets: {
			sec1: {},
			sec2: {},
			sec3: {},
			sec4: {},
			sec5: {},
			sec6: {},
			sec7: {}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	stacks, libs, secrets := pruneConfig(root)
	expStacks := []string{"stack2"}
	expLibs := []string{"libUNUSED1", "libUNUSED2", "libUNUSED3"}
	expSecrets := []string{"sec6", "sec7"}

	var gotStacks []string
	for _, s := range stacks {
		gotStacks = append(gotStacks, s.Name)
	}

	sort.Strings(gotStacks)

	var gotLibs []string
	for _, l := range libs {
		gotLibs = append(gotLibs, l.Name)
	}

	sort.Strings(gotLibs)

	var gotSecrets []string
	for _, s := range secrets {
		gotSecrets = append(gotSecrets, s.Name)
	}

	sort.Strings(gotSecrets)

	if !reflect.DeepEqual(expStacks, gotStacks) {
		t.Fatalf("expected stacks %v but got %v", expStacks, gotStacks)
	}

	if !reflect.DeepEqual(expLibs, gotLibs) {
		t.Fatalf("expected libs %v but got %v", expLibs, gotLibs)
	}

	if !reflect.DeepEqual(expSecrets, gotSecrets) {
		t.Fatalf("expected secrets %v but got %v", expSecrets, gotSecrets)
	}

	expRoot, err := config.Parse(bytes.NewBufferString(`{
		systems: {
			sys1: {
				requirements: [{library: lib1}],
				git: {credentials: sec1},
				labels: {foo: bar}
			}
		},
		stacks: {
			stack1: {
				selector: {foo: [bar]},
				requirements: [{library: lib2}]
			},
		},
		libraries: {
			lib1: {
				requirements: [{library: lib3}],
				git: {credentials: sec2}
			},
			lib2: {
				requirements: [{library: lib4}],
				git: {credentials: sec3}
			},
			lib3: {
				git: {credentials: sec4}
			},
			lib4: {
				git: {credentials: sec5}
			},
		},
		secrets: {
			sec1: {},
			sec2: {},
			sec3: {},
			sec4: {},
			sec5: {},
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expRoot, root) {
		t.Fatal("expected root differed from pruned root")
	}
}
