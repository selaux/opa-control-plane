package cmd

import (
	"fmt"
	"reflect"
	"testing"
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
