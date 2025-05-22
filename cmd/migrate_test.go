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
