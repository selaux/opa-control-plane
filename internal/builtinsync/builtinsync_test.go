package builtinsync_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tsandall/lighthouse/internal/builtinsync"
	"github.com/tsandall/lighthouse/internal/test/libraries"
	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

func TestBuiltinSync(t *testing.T) {
	tempfs.WithTempFS(t, map[string]string{}, func(t *testing.T, dir string) {
		s := builtinsync.New(libraries.FS, dir, "root/subdir")
		err := s.Execute(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			paths = append(paths, strings.TrimPrefix(path, dir))
			return nil
		})
		// root directory is included so expect "" in addition to fixtures
		exp := []string{"", "/test", "/test/test.rego"}
		if !reflect.DeepEqual(paths, exp) {
			t.Fatalf("exp: %v\ngot: %v", exp, paths)
		}
	})
}
