package tempfs

import (
	"os"
	"path/filepath"
	"testing"
)

/* copied from https://github.com/open-policy-agent/opa/blob/main/v1/util/test/tempfs.go */

func WithTempFS(t *testing.T, files map[string]string, f func(t *testing.T, dir string)) {
	rootDir, cleanup, err := makeTempFS("", "opa-control-plane_test", files)
	if err != nil {
		panic(err)
	}
	defer func() {
		if !t.Failed() {
			cleanup()
		}
	}()

	f(t, rootDir)
}

// makeTempFS creates a temporary directory structure for test purposes rooted at root.
// If root is empty, the dir is created in the default system temp location.
// If the creation fails, cleanup is nil and the caller does not have to invoke it. If
// creation succeeds, the caller should invoke cleanup when they are done.
func makeTempFS(root, prefix string, files map[string]string) (rootDir string, cleanup func(), err error) {

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
