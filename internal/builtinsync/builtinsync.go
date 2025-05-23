package builtinsync

import (
	"context"
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type BuiltinSynchronizer struct {
	fs   embed.FS
	path string // path where builtin library should be saved
	key  string
}

func New(fs embed.FS, path string, key string) *BuiltinSynchronizer {
	return &BuiltinSynchronizer{fs: fs, path: path, key: key}
}

func (s *BuiltinSynchronizer) Execute(ctx context.Context) error {
	return fs.WalkDir(s.fs, s.key, func(filename string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		dstFilename := strings.TrimPrefix(filename, s.key)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(s.path, dstFilename), 0755)
		}

		bs, err := s.fs.ReadFile(filename)
		if err != nil {
			return err
		}

		return os.WriteFile(filepath.Join(s.path, dstFilename), bs, 0644)
	})
}
