package util

import (
	"io/fs"
	"path/filepath"

	"github.com/gobwas/glob"
)

var _ fs.FS = &FilterFS{}

type FilterFS struct {
	fs       fs.FS
	excluded []glob.Glob // List of file patterns to exclude
}

type filteredDir struct {
	d        fs.ReadDirFile
	path     string
	excluded []glob.Glob
}

func NewFilterFS(fs fs.FS, exclude []string) (*FilterFS, error) {
	ffs := FilterFS{fs: fs}

	for _, pattern := range exclude {
		g, err := glob.Compile(pattern)
		if err != nil {
			return nil, err
		}

		ffs.excluded = append(ffs.excluded, g)
	}

	return &ffs, nil
}

func (f *FilterFS) Open(name string) (fs.File, error) {
	sname := filepath.Clean(filepath.ToSlash(name))

	if isExcluded(f.excluded, name) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: name,
			Err:  fs.ErrNotExist,
		}
	}

	file, err := f.fs.Open(name)
	if err != nil {
		return nil, err
	}

	if dir, ok := file.(fs.ReadDirFile); ok {
		return &filteredDir{d: dir, path: sname, excluded: f.excluded}, nil
	}

	return file, nil
}

func (d *filteredDir) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.d.ReadDir(n)
	if err != nil {
		return nil, err
	}

	var filtered []fs.DirEntry
	for _, entry := range entries {
		if !isExcluded(d.excluded, d.path+"/"+entry.Name()) {
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

func (d *filteredDir) Close() error {
	return d.d.Close()
}

func (d *filteredDir) Stat() (fs.FileInfo, error) {
	return d.d.Stat()
}

func (d *filteredDir) Read(bs []byte) (int, error) {
	return d.d.Read(bs)
}

func isExcluded(excluded []glob.Glob, name string) bool {
	for _, g := range excluded {
		if g.Match(name) {
			return true
		}
	}

	return false
}
