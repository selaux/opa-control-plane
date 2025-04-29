package builder

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
)

type LibrarySpec struct {
	Roots []ast.Ref
	Repo  string
}

type SystemSpec struct {
	Repo string
}

type Builder struct {
	systemSpec   *SystemSpec
	librarySpecs []*LibrarySpec
	output       io.Writer
}

func New() *Builder {
	return &Builder{}
}

func (b *Builder) WithOutput(w io.Writer) *Builder {
	b.output = w
	return b
}

func (b *Builder) WithSystemSpec(ss *SystemSpec) *Builder {
	b.systemSpec = ss
	return b
}

func (b *Builder) WithLibrarySpecs(librarySpecs []*LibrarySpec) *Builder {
	b.librarySpecs = librarySpecs
	return b
}

func (b *Builder) Build(ctx context.Context) error {

	toBuild := map[string]struct{}{b.systemSpec.Repo: {}}
	toProcess, err := listRegoFilesRecursive(b.systemSpec.Repo)
	if err != nil {
		return err
	}

	for len(toProcess) > 0 {
		var next string
		next, toProcess = toProcess[0], toProcess[1:]
		bs, err := os.ReadFile(next)
		if err != nil {
			return err
		}

		module, err := ast.ParseModule(next, string(bs))
		if err != nil {
			return err
		}

		var errInner error

		ast.WalkRefs(module, func(r ast.Ref) bool {
			if errInner != nil {
				return true
			}
			p := r.ConstantPrefix()
			for _, l := range b.librarySpecs {
				if _, ok := toBuild[l.Repo]; ok {
					continue
				}
				for _, root := range l.Roots {
					if root.HasPrefix(p) || p.HasPrefix(root) {
						toBuild[l.Repo] = struct{}{}
						files, err := listRegoFilesRecursive(l.Repo)
						if err != nil {
							errInner = err
						}
						toProcess = append(toProcess, files...)
						break
					}
				}
			}
			return false
		})
	}

	sortedSrcs := make([]string, 0, len(toBuild))
	for k := range toBuild {
		sortedSrcs = append(sortedSrcs, k)
	}

	sort.Strings(sortedSrcs)

	// NOTE(tsandall): we want control over the filenames in the emitted bundle
	// so that we don't include information about the filesystem where the build
	// ran... the upstream compile package doesn't provide this control at the
	// moment. Once upstream supports that control, we could replace this in
	// favour of the compile package which would give us support for
	// optimization levels, other targets, etc.
	var result bundle.Bundle
	result.Data = map[string]interface{}{} // TODO(tsandall): add data

	for _, srcDir := range sortedSrcs {

		err := walkRegoFilesRecursive(srcDir, func(path string, _ os.FileInfo) error {
			bs, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result.Modules = append(result.Modules, bundle.ModuleFile{
				Path: strings.TrimPrefix(path, srcDir),
				Raw:  bs,
			})
			return nil
		})
		if err != nil {
			return err
		}
	}

	return bundle.Write(b.output, result)
}

func listRegoFilesRecursive(roots ...string) ([]string, error) {
	var files []string
	for _, root := range roots {
		err := walkRegoFilesRecursive(root, func(path string, fi os.FileInfo) error {
			files = append(files, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func walkRegoFilesRecursive(root string, fn func(path string, fi os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".rego" {
			return nil
		}
		return fn(path, fi)
	})
}
