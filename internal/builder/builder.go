package builder

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/compile"
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
	librarySpecs []LibrarySpec
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

func (b *Builder) WithLibrarySpecs(librarySpecs []LibrarySpec) *Builder {
	b.librarySpecs = librarySpecs
	return b
}

func (b *Builder) Build(ctx context.Context) error {

	toBuild := map[string]struct{}{b.systemSpec.Repo: struct{}{}}
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

		var inner error

		ast.WalkRefs(module, func(r ast.Ref) bool {
			if inner != nil {
				return true
			}
			p := r.ConstantPrefix()
			for _, l := range b.librarySpecs {
				if _, ok := toBuild[l.Repo]; ok {
					continue
				}
				for _, root := range l.Roots {
					if root.HasPrefix(p) {
						toBuild[l.Repo] = struct{}{}
						files, err := listRegoFilesRecursive(l.Repo)
						if err != nil {
							inner = err
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

	// XXX(tsandall): stopped here for now -- need to replace this with code that manually contructs an github.com/open-policy-agent/opa/bundle.
	return compile.New().WithPaths(sortedSrcs...).WithOutput(b.output).Build(ctx)
}

func listRegoFilesRecursive(root string) ([]string, error) {
	var files []string
	err := walkFiles(root, func(path string, fi os.FileInfo) error {
		if filepath.Ext(path) == ".rego" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func walkFiles(root string, fn func(path string, fi os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		return fn(path, fi)
	})
}

type compiler struct {
}
