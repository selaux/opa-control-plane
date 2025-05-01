package builder

import (
	"context"
	"encoding/json"
	"errors"
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

type FileSpec struct {
	Path string // Directory on disk holding files to include in the bundle.
}

type Builder struct {
	systemSpec   *SystemSpec
	librarySpecs []*LibrarySpec
	fileSpecs    []*FileSpec
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

func (b *Builder) WithFileSpecs(fileSpecs []*FileSpec) *Builder {
	b.fileSpecs = fileSpecs
	return b
}

func (b *Builder) Build(ctx context.Context) error {

	// NOTE(tsandall): if roots cannot be computed for any library then we will bail
	// this means that libraries must be syntactically valid when synched otherwise
	// all builds will stop.
	// TODO(tsandall): precompute if this becomes a bottleneck
	for i := range b.librarySpecs {
		if b.librarySpecs[i].Roots == nil {
			var err error
			b.librarySpecs[i].Roots, err = getRootsForRepo(b.librarySpecs[i].Repo)
			if err != nil {
				return err
			}
		}
	}

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

	for _, spec := range b.fileSpecs {
		err := filepath.Walk(spec.Path, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}

			bs, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			if fi.Name() == ".manifest" {
				if err := json.Unmarshal(bs, &result.Manifest); err != nil {
					return err
				}
			} else if filepath.Ext(path) == ".rego" {
				result.Modules = append(result.Modules, bundle.ModuleFile{
					Path: strings.TrimPrefix(path, spec.Path),
					Raw:  bs,
				})
			} else if filepath.Ext(path) == ".json" {
				var value interface{}
				err := json.Unmarshal(bs, &value)
				if err != nil {
					return err
				}

				dirpath := strings.TrimLeft(filepath.ToSlash(filepath.Dir(path)), "/.")

				var key []string
				if dirpath != "" {
					key = strings.Split(dirpath, "/")
				}

				var bundleWithData bundle.Bundle
				bundleWithData.Data, err = mktree(key, value)
				if err != nil {
					return err
				}

				merged, err := bundle.Merge([]*bundle.Bundle{&result, &bundleWithData})
				if err != nil {
					return err
				}

				result = *merged
			}

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

func getRootsForRepo(dir string) ([]ast.Ref, error) {
	set := ast.NewSet()

	err := walkRegoFilesRecursive(dir, func(path string, _ os.FileInfo) error {

		bs, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		module, err := ast.ParseModule(path, string(bs))
		if err != nil {
			return err
		}

		set.Add(ast.NewTerm(module.Package.Path))
		return nil
	})

	sl := set.Slice()
	result := make([]ast.Ref, len(sl))
	for i := range sl {
		result[i] = sl[i].Value.(ast.Ref)
	}

	return result, err
}

func mktree(path []string, value interface{}) (map[string]interface{}, error) {
	if len(path) == 0 {
		// For 0 length path the value is the full tree.
		obj, ok := value.(map[string]interface{})
		if !ok {
			return nil, errors.New("root value must be object")
		}
		return obj, nil
	}

	dir := map[string]interface{}{}
	for i := len(path) - 1; i > 0; i-- {
		dir[path[i]] = value
		value = dir
		dir = map[string]interface{}{}
	}
	dir[path[0]] = value

	return dir, nil
}
