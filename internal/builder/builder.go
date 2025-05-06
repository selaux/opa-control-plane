package builder

import (
	"context"
	"encoding/json"
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

	toBuild := map[string]struct{}{}
	var toProcess []string

	if b.systemSpec.Repo != "" {
		toBuild[b.systemSpec.Repo] = struct{}{}
		var err error
		toProcess, err = listRegoFilesRecursive(b.systemSpec.Repo)
		if err != nil {
			return err
		}
	}

	// Add the files unconditionally to the build list.
	for _, spec := range b.fileSpecs {
		toBuild[spec.Path] = struct{}{}
		files, err := listRegoFilesRecursive(spec.Path)
		if err != nil {
			return err
		}

		toProcess = append(toProcess, files...)
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

			// If the extra files were to be added conditionally, check for matching here.
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
	result.Data = map[string]interface{}{}

	for _, srcDir := range sortedSrcs {
		err := filepath.Walk(srcDir, func(path string, fi os.FileInfo, err error) error {
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
					Path: strings.TrimPrefix(path, srcDir),
					Raw:  bs,
				})

			} else if filepath.Ext(path) == ".json" {
				var value map[string]interface{}
				err := json.Unmarshal(bs, &value)
				if err != nil {
					return err
				}

				path = strings.TrimPrefix(path, srcDir)
				dirpath := strings.TrimLeft(filepath.ToSlash(filepath.Dir(path)), "/.")

				var key []string
				if dirpath != "" {
					key = strings.Split(dirpath, "/")
				}

				if len(key) == 0 {
					// TODO: Not able to merge root and non-root data. Is that ever allowed in bundles?
					result.Data = value
					return nil
				}

				m := result.Data

				for i := 0; i < len(key); i++ {
					last := i == len(key)-1

					if last {
						m[key[i]] = value
						break
					}

					var n map[string]interface{}
					x, ok := m[key[i]]
					if !ok {
						n = make(map[string]interface{})
						m[key[i]] = n
					} else {
						n, ok = x.(map[string]interface{})
						if !ok {
							n = make(map[string]interface{})
							m[key[i]] = n
						}
					}

					m = n
				}
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
