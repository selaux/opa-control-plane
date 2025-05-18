package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/tsandall/lighthouse/internal/config"
)

type LibrarySpec struct {
	Name    string
	Roots   []ast.Ref
	RepoDir string
	FileDir string
}

type SystemSpec struct {
	RepoDir      string
	FileDir      string
	Requirements []config.Requirement
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

	// NOTE(tsandall): if roots cannot be computed for any library then we will bail
	// this means that libraries must be syntactically valid when synched otherwise
	// all builds will stop.
	// TODO(tsandall): precompute if this becomes a bottleneck

	for i := range b.librarySpecs {
		if b.librarySpecs[i].Roots == nil {
			var err error
			// TODO(tsandall): add support for lib datasources here; need to include their roots)
			dirs := []string{}
			if b.librarySpecs[i].FileDir != "" {
				dirs = append(dirs, b.librarySpecs[i].FileDir)
			}
			if b.librarySpecs[i].RepoDir != "" {
				dirs = append(dirs, b.librarySpecs[i].RepoDir)
			}
			b.librarySpecs[i].Roots, err = getRootsForRepo(dirs...)
			if err != nil {
				return fmt.Errorf("failed to get library roots: %w", err)
			}
		}
	}

	toBuild := map[string]struct{}{} // set of paths to include in bundle
	var toAnalyze []string           // set of paths to analyze for depedencies

	if b.systemSpec.RepoDir != "" {
		toBuild[b.systemSpec.RepoDir] = struct{}{}
		files, err := listRegoFilesRecursive(b.systemSpec.RepoDir)
		if err != nil {
			return fmt.Errorf("failed to list system repo: %w", err)
		}
		toAnalyze = append(toAnalyze, files...)
	}

	if b.systemSpec.FileDir != "" {
		toBuild[b.systemSpec.FileDir] = struct{}{}
		files, err := listRegoFilesRecursive(b.systemSpec.FileDir)
		if err != nil {
			return fmt.Errorf("failed to list system files: %w", err)
		}
		toAnalyze = append(toAnalyze, files...)
	}

	addedLibs := map[*LibrarySpec]struct{}{}

	// closure to add libraries into build that is reused for adding
	// requirements and system/namespace dependencies to build and analysis set
	addLibToBuild := func(l *LibrarySpec) error {
		if l.RepoDir != "" {
			toBuild[l.RepoDir] = struct{}{}
			files, err := listRegoFilesRecursive(l.RepoDir)
			if err != nil {
				return err
			}
			toAnalyze = append(toAnalyze, files...)
		}
		if l.FileDir != "" {
			toBuild[l.FileDir] = struct{}{}
			files, err := listRegoFilesRecursive(l.FileDir)
			if err != nil {
				return err
			}
			toAnalyze = append(toAnalyze, files...)
		}
		addedLibs[l] = struct{}{}
		return nil
	}

	for _, req := range b.systemSpec.Requirements {
		if req.Library != nil {
			for _, l := range b.librarySpecs {
				if err := addLibToBuild(l); err != nil {
					return err
				}
			}
		}
	}

	for len(toAnalyze) > 0 {
		var next string
		next, toAnalyze = toAnalyze[0], toAnalyze[1:]
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

			// only data refs can introduce library dependencies so skip
			// everything else (e.g., input.foo, f(x)[_], etc.) but be sure to
			// continue recursing so we visit all nodes.
			p := r.ConstantPrefix()
			if !p.HasPrefix(ast.DefaultRootRef) {
				return false
			}

			for _, l := range b.librarySpecs {
				if _, ok := addedLibs[l]; ok {
					continue
				}
				for _, root := range l.Roots {
					if root.HasPrefix(p) || p.HasPrefix(root) {
						if err := addLibToBuild(l); err != nil {
							errInner = err
						}
						break
					}
				}
			}

			// If the extra files were to be added conditionally, check for matching here.
			return false
		})

		if errInner != nil {
			return err
		}
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
				var value interface{}
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
					valueAsMap, ok := value.(map[string]interface{})
					if !ok {
						return fmt.Errorf("expected root data document to be object (got %T)", value)
					}
					result.Data = valueAsMap
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

func getRootsForRepo(dirs ...string) ([]ast.Ref, error) {
	set := ast.NewSet()

	for _, dir := range dirs {

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

		if err != nil {
			return nil, err
		}
	}

	sl := set.Slice()
	result := make([]ast.Ref, len(sl))
	for i := range sl {
		result[i] = sl[i].Value.(ast.Ref)
	}

	return result, nil
}
