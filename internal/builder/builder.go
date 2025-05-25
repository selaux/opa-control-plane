package builder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/tsandall/lighthouse/internal/config"
)

type Source struct {
	Name         string
	Dirs         []Dir
	Requirements []config.Requirement
}

type Dir struct {
	Path string // local fs path to source files
	Wipe bool   // bit indicates if worker should delete directory before synchronization
}

type Builder struct {
	sources []*Source
	output  io.Writer
}

func New() *Builder {
	return &Builder{}
}

func (b *Builder) WithOutput(w io.Writer) *Builder {
	b.output = w
	return b
}

func (b *Builder) WithSources(srcs []*Source) *Builder {
	b.sources = srcs
	return b
}

type PackageConflictErr struct {
	Requirement *Source
	Package     *ast.Package
	rootMap     map[string]*Source
	overlap     []ast.Ref
}

func (err *PackageConflictErr) Error() string {
	// TODO(tsandall): once mounts are available improve to suggest
	lines := []string{fmt.Sprintf("requirement %q contains conflicting %v", err.Requirement.Name, err.Package)}
	for i := range err.overlap {
		if src, ok := err.rootMap[err.overlap[i].String()]; ok {
			lines = append(lines, fmt.Sprintf("- %v from %q", &ast.Package{Path: err.overlap[i]}, src.Name))
		}
	}
	return strings.Join(lines, "\n")
}

func (b *Builder) Build(ctx context.Context) error {

	var existingRoots []ast.Ref
	toProcess := []*Source{b.sources[0]}
	toBuild := []Dir{}
	sourceMap := make(map[string]*Source)
	for _, src := range b.sources {
		sourceMap[src.Name] = src
	}

	processed := map[string]struct{}{}
	rootMap := map[string]*Source{}

	for len(toProcess) > 0 {
		var next *Source
		next, toProcess = toProcess[0], toProcess[1:]
		newRoots, err := getRegoAndJSONRootsForDirs(next.Dirs)
		if err != nil {
			return fmt.Errorf("%v: %w", next.Name, err)
		}
		for _, root := range newRoots {
			if overlap := rootsOverlap(existingRoots, root); len(overlap) > 0 {
				return &PackageConflictErr{
					Requirement: next,
					Package:     &ast.Package{Path: root},
					rootMap:     rootMap,
					overlap:     overlap,
				}
			}
			rootMap[root.String()] = next
		}
		existingRoots = append(existingRoots, newRoots...)
		toBuild = append(toBuild, next.Dirs...)
		for _, r := range next.Requirements {
			if r.Library != nil {
				src, ok := sourceMap[*r.Library]
				if !ok {
					return fmt.Errorf("missing library %q", *r.Library)
				}
				if _, ok := processed[src.Name]; !ok {
					toProcess = append(toProcess, src)
					processed[src.Name] = struct{}{}
				}
			}
		}
	}

	// NOTE(tsandall): we want control over the filenames in the emitted bundle
	// so that we don't include information about the filesystem where the build
	// ran... the upstream compile package doesn't provide this control at the
	// moment. Once upstream supports that control, we could replace this in
	// favour of the compile package which would give us support for
	// optimization levels, other targets, etc.
	var result bundle.Bundle
	result.Data = map[string]interface{}{}

	for _, srcDir := range toBuild {
		err := filepath.Walk(srcDir.Path, func(path string, fi os.FileInfo, err error) error {
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
					Path: strings.TrimPrefix(path, srcDir.Path),
					Raw:  bs,
				})

			} else if filepath.Ext(path) == ".json" {
				// Merge JSON files in, assuming their paths do not conflict. If conflict, the last one wins.
				var value interface{}
				err := json.Unmarshal(bs, &value)
				if err != nil {
					return err
				}

				path = strings.TrimPrefix(path, srcDir.Path)
				dirpath := strings.TrimLeft(filepath.ToSlash(filepath.Dir(path)), "/.")

				var key []string
				if dirpath != "" {
					key = strings.Split(dirpath, "/")
				}

				if len(key) == 0 {
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

func walkFilesRecursive(root string, suffix string, fn func(path string, fi os.FileInfo) error) error {
	return filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(path) != suffix {
			return nil
		}
		return fn(path, fi)
	})
}

// getRegoAndJSONRootsForDirs returns the set of roots for the given directories. The
// returned roots are the package paths for rego files and the directories
// holding the JSON files.
func getRegoAndJSONRootsForDirs(dirs []Dir) ([]ast.Ref, error) {
	set := ast.NewSet()

	for _, dir := range dirs {

		err := walkFilesRecursive(dir.Path, ".rego", func(path string, _ os.FileInfo) error {

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

		err = walkFilesRecursive(dir.Path, ".json", func(path string, _ os.FileInfo) error {

			path, err := filepath.Rel(dir.Path, path)
			if err != nil {
				return err
			}

			path = filepath.ToSlash(filepath.Dir(path))

			var keys []*ast.Term
			for path != "" && path != "." {
				dir := filepath.Base(path)
				path = filepath.Dir(path)
				keys = append([]*ast.Term{ast.StringTerm(dir)}, keys...)
			}

			keys = append([]*ast.Term{ast.DefaultRootDocument}, keys...)
			set.Add(ast.RefTerm(keys...))
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

func rootsOverlap(roots []ast.Ref, root ast.Ref) (result []ast.Ref) {
	for _, other := range roots {
		if other.HasPrefix(root) || root.HasPrefix(other) {
			result = append(result, other)
		}
	}
	return result
}
