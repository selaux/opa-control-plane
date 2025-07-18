package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/styrainc/lighthouse/internal/builder"
	"github.com/styrainc/lighthouse/internal/builtinsync"
	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/database"
	"github.com/styrainc/lighthouse/internal/gitsync"
	"github.com/styrainc/lighthouse/internal/httpsync"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/internal/pool"
	"github.com/styrainc/lighthouse/internal/progress"
	"github.com/styrainc/lighthouse/internal/s3"
	"github.com/styrainc/lighthouse/internal/sqlsync"
	_ "modernc.org/sqlite"
)

const internalPrincipal = "internal"
const reconfigurationInterval = 15 * time.Second

type Service struct {
	config         *config.Root
	persistenceDir string
	pool           *pool.Pool
	workers        map[string]*BundleWorker
	database       database.Database
	builtinFS      fs.FS
	singleShot     bool
	report         *Report
	log            *logging.Logger
	noninteractive bool
}

type Report struct {
	Bundles map[string]Status
}

type BuildState int

const (
	BuildStateInternalError BuildState = iota
	BuildStateSuccess
	BuildStateSyncFailed
	BuildStateTransformFailed
	BuildStateBuildFailed
	BuildStatePushFailed
)

func (s BuildState) String() string {
	switch s {
	case BuildStateSuccess:
		return "SUCCESS"
	case BuildStateSyncFailed:
		return "SYNC_FAILED"
	case BuildStateTransformFailed:
		return "TRANSFORM_FAILED"
	case BuildStateBuildFailed:
		return "BUILD_FAILED"
	case BuildStatePushFailed:
		return "PUSH_FAILED"
	case BuildStateInternalError:
		fallthrough
	default:
		return "INTERNAL_ERROR"
	}
}

type Status struct {
	State   BuildState
	Message string
}

func New() *Service {
	return &Service{
		pool:           pool.New(10),
		workers:        make(map[string]*BundleWorker),
		noninteractive: true,
	}
}

func (s *Service) WithPersistenceDir(d string) *Service {
	s.persistenceDir = d
	return s
}

func (s *Service) WithConfig(config *config.Root) *Service {
	s.config = config
	s.database = *s.database.WithConfig(config.Database)
	return s
}

func (s *Service) WithBuiltinFS(fs fs.FS) *Service {
	s.builtinFS = fs
	return s
}

func (s *Service) WithSingleShot(singleShot bool) *Service {
	s.singleShot = singleShot
	return s
}

func (s *Service) Database() *database.Database {
	return &s.database
}

func (s *Service) WithLogger(logger *logging.Logger) *Service {
	s.log = logger
	s.database = *s.database.WithLogger(logger)
	return s
}

func (s *Service) WithNoninteractive(yes bool) *Service {
	s.noninteractive = yes
	return s
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.initDB(ctx); err != nil {
		return err
	}

	defer s.database.CloseDB()

	// Launch new workers for new bundles and bundles with updated configuration until it is time to shutdown.

shutdown:
	for {
		s.launchWorkers(ctx)

		for s.singleShot {
			if s.allWorkersDone() {
				break shutdown
			}

			time.Sleep(100 * time.Millisecond)
		}

		select {
		case <-time.After(reconfigurationInterval):
		case <-ctx.Done():
			break shutdown
		}
	}

	for _, w := range s.workers {
		w.UpdateConfig(nil, nil, nil)
	}

	if s.singleShot {
		s.report = &Report{
			Bundles: make(map[string]Status, len(s.workers)),
		}
		for _, w := range s.workers {
			s.report.Bundles[w.bundleConfig.Name] = w.status
		}
	}

	return nil

}

func (s *Service) Report() *Report {
	return s.report
}

func (s *Service) initDB(ctx context.Context) error {
	bar := progress.New(s.noninteractive, -1, "loading configuration")
	defer bar.Finish()

	if err := s.database.InitDB(ctx); err != nil {
		return err
	}

	if err := s.database.UpsertPrincipal(ctx, database.Principal{Id: internalPrincipal, Role: "administrator"}); err != nil {
		return err
	}

	if err := s.database.LoadConfig(ctx, bar, internalPrincipal, s.config); err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	return nil
}

func (s *Service) launchWorkers(ctx context.Context) {

	bundles, _, err := s.database.ListBundles(ctx, internalPrincipal, database.ListOptions{})
	if err != nil {
		s.log.Errorf("error listing bundles: %s", err.Error())
		return
	}

	sourceDefs, _, err := s.database.ListSources(ctx, internalPrincipal, database.ListOptions{})
	if err != nil {
		s.log.Errorf("error listing sources: %s", err.Error())
		return
	}

	sourceDefsByName := make(map[string]*config.Source)
	for _, src := range sourceDefs {
		sourceDefsByName[src.Name] = src
	}

	stacks, _, err := s.database.ListStacks(ctx, internalPrincipal, database.ListOptions{})
	if err != nil {
		s.log.Errorf("error listing stacks: %s", err.Error())
		return
	}

	activeBundles := make(map[string]struct{})
	for _, b := range bundles {
		activeBundles[b.Name] = struct{}{}
	}

	// Remove any worker already shutdown from bookkeeping, as well as initiate shutdown for any bundle (worker) not in the current configuration.
	for id, w := range s.workers {
		if w.Done() {
			delete(s.workers, id)
			continue
		}

		if _, ok := activeBundles[id]; !ok {
			w.UpdateConfig(nil, nil, nil)
		}
	}

	// Start any new workers for bundles that are in the current configuration but not yet running. Inform any existing
	// workers of the current configuration, which will cause them to shutdown if configuration has changed.
	//
	// For each bundle, create the following directory structure under persistencyDir for the builder to use
	// when constructing bundles:
	//
	// persistenceDir/
	// └── {md5(bundle.Name)}/
	//     └── sources/
	//         └── {source.Name}/
	//             ├── builtin/           # Built-in source specific files
	//             ├── database/          # Source-specific files from SQL database
	//             ├── datasources/       # Source-specific HTTP datasources
	//             └── repo/              # Source git repository

	bar := progress.New(s.noninteractive, len(bundles), "building and pushing bundles")

	for _, b := range bundles {
		if w, ok := s.workers[b.Name]; ok {
			w.UpdateConfig(b, sourceDefs, stacks)
			continue
		}

		s.log.Debugf("(re)starting worker for bundle: %s", b.Name)
		root := newSource(b.Name).AddRequirements(b.Requirements)

		for _, stack := range stacks {
			if stack.Selector.Matches(b.Labels) && !stack.ExcludeSelector.PtrMatches(b.Labels) {
				root = root.AddRequirements(stack.Requirements)
			}
		}

		syncs := []Synchronizer{}
		sources := []*builder.Source{&root.Source}
		bundleDir := path.Join(s.persistenceDir, md5sum(b.Name))

		for _, l := range getDeps(root.Requirements, sourceDefsByName) {
			srcDir := path.Join(bundleDir, "sources", l.Name)

			src := newSource(l.Name).
				SyncBuiltin(&syncs, l.Builtin, s.builtinFS, path.Join(srcDir, "builtin")).
				SyncSourceSQL(&syncs, l.Name, &s.database, path.Join(srcDir, "database")).
				SyncDatasources(&syncs, l.Datasources, path.Join(srcDir, "datasources")).
				SyncGit(&syncs, l.Name, l.Git, path.Join(srcDir, "repo")).
				AddRequirements(l.Requirements)

			sources = append(sources, &src.Source)
		}

		storage, err := s3.New(ctx, b.ObjectStorage)
		if err != nil {
			s.log.Errorf("error creating object storage client: %s", err.Error())
			continue
		}

		w := NewBundleWorker(bundleDir, b, sourceDefs, stacks, s.log, bar).
			WithSources(sources).
			WithSynchronizers(syncs).
			WithStorage(storage).
			WithSingleShot(s.singleShot)
		s.pool.Add(w.Execute)

		s.workers[b.Name] = w
	}
}

func (s *Service) allWorkersDone() bool {
	for _, worker := range s.workers {
		if !worker.Done() {
			return false
		}
	}
	return true
}

func getDeps(rs config.Requirements, byName map[string]*config.Source) []*config.Source {
	var result []*config.Source
	visited := make(map[string]struct{})
	for len(rs) > 0 {
		next, tail := rs[0], rs[1:]
		rs = tail
		if next.Source == nil {
			continue
		} else if _, ok := visited[*next.Source]; ok {
			continue
		} else if src, ok := byName[*next.Source]; !ok {
			continue
		} else {
			visited[*next.Source] = struct{}{}
			result = append(result, src)
			rs = append(rs, src.Requirements...)
		}
	}
	return result
}

type source struct {
	builder.Source
}

func newSource(name string) *source {
	return &source{
		Source: *builder.NewSource(name),
	}
}

func (src *source) addDir(dir string, wipe bool, includedFiles []string, excludedFiles []string) {
	src.Source.Dirs = append(src.Source.Dirs, builder.Dir{
		Path:          dir,
		Wipe:          wipe,
		IncludedFiles: includedFiles,
		ExcludedFiles: excludedFiles,
	})
}

func (src *source) SyncGit(syncs *[]Synchronizer, sourceName string, git config.Git, repoDir string) *source {
	if git.Repo != "" {
		srcDir := repoDir
		if git.Path != nil {
			srcDir = path.Join(srcDir, *git.Path)
		}
		src.addDir(srcDir, false, git.IncludedFiles, git.ExcludedFiles)
		*syncs = append(*syncs, gitsync.New(repoDir, git, sourceName))
	}

	return src
}

func (src *source) SyncBuiltin(syncs *[]Synchronizer, builtin *string, fs fs.FS, dir string) *source {
	if builtin != nil {
		src.addDir(dir, true, nil, nil)
		*syncs = append(*syncs, builtinsync.New(fs, dir, *builtin))
	}
	return src
}

func (src *source) SyncDatasources(syncs *[]Synchronizer, datasources []config.Datasource, dir string) *source {
	for _, datasource := range datasources {
		switch datasource.Type {
		case "http":
			url, _ := datasource.Config["url"].(string)
			credentials := datasource.Credentials
			*syncs = append(*syncs, httpsync.New(path.Join(dir, datasource.Path, "data.json"), url, credentials))
		}

		if datasource.TransformQuery != "" {
			src.Transforms = append(src.Transforms, builder.Transform{
				Query: datasource.TransformQuery,
				Path:  path.Join(dir, datasource.Path, "data.json"),
			})
		}
	}
	if len(datasources) > 0 {
		src.addDir(dir, true, nil, nil)
	}
	return src
}

func (src *source) SyncSourceSQL(syncs *[]Synchronizer, name string, database *database.Database, dir string) *source {
	*syncs = append(*syncs, sqlsync.NewSQLSourceDataSynchronizer(dir, database, name))
	src.addDir(dir, true, nil, nil)
	return src
}

func (src *source) AddRequirements(requirements []config.Requirement) *source {
	for _, r := range requirements {
		if r.Source != nil {
			src.Requirements = append(src.Requirements, r)
		}
	}
	return src
}

func md5sum(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
