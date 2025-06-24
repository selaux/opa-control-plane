package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io/fs"
	"path"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/builtinsync"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/database"
	"github.com/tsandall/lighthouse/internal/gitsync"
	"github.com/tsandall/lighthouse/internal/httpsync"
	"github.com/tsandall/lighthouse/internal/logging"
	"github.com/tsandall/lighthouse/internal/pool"
	"github.com/tsandall/lighthouse/internal/s3"
	"github.com/tsandall/lighthouse/internal/sqlsync"
)

const internalPrincipal = "internal"
const reconfigurationInterval = 15 * time.Second

type Service struct {
	config         []byte
	persistenceDir string
	pool           *pool.Pool
	workers        map[string]*BundleWorker
	database       database.Database
	builtinFS      fs.FS
	singleShot     bool
	log            *logging.Logger
}

func New() *Service {
	return &Service{
		pool:    pool.New(10),
		workers: make(map[string]*BundleWorker),
	}
}

func (s *Service) WithPersistenceDir(d string) *Service {
	s.persistenceDir = d
	return s
}

func (s *Service) WithConfig(bs []byte) *Service {
	s.config = bs
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
	return s
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.database.InitDB(ctx, s.persistenceDir); err != nil {
		return err
	}

	if err := database.InsertPrincipal(ctx, &s.database, database.Principal{Id: internalPrincipal, Role: "administrator"}); err != nil {
		return err
	}

	defer s.database.CloseDB()

	if err := s.database.LoadConfig(ctx, s.config); err != nil {
		return err
	}

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

	return nil
}

func (s *Service) launchWorkers(ctx context.Context) {

	bundles, err := s.database.ListBundlesToBuild()
	if err != nil {
		s.log.Errorf("error listing bundles: %s", err.Error())
		return
	}

	sourceDefs, err := s.database.ListSourcesWithGitCredentials(ctx, internalPrincipal)
	if err != nil {
		s.log.Errorf("error listing sources: %s", err.Error())
		return
	}

	stacks, err := s.database.ListStacks()
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

	for _, b := range bundles {
		if w, ok := s.workers[b.Name]; ok {
			w.UpdateConfig(b, sourceDefs, stacks)
			continue
		}

		s.log.Debugf("(re)starting worker for bundle: %s", b.Name)

		syncs := []Synchronizer{}
		sources := []*builder.Source{}

		bundleDir := path.Join(s.persistenceDir, md5sum(b.Name))

		src := newSource(b.Name).AddRequirements(b.Requirements)

		for _, stack := range stacks {
			if stack.Selector.Matches(b.Labels) {
				src = src.AddRequirements(stack.Requirements)
			}
		}

		sources = append(sources, &src.Source)

		for _, l := range sourceDefs {
			srcDir := path.Join(bundleDir, "sources", l.Name)

			src := newSource(l.Name).
				SyncBuiltin(&syncs, l.Builtin, s.builtinFS, path.Join(srcDir, "builtin")).
				SyncSourceSQL(&syncs, l.Name, &s.database, path.Join(srcDir, "database")).
				SyncDatasources(&syncs, l.Datasources, path.Join(srcDir, "datasources")).
				SyncGit(&syncs, l.Git, path.Join(srcDir, "repo")).
				AddRequirements(l.Requirements)

			sources = append(sources, &src.Source)
		}

		storage, err := s3.New(ctx, b.ObjectStorage)
		if err != nil {
			s.log.Errorf("error creating object storage client: %s", err.Error())
			continue
		}

		w := NewBundleWorker(b, sourceDefs, stacks, s.log).
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

type source struct {
	builder.Source
}

func newSource(name string) *source {
	return &source{
		Source: *builder.NewSource(name),
	}
}

func (src *source) addDir(dir string, wipe bool, includedFiles []string) {
	src.Source.Dirs = append(src.Source.Dirs, builder.Dir{
		Path:          dir,
		Wipe:          wipe,
		IncludedFiles: includedFiles,
	})
}

func (src *source) SyncGit(syncs *[]Synchronizer, git config.Git, repoDir string) *source {
	if git.Repo != "" {
		srcDir := repoDir
		if git.Path != nil {
			srcDir = path.Join(srcDir, *git.Path)
		}
		src.addDir(srcDir, false, git.IncludedFiles)
		*syncs = append(*syncs, gitsync.New(repoDir, git))
	}

	return src
}

func (src *source) SyncBuiltin(syncs *[]Synchronizer, builtin *string, fs fs.FS, dir string) *source {
	if builtin != nil {
		src.addDir(dir, true, nil)
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
		src.addDir(dir, true, nil)
	}
	return src
}

func (src *source) SyncSourceSQL(syncs *[]Synchronizer, name string, database *database.Database, dir string) *source {
	*syncs = append(*syncs, sqlsync.NewSQLSourceDataSynchronizer(dir, database, name))
	src.addDir(dir, true, nil)
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
