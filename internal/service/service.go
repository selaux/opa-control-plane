package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"io/fs"
	"log"
	"path"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/builtinsync"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/database"
	"github.com/tsandall/lighthouse/internal/gitsync"
	"github.com/tsandall/lighthouse/internal/httpsync"
	"github.com/tsandall/lighthouse/internal/pool"
	"github.com/tsandall/lighthouse/internal/s3"
	"github.com/tsandall/lighthouse/internal/sqlsync"
)

const reconfigurationInterval = 15 * time.Second

type Service struct {
	config         []byte
	persistenceDir string
	pool           *pool.Pool
	workers        map[string]*SystemWorker
	database       database.Database
	builtinFS      fs.FS
	singleShot     bool
}

func New() *Service {
	return &Service{
		pool:    pool.New(10),
		workers: make(map[string]*SystemWorker),
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

func (s *Service) Run(ctx context.Context) error {

	if err := s.database.InitDB(ctx, s.persistenceDir); err != nil {
		return err
	}
	defer s.database.CloseDB()

	if err := s.database.LoadConfig(ctx, s.config); err != nil {
		return err
	}

	// Launch new workers for new systems and systems with updated configuration until it is time to shutdown.

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

	systems, err := s.database.ListSystemsWithGitCredentials()
	if err != nil {
		log.Println("error listing systems:", err)
		return
	}

	libraries, err := s.database.ListLibrariesWithGitCredentials()
	if err != nil {
		log.Println("error listing libraries:", err)
		return
	}

	stacks, err := s.database.ListStacks()
	if err != nil {
		log.Println("error listing stacks:", err)
		return
	}

	activeSystems := make(map[string]struct{})
	for _, system := range systems {
		activeSystems[system.Name] = struct{}{}
	}

	// Remove any worker already shutdown from bookkeeping, as well as initiate shutdown for any system (worker) not in the current configuration.
	for id, w := range s.workers {
		if w.Done() {
			delete(s.workers, id)
			continue
		}

		if _, ok := activeSystems[id]; !ok {
			w.UpdateConfig(nil, nil, nil)
		}
	}

	// Start any new workers for systems that are in the current configuration but not yet running. Inform any existing
	// workers of the current configuration, which will cause them to shutdown if configuration has changed.
	//
	// For each system, create the following directory structure under persistencyDir for the builder to use
	// when constructing bundles:
	//
	// persistenceDir/
	// └── {md5(system.Name)}/
	//     ├── database/                  # System-specific files from SQL database
	//     ├── datasources/               # System-specific HTTP datasources
	//     ├── repo/                      # System git repository
	//     └── libraries/
	//         └── {library.Name}/
	//             ├── builtin/           # Built-in library specific files
	//             ├── database/          # Library-specific files from SQL database
	//             ├── datasources/       # Library-specific HTTP datasources
	//             └── repo/              # Library git repository

	for _, system := range systems {
		if w, ok := s.workers[system.Name]; ok {
			w.UpdateConfig(system, libraries, stacks)
			continue
		}

		log.Println("(re)starting worker for system:", system.Name)

		syncs := []Synchronizer{}
		sources := []*builder.Source{}

		systemDir := path.Join(s.persistenceDir, md5sum(system.Name))

		src := newSource(system.Name).
			SyncSystemSQL(&syncs, system.Name, &s.database, path.Join(systemDir, "database")).
			SyncDatasources(&syncs, system.Datasources, path.Join(systemDir, "datasources")).
			SyncGit(&syncs, system.Git, path.Join(systemDir, "repo")).
			AddRequirements(system.Requirements)

		for _, stack := range stacks {
			if stack.Selector.Matches(system.Labels) {
				src = src.AddRequirements(stack.Requirements)
			}
		}

		sources = append(sources, &src.Source)

		for _, l := range libraries {
			libraryDir := path.Join(systemDir, "libraries", l.Name)

			src := newSource(l.Name).
				SyncBuiltin(&syncs, l.Builtin, s.builtinFS, path.Join(libraryDir, "builtin")).
				SyncLibrarySQL(&syncs, l.Name, &s.database, path.Join(libraryDir, "database")).
				SyncDatasources(&syncs, l.Datasources, path.Join(libraryDir, "datasources")).
				SyncGit(&syncs, l.Git, path.Join(libraryDir, "repo")).
				AddRequirements(l.Requirements)

			sources = append(sources, &src.Source)
		}

		storage, err := s3.New(ctx, system.ObjectStorage)
		if err != nil {
			log.Println("error creating object storage client:", err)
			continue
		}

		w := NewSystemWorker(system, libraries, stacks).
			WithSources(sources).
			WithSynchronizers(syncs).
			WithStorage(storage).
			WithSingleShot(s.singleShot)
		s.pool.Add(w.Execute)

		s.workers[system.Name] = w
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

func (src *source) addDir(dir string, wipe bool) {
	src.Source.Dirs = append(src.Source.Dirs, builder.Dir{
		Path: dir,
		Wipe: wipe,
	})
}

func (src *source) SyncGit(syncs *[]Synchronizer, git config.Git, repoDir string) *source {
	if git.Repo != "" {
		srcDir := repoDir
		if git.Path != nil {
			srcDir = path.Join(srcDir, *git.Path)
		}
		src.addDir(srcDir, false)
		*syncs = append(*syncs, gitsync.New(repoDir, git))
	}

	return src
}

func (src *source) SyncBuiltin(syncs *[]Synchronizer, builtin *string, fs fs.FS, dir string) *source {
	if builtin != nil {
		src.addDir(dir, true)
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
	}
	if len(datasources) > 0 {
		src.addDir(dir, true)
	}
	return src
}

func (src *source) SyncSystemSQL(syncs *[]Synchronizer, name string, database *database.Database, dir string) *source {
	*syncs = append(*syncs, sqlsync.NewSQLSystemDataSynchronizer(dir, database, name))
	src.addDir(dir, true)
	return src
}

func (src *source) SyncLibrarySQL(syncs *[]Synchronizer, name string, database *database.Database, dir string) *source {
	*syncs = append(*syncs, sqlsync.NewSQLLibraryDataSynchronizer(dir, database, name))
	src.addDir(dir, true)
	return src
}

func (src *source) AddRequirements(requirements []config.Requirement) *source {
	for _, r := range requirements {
		if r.Library != nil {
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
