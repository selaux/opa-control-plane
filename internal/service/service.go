package service

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"log"
	"path"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/database"
	"github.com/tsandall/lighthouse/internal/gitsync"
	"github.com/tsandall/lighthouse/internal/httpsync"
	"github.com/tsandall/lighthouse/internal/pool"
	"github.com/tsandall/lighthouse/internal/s3"
	"github.com/tsandall/lighthouse/internal/sqlsync"
)

const reconfigurationInterval = 15 * time.Second

type Service struct {
	configFile     string
	persistenceDir string
	pool           *pool.Pool
	workers        map[string]*SystemWorker
	database       database.Database
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

func (s *Service) WithConfigFile(configFile string) *Service {
	s.configFile = configFile
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

	if err := s.database.LoadConfig(ctx, s.configFile); err != nil {
		return err
	}

	// Launch new workers for new systems and systems with updated configuration until it is time to shutdown.

shutdown:
	for {
		s.launchWorkers(ctx)

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

	// Start any new workers for systems that are in the current configuration but not yet running. Inform any existing workers of the current configuration, which
	// will cause them to shutdown if configuration has changed.

	for _, system := range systems {
		if w, ok := s.workers[system.Name]; ok {
			w.UpdateConfig(system, libraries, stacks)
			continue
		}

		log.Println("(re)starting worker for system:", system.Name)

		sources := []*builder.Source{
			{
				Name: system.Name,
				Dirs: []builder.Dir{{Path: path.Join(s.persistenceDir, "files", md5sum(system.Name)), Wipe: true}},
			},
		}

		syncs := []Synchronizer{
			sqlsync.NewSQLSystemDataSynchronizer(sources[0].Dirs[0].Path, &s.database, system.Name),
		}

		if system.Git.Repo != "" {
			repoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name))
			syncs = append(syncs, gitsync.New(repoDir, system.Git))
			srcDir := repoDir
			if system.Git.Path != nil {
				srcDir = path.Join(srcDir, *system.Git.Path)
			}
			sources[0].Dirs = append(sources[0].Dirs, builder.Dir{Path: srcDir})
		}

		for _, r := range system.Requirements {
			if r.Library != nil {
				sources[0].Requirements = append(sources[0].Requirements, r)
			}
		}

		for _, datasource := range system.Datasources {
			switch datasource.Type {
			case "http":
				url, _ := datasource.Config["url"].(string)
				credentials := datasource.Credentials
				syncs = append(syncs, httpsync.New(path.Join(sources[0].Dirs[0].Path, datasource.Path, "data.json"), url, credentials))
			}
		}

		for _, l := range libraries {

			src := &builder.Source{
				Name: l.Name,
				Dirs: []builder.Dir{{Path: path.Join(s.persistenceDir, "files", md5sum(system.Name+"@"+l.Name)), Wipe: true}},
			}

			if l.Git.Repo != "" {
				repoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name+"@"+l.Name))
				syncs = append(syncs, gitsync.New(repoDir, l.Git))
				srcDir := repoDir
				if l.Git.Path != nil {
					srcDir = path.Join(srcDir, *l.Git.Path)
				}
				src.Dirs = append(src.Dirs, builder.Dir{Path: srcDir})
			}

			for _, datasource := range l.Datasources {
				switch datasource.Type {
				case "http":
					url, _ := datasource.Config["url"].(string)
					credentials := datasource.Credentials
					syncs = append(syncs, httpsync.New(path.Join(src.Dirs[0].Path, datasource.Path, "data.json"), url, credentials))
				}
			}

			src.Requirements = append(src.Requirements, l.Requirements...)

			syncs = append(syncs, sqlsync.NewSQLLibraryDataSynchronizer(src.Dirs[0].Path, &s.database, l.Name))
			sources = append(sources, src)
		}

		for _, stack := range stacks {
			if stack.Selector.Matches(system.Labels) {
				sources[0].Requirements = append(sources[0].Requirements, stack.Requirements...)
			}
		}

		storage, err := s3.New(ctx, system.ObjectStorage)
		if err != nil {
			log.Println("error creating object storage client:", err)
			continue
		}

		w := NewSystemWorker(system, libraries, stacks).
			WithSources(sources).
			WithSynchronizers(syncs).
			WithStorage(storage)
		s.pool.Add(w.Execute)

		s.workers[system.Name] = w
	}
}

func md5sum(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
