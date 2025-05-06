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
	database       Database
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

func (s *Service) Database() *Database {
	return &s.database
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.database.InitDB(s.persistenceDir); err != nil {
		return err
	}
	defer s.database.CloseDB()

	if err := s.database.loadConfig(ctx, s.configFile); err != nil {
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

	systems, err := s.database.listSystemsWithGitCredentials()
	if err != nil {
		log.Println("error listing systems:", err)
	}

	libraries, err := s.database.listLibrariesWithGitCredentials()
	if err != nil {
		log.Println("error listing libraries:", err)
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
			w.UpdateConfig(nil, nil)
		}
	}

	// Start any new workers for systems that are in the current configuration but not yet running. Inform any existing workers of the current configuration, which
	// will cause them to shutdown if configuration has changed.

	for _, system := range systems {
		if w, ok := s.workers[system.Name]; ok {
			w.UpdateConfig(system, libraries)
			continue
		}

		log.Println("(re)starting worker for system:", system.Name)

		ss := &builder.SystemSpec{}

		systemFileDir := path.Join(s.persistenceDir, "files", md5sum(system.Name))
		fs := []*builder.FileSpec{{Path: systemFileDir}}

		syncs := []Synchronizer{
			sqlsync.NewSQLDataSynchronizer(systemFileDir, s.database.db, "systems_data", "system_id", system.Name),
		}

		if system.Git.Repo != "" {
			ss.Repo = path.Join(s.persistenceDir, "repos", md5sum(system.Name))
			syncs = append(syncs, gitsync.New(ss.Repo, system.Git))
		}

		for _, datasource := range system.Datasources {
			switch datasource.Type {
			case "http":
				url, _ := datasource.Config["url"].(string)
				syncs = append(syncs, httpsync.New(path.Join(systemFileDir, datasource.Path, "data.json"), url))
			}
		}

		var ls []*builder.LibrarySpec
		for _, l := range libraries {
			if l.Git.Repo != "" {
				libRepoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name+"@"+l.Name))
				ls = append(ls, &builder.LibrarySpec{Repo: libRepoDir})
				syncs = append(syncs, gitsync.New(libRepoDir, l.Git))
			}

			for _, datasource := range l.Datasources {
				switch datasource.Type {
				case "http":
					url, _ := datasource.Config["url"].(string)
					syncs = append(syncs, httpsync.New(path.Join(systemFileDir, datasource.Path, "data.json"), url))
				}
			}

			libFileDir := path.Join(s.persistenceDir, "files", md5sum(system.Name)+"@"+l.Name)
			syncs = append(syncs, sqlsync.NewSQLDataSynchronizer(libFileDir, s.database.db, "libraries_data", "library_id", l.Name))
			fs = append(fs, &builder.FileSpec{Path: libFileDir})
		}

		storage, err := s3.New(ctx, system.ObjectStorage)
		if err != nil {
			log.Println("error creating object storage client:", err)
			continue
		}

		w := NewSystemWorker(system, libraries).
			WithSystem(ss).
			WithLibraries(ls).
			WithFiles(fs).
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
