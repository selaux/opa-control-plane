package service

import (
	"context"
	"database/sql"
	"log"
	"path"
	"sort"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/config"
)

type Service struct {
	configFile     string
	persistenceDir string
	resetDb        bool
	db             *sql.DB
}

func New() *Service {
	return &Service{}
}

func (s *Service) WithPersistenceDir(d string) *Service {
	s.persistenceDir = d
	return s
}

func (s *Service) WithConfigFile(configFile string) *Service {
	s.configFile = configFile
	return s
}

func (s *Service) WithResetDb(resetDb bool) *Service {
	s.resetDb = resetDb
	return s
}

func (s *Service) Run(ctx context.Context) error {

	var err error
	s.db, err = sql.Open("sqlite3", path.Join(s.persistenceDir, "sqlite.db"))
	if err != nil {
		return err
	}

	defer s.db.Close()

	s.initDb()

	if err := s.loadConfig(ctx); err != nil {
		return err
	}

	_ = <-ctx.Done()

	return nil
}

func (s *Service) loadConfig(_ context.Context) error {

	root, warnings, err := config.ParseFile(s.configFile)
	if err != nil {
		return err
	}

	// TODO(tsandall): make default behaviour treat warnings as errors
	for _, warning := range warnings {
		log.Println("warning:", warning)
	}

	s.loadSystems(root)

	return nil
}

func (s *Service) loadSystems(root *config.Root) {

	var names []string
	for _, system := range root.Systems {
		names = append(names, system.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		system := root.Systems[name]
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO systems (id, repo, ref, gitcommit, path) VALUES (?, ?, ?, ?, ?)`, system.Name, system.Git.Repo, system.Git.Reference, system.Git.Commit, system.Git.Path); err != nil {
			log.Fatal(err)
		}
	}
}

func (s *Service) initDb() {

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS systems (
			id TEXT PRIMARY KEY,
			repo TEXT NOT NULL,
			ref TEXT,
			gitcommit TEXT,
			path TEXT
		);`,
	}

	for _, stmt := range stmts {
		_, err := s.db.Exec(stmt)
		if err != nil {
			log.Fatal(err)
		}
	}
}
