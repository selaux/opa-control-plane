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

	// TODO: start a worker per system to process bundles

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

	if err := s.loadSecrets(root); err != nil {
		return err
	}

	if err := s.loadSystems(root); err != nil {
		return err
	}

	return nil
}

func (s *Service) loadSystems(root *config.Root) error {

	var names []string
	for _, system := range root.Systems {
		names = append(names, system.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		system := root.Systems[name]
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO systems (id, repo, ref, gitcommit, path) VALUES (?, ?, ?, ?, ?)`, system.Name, system.Git.Repo, system.Git.Reference, system.Git.Commit, system.Git.Path); err != nil {
			return err
		}

		if system.Git.Credentials.HTTP != nil {
			s.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, usage_type) VALUES (?, ?, ?)`, system.Name, system.Git.Credentials.HTTP, "http")
		}

		if system.Git.Credentials.SSHPassphrase != nil {
			s.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, usage_type) VALUES (?, ?, ?)`, system.Name, system.Git.Credentials.SSHPassphrase, "ssh_passphrase")
		}

		if system.Git.Credentials.SSHPrivateKey != nil {
			s.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, usage_type) VALUES (?, ?, ?)`, system.Name, system.Git.Credentials.SSHPrivateKey, "ssh_private_key")
		}
	}

	return nil
}

func (s *Service) loadSecrets(root *config.Root) error {

	var names []string
	for _, secret := range root.Secrets {
		names = append(names, secret.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		secret := root.Secrets[name]
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO secrets (id, value) VALUES (?, ?)`, secret.Name, secret.Value); err != nil {
			return err
		}
	}

	return nil
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
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			value TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS systems_secrets (
			system_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			usage_type TEXT NOT NULL,
			PRIMARY KEY (system_id, secret_id),
			FOREIGN KEY (system_id) REFERENCES systems(id),
			FOREIGN KEY (secret_id) REFERENCES secrets(id)
		);`,
	}

	for _, stmt := range stmts {
		_, err := s.db.Exec(stmt)
		if err != nil {
			log.Fatal(err)
		}
	}
}
