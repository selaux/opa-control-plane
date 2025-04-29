package service

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"log"
	"path"
	"sort"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/gitsync"
	"github.com/tsandall/lighthouse/internal/pool"
)

type Service struct {
	configFile     string
	persistenceDir string
	db             *sql.DB
	pool           *pool.Pool
}

func New() *Service {
	return &Service{
		pool: pool.New(10),
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

	s.launchWorkers()

	_ = <-ctx.Done()

	return nil
}

func (s *Service) launchWorkers() {

	result, err := s.listSystemsWithGitCredentials()
	if err != nil {
		log.Println("error listing systems:", err)
	}

	for _, system := range result {
		systemRepoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name))
		ss := builder.SystemSpec{
			Repo: systemRepoDir,
		}
		syncs := []*gitsync.Synchronizer{
			gitsync.New(systemRepoDir, system.Git),
		}
		w := NewSystemWorker().WithSystem(&ss).WithSynchronizers(syncs)
		s.pool.Add(w.Execute)
	}
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
func (s *Service) listSystemsWithGitCredentials() ([]*config.System, error) {
	rows, err := s.db.Query(`SELECT
        systems.id AS system_id,
        systems.repo,
        systems.ref,
        systems.gitcommit,
        systems.path,
        secrets.id AS secret_id,
        secrets.value AS secret_value,
        systems_secrets.usage_type AS secret_usage_type
    FROM
        systems
    LEFT JOIN
        systems_secrets ON systems.id = systems_secrets.system_id
    LEFT JOIN
        secrets ON systems_secrets.secret_id = secrets.id
    ORDER BY
        systems.id, systems_secrets.usage_type;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	systemMap := make(map[string]*config.System)

	for rows.Next() {
		var systemID, repo, secretID, secretValue, usageType string
		var ref, gitCommit, path *string
		if err := rows.Scan(&systemID, &repo, &ref, &gitCommit, &path, &secretID, &secretValue, &usageType); err != nil {
			return nil, err
		}

		system, exists := systemMap[systemID]
		if !exists {
			system = &config.System{
				Name: systemID,
				Git: config.Git{
					Repo: repo,
				},
			}
			if ref != nil {
				system.Git.Reference = ref
			}
			if gitCommit != nil {
				system.Git.Commit = gitCommit
			}
			if path != nil {
				system.Git.Path = path
			}
			systemMap[systemID] = system
		}

		if secretID != "" && secretValue != "" {
			switch usageType {
			case "http":
				system.Git.Credentials.HTTP = &secretValue
			case "ssh_passphrase":
				system.Git.Credentials.SSHPassphrase = &secretValue
			case "ssh_private_key":
				system.Git.Credentials.SSHPrivateKey = &secretValue
			}
		}
	}

	var systems []*config.System
	for _, system := range systemMap {
		systems = append(systems, system)
	}

	return systems, nil
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

func md5sum(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}
