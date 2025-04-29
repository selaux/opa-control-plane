package service

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"path"
	"sort"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/gitsync"
	"github.com/tsandall/lighthouse/internal/pool"
)

const reconfigurationInterval = 15 * time.Second

type Service struct {
	configFile     string
	persistenceDir string
	db             *sql.DB
	pool           *pool.Pool
	workers        map[string]*SystemWorker
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

	// Launch new workers for new systems and systems with updated configuration until it is time to shutdown.

shutdown:
	for {
		s.launchWorkers()

		select {
		case <-time.After(reconfigurationInterval):
		case <-ctx.Done():
			break shutdown
		}
	}

	return nil
}

func (s *Service) launchWorkers() {

	result, err := s.listSystemsWithGitCredentials()
	if err != nil {
		log.Println("error listing systems:", err)
	}

	activeSystems := make(map[string]struct{})
	for _, system := range result {
		activeSystems[system.Name] = struct{}{}
	}

	// Remove any worker already shutdown from bookkeeping, as well as initiate shutdown for any system (worker) not in the current configuration.
	for id, w := range s.workers {
		if w.Done() {
			delete(s.workers, id)
			continue
		}

		if _, ok := activeSystems[id]; !ok {
			w.UpdateConfig(nil)
		}
	}

	// Start any new workers for systems that are in the current configuration but not yet running. Inform any existing workers of the current configuration, which
	// will cause them to shutdown if configuration has changed.

	for _, system := range result {
		if w, ok := s.workers[system.Name]; ok {
			w.UpdateConfig(system)
			continue
		}

		log.Println("(re)starting worker for system:", system.Name)

		systemRepoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name))
		ss := builder.SystemSpec{
			Repo: systemRepoDir,
		}
		syncs := []*gitsync.Synchronizer{
			gitsync.New(systemRepoDir, system.Git),
		}
		w := NewSystemWorker(system).WithSystem(&ss).WithSynchronizers(syncs)
		s.pool.Add(w.Execute)

		s.workers[system.Name] = w
	}

}

// loadConfig loads the configuration from the configuration file into the database.
func (s *Service) loadConfig(_ context.Context) error {

	root, err := config.ParseFile(s.configFile)
	if err != nil {
		return err
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
        secrets.value AS secret_value
    FROM
        systems
    LEFT JOIN
        systems_secrets ON systems.id = systems_secrets.system_id
    LEFT JOIN
        secrets ON systems_secrets.secret_id = secrets.id
	WHERE systems_secrets.ref_type = 'git_credentials'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	systemMap := make(map[string]*config.System)

	for rows.Next() {
		var systemId, repo, secretId, secretValue string
		var ref, gitCommit, path *string
		if err := rows.Scan(&systemId, &repo, &ref, &gitCommit, &path, &secretId, &secretValue); err != nil {
			return nil, err
		}

		system, exists := systemMap[systemId]
		if !exists {
			system = &config.System{
				Name: systemId,
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

			if secretId != "" {
				s := config.Secret{Name: secretId}
				if err := json.Unmarshal([]byte(secretValue), &s.Value); err != nil {
					return nil, err
				}
				system.Git.Credentials = s.Ref()
			}

			systemMap[systemId] = system
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

		if system.Git.Credentials != nil {
			s.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, ref_type) VALUES (?, ?, ?)`, system.Name, system.Git.Credentials.Name, "git_credentials")
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
		bs, err := json.Marshal(secret.Value)
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO secrets (id, value) VALUES (?, ?)`, secret.Name, string(bs)); err != nil {
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
			ref_type TEXT NOT NULL,
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
