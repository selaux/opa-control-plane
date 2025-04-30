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
	"github.com/tsandall/lighthouse/internal/s3"
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

	systems, err := s.listSystemsWithGitCredentials()
	if err != nil {
		log.Println("error listing systems:", err)
	}

	libraries, err := s.listLibrariesWithGitCredentials()
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

		systemRepoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name))
		ss := &builder.SystemSpec{
			Repo: systemRepoDir,
		}

		syncs := []*gitsync.Synchronizer{
			gitsync.New(systemRepoDir, system.Git),
		}

		ls := make([]*builder.LibrarySpec, len(libraries))
		for i := range libraries {
			libRepoDir := path.Join(s.persistenceDir, "repos", md5sum(system.Name+"@"+libraries[i].Name))
			ls[i] = &builder.LibrarySpec{Repo: libRepoDir}
			syncs = append(syncs, gitsync.New(libRepoDir, libraries[i].Git))
		}

		storage, err := s3.New(ctx, system.ObjectStorage)
		if err != nil {
			log.Println("error creating object storage client:", err)
			continue
		}

		w := NewSystemWorker(system, libraries).
			WithSystem(ss).
			WithLibraries(ls).
			WithSynchronizers(syncs).
			WithStorage(storage)
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

	if err := s.loadLibraries(root); err != nil {
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
		systems.s3url,
		systems.s3region,
		systems.s3bucket,
		systems.s3key,
        secrets.id AS secret_id,
		systems_secrets.ref_type as secret_ref_type,
        secrets.value AS secret_value
    FROM
        systems
    LEFT JOIN
        systems_secrets ON systems.id = systems_secrets.system_id
    LEFT JOIN
        secrets ON systems_secrets.secret_id = secrets.id
	WHERE systems_secrets.ref_type = 'git_credentials' OR systems_secrets.ref_type IS NULL OR systems_secrets.ref_type = 'aws'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	systemMap := make(map[string]*config.System)

	for rows.Next() {
		var systemId, repo string
		var secretId, secretRefType, secretValue *string
		var ref, gitCommit, path *string
		var s3url, s3region, s3bucket, s3key *string
		if err := rows.Scan(&systemId, &repo, &ref, &gitCommit, &path, &s3url, &s3region, &s3bucket, &s3key, &secretId, &secretRefType, &secretValue); err != nil {
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
			systemMap[systemId] = system

			if ref != nil {
				system.Git.Reference = ref
			}
			if gitCommit != nil {
				system.Git.Commit = gitCommit
			}
			if path != nil {
				system.Git.Path = path
			}

			if s3region != nil && s3bucket != nil && s3key != nil {
				system.ObjectStorage.AmazonS3 = &config.AmazonS3{
					Region: *s3region,
					Bucket: *s3bucket,
					Key:    *s3key,
				}
				if s3url != nil {
					system.ObjectStorage.AmazonS3.URL = *s3url
				}
			}
		}

		if secretId != nil {
			s := config.Secret{Name: *secretId}
			if err := json.Unmarshal([]byte(*secretValue), &s.Value); err != nil {
				return nil, err
			}

			switch *secretRefType {
			case "git_credentials":
				system.Git.Credentials = s.Ref()
			case "aws":
				if system.ObjectStorage.AmazonS3 != nil {
					system.ObjectStorage.AmazonS3.Credentials = s.Ref()
				}
			}
		}
	}

	var systems []*config.System
	for _, system := range systemMap {
		systems = append(systems, system)
	}

	return systems, nil
}

func (s *Service) listLibrariesWithGitCredentials() ([]*config.Library, error) {
	rows, err := s.db.Query(`SELECT
	libraries.id AS library_id,
	libraries.repo,
	libraries.ref,
	libraries.gitcommit,
	libraries.path,
	secrets.id AS secret_id,
	libraries_secrets.ref_type as secret_ref_type,
	secrets.value AS secret_value
FROM
	libraries
LEFT JOIN
	libraries_secrets ON libraries.id = libraries_secrets.library_id
LEFT JOIN
	secrets ON libraries_secrets.secret_id = secrets.id
WHERE libraries_secrets.ref_type = 'git_credentials'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	libraryMap := make(map[string]*config.Library)

	for rows.Next() {
		var libraryId, repo, secretId, secretRefType, secretValue string
		var ref, gitCommit, path *string
		if err := rows.Scan(&libraryId, &repo, &ref, &gitCommit, &path, &secretId, &secretRefType, &secretValue); err != nil {
			return nil, err
		}

		library, exists := libraryMap[libraryId]
		if !exists {
			library = &config.Library{
				Name: libraryId,
				Git: config.Git{
					Repo: repo,
				},
			}
			libraryMap[libraryId] = library

			if ref != nil {
				library.Git.Reference = ref
			}
			if gitCommit != nil {
				library.Git.Commit = gitCommit
			}
			if path != nil {
				library.Git.Path = path
			}
		}

		if secretId != "" {
			s := config.Secret{Name: secretId}
			if err := json.Unmarshal([]byte(secretValue), &s.Value); err != nil {
				return nil, err
			}

			switch secretRefType {
			case "git_credentials":
				library.Git.Credentials = s.Ref()
			}
		}
	}

	var libraries []*config.Library
	for _, library := range libraryMap {
		libraries = append(libraries, library)
	}

	return libraries, nil

}

func (s *Service) loadSystems(root *config.Root) error {

	var names []string
	for _, system := range root.Systems {
		names = append(names, system.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		system := root.Systems[name]
		var s3url, s3region, s3bucket, s3key string
		if system.ObjectStorage.AmazonS3 != nil {
			s3url = system.ObjectStorage.AmazonS3.URL
			s3region = system.ObjectStorage.AmazonS3.Region
			s3bucket = system.ObjectStorage.AmazonS3.Bucket
			s3key = system.ObjectStorage.AmazonS3.Key
		}
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO systems (id, repo, ref, gitcommit, path, s3url, s3region, s3bucket, s3key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			system.Name, system.Git.Repo, system.Git.Reference, system.Git.Commit, system.Git.Path, s3url, s3region, s3bucket, s3key); err != nil {
			return err
		}

		if system.Git.Credentials != nil {
			s.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, ref_type) VALUES (?, ?, ?)`, system.Name, system.Git.Credentials.Name, "git_credentials")
		}

		if system.ObjectStorage.AmazonS3 != nil {
			if system.ObjectStorage.AmazonS3.Credentials != nil {
				s.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, ref_type) VALUES (?, ?, ?)`, system.Name, system.ObjectStorage.AmazonS3.Credentials.Name, "aws")
			}
		}
	}

	return nil
}

func (s *Service) loadLibraries(root *config.Root) error {

	var names []string
	for _, library := range root.Libraries {
		names = append(names, library.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		library := root.Libraries[name]
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO libraries (id, repo, ref, gitcommit, path) VALUES (?, ?, ?, ?, ?)`, library.Name, library.Git.Repo, library.Git.Reference, library.Git.Commit, library.Git.Path); err != nil {
			return err
		}

		if library.Git.Credentials != nil {
			s.db.Exec(`INSERT OR REPLACE INTO libraries_secrets (library_id, secret_id, ref_type) VALUES (?, ?, ?)`, library.Name, library.Git.Credentials.Name, "git_credentials")
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
			path TEXT,
			s3url TEXT,
			s3region TEXT,
			s3bucket TEXT,
			s3key TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS libraries (
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
		`CREATE TABLE IF NOT EXISTS libraries_secrets (
			library_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			ref_type TEXT NOT NULL,
			PRIMARY KEY (library_id, secret_id),
			FOREIGN KEY (library_id) REFERENCES libraries(id),
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
