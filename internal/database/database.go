package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql compatible driver for pgx
	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/aws"
	"github.com/tsandall/lighthouse/internal/config"
)

// Database implements the database operations. It will hide any differences between the varying SQL databases from the rest of the codebase.
type Database struct {
	db     *sql.DB
	config *config.Database
}

type Data struct {
	Path string
	Data []byte
}

func (d *Database) WithConfig(config *config.Database) *Database {
	d.config = config
	return d
}

func (d *Database) InitDB(ctx context.Context, persistenceDir string) error {
	switch {
	case d.config != nil && d.config.AWSRDS != nil:
		config := d.config.AWSRDS
		driver := config.Driver
		endpoint := config.Endpoint
		region := config.Region
		dbUser := config.DatabaseUser
		dbName := config.DatabaseName

		credentials := aws.NewSecretCredentialsProvider(d.config.AWSRDS.Credentials)
		authenticationToken, err := auth.BuildAuthToken(ctx, endpoint, region, dbUser, credentials)
		if err != nil {
			return err
		}

		dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?tls=true&allowCleartextPasswords=true", dbUser, authenticationToken, endpoint, dbName)
		d.db, err = sql.Open(driver, dsn)
		if err != nil {
			return err
		}

	case d.config == nil:
		// Default to SQLite3 if no config is provided.
		fallthrough
	case d.config != nil && d.config.SQL != nil && d.config.SQL.Driver == "sqlite3":
		err := os.MkdirAll(persistenceDir, 0755)
		if err != nil {
			return err
		}

		d.db, err = sql.Open("sqlite3", filepath.Join(persistenceDir, "sqlite.db"))
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported database connection type")
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS systems (
			id TEXT PRIMARY KEY,
			labels TEXT,
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
		`CREATE TABLE IF NOT EXISTS stacks (
			id TEXT PRIMARY KEY,
			selector TEXT NOT NULL
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
		`CREATE TABLE IF NOT EXISTS systems_data (
			system_id TEXT NOT NULL,
			path TEXT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (system_id, path),
			FOREIGN KEY (system_id) REFERENCES systems(id)
		);`,
		`CREATE TABLE IF NOT EXISTS systems_datasources (
			name TEXT NOT NULL,
			system_id TEXT NOT NULL,
			type TEXT NOT NULL,
			path TEXT NOT NULL,
			config TEXT NOT NULL,
			PRIMARY KEY (system_id, name),
			FOREIGN KEY (system_id) REFERENCES systems(id)
		);`,
		`CREATE TABLE IF NOT EXISTS systems_requirements (
			system_id TEXT NOT NULL,
			library_id TEXT NOT NULL,
			PRIMARY KEY (system_id, library_id),
			FOREIGN KEY (system_id) REFERENCES systems(id),
			FOREIGN KEY (library_id) REFERENCES libraries(id)
		);`,
		`CREATE TABLE IF NOT EXISTS stacks_requirements (
			stack_id TEXT NOT NULL,
			library_id TEXT NOT NULL,
			PRIMARY KEY (stack_id, library_id),
			FOREIGN KEY (stack_id) REFERENCES stacks(id),
			FOREIGN KEY (library_id) REFERENCES libraries(id)
		);`,
		`CREATE TABLE IF NOT EXISTS libraries_requirements (
			library_id TEXT NOT NULL,
			requirement_id TEXT NOT NULL,
			PRIMARY KEY (library_id, requirement_id),
			FOREIGN KEY (library_id) REFERENCES libraries(id),
			FOREIGN KEY (requirement_id) REFERENCES libraries(id)
		);`,
		`CREATE TABLE IF NOT EXISTS libraries_secrets (
			library_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			ref_type TEXT NOT NULL,
			PRIMARY KEY (library_id, secret_id),
			FOREIGN KEY (library_id) REFERENCES libraries(id),
			FOREIGN KEY (secret_id) REFERENCES secrets(id)
		);`,
		`CREATE TABLE IF NOT EXISTS libraries_data (
			library_id TEXT NOT NULL,
			path TEXT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (library_id, path),
			FOREIGN KEY (library_id) REFERENCES libraries(id)
		);`,
		`CREATE TABLE IF NOT EXISTS libraries_datasources (
			name TEXT NOT NULL,
			library_id TEXT NOT NULL,
			type TEXT NOT NULL,
			path TEXT NOT NULL,
			config TEXT NOT NULL,
			PRIMARY KEY (library_id, name),
			FOREIGN KEY (library_id) REFERENCES library(id)
		);`,
	}

	for _, stmt := range stmts {
		_, err := d.db.Exec(stmt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *Database) CloseDB() {
	d.db.Close()
}

func (d *Database) SystemsDataGet(ctx context.Context, systemId, path string) (interface{}, bool, error) {
	rows, err := d.db.Query(`SELECT
	data
FROM
	systems_data
WHERE system_id = ? AND path = ?`, systemId, path)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, false, nil
	}

	var bs []byte
	if err := rows.Scan(&bs); err != nil {
		return nil, false, err
	}

	var data interface{}
	if err := json.Unmarshal(bs, &data); err != nil {
		return nil, false, err
	}

	return data, true, nil
}

func (d *Database) SystemsDataPut(ctx context.Context, systemId, path string, data interface{}) error {
	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`INSERT OR REPLACE INTO systems_data (system_id, path, data) VALUES (?, ?, ?)`, systemId, path, bs)
	return err
}

func (d *Database) SystemsDataDelete(ctx context.Context, systemId, path string) error {
	_, err := d.db.Exec(`DELETE FROM systems_data WHERE system_id = ? AND path = ?`, systemId, path)
	return err
}

// LoadConfig loads the configuration from the configuration file into the database.
func (d *Database) LoadConfig(_ context.Context, configFile string) error {

	root, err := config.ParseFile(configFile)
	if err != nil {
		return err
	}

	if err := d.loadSecrets(root); err != nil {
		return err
	}

	if err := d.loadSystems(root); err != nil {
		return err
	}

	if err := d.loadLibraries(root); err != nil {
		return err
	}

	if err := d.loadStacks(root); err != nil {
		return err
	}

	return nil
}

func (d *Database) ListSystemsWithGitCredentials() ([]*config.System, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer txn.Commit()

	rows, err := txn.Query(`SELECT
        systems.id AS system_id,
		systems.labels,
        systems.repo,
        systems.ref,
        systems.gitcommit,
        systems.path,
		systems.s3url,
		systems.s3region,
		systems.s3bucket,
		systems.s3key,
        secrets.id AS secret_id,
		systems_secrets.ref_type AS secret_ref_type,
        secrets.value AS secret_value,
		systems_requirements.library_id AS req_lib
    FROM
        systems
    LEFT JOIN
        systems_secrets ON systems.id = systems_secrets.system_id
    LEFT JOIN
        secrets ON systems_secrets.secret_id = secrets.id
	LEFT JOIN
		systems_requirements ON systems.id = systems_requirements.system_id
	WHERE (systems.s3bucket IS NOT NULL) AND
		((systems_secrets.ref_type = 'git_credentials' AND secrets.value IS NOT NULL) OR systems_secrets.ref_type IS NULL) OR
		systems_secrets.ref_type = 'aws'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	systemMap := make(map[string]*config.System)

	for rows.Next() {
		var systemId, repo string
		var labels *string
		var secretId, secretRefType, secretValue *string
		var ref, gitCommit, path *string
		var s3url, s3region, s3bucket, s3key *string
		var reqLib *string
		if err := rows.Scan(&systemId, &labels, &repo, &ref, &gitCommit, &path, &s3url, &s3region, &s3bucket, &s3key, &secretId, &secretRefType, &secretValue, &reqLib); err != nil {
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

			if labels != nil {
				if err := json.Unmarshal([]byte(*labels), &system.Labels); err != nil {
					return nil, fmt.Errorf("failed to unmarshal labels for %q: %w", system.Name, err)
				}
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

		if reqLib != nil {
			system.Requirements = append(system.Requirements, config.Requirement{Library: reqLib})
		}
	}

	// Load datasources for each system.

	rows2, err := txn.Query(`SELECT
	systems_datasources.name,
	systems_datasources.system_id,
	systems_datasources.path,
	systems_datasources.type,
	systems_datasources.config
FROM
	systems_datasources
`)
	if err != nil {
		return nil, err
	}

	defer rows2.Close()

	for rows2.Next() {
		var name, system_id, path, type_, configuration string
		if err := rows2.Scan(&name, &system_id, &path, &type_, &configuration); err != nil {
			return nil, err
		}

		datasource := config.Datasource{
			Name: name,
			Type: type_,
			Path: path,
		}

		if err := json.Unmarshal([]byte(configuration), &datasource.Config); err != nil {
			return nil, err
		}

		system, ok := systemMap[system_id]
		if ok {
			system.Datasources = append(system.Datasources, datasource)
		}
	}

	var systems []*config.System
	for _, system := range systemMap {
		systems = append(systems, system)
	}

	return systems, nil
}

func (d *Database) ListLibrariesWithGitCredentials() ([]*config.Library, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer txn.Commit()

	rows, err := txn.Query(`SELECT
	libraries.id AS library_id,
	libraries.repo,
	libraries.ref,
	libraries.gitcommit,
	libraries.path,
	secrets.id AS secret_id,
	libraries_secrets.ref_type as secret_ref_type,
	secrets.value AS secret_value,
	libraries_requirements.requirement_id
FROM
	libraries
LEFT JOIN
	libraries_secrets ON libraries.id = libraries_secrets.library_id
LEFT JOIN
	secrets ON libraries_secrets.secret_id = secrets.id
LEFT JOIN
	libraries_requirements ON libraries.id = libraries_requirements.library_id = libraries.id
WHERE (libraries_secrets.ref_type = 'git_credentials' AND secrets.value IS NOT NULL) OR libraries_secrets.ref_type IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	libraryMap := make(map[string]*config.Library)

	for rows.Next() {
		var libraryId, repo string
		var secretId, secretRefType, secretValue *string
		var ref, gitCommit, path *string
		var requirementId *string
		if err := rows.Scan(&libraryId, &repo, &ref, &gitCommit, &path, &secretId, &secretRefType, &secretValue, &requirementId); err != nil {
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

		if secretId != nil {
			s := config.Secret{Name: *secretId}
			if err := json.Unmarshal([]byte(*secretValue), &s.Value); err != nil {
				return nil, err
			}

			switch *secretRefType {
			case "git_credentials":
				library.Git.Credentials = s.Ref()
			}
		}

		if requirementId != nil {
			library.Requirements = append(library.Requirements, config.Requirement{Library: requirementId})
		}
	}

	// Load datasources for each library.

	rows2, err := txn.Query(`SELECT
		libraries_datasources.name,
		libraries_datasources.library_id,
		libraries_datasources.path,
		libraries_datasources.type,
		libraries_datasources.config
	FROM
		libraries_datasources
	`)
	if err != nil {
		return nil, err
	}

	defer rows2.Close()

	for rows2.Next() {
		var name, library_id, path, type_, configuration string
		if err := rows2.Scan(&name, &library_id, &path, &type_, &configuration); err != nil {
			return nil, err
		}

		datasource := config.Datasource{
			Name: name,
			Type: type_,
			Path: path,
		}

		if err := json.Unmarshal([]byte(configuration), &datasource.Config); err != nil {
			return nil, err
		}

		library, ok := libraryMap[library_id]
		if ok {
			library.Datasources = append(library.Datasources, datasource)
		}
	}

	var libraries []*config.Library
	for _, library := range libraryMap {
		libraries = append(libraries, library)
	}

	return libraries, nil

}

func (d *Database) ListStacks() ([]*config.Stack, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer txn.Commit()

	rows, err := txn.Query(`SELECT
        stacks.id AS stack_id,
        stacks.selector,
        stacks_requirements.library_id
    FROM
        stacks
	LEFT JOIN
		stacks_requirements ON stacks.id = stacks_requirements.stack_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stacks []*config.Stack
	stacksMap := map[string]*config.Stack{}

	for rows.Next() {
		var stackId, selectorJSON, libraryId string
		if err := rows.Scan(&stackId, &selectorJSON, &libraryId); err != nil {
			return nil, err
		}

		var selector config.Selector
		if err := json.Unmarshal([]byte(selectorJSON), &selector); err != nil {
			return nil, err
		}

		stack, ok := stacksMap[stackId]
		if !ok {
			stack = &config.Stack{
				Name:     stackId,
				Selector: selector,
			}
			stacksMap[stackId] = stack
		}

		stack.Requirements = append(stack.Requirements, config.Requirement{
			Library: &libraryId,
		})

		stacks = append(stacks, stack)
	}

	return stacks, nil
}

func (d *Database) QueryLibraryData(id string) (*DataCursor, error) {
	return d.queryData("libraries_data", "library_id", id)
}

func (d *Database) QuerySystemData(id string) (*DataCursor, error) {
	return d.queryData("systems_data", "system_id", id)
}

func (d *Database) queryData(table, pk, id string) (*DataCursor, error) {
	rows, err := d.db.Query(fmt.Sprintf(`SELECT
	path,
	data
FROM
	%v
WHERE
	%v = ?`, table, pk), id)
	if err != nil {
		return nil, err
	}
	return &DataCursor{rows: rows}, nil
}

type DataCursor struct {
	rows *sql.Rows
}

func (c *DataCursor) Next() bool {
	return c.rows.Next()
}

func (c *DataCursor) Close() error {
	return c.rows.Close()
}

func (c *DataCursor) Value() (Data, error) {
	var path string
	var data []byte
	if err := c.rows.Scan(&path, &data); err != nil {
		return Data{}, err
	}

	return Data{Path: path, Data: data}, nil
}

func (d *Database) loadSystems(root *config.Root) error {

	var names []string
	for _, system := range root.Systems {
		names = append(names, system.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		system := root.Systems[name]
		var s3url, s3region, s3bucket, s3key *string
		if system.ObjectStorage.AmazonS3 != nil {
			s3url = &system.ObjectStorage.AmazonS3.URL
			s3region = &system.ObjectStorage.AmazonS3.Region
			s3bucket = &system.ObjectStorage.AmazonS3.Bucket
			s3key = &system.ObjectStorage.AmazonS3.Key
		}

		bs, err := json.Marshal(system.Labels)
		if err != nil {
			return err
		}

		if _, err := d.db.Exec(`INSERT OR REPLACE INTO systems (id, labels, repo, ref, gitcommit, path, s3url, s3region, s3bucket, s3key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			system.Name, string(bs), system.Git.Repo, system.Git.Reference, system.Git.Commit, system.Git.Path, s3url, s3region, s3bucket, s3key); err != nil {
			return err
		}

		if system.Git.Credentials != nil {
			d.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, ref_type) VALUES (?, ?, ?)`, system.Name, system.Git.Credentials.Name, "git_credentials")
		}

		if system.ObjectStorage.AmazonS3 != nil {
			if system.ObjectStorage.AmazonS3.Credentials != nil {
				d.db.Exec(`INSERT OR REPLACE INTO systems_secrets (system_id, secret_id, ref_type) VALUES (?, ?, ?)`, system.Name, system.ObjectStorage.AmazonS3.Credentials.Name, "aws")
			}
		}

		for _, datasource := range system.Datasources {
			bs, err := json.Marshal(datasource.Config)
			if err != nil {
				return err
			}
			if _, err := d.db.Exec(`INSERT OR REPLACE INTO systems_datasources (name, system_id, type, path, config) VALUES (?, ?, ?, ?, ?)`,
				datasource.Name, system.Name, datasource.Type, datasource.Path, string(bs)); err != nil {
				return err
			}
		}

		for path, data := range system.Files {
			if _, err := d.db.Exec(`INSERT OR REPLACE INTO systems_data (system_id, path, data) VALUES (?, ?, ?)`, name, path, data); err != nil {
				return err
			}
		}

		for _, src := range system.Requirements {
			if src.Library != nil {
				// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
				if _, err := d.db.Exec(`INSERT OR REPLACE INTO systems_requirements (system_id, library_id) VALUES (?, ?)`, name, src.Library); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (d *Database) loadLibraries(root *config.Root) error {

	var names []string
	for _, library := range root.Libraries {
		names = append(names, library.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		library := root.Libraries[name]
		if _, err := d.db.Exec(`INSERT OR REPLACE INTO libraries (id, repo, ref, gitcommit, path) VALUES (?, ?, ?, ?, ?)`, library.Name, library.Git.Repo, library.Git.Reference, library.Git.Commit, library.Git.Path); err != nil {
			return err
		}

		if library.Git.Credentials != nil {
			d.db.Exec(`INSERT OR REPLACE INTO libraries_secrets (library_id, secret_id, ref_type) VALUES (?, ?, ?)`, library.Name, library.Git.Credentials.Name, "git_credentials")
		}

		for _, datasource := range library.Datasources {
			bs, err := json.Marshal(datasource.Config)
			if err != nil {
				return err
			}
			if _, err := d.db.Exec(`INSERT OR REPLACE INTO libraries_datasources (name, library_id, type, path, config) VALUES (?, ?, ?, ?, ?)`,
				datasource.Name, library.Name, datasource.Type, datasource.Path, string(bs)); err != nil {
				return err
			}
		}

		for path, data := range library.Files {
			if _, err := d.db.Exec(`INSERT OR REPLACE INTO libraries_data (library_id, path, data) VALUES (?, ?, ?)`, name, path, data); err != nil {
				return err
			}
		}

		for _, r := range library.Requirements {
			if r.Library != nil {
				if _, err := d.db.Exec(`INSERT OR REPLACE INTO libraries_requirements (library_id, requirement_id) VALUES (?, ?)`, name, r.Library); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (d *Database) loadSecrets(root *config.Root) error {

	var names []string
	for _, secret := range root.Secrets {
		names = append(names, secret.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		secret := root.Secrets[name]
		if len(secret.Value) > 0 {
			bs, err := json.Marshal(secret.Value)
			if err != nil {
				return err
			}
			if _, err := d.db.Exec(`INSERT OR REPLACE INTO secrets (id, value) VALUES (?, ?)`, secret.Name, string(bs)); err != nil {
				return err
			}
		} else {
			if _, err := d.db.Exec(`INSERT OR REPLACE INTO secrets (id) VALUES (?)`, secret.Name); err != nil {
				return err
			}
		}
	}

	return nil
}

func (d *Database) loadStacks(root *config.Root) error {
	var names []string
	for _, stack := range root.Stacks {
		names = append(names, stack.Name)
	}

	sort.Strings(names)

	for _, name := range names {
		stack := root.Stacks[name]

		bs, err := json.Marshal(stack.Selector)
		if err != nil {
			return fmt.Errorf("failed to marshal selector for stack %q: %w", name, err)
		}

		if _, err := d.db.Exec(`INSERT OR REPLACE INTO stacks (id, selector) VALUES (?, ?)`, stack.Name, string(bs)); err != nil {
			return fmt.Errorf("failed to insert stack %q: %w", name, err)
		}

		for _, r := range stack.Requirements {
			if r.Library != nil {
				// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
				if _, err := d.db.Exec(`INSERT OR REPLACE INTO stacks_requirements (stack_id, library_id) VALUES (?, ?)`, name, r.Library); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
