package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql compatible driver for pgx
	_ "github.com/mattn/go-sqlite3"
	"github.com/tsandall/lighthouse/internal/authz"
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
		`CREATE TABLE IF NOT EXISTS bundles (
			id TEXT PRIMARY KEY,
			labels TEXT,
			s3url TEXT,
			s3region TEXT,
			s3bucket TEXT,
			s3key TEXT,
			excluded TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS sources (
			id TEXT PRIMARY KEY,
			builtin TEXT,
			repo TEXT NOT NULL,
			ref TEXT,
			gitcommit TEXT,
			path TEXT,
			git_included_files TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS stacks (
			id TEXT PRIMARY KEY,
			selector TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			value TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			api_key TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS bundles_secrets (
			bundle_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			ref_type TEXT NOT NULL,
			PRIMARY KEY (bundle_id, secret_id),
			FOREIGN KEY (bundle_id) REFERENCES bundles(id),
			FOREIGN KEY (secret_id) REFERENCES secrets(id)
		);`,
		`CREATE TABLE IF NOT EXISTS bundles_requirements (
			bundle_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			PRIMARY KEY (bundle_id, source_id),
			FOREIGN KEY (bundle_id) REFERENCES bundles(id),
			FOREIGN KEY (source_id) REFERENCES sources(id)
		);`,
		`CREATE TABLE IF NOT EXISTS stacks_requirements (
			stack_id TEXT NOT NULL,
			source_id TEXT NOT NULL,
			PRIMARY KEY (stack_id, source_id),
			FOREIGN KEY (stack_id) REFERENCES stacks(id),
			FOREIGN KEY (source_id) REFERENCES sources(id)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_requirements (
			source_id TEXT NOT NULL,
			requirement_id TEXT NOT NULL,
			PRIMARY KEY (source_id, requirement_id),
			FOREIGN KEY (source_id) REFERENCES sources(id),
			FOREIGN KEY (requirement_id) REFERENCES sources(id)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_secrets (
			source_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			ref_type TEXT NOT NULL,
			PRIMARY KEY (source_id, secret_id),
			FOREIGN KEY (source_id) REFERENCES sources(id),
			FOREIGN KEY (secret_id) REFERENCES secrets(id)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_data (
			source_id TEXT NOT NULL,
			path TEXT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (source_id, path),
			FOREIGN KEY (source_id) REFERENCES sources(id)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_datasources (
			name TEXT NOT NULL,
			source_id TEXT NOT NULL,
			type TEXT NOT NULL,
			path TEXT NOT NULL,
			config TEXT NOT NULL,
			transform_query TEXT NOT NULL,
			PRIMARY KEY (source_id, name),
			FOREIGN KEY (source_id) REFERENCES sources(id)
		);`,
		`CREATE TABLE IF NOT EXISTS principals (
			id TEXT PRIMARY KEY,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS resource_permissions (
			id TEXT	NOT NULL,
			resource TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			role TEXT,
			permission TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id, resource),
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE -- TODO(tsandall): e2e test
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

func (d *Database) SourcesDataGet(ctx context.Context, srcId, path string, principal string) (interface{}, bool, error) {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}

	defer tx.Rollback()

	if err := d.resourceExists(ctx, tx, "sources", srcId); err != nil {
		return nil, false, err
	}

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Permission: "sources.data.read",
		Resource:   "sources",
		Id:         srcId,
	}, nil)
	if err != nil {
		return nil, false, err
	}

	rows, err := tx.Query(`SELECT
	data
FROM
	sources_data
WHERE source_id = ? AND path = ? AND `+expr.SQL(), srcId, path)
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

func (d *Database) SourcesDataPut(ctx context.Context, srcId, path string, data interface{}, principal string) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.resourceExists(ctx, tx, "sources", srcId); err != nil {
		return err
	}

	allowed := authz.Check(ctx, tx, authz.Access{
		Principal:  principal,
		Permission: "sources.data.write",
		Resource:   "sources",
		Id:         srcId,
	})
	if !allowed {
		_ = tx.Rollback()
		return fmt.Errorf("unauthorized")
	}

	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_data (source_id, path, data) VALUES (?, ?, ?)`, srcId, path, bs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for source data update %q: %w", srcId, err)
	}

	return nil
}

func (d *Database) SourcesDataDelete(ctx context.Context, srcId, path string, principal string) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.resourceExists(ctx, tx, "sources", srcId); err != nil {
		return err
	}

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Permission: "sources.data.write",
		Resource:   "sources",
		Id:         srcId,
	}, nil)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sources_data WHERE source_id = ? AND path = ? AND `+expr.SQL(), srcId, path); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for source data delete %q: %w", srcId, err)
	}

	return nil
}

// LoadConfig loads the configuration from the configuration file into the database.
func (d *Database) LoadConfig(ctx context.Context, principal string, bs []byte) error {

	root, err := config.Parse(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}

	for _, secret := range root.SortedSecrets() {
		if err := d.UpsertSecret(ctx, principal, secret); err != nil {
			return err
		}
	}

	for _, b := range root.SortedBundles() {
		if err := d.UpsertBundle(ctx, principal, b); err != nil {
			return err
		}
	}

	for _, src := range root.SortedSources() {
		if err := d.UpsertSource(ctx, principal, src); err != nil {
			return err
		}
	}

	for _, stack := range root.SortedStacks() {
		if err := d.UpsertStack(ctx, principal, stack); err != nil {
			return err
		}
	}
	for _, token := range root.Tokens {
		if err := d.UpsertToken(ctx, principal, token); err != nil {
			return err
		}
	}

	return nil
}

func (d *Database) ListBundlesToBuild() ([]*config.Bundle, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer txn.Commit()

	rows, err := txn.Query(`SELECT
        bundles.id AS bundle_id,
		bundles.labels,
		bundles.s3url,
		bundles.s3region,
		bundles.s3bucket,
		bundles.s3key,
		bundles.excluded,
        secrets.id AS secret_id,
		bundles_secrets.ref_type AS secret_ref_type,
        secrets.value AS secret_value,
		bundles_requirements.source_id AS req_src
    FROM
        bundles
    LEFT JOIN
        bundles_secrets ON bundles.id = bundles_secrets.bundle_id
    LEFT JOIN
        secrets ON bundles_secrets.secret_id = secrets.id
	LEFT JOIN
		bundles_requirements ON bundles.id = bundles_requirements.bundle_id
	WHERE (bundles.s3bucket IS NOT NULL) AND
		(bundles_secrets.ref_type IS NULL OR bundles_secrets.ref_type = 'aws')`) // TODO(tsandall): do we support object storage w/o credentials?
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	bundleMap := make(map[string]*config.Bundle)

	for rows.Next() {
		var bundleId string
		var labels *string
		var secretId, secretRefType, secretValue *string
		var s3url, s3region, s3bucket, s3key *string
		var excluded *string
		var reqSrc *string
		if err := rows.Scan(&bundleId, &labels, &s3url, &s3region, &s3bucket, &s3key, &excluded, &secretId, &secretRefType, &secretValue, &reqSrc); err != nil {
			return nil, err
		}

		bundle, exists := bundleMap[bundleId]
		if !exists {
			bundle = &config.Bundle{
				Name: bundleId,
			}

			if labels != nil {
				if err := json.Unmarshal([]byte(*labels), &bundle.Labels); err != nil {
					return nil, fmt.Errorf("failed to unmarshal labels for %q: %w", bundle.Name, err)
				}
			}

			bundleMap[bundleId] = bundle

			if s3region != nil && s3bucket != nil && s3key != nil {
				bundle.ObjectStorage.AmazonS3 = &config.AmazonS3{
					Region: *s3region,
					Bucket: *s3bucket,
					Key:    *s3key,
				}
				if s3url != nil {
					bundle.ObjectStorage.AmazonS3.URL = *s3url
				}
			}

			if excluded != nil {
				if err := json.Unmarshal([]byte(*excluded), &bundle.ExcludedFiles); err != nil {
					return nil, fmt.Errorf("failed to unmarshal excluded files for %q: %w", bundle.Name, err)
				}
			}
		}

		if secretId != nil {
			s := config.Secret{Name: *secretId}
			if err := json.Unmarshal([]byte(*secretValue), &s.Value); err != nil {
				return nil, err
			}

			switch *secretRefType {
			case "aws":
				if bundle.ObjectStorage.AmazonS3 != nil {
					bundle.ObjectStorage.AmazonS3.Credentials = s.Ref()
				}
			}
		}

		if reqSrc != nil {
			bundle.Requirements = append(bundle.Requirements, config.Requirement{Source: reqSrc})
		}
	}

	return slices.Collect(maps.Values(bundleMap)), nil
}

func (d *Database) ListSourcesWithGitCredentials(ctx context.Context, principal string) ([]*config.Source, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, err
	}
	defer txn.Commit()

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Resource:   "sources",
		Permission: "sources.view",
	}, map[string]authz.ColumnRef{
		"input.id": {Table: "sources", Column: "id"},
	})
	if err != nil {
		return nil, err
	}

	query := `SELECT
	sources.id AS source_id,
	sources.builtin,
	sources.repo,
	sources.ref,
	sources.gitcommit,
	sources.path,
	sources.git_included_files,
	secrets.id AS secret_id,
	sources_secrets.ref_type as secret_ref_type,
	secrets.value AS secret_value,
	sources_requirements.requirement_id
FROM
	sources
LEFT JOIN
	sources_secrets ON sources.id = sources_secrets.source_id
LEFT JOIN
	secrets ON sources_secrets.secret_id = secrets.id
LEFT JOIN
	sources_requirements ON sources.id = sources_requirements.source_id
WHERE ((sources_secrets.ref_type = 'git_credentials' AND secrets.value IS NOT NULL) OR sources_secrets.ref_type IS NULL) AND ` + expr.SQL()

	rows, err := txn.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	srcMap := make(map[string]*config.Source)

	for rows.Next() {
		var srcId, repo string
		var builtin *string
		var secretId, secretRefType, secretValue *string
		var ref, gitCommit, path, includePaths *string
		var requirementId *string
		if err := rows.Scan(&srcId, &builtin, &repo, &ref, &gitCommit, &path, &includePaths, &secretId, &secretRefType, &secretValue, &requirementId); err != nil {
			return nil, err
		}

		src, exists := srcMap[srcId]
		if !exists {
			src = &config.Source{
				Name:    srcId,
				Builtin: builtin,
				Git: config.Git{
					Repo: repo,
				},
			}
			srcMap[srcId] = src

			if ref != nil {
				src.Git.Reference = ref
			}
			if gitCommit != nil {
				src.Git.Commit = gitCommit
			}
			if path != nil {
				src.Git.Path = path
			}
			if includePaths != nil {
				if err := json.Unmarshal([]byte(*includePaths), &src.Git.IncludedFiles); err != nil {
					return nil, fmt.Errorf("failed to unmarshal include paths for %q: %w", src.Name, err)
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
				src.Git.Credentials = s.Ref()
			}
		}

		if requirementId != nil {
			src.Requirements = append(src.Requirements, config.Requirement{Source: requirementId})
		}
	}

	// Load datasources for each source.

	rows2, err := txn.Query(`SELECT
		sources_datasources.name,
		sources_datasources.source_id,
		sources_datasources.path,
		sources_datasources.type,
		sources_datasources.config,
		sources_datasources.transform_query
	FROM
		sources_datasources
	`)
	if err != nil {
		return nil, err
	}

	defer rows2.Close()

	for rows2.Next() {
		var name, source_id, path, type_, configuration, transformQuery string
		if err := rows2.Scan(&name, &source_id, &path, &type_, &configuration, &transformQuery); err != nil {
			return nil, err
		}

		datasource := config.Datasource{
			Name:           name,
			Type:           type_,
			Path:           path,
			TransformQuery: transformQuery,
		}

		if err := json.Unmarshal([]byte(configuration), &datasource.Config); err != nil {
			return nil, err
		}

		src, ok := srcMap[source_id]
		if ok {
			src.Datasources = append(src.Datasources, datasource)
		}
	}

	return slices.Collect(maps.Values(srcMap)), nil
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
        stacks_requirements.source_id
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
		var stackId, selectorJSON, srcId string
		if err := rows.Scan(&stackId, &selectorJSON, &srcId); err != nil {
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
			Source: &srcId,
		})

		stacks = append(stacks, stack)
	}

	return stacks, nil
}

func (d *Database) QuerySourceData(id string) (*DataCursor, error) {
	rows, err := d.db.Query(`SELECT
	path,
	data
FROM
	sources_data
WHERE
	source_id = ?`, id)
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

func (d *Database) UpsertBundle(ctx context.Context, principal string, bundle *config.Bundle) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.checkUpsert(ctx, tx, principal, "bundles", bundle.Name, "bundles.create", "bundles.manage"); err != nil {
		return err
	}

	var s3url, s3region, s3bucket, s3key *string
	if bundle.ObjectStorage.AmazonS3 != nil {
		s3url = &bundle.ObjectStorage.AmazonS3.URL
		s3region = &bundle.ObjectStorage.AmazonS3.Region
		s3bucket = &bundle.ObjectStorage.AmazonS3.Bucket
		s3key = &bundle.ObjectStorage.AmazonS3.Key
	}

	labels, err := json.Marshal(bundle.Labels)
	if err != nil {
		return err
	}

	excluded, err := json.Marshal(bundle.ExcludedFiles)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO bundles (id, labels, s3url, s3region, s3bucket, s3key, excluded) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		bundle.Name, string(labels), s3url, s3region, s3bucket, s3key, string(excluded)); err != nil {
		return err
	}

	if bundle.ObjectStorage.AmazonS3 != nil {
		if bundle.ObjectStorage.AmazonS3.Credentials != nil {
			tx.Exec(`INSERT OR REPLACE INTO bundles_secrets (bundle_id, secret_id, ref_type) VALUES (?, ?, ?)`, bundle.Name, bundle.ObjectStorage.AmazonS3.Credentials.Name, "aws")
		}
	}

	for _, src := range bundle.Requirements {
		if src.Source != nil {
			// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
			if _, err := tx.Exec(`INSERT OR REPLACE INTO bundles_requirements (bundle_id, source_id) VALUES (?, ?)`, bundle.Name, src.Source); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for bundle %q: %w", bundle.Name, err)
	}

	return nil
}

func (d *Database) UpsertSource(ctx context.Context, principal string, source *config.Source) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.checkUpsert(ctx, tx, principal, "sources", source.Name, "sources.create", "sources.manage"); err != nil {
		return err
	}

	includedFiles, err := json.Marshal(source.Git.IncludedFiles)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO sources (id, builtin, repo, ref, gitcommit, path, git_included_files) VALUES (?, ?, ?, ?, ?, ?, ?)`, source.Name, source.Builtin, source.Git.Repo, source.Git.Reference, source.Git.Commit, source.Git.Path, string(includedFiles)); err != nil {
		return err
	}

	if source.Git.Credentials != nil {
		tx.Exec(`INSERT OR REPLACE INTO sources_secrets (source_id, secret_id, ref_type) VALUES (?, ?, ?)`, source.Name, source.Git.Credentials.Name, "git_credentials")
	}

	for _, datasource := range source.Datasources {
		bs, err := json.Marshal(datasource.Config)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_datasources (name, source_id, type, path, config, transform_query) VALUES (?, ?, ?, ?, ?, ?)`,
			datasource.Name, source.Name, datasource.Type, datasource.Path, string(bs), datasource.TransformQuery); err != nil {
			return err
		}
	}

	for path, data := range source.Files() {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_data (source_id, path, data) VALUES (?, ?, ?)`, source.Name, path, data); err != nil {
			return err
		}
	}

	for _, r := range source.Requirements {
		if r.Source != nil {
			if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_requirements (source_id, requirement_id) VALUES (?, ?)`, source.Name, r.Source); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for source %q: %w", source.Name, err)
	}

	return nil
}

func (d *Database) UpsertSecret(ctx context.Context, principal string, secret *config.Secret) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.checkUpsert(ctx, tx, principal, "secrets", secret.Name, "secrets.create", "secrets.manage"); err != nil {
		return err
	}

	if len(secret.Value) > 0 {
		bs, err := json.Marshal(secret.Value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO secrets (id, value) VALUES (?, ?)`, secret.Name, string(bs)); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO secrets (id) VALUES (?)`, secret.Name); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for secret %q: %v", secret.Name, err)
	}

	return nil
}

func (d *Database) UpsertStack(ctx context.Context, principal string, stack *config.Stack) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.checkUpsert(ctx, tx, principal, "stacks", stack.Name, "stacks.create", "stacks.manage"); err != nil {
		return err
	}

	bs, err := json.Marshal(stack.Selector)
	if err != nil {
		return fmt.Errorf("failed to marshal selector for stack %q: %w", stack.Name, err)
	}

	if _, err = tx.Exec(`INSERT OR REPLACE INTO stacks (id, selector) VALUES (?, ?)`, stack.Name, string(bs)); err != nil {
		return fmt.Errorf("failed to insert stack %q: %w", stack.Name, err)
	}

	for _, r := range stack.Requirements {
		if r.Source != nil {
			// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
			if _, err = tx.Exec(`INSERT OR REPLACE INTO stacks_requirements (stack_id, source_id) VALUES (?, ?)`, stack.Name, r.Source); err != nil {
				return fmt.Errorf("failed to insert stack requirement %q: %w", stack.Name, err)
			}
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for stack %q: %w", stack.Name, err)
	}

	return nil
}

func (d *Database) UpsertToken(ctx context.Context, principal string, token *config.Token) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.checkUpsert(ctx, tx, principal, "tokens", token.Name, "tokens.create", "tokens.manage"); err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO tokens (id, api_key) VALUES (?, ?)`, token.Name, token.APIKey); err != nil {
		return err
	}

	if len(token.Scopes) != 1 {
		return fmt.Errorf("exactly one scope must be provided for token %q", token.Name)
	}

	if err := UpsertPrincipalTx(ctx, tx, Principal{Id: token.Name, Role: token.Scopes[0].Role}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for token %q: %w", token.Name, err)
	}

	return nil
}

func (d *Database) checkUpsert(ctx context.Context, tx *sql.Tx, principal, resource, id string, permCreate, permUpdate string) error {

	var a authz.Access

	if err := d.resourceExists(ctx, tx, resource, id); err == nil {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permUpdate,
			Id:         id,
		}
	} else if err == ErrNotFound {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permCreate,
		}
	} else {
		return err
	}

	if !authz.Check(ctx, tx, a) {
		return ErrNotAuthorized
	}

	return nil
}

func (d *Database) resourceExists(ctx context.Context, tx *sql.Tx, table string, id string) error {
	var exists any
	if err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM %v as T WHERE T.id = ?", table), id).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	return nil
}
