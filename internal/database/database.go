package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql compatible driver for pgx
	_ "github.com/mattn/go-sqlite3"
	"github.com/styrainc/lighthouse/internal/authz"
	"github.com/styrainc/lighthouse/internal/aws"
	"github.com/styrainc/lighthouse/internal/config"
)

// Database implements the database operations. It will hide any differences between the varying SQL databases from the rest of the codebase.
type Database struct {
	db     *sql.DB
	config *config.Database
}

type ListOptions struct {
	Limit  int
	Cursor string
	name   string
}

func (opts ListOptions) cursor() int64 {
	if opts.Cursor != "" {
		decoded, err := base64.URLEncoding.DecodeString(opts.Cursor)
		if err == nil {
			after, _ := strconv.ParseInt(string(decoded), 10, 64)
			return after
		}
	}
	return 0
}

func encodeCursor(id int64) string {
	cursor := strconv.FormatInt(id, 10)
	return base64.URLEncoding.EncodeToString([]byte(cursor))
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

		if _, err := d.db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			return err
		}
	default:
		return errors.New("unsupported database connection type")
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS bundles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			labels TEXT,
			s3url TEXT,
			s3region TEXT,
			s3bucket TEXT,
			s3key TEXT,
			filepath TEXT,
			excluded TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS sources (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			builtin TEXT,
			repo TEXT NOT NULL,
			ref TEXT,
			gitcommit TEXT,
			path TEXT,
			git_included_files TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS stacks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			selector TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS secrets (
			name TEXT PRIMARY KEY,
			value TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS tokens (
			name TEXT PRIMARY KEY,
			api_key TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS bundles_secrets (
			bundle_name TEXT NOT NULL,
			secret_name TEXT NOT NULL,
			ref_type TEXT NOT NULL,
			PRIMARY KEY (bundle_name, secret_name),
			FOREIGN KEY (bundle_name) REFERENCES bundles(name),
			FOREIGN KEY (secret_name) REFERENCES secrets(name)
		);`,
		`CREATE TABLE IF NOT EXISTS bundles_requirements (
			bundle_name TEXT NOT NULL,
			source_name TEXT NOT NULL,
			PRIMARY KEY (bundle_name, source_name),
			FOREIGN KEY (bundle_name) REFERENCES bundles(name),
			FOREIGN KEY (source_name) REFERENCES sources(name)
		);`,
		`CREATE TABLE IF NOT EXISTS stacks_requirements (
			stack_name TEXT NOT NULL,
			source_name TEXT NOT NULL,
			PRIMARY KEY (stack_name, source_name),
			FOREIGN KEY (stack_name) REFERENCES stacks(name),
			FOREIGN KEY (source_name) REFERENCES sources(name)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_requirements (
			source_name TEXT NOT NULL,
			requirement_name TEXT NOT NULL,
			PRIMARY KEY (source_name, requirement_name),
			FOREIGN KEY (source_name) REFERENCES sources(name),
			FOREIGN KEY (requirement_name) REFERENCES sources(name)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_secrets (
			source_name TEXT NOT NULL,
			secret_name TEXT NOT NULL,
			ref_type TEXT NOT NULL,
			PRIMARY KEY (source_name, secret_name),
			FOREIGN KEY (source_name) REFERENCES sources(name),
			FOREIGN KEY (secret_name) REFERENCES secrets(name)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_data (
			source_name TEXT NOT NULL,
			path TEXT NOT NULL,
			data BLOB NOT NULL,
			PRIMARY KEY (source_name, path),
			FOREIGN KEY (source_name) REFERENCES sources(name)
		);`,
		`CREATE TABLE IF NOT EXISTS sources_datasources (
			name TEXT NOT NULL,
			source_name TEXT NOT NULL,
			type TEXT NOT NULL,
			path TEXT NOT NULL,
			config TEXT NOT NULL,
			transform_query TEXT NOT NULL,
			PRIMARY KEY (source_name, name),
			FOREIGN KEY (source_name) REFERENCES sources(name)
		);`,
		`CREATE TABLE IF NOT EXISTS principals (
			id TEXT PRIMARY KEY,
			role TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS resource_permissions (
			name TEXT NOT NULL,
			resource TEXT NOT NULL,
			principal_id TEXT NOT NULL,
			role TEXT,
			permission TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (name, resource),
			FOREIGN KEY (principal_id) REFERENCES principals(id) ON DELETE CASCADE
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

func (d *Database) SourcesDataGet(ctx context.Context, sourceName, path string, principal string) (interface{}, bool, error) {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}

	defer tx.Rollback()

	if err := d.resourceExists(ctx, tx, "sources", sourceName); err != nil {
		return nil, false, err
	}

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Permission: "sources.data.read",
		Resource:   "sources",
		Name:       sourceName,
	}, nil)
	if err != nil {
		return nil, false, err
	}

	rows, err := tx.Query(`SELECT
	data
FROM
	sources_data
WHERE source_name = ? AND path = ? AND `+expr.SQL(), sourceName, path)
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

func (d *Database) SourcesDataPut(ctx context.Context, sourceName, path string, data interface{}, principal string) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.resourceExists(ctx, tx, "sources", sourceName); err != nil {
		return err
	}

	allowed := authz.Check(ctx, tx, authz.Access{
		Principal:  principal,
		Permission: "sources.data.write",
		Resource:   "sources",
		Name:       sourceName,
	})
	if !allowed {
		_ = tx.Rollback()
		return fmt.Errorf("unauthorized")
	}

	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_data (source_name, path, data) VALUES (?, ?, ?)`, sourceName, path, bs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for source data update %q: %w", sourceName, err)
	}

	return nil
}

func (d *Database) SourcesDataDelete(ctx context.Context, sourceName, path string, principal string) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.resourceExists(ctx, tx, "sources", sourceName); err != nil {
		return err
	}

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Permission: "sources.data.write",
		Resource:   "sources",
		Name:       sourceName,
	}, nil)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sources_data WHERE source_name = ? AND path = ? AND `+expr.SQL(), sourceName, path); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit txn for source data delete %q: %w", sourceName, err)
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
			return fmt.Errorf("upsert secret %q failed: %w", secret.Name, err)
		}
	}

	sources, err := root.TopologicalSortedSources()
	if err != nil {
		return err
	}

	for _, src := range sources {
		if err := d.UpsertSource(ctx, principal, src); err != nil {
			return fmt.Errorf("upsert source %q failed: %w", src.Name, err)
		}
	}

	for _, b := range root.SortedBundles() {
		if err := d.UpsertBundle(ctx, principal, b); err != nil {
			return fmt.Errorf("upsert bundle %q failed: %w", b.Name, err)
		}
	}

	for _, stack := range root.SortedStacks() {
		if err := d.UpsertStack(ctx, principal, stack); err != nil {
			return fmt.Errorf("upsert stack %q failed: %w", stack.Name, err)
		}
	}
	for _, token := range root.Tokens {
		if err := d.UpsertToken(ctx, principal, token); err != nil {
			return fmt.Errorf("upsert token %q failed: %w", token.Name, err)
		}
	}

	return nil
}

func (d *Database) GetBundle(ctx context.Context, principal string, name string) (*config.Bundle, error) {
	bundles, _, err := d.ListBundles(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(bundles) == 0 {
		return nil, ErrNotFound
	}

	return bundles[0], nil
}

func (d *Database) ListBundles(ctx context.Context, principal string, opts ListOptions) ([]*config.Bundle, string, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer txn.Commit()

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Resource:   "bundles",
		Permission: "bundles.view",
	}, map[string]authz.ColumnRef{
		"input.name": {Table: "bundles", Column: "name"},
	})
	if err != nil {
		return nil, "", err
	}

	// TODO(tsandall): do we support object storage w/o credentials?
	query := `SELECT
		bundles.id,
        bundles.name AS bundle_name,
		bundles.labels,
		bundles.s3url,
		bundles.s3region,
		bundles.s3bucket,
		bundles.s3key,
		bundles.filepath,
		bundles.excluded,
        secrets.name AS secret_name,
		bundles_secrets.ref_type AS secret_ref_type,
        secrets.value AS secret_value,
		bundles_requirements.source_name AS req_src
    FROM
        bundles
    LEFT JOIN
        bundles_secrets ON bundles.name = bundles_secrets.bundle_name
    LEFT JOIN
        secrets ON bundles_secrets.secret_name = secrets.name
	LEFT JOIN
		bundles_requirements ON bundles.name = bundles_requirements.bundle_name ` +
		// Bundles stored to S3 object storages
		`WHERE ((bundles.s3bucket IS NOT NULL) AND
		(bundles_secrets.ref_type IS NULL OR bundles_secrets.ref_type = 'aws')` +
		// Bundles stored to filesystem
		" OR (bundles.filepath IS NOT NULL))" +
		// Authorization
		" AND (" + expr.SQL() + ")"
	var args []any

	if opts.name != "" {
		query += " AND (bundles.name = ?)"
		args = append(args, opts.name)
	}

	if after := opts.cursor(); after > 0 {
		query += " AND (bundles.id > ?)"
		args = append(args, after)
	}
	query += " ORDER BY bundles.id"
	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := txn.Query(query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	type bundleRow struct {
		id                                         int64
		bundleName                                 string
		labels                                     *string
		s3url, s3region, s3bucket, s3key, filepath *string
		excluded                                   *string
		secretName, secretRefType, secretValue     *string
		reqSrc                                     *string
	}
	bundleMap := make(map[string]*config.Bundle)
	idMap := make(map[string]int64)
	var lastId int64

	for rows.Next() {
		var row bundleRow
		if err := rows.Scan(&row.id, &row.bundleName, &row.labels, &row.s3url, &row.s3region, &row.s3bucket, &row.s3key, &row.filepath, &row.excluded, &row.secretName, &row.secretRefType, &row.secretValue, &row.reqSrc); err != nil {
			return nil, "", err
		}

		bundle, exists := bundleMap[row.bundleName]
		if !exists {
			bundle = &config.Bundle{
				Name: row.bundleName,
			}

			if row.labels != nil {
				if err := json.Unmarshal([]byte(*row.labels), &bundle.Labels); err != nil {
					return nil, "", fmt.Errorf("failed to unmarshal labels for %q: %w", bundle.Name, err)
				}
			}

			bundleMap[row.bundleName] = bundle
			idMap[row.bundleName] = row.id

			if row.s3region != nil && row.s3bucket != nil && row.s3key != nil {
				bundle.ObjectStorage.AmazonS3 = &config.AmazonS3{
					Region: *row.s3region,
					Bucket: *row.s3bucket,
					Key:    *row.s3key,
				}
				if row.s3url != nil {
					bundle.ObjectStorage.AmazonS3.URL = *row.s3url
				}
			} else if row.filepath != nil {
				bundle.ObjectStorage.FileSystemStorage = &config.FileSystemStorage{
					Path: *row.filepath,
				}
			}

			if row.excluded != nil {
				if err := json.Unmarshal([]byte(*row.excluded), &bundle.ExcludedFiles); err != nil {
					return nil, "", fmt.Errorf("failed to unmarshal excluded files for %q: %w", bundle.Name, err)
				}
			}
		}

		if row.secretName != nil {
			s := config.Secret{Name: *row.secretName}
			if err := json.Unmarshal([]byte(*row.secretValue), &s.Value); err != nil {
				return nil, "", err
			}

			switch *row.secretRefType {
			case "aws":
				if bundle.ObjectStorage.AmazonS3 != nil {
					bundle.ObjectStorage.AmazonS3.Credentials = s.Ref()
				}
			}
		}

		if row.reqSrc != nil {
			bundle.Requirements = append(bundle.Requirements, config.Requirement{Source: row.reqSrc})
		}

		if row.id > lastId {
			lastId = row.id
		}
	}

	sl := slices.Collect(maps.Values(bundleMap))
	sort.Slice(sl, func(i, j int) bool {
		return idMap[sl[i].Name] < idMap[sl[j].Name]
	})

	var nextCursor string
	if opts.Limit > 0 && len(sl) == opts.Limit {
		nextCursor = encodeCursor(lastId)
	}

	return sl, nextCursor, nil
}

func (d *Database) GetSource(ctx context.Context, principal string, name string) (*config.Source, error) {
	sources, _, err := d.ListSources(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(sources) == 0 {
		return nil, ErrNotFound
	}

	return sources[0], nil
}

func (d *Database) ListSources(ctx context.Context, principal string, opts ListOptions) ([]*config.Source, string, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer txn.Commit()

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Resource:   "sources",
		Permission: "sources.view",
	}, map[string]authz.ColumnRef{
		"input.name": {Table: "sources", Column: "name"},
	})
	if err != nil {
		return nil, "", err
	}

	query := `SELECT
	sources.id,
	sources.name AS source_name,
	sources.builtin,
	sources.repo,
	sources.ref,
	sources.gitcommit,
	sources.path,
	sources.git_included_files,
	secrets.name AS secret_name,
	sources_secrets.ref_type as secret_ref_type,
	secrets.value AS secret_value,
	sources_requirements.requirement_name
FROM
	sources
LEFT JOIN
	sources_secrets ON sources.name = sources_secrets.source_name
LEFT JOIN
	secrets ON sources_secrets.secret_name = secrets.name
LEFT JOIN
	sources_requirements ON sources.name = sources_requirements.source_name
WHERE ((sources_secrets.ref_type = 'git_credentials' AND secrets.value IS NOT NULL) OR sources_secrets.ref_type IS NULL) AND (` + expr.SQL() + ")"

	var args []any

	if opts.name != "" {
		query += " AND (sources.name = ?)"
		args = append(args, opts.name)
	}

	if after := opts.cursor(); after > 0 {
		query += " AND (sources.id > ?)"
		args = append(args, after)
	}
	query += " ORDER BY sources.id"
	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := txn.Query(query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	type sourceRow struct {
		id                                     int64
		sourceName                             string
		builtin                                *string
		repo                                   string
		ref, gitCommit, path, includePaths     *string
		secretName, secretRefType, secretValue *string
		requirementName                        *string
	}

	srcMap := make(map[string]*config.Source)
	idMap := make(map[string]int64)
	var last int64

	for rows.Next() {
		var row sourceRow
		if err := rows.Scan(&row.id, &row.sourceName, &row.builtin, &row.repo, &row.ref, &row.gitCommit, &row.path, &row.includePaths, &row.secretName, &row.secretRefType, &row.secretValue, &row.requirementName); err != nil {
			return nil, "", err
		}

		src, exists := srcMap[row.sourceName]
		if !exists {
			src = &config.Source{
				Name:    row.sourceName,
				Builtin: row.builtin,
				Git: config.Git{
					Repo: row.repo,
				},
			}
			srcMap[row.sourceName] = src
			idMap[row.sourceName] = row.id

			if row.ref != nil {
				src.Git.Reference = row.ref
			}
			if row.gitCommit != nil {
				src.Git.Commit = row.gitCommit
			}
			if row.path != nil {
				src.Git.Path = row.path
			}
			if row.includePaths != nil {
				if err := json.Unmarshal([]byte(*row.includePaths), &src.Git.IncludedFiles); err != nil {
					return nil, "", fmt.Errorf("failed to unmarshal include paths for %q: %w", src.Name, err)
				}
			}
		}

		if row.secretName != nil {
			s := config.Secret{Name: *row.secretName}
			if err := json.Unmarshal([]byte(*row.secretValue), &s.Value); err != nil {
				return nil, "", err
			}

			switch *row.secretRefType {
			case "git_credentials":
				src.Git.Credentials = s.Ref()
			}
		}

		if row.requirementName != nil {
			src.Requirements = append(src.Requirements, config.Requirement{Source: row.requirementName})
		}

		if row.id > last {
			last = row.id
		}
	}

	// Load datasources for each source.

	rows2, err := txn.Query(`SELECT
		sources_datasources.name,
		sources_datasources.source_name,
		sources_datasources.path,
		sources_datasources.type,
		sources_datasources.config,
		sources_datasources.transform_query
	FROM
		sources_datasources
	`)
	if err != nil {
		return nil, "", err
	}

	defer rows2.Close()

	for rows2.Next() {
		var name, source_name, path, type_, configuration, transformQuery string
		if err := rows2.Scan(&name, &source_name, &path, &type_, &configuration, &transformQuery); err != nil {
			return nil, "", err
		}

		datasource := config.Datasource{
			Name:           name,
			Type:           type_,
			Path:           path,
			TransformQuery: transformQuery,
		}

		if err := json.Unmarshal([]byte(configuration), &datasource.Config); err != nil {
			return nil, "", err
		}

		src, ok := srcMap[source_name]
		if ok {
			src.Datasources = append(src.Datasources, datasource)
		}
	}

	sl := slices.Collect(maps.Values(srcMap))
	sort.Slice(sl, func(i, j int) bool {
		return idMap[sl[i].Name] < idMap[sl[j].Name]
	})

	var nextCursor string
	if opts.Limit > 0 && len(sl) == opts.Limit {
		cursor := strconv.FormatInt(last, 10)
		nextCursor = base64.URLEncoding.EncodeToString([]byte(cursor))
	}

	return sl, nextCursor, nil
}

func (d *Database) GetStack(ctx context.Context, principal string, name string) (*config.Stack, error) {
	stacks, _, err := d.ListStacks(ctx, principal, ListOptions{name: name})
	if err != nil {
		return nil, err
	}

	if len(stacks) == 0 {
		return nil, ErrNotFound
	}

	return stacks[0], nil
}

func (d *Database) ListStacks(ctx context.Context, principal string, opts ListOptions) ([]*config.Stack, string, error) {
	txn, err := d.db.Begin()
	if err != nil {
		return nil, "", err
	}
	defer txn.Commit()

	expr, err := authz.Partial(ctx, authz.Access{
		Principal:  principal,
		Resource:   "stacks",
		Permission: "stacks.view",
	}, map[string]authz.ColumnRef{
		"input.name": {Table: "stacks", Column: "name"},
	})
	if err != nil {
		return nil, "", err
	}

	query := `SELECT
        stacks.id,
        stacks.name AS stack_name,
        stacks.selector,
        stacks_requirements.source_name
    FROM
        stacks
    LEFT JOIN
        stacks_requirements ON stacks.name = stacks_requirements.stack_name
    WHERE (` + expr.SQL() + ")"

	var args []any

	if opts.name != "" {
		query += " AND (stacks.name = ?)"
		args = append(args, opts.name)
	}

	if after := opts.cursor(); after > 0 {
		query += " AND (stacks.id > ?)"
		args = append(args, after)
	}
	query += " ORDER BY stacks.id"
	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}

	rows, err := txn.Query(query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	type stackRow struct {
		id         int64
		stackName  string
		selector   string
		sourceName *string
	}

	stacksMap := map[string]*config.Stack{}
	idMap := map[string]int64{}
	var lastId int64

	for rows.Next() {
		var row stackRow
		if err := rows.Scan(&row.id, &row.stackName, &row.selector, &row.sourceName); err != nil {
			return nil, "", err
		}

		var selector config.Selector
		if err := json.Unmarshal([]byte(row.selector), &selector); err != nil {
			return nil, "", err
		}

		stack, ok := stacksMap[row.stackName]
		if !ok {
			stack = &config.Stack{
				Name:     row.stackName,
				Selector: selector,
			}
			stacksMap[row.stackName] = stack
			idMap[row.stackName] = row.id
		}

		if row.sourceName != nil {
			stack.Requirements = append(stack.Requirements, config.Requirement{
				Source: row.sourceName,
			})
		}

		if row.id > lastId {
			lastId = row.id
		}
	}

	sl := slices.Collect(maps.Values(stacksMap))
	sort.Slice(sl, func(i, j int) bool {
		return idMap[sl[i].Name] < idMap[sl[j].Name]
	})

	var nextCursor string
	if opts.Limit > 0 && len(sl) == opts.Limit {
		nextCursor = encodeCursor(lastId)
	}

	return sl, nextCursor, nil
}

func (d *Database) QuerySourceData(sourceName string) (*DataCursor, error) {
	rows, err := d.db.Query(`SELECT
	path,
	data
FROM
	sources_data
WHERE
	source_name = ?`, sourceName)
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

	if err := d.prepareUpsert(ctx, tx, principal, "bundles", bundle.Name, "bundles.create", "bundles.manage"); err != nil {
		return err
	}

	var s3url, s3region, s3bucket, s3key, filepath *string
	if bundle.ObjectStorage.AmazonS3 != nil {
		s3url = &bundle.ObjectStorage.AmazonS3.URL
		s3region = &bundle.ObjectStorage.AmazonS3.Region
		s3bucket = &bundle.ObjectStorage.AmazonS3.Bucket
		s3key = &bundle.ObjectStorage.AmazonS3.Key
	}
	if bundle.ObjectStorage.FileSystemStorage != nil {
		filepath = &bundle.ObjectStorage.FileSystemStorage.Path
	}

	labels, err := json.Marshal(bundle.Labels)
	if err != nil {
		return err
	}

	excluded, err := json.Marshal(bundle.ExcludedFiles)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO bundles (name, labels, s3url, s3region, s3bucket, s3key, filepath, excluded) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		bundle.Name, string(labels), s3url, s3region, s3bucket, s3key, filepath, string(excluded)); err != nil {
		return err
	}

	if bundle.ObjectStorage.AmazonS3 != nil {
		if bundle.ObjectStorage.AmazonS3.Credentials != nil {
			if _, err := tx.Exec(`INSERT OR REPLACE INTO bundles_secrets (bundle_name, secret_name, ref_type) VALUES (?, ?, ?)`, bundle.Name, bundle.ObjectStorage.AmazonS3.Credentials.Name, "aws"); err != nil {
				return err
			}
		}
	}

	for _, src := range bundle.Requirements {
		if src.Source != nil {
			// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
			if _, err := tx.Exec(`INSERT OR REPLACE INTO bundles_requirements (bundle_name, source_name) VALUES (?, ?)`, bundle.Name, src.Source); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (d *Database) UpsertSource(ctx context.Context, principal string, source *config.Source) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.prepareUpsert(ctx, tx, principal, "sources", source.Name, "sources.create", "sources.manage"); err != nil {
		return err
	}

	includedFiles, err := json.Marshal(source.Git.IncludedFiles)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO sources (name, builtin, repo, ref, gitcommit, path, git_included_files) VALUES (?, ?, ?, ?, ?, ?, ?)`, source.Name, source.Builtin, source.Git.Repo, source.Git.Reference, source.Git.Commit, source.Git.Path, string(includedFiles)); err != nil {
		return err
	}

	if source.Git.Credentials != nil {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_secrets (source_name, secret_name, ref_type) VALUES (?, ?, ?)`, source.Name, source.Git.Credentials.Name, "git_credentials"); err != nil {
			return err
		}
	}

	for _, datasource := range source.Datasources {
		bs, err := json.Marshal(datasource.Config)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_datasources (name, source_name, type, path, config, transform_query) VALUES (?, ?, ?, ?, ?, ?)`,
			datasource.Name, source.Name, datasource.Type, datasource.Path, string(bs), datasource.TransformQuery); err != nil {
			return err
		}
	}

	files, err := source.Files()
	if err != nil {
		return err
	}

	for path, data := range files {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_data (source_name, path, data) VALUES (?, ?, ?)`, source.Name, path, data); err != nil {
			return err
		}
	}

	for _, r := range source.Requirements {
		if r.Source != nil {
			if _, err := tx.Exec(`INSERT OR REPLACE INTO sources_requirements (source_name, requirement_name) VALUES (?, ?)`, source.Name, r.Source); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (d *Database) UpsertSecret(ctx context.Context, principal string, secret *config.Secret) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.prepareUpsert(ctx, tx, principal, "secrets", secret.Name, "secrets.create", "secrets.manage"); err != nil {
		return err
	}

	if len(secret.Value) > 0 {
		bs, err := json.Marshal(secret.Value)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO secrets (name, value) VALUES (?, ?)`, secret.Name, string(bs)); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(`INSERT OR REPLACE INTO secrets (name) VALUES (?)`, secret.Name); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (d *Database) UpsertStack(ctx context.Context, principal string, stack *config.Stack) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.prepareUpsert(ctx, tx, principal, "stacks", stack.Name, "stacks.create", "stacks.manage"); err != nil {
		return err
	}

	bs, err := json.Marshal(stack.Selector)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO stacks (name, selector) VALUES (?, ?)`, stack.Name, string(bs)); err != nil {
		return err
	}

	for _, r := range stack.Requirements {
		if r.Source != nil {
			// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
			if _, err := tx.Exec(`INSERT OR REPLACE INTO stacks_requirements (stack_name, source_name) VALUES (?, ?)`, stack.Name, r.Source); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (d *Database) UpsertToken(ctx context.Context, principal string, token *config.Token) error {

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := d.prepareUpsert(ctx, tx, principal, "tokens", token.Name, "tokens.create", "tokens.manage"); err != nil {
		return err
	}

	if _, err := tx.Exec(`INSERT OR REPLACE INTO tokens (name, api_key) VALUES (?, ?)`, token.Name, token.APIKey); err != nil {
		return err
	}

	if len(token.Scopes) != 1 {
		return fmt.Errorf("exactly one scope must be provided for token %q", token.Name)
	}

	if err := UpsertPrincipalTx(ctx, tx, Principal{Id: token.Name, Role: token.Scopes[0].Role}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

func (d *Database) prepareUpsert(ctx context.Context, tx *sql.Tx, principal, resource, name string, permCreate, permUpdate string) error {

	var a authz.Access

	if err := d.resourceExists(ctx, tx, resource, name); err == nil {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permUpdate,
			Name:       name,
		}
	} else if err == ErrNotFound {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permCreate,
		}
		if _, err := tx.Exec(`INSERT OR REPLACE INTO resource_permissions (name, resource, principal_id, role) VALUES (?, ?, ?, ?)`, name, resource, principal, "owner"); err != nil {
			return err
		}
	} else {
		return err
	}

	if !authz.Check(ctx, tx, a) {
		return ErrNotAuthorized
	}

	return nil
}

func (d *Database) resourceExists(ctx context.Context, tx *sql.Tx, table string, name string) error {
	var exists any
	if err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM %v as T WHERE T.name = ?", table), name).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		return err
	}
	return nil
}
