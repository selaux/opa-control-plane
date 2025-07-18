package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib" // database/sql compatible driver for pgx
	"github.com/styrainc/lighthouse/internal/authz"
	"github.com/styrainc/lighthouse/internal/aws"
	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/logging"
	"github.com/styrainc/lighthouse/internal/progress"
	_ "modernc.org/sqlite"
)

const (
	sqlite = iota
	postgres
	mysql
)

const SQLiteMemoryOnlyDSN = "file::memory:?cache=shared"

// Database implements the database operations. It will hide any differences between the varying SQL databases from the rest of the codebase.
type Database struct {
	db     *sql.DB
	config *config.Database
	kind   int
	log    *logging.Logger
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

func (d *Database) WithLogger(log *logging.Logger) *Database {
	d.log = log
	return d
}

func (d *Database) InitDB(ctx context.Context) error {
	switch {
	case d.config != nil && d.config.AWSRDS != nil:
		// There are three options for authentication to Amazon RDS:
		//
		// 1. Using a secret of type "password". This requires the database user configured with the password.
		// 2. Using a secret of type "aws_auth". The secret stores the AWS credentials to use to authenticate to the database. The database
		//    has no password configured for the user.
		// 3. Using no secret at all. In this case, the AWS SDK will use the default credential provider chain to authenticate to the database. It proceeds
		//    the following in order:
		//    a) Environment variables.
		//    b) Shared credentials file.
		//    c) If your application uses an ECS task definition or RunTask API operation, IAM role for tasks.
		//    d) If your application is running on an Amazon EC2 instance, IAM role for Amazon EC2.
		//
		// In case of the second and third option, the SQL driver will use the AWS SDK to regenerate an authentication token for
		// the database user as necessary.

		config := d.config.AWSRDS
		drv := config.Driver
		endpoint := config.Endpoint
		region := config.Region
		dbUser := config.DatabaseUser
		dbName := config.DatabaseName
		rootCertificates := config.RootCertificates

		var authCallback func(ctx context.Context) (string, error)

		if d.config.AWSRDS.Credentials != nil {
			// Authentication options 1 and 2:
			authCallback = func(ctx context.Context) (string, error) {
				secret, err := d.config.AWSRDS.Credentials.Resolve()
				if err != nil {
					return "", err
				}

				var password string

				if secret.Value != nil {
					switch t, _ := secret.Value["type"].(string); t {
					case "password":
						password, _ = secret.Value["password"].(string)
						if password == "" {
							return "", fmt.Errorf("missing or invalid password value in secret %q", d.config.AWSRDS.Credentials.Name)
						}

					case "aws_auth":
						credentials := aws.NewSecretCredentialsProvider(d.config.AWSRDS.Credentials)
						password, err = auth.BuildAuthToken(ctx, endpoint, region, dbUser, credentials)
						if err != nil {
							return "", err
						}

					default:
						return "", fmt.Errorf("unsupported secret type '%s' for RDS credentials", t)
					}
				}

				d.log.Debugf("Using a secret for RDS authentication at %s", endpoint)

				return password, nil
			}

		} else {
			// Authentication option 3: no explicit credentials configured, use AWS default credential provider chain.

			var options []func(*awsconfig.LoadOptions) error

			if region != "" {
				options = append(options, awsconfig.WithRegion(region))
			}

			cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
			if err != nil {
				return err
			}

			authCallback = func(ctx context.Context) (string, error) {
				return auth.BuildAuthToken(ctx, endpoint, region, dbUser, cfg.Credentials)
			}

			d.log.Debugf("Using AWS default credential provider chain for RDS authentication at %s", endpoint)
		}

		var connector driver.Connector

		switch drv {
		case "postgres":
			drv = "pgx" // Convenience
			fallthrough
		case "pgx":
			dbHost, dbPort, found := strings.Cut(endpoint, ":")
			if !found {
				return fmt.Errorf("invalid endpoint format, expected host:port, got %s", endpoint)
			}

			port, err := strconv.Atoi(dbPort)
			if err != nil {
				return fmt.Errorf("invalid port in endpoint, expected host:port, got %s", endpoint)
			}

			if port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port number in endpoint, expected host:port, got %s", endpoint)
			}

			var cfg *pgx.ConnConfig
			if config.DSN != "" {
				cfg, err = pgx.ParseConfig(config.DSN)
				if err != nil {
					return err
				}

			} else {
				password, err := authCallback(ctx)
				if err != nil {
					return err
				}

				dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=require", dbHost, port, dbUser, password, dbName)
				cfg, err = pgx.ParseConfig(dsn)
				if err != nil {
					return err
				}
			}

			connector = stdlib.GetConnector(*cfg)
			d.kind = postgres

		case "mysql":
			tlsConfigName := "true"
			if rootCertificates != "" {
				rootCertPool := x509.NewCertPool()
				pem, err := os.ReadFile(rootCertificates)
				if err != nil {
					return err
				}

				if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
					return fmt.Errorf("failed to process X.509 root certificate PEM file")
				}

				mysqldriver.RegisterTLSConfig("custom", &tls.Config{
					RootCAs: rootCertPool,
				})
				tlsConfigName = "custom"
			}

			var cfg *mysqldriver.Config
			var err error

			if config.DSN != "" {
				cfg, err = mysqldriver.ParseDSN(config.DSN)
			} else {
				var password string
				password, err = authCallback(ctx)
				if err != nil {
					return err
				}

				cfg = &mysqldriver.Config{
					User:                    dbUser,
					Passwd:                  password,
					Net:                     "tcp",
					Addr:                    endpoint,
					DBName:                  dbName,
					AllowCleartextPasswords: true,
					AllowNativePasswords:    true,
					AllowOldPasswords:       true,
					TLSConfig:               tlsConfigName,
				}

				err = cfg.Apply(mysqldriver.BeforeConnect(func(ctx context.Context, config *mysqldriver.Config) (err error) {
					config.Passwd, err = authCallback(ctx)
					return err
				}))
			}

			if err != nil {
				return err
			}

			connector, err = mysqldriver.NewConnector(cfg)
			if err != nil {
				return err
			}

			d.kind = mysql
		default:
			return fmt.Errorf("unsupported AWS RDS driver: %s", drv)
		}

		d.db = sql.OpenDB(connector)

		d.log.Debugf("Connected to %s RDS instance at %s", drv, endpoint)

	case d.config == nil:
		// Default to memory-only SQLite3 if no config is provided.
		fallthrough
	case d.config != nil && d.config.SQL != nil && (d.config.SQL.Driver == "sqlite3" || d.config.SQL.Driver == "sqlite"):
		var dsn string
		if d.config != nil && d.config.SQL != nil && d.config.SQL.DSN != "" {
			dsn = d.config.SQL.DSN
		} else {
			dsn = SQLiteMemoryOnlyDSN
		}

		d.kind = sqlite

		var err error
		d.db, err = sql.Open("sqlite", dsn)
		if err != nil {
			return err
		}

		if _, err := d.db.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
			return err
		}
	case d.config != nil && d.config.SQL != nil && (d.config.SQL.Driver == "postgres" || d.config.SQL.Driver == "pgx"):
		dsn := d.config.SQL.DSN
		d.kind = postgres

		var err error
		d.db, err = sql.Open("pgx", dsn)
		if err != nil {
			return err
		}

	case d.config != nil && d.config.SQL != nil && d.config.SQL.Driver == "mysql":
		dsn := d.config.SQL.DSN
		d.kind = mysql

		var err error
		d.db, err = sql.Open("mysql", dsn)
		if err != nil {
			return err
		}

	default:
		return errors.New("unsupported database connection type")
	}

	for _, table := range schema {
		if _, err := d.db.Exec(table.SQL(d.kind)); err != nil {
			return err
		}
	}

	return nil
}

func (d *Database) CloseDB() {
	d.db.Close()
}

func (d *Database) SourcesDataGet(ctx context.Context, sourceName, path string, principal string) (interface{}, bool, error) {
	return tx3(ctx, d, func(tx *sql.Tx) (interface{}, bool, error) {
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

		rows, err := tx.Query(fmt.Sprintf(`SELECT
	data
FROM
	sources_data
WHERE source_name = %s AND path = %s AND (`+expr.SQL()+")", d.arg(0), d.arg(1)), sourceName, path)
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
	})
}

func (d *Database) SourcesDataPut(ctx context.Context, sourceName, path string, data interface{}, principal string) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
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
			return fmt.Errorf("unauthorized")
		}

		bs, err := json.Marshal(data)
		if err != nil {
			return err
		}

		return d.upsert(ctx, tx, "sources_data", []string{"source_name", "path", "data"}, []string{"source_name", "path"}, sourceName, path, bs)
	})
}

func (d *Database) SourcesDataDelete(ctx context.Context, sourceName, path string, principal string) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
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

		_, err = tx.Exec(fmt.Sprintf(`DELETE FROM sources_data WHERE source_name = %s AND path = %s AND (`+expr.SQL()+")", d.arg(0), d.arg(1)), sourceName, path)
		return err
	})
}

// LoadConfig loads the configuration from the configuration file into the database.
func (d *Database) LoadConfig(ctx context.Context, bar *progress.Bar, principal string, root *config.Root) error {

	bar.AddMax(len(root.Sources) + len(root.Stacks) + len(root.Secrets) + len(root.Tokens))

	for _, secret := range root.SortedSecrets() {
		if err := d.UpsertSecret(ctx, principal, secret); err != nil {
			return fmt.Errorf("upsert secret %q failed: %w", secret.Name, err)
		}
		bar.Add(1)
	}

	sources, err := root.TopologicalSortedSources()
	if err != nil {
		return err
	}

	for _, src := range sources {
		if err := d.UpsertSource(ctx, principal, src); err != nil {
			return fmt.Errorf("upsert source %q failed: %w", src.Name, err)
		}
		bar.Add(1)
	}

	for _, b := range root.SortedBundles() {
		if err := d.UpsertBundle(ctx, principal, b); err != nil {
			return fmt.Errorf("upsert bundle %q failed: %w", b.Name, err)
		}
		bar.Add(1)
	}

	for _, stack := range root.SortedStacks() {
		if err := d.UpsertStack(ctx, principal, stack); err != nil {
			return fmt.Errorf("upsert stack %q failed: %w", stack.Name, err)
		}
		bar.Add(1)
	}
	for _, token := range root.Tokens {
		if err := d.UpsertToken(ctx, principal, token); err != nil {
			return fmt.Errorf("upsert token %q failed: %w", token.Name, err)
		}
		bar.Add(1)
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
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.Bundle, string, error) {
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

		// TODO: object storage credential types beyond aws.
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
			query += fmt.Sprintf(" AND (bundles.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			query += fmt.Sprintf(" AND (bundles.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		query += " ORDER BY bundles.id"
		if opts.Limit > 0 {
			query += fmt.Sprintf(" LIMIT %s", d.arg(len(args)))
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
	})
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

// ListSources returns a list of sources in the database. Note it does not return the source data.
func (d *Database) ListSources(ctx context.Context, principal string, opts ListOptions) ([]*config.Source, string, error) {
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.Source, string, error) {
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
	sources.git_excluded_files,
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
WHERE (sources_secrets.ref_type = 'git_credentials' OR sources_secrets.ref_type IS NULL) AND (` + expr.SQL() + ")"

		var args []any

		if opts.name != "" {
			query += fmt.Sprintf(" AND (sources.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			query += fmt.Sprintf(" AND (sources.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		query += " ORDER BY sources.id"
		if opts.Limit > 0 {
			query += fmt.Sprintf(" LIMIT %s", d.arg(len(args)))
			args = append(args, opts.Limit)
		}

		rows, err := txn.Query(query, args...)
		if err != nil {
			return nil, "", err
		}
		defer rows.Close()

		type sourceRow struct {
			id                                               int64
			sourceName                                       string
			builtin                                          *string
			repo                                             string
			ref, gitCommit, path, includePaths, excludePaths *string
			secretName, secretRefType, secretValue           *string
			requirementName                                  *string
		}

		srcMap := make(map[string]*config.Source)
		idMap := make(map[string]int64)
		var last int64

		for rows.Next() {
			var row sourceRow
			if err := rows.Scan(&row.id, &row.sourceName, &row.builtin, &row.repo, &row.ref, &row.gitCommit, &row.path, &row.includePaths, &row.excludePaths, &row.secretName, &row.secretRefType, &row.secretValue, &row.requirementName); err != nil {
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
				if row.excludePaths != nil {
					if err := json.Unmarshal([]byte(*row.excludePaths), &src.Git.ExcludedFiles); err != nil {
						return nil, "", fmt.Errorf("failed to unmarshal exclude paths for %q: %w", src.Name, err)
					}
				}
			}

			if row.secretRefType != nil && *row.secretRefType == "git_credentials" && row.secretName != nil {
				s := config.Secret{Name: *row.secretName}
				if row.secretValue != nil {
					if err := json.Unmarshal([]byte(*row.secretValue), &s.Value); err != nil {
						return nil, "", err
					}
				}
				src.Git.Credentials = s.Ref()
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
	})
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
	return tx3(ctx, d, func(txn *sql.Tx) ([]*config.Stack, string, error) {
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
			query += fmt.Sprintf(" AND (stacks.name = %s)", d.arg(len(args)))
			args = append(args, opts.name)
		}

		if after := opts.cursor(); after > 0 {
			query += fmt.Sprintf(" AND (stacks.id > %s)", d.arg(len(args)))
			args = append(args, after)
		}
		query += " ORDER BY stacks.id"
		if opts.Limit > 0 {
			query += fmt.Sprintf(" LIMIT %s", d.arg(len(args)))
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
	})
}

func (d *Database) QuerySourceData(ctx context.Context, sourceName string) (*DataCursor, error) {
	rows, err := d.db.QueryContext(ctx, fmt.Sprintf(`SELECT
	path,
	data
FROM
	sources_data
WHERE
	source_name = %s`, d.arg(0)), sourceName)
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
	return tx1(ctx, d, func(tx *sql.Tx) error {
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

		if err := d.upsert(ctx, tx, "bundles", []string{"name", "labels", "s3url", "s3region", "s3bucket", "s3key", "filepath", "excluded"}, []string{"name"},
			bundle.Name, string(labels), s3url, s3region, s3bucket, s3key, filepath, string(excluded)); err != nil {
			return err
		}

		if bundle.ObjectStorage.AmazonS3 != nil {
			if bundle.ObjectStorage.AmazonS3.Credentials != nil {
				if err := d.upsert(ctx, tx, "bundles_secrets", []string{"bundle_name", "secret_name", "ref_type"}, []string{"bundle_name", "secret_name"},
					bundle.Name, bundle.ObjectStorage.AmazonS3.Credentials.Name, "aws"); err != nil {
					return err
				}
			}
		}

		for _, src := range bundle.Requirements {
			if src.Source != nil {
				// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
				if err := d.upsert(ctx, tx, "bundles_requirements", []string{"bundle_name", "source_name"}, []string{"bundle_name", "source_name"},
					bundle.Name, src.Source); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (d *Database) UpsertSource(ctx context.Context, principal string, source *config.Source) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "sources", source.Name, "sources.create", "sources.manage"); err != nil {
			return err
		}

		includedFiles, err := json.Marshal(source.Git.IncludedFiles)
		if err != nil {
			return err
		}

		excludedFiles, err := json.Marshal(source.Git.ExcludedFiles)
		if err != nil {
			return err
		}

		if err := d.upsert(ctx, tx, "sources", []string{"name", "builtin", "repo", "ref", "gitcommit", "path", "git_included_files", "git_excluded_files"}, []string{"name"},
			source.Name, source.Builtin, source.Git.Repo, source.Git.Reference, source.Git.Commit, source.Git.Path, string(includedFiles), string(excludedFiles)); err != nil {
			return err
		}

		if source.Git.Credentials != nil {
			if err := d.upsert(ctx, tx, "sources_secrets", []string{"source_name", "secret_name", "ref_type"}, []string{"source_name", "secret_name"},
				source.Name, source.Git.Credentials.Name, "git_credentials"); err != nil {
				return err
			}
		}

		for _, datasource := range source.Datasources {
			bs, err := json.Marshal(datasource.Config)
			if err != nil {
				return err
			}

			if err := d.upsert(ctx, tx, "sources_datasources", []string{"source_name", "name", "type", "path", "config", "transform_query"},
				[]string{"source_name", "name"},
				source.Name, datasource.Name, datasource.Type, datasource.Path, string(bs), datasource.TransformQuery); err != nil {
				return err
			}
		}

		files, err := source.Files()
		if err != nil {
			return err
		}

		for path, data := range files {
			if err := d.upsert(ctx, tx, "sources_data", []string{"source_name", "path", "data"}, []string{"source_name", "path"}, source.Name, path, []byte(data)); err != nil {
				return err
			}
		}

		for _, r := range source.Requirements {
			if r.Source != nil {
				if err := d.upsert(ctx, tx, "sources_requirements", []string{"source_name", "requirement_name"}, []string{"source_name", "requirement_name"}, source.Name, r.Source); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (d *Database) UpsertSecret(ctx context.Context, principal string, secret *config.Secret) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "secrets", secret.Name, "secrets.create", "secrets.manage"); err != nil {
			return err
		}

		if len(secret.Value) > 0 {
			bs, err := json.Marshal(secret.Value)
			if err != nil {
				return err
			}

			return d.upsert(ctx, tx, "secrets", []string{"name", "value"}, []string{"name"}, secret.Name, string(bs))
		}

		return d.upsert(ctx, tx, "secrets", []string{"name", "value"}, []string{"name"}, secret.Name, nil)
	})
}

func (d *Database) UpsertStack(ctx context.Context, principal string, stack *config.Stack) error {
	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "stacks", stack.Name, "stacks.create", "stacks.manage"); err != nil {
			return err
		}

		bs, err := json.Marshal(stack.Selector)
		if err != nil {
			return err
		}

		if err := d.upsert(ctx, tx, "stacks", []string{"name", "selector"}, []string{"name"}, stack.Name, string(bs)); err != nil {
			return err
		}

		for _, r := range stack.Requirements {
			if r.Source != nil {
				// TODO: add support for mounts on requirements; currently that is only used internally for stacks.
				if err := d.upsert(ctx, tx, "stacks_requirements", []string{"stack_name", "source_name"}, []string{"stack_name", "source_name"}, stack.Name, r.Source); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func (d *Database) UpsertToken(ctx context.Context, principal string, token *config.Token) error {

	if len(token.Scopes) != 1 {
		return fmt.Errorf("exactly one scope must be provided for token %q", token.Name)
	}

	return tx1(ctx, d, func(tx *sql.Tx) error {
		if err := d.prepareUpsert(ctx, tx, principal, "tokens", token.Name, "tokens.create", "tokens.manage"); err != nil {
			return err
		}

		if err := d.upsert(ctx, tx, "tokens", []string{"name", "api_key"}, []string{"name"}, token.Name, token.APIKey); err != nil {
			return err
		}

		return d.UpsertPrincipalTx(ctx, tx, Principal{Id: token.Name, Role: token.Scopes[0].Role})
	})
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
	} else if errors.Is(err, ErrNotFound) {
		a = authz.Access{
			Principal:  principal,
			Resource:   resource,
			Permission: permCreate,
		}
		if err := d.upsert(ctx, tx, "resource_permissions", []string{"name", "resource", "principal_id", "role"}, []string{"name", "resource"}, name, resource, principal, "owner"); err != nil {
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
	err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT 1 FROM %v as T WHERE T.name = %s", table, d.arg(0)), name).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (d *Database) upsert(ctx context.Context, tx *sql.Tx, table string, columns []string, primaryKey []string, values ...any) error {
	if err := checkTablePrimaryKey(table, primaryKey); err != nil {
		return err
	}

	var query string
	switch d.kind {
	case sqlite:
		query = fmt.Sprintf(`INSERT OR REPLACE INTO %s (%s) VALUES (%s)`, table, strings.Join(columns, ", "),
			strings.Join(d.args(len(columns)), ", "))

	case postgres:
		set := make([]string, 0, len(columns))
		for i := range columns {
			if !slices.Contains(primaryKey, columns[i]) { // do not update primary key columns
				set = append(set, fmt.Sprintf("%s = EXCLUDED.%s", columns[i], columns[i]))
			}
		}

		values := d.args(len(columns))

		if len(set) == 0 {
			query = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO NOTHING`, table, strings.Join(columns, ", "),
				strings.Join(values, ", "),
				strings.Join(primaryKey, ", "))
		} else {
			query = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s`, table, strings.Join(columns, ", "),
				strings.Join(values, ", "),
				strings.Join(primaryKey, ", "),
				strings.Join(set, ", "))
		}

	case mysql:
		set := make([]string, 0, len(columns))
		for i := range columns {
			set = append(set, fmt.Sprintf("%s = VALUES(%s)", columns[i], columns[i]))
		}

		values := d.args(len(columns))

		query = fmt.Sprintf(`INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE %s`, table, strings.Join(columns, ", "),
			strings.Join(values, ", "),
			strings.Join(set, ", "))
	}

	_, err := tx.ExecContext(ctx, query, values...)
	return err
}

func (d *Database) arg(i int) string {
	if d.kind == postgres {
		return "$" + strconv.Itoa(i+1)
	}
	return "?"
}

func (d *Database) args(n int) []string {
	args := make([]string, n)
	for i := 0; i < n; i++ {
		args[i] = d.arg(i)
	}

	return args
}

func tx1(ctx context.Context, db *Database, f func(tx *sql.Tx) error) error {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer tx.Rollback()

	if err := f(tx); err != nil {
		return err
	}

	return tx.Commit()
}

func tx3[T any, U bool | string](ctx context.Context, db *Database, f func(tx *sql.Tx) (T, U, error)) (T, U, error) {
	tx, err := db.db.BeginTx(ctx, nil)
	if err != nil {
		var t T
		var u U
		return t, u, err
	}

	defer tx.Rollback()

	result, result2, err := f(tx)
	if err != nil {
		var t T
		var u U
		return t, u, err
	}

	if err := tx.Commit(); err != nil {
		var t T
		var u U
		return t, u, err
	}

	return result, result2, nil
}
