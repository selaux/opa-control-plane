package database_test

import (
	"context"
	"log"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/database"
	"github.com/styrainc/lighthouse/internal/service"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestDatabaseSourcesData(t *testing.T) {
	ctx := context.Background()

	type Setup struct {
		Setup    func(ctx context.Context, t *testing.T) testcontainers.Container
		Database func(ctx context.Context, ctr testcontainers.Container) *config.Root
	}

	configs := map[string]Setup{
		"sqlite-memory-only": {
			Database: func(ctx context.Context, ctr testcontainers.Container) *config.Root {
				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "sqlite3",
							DSN:    database.SQLiteMemoryOnlyDSN,
						},
					},
				}
			},
		},
		"sqlite-persistence": {
			Database: func(context.Context, testcontainers.Container) *config.Root {
				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "sqlite3",
							DSN:    filepath.Join(t.TempDir(), "test.db"),
						},
					},
				}
			},
		},
		"postgres": {
			Setup: func(ctx context.Context, t *testing.T) testcontainers.Container {
				ctr, err := postgres.Run(
					ctx,
					"postgres:16-alpine",
					postgres.WithDatabase("db"),
					postgres.WithUsername("user"),
					postgres.WithPassword("password"),
					postgres.BasicWaitStrategies(),
					postgres.WithSQLDriver("pgx"),
				)
				if err != nil {
					t.Fatal("failed to start postgres container:", err)
				}
				return ctr
			},
			Database: func(ctx context.Context, container testcontainers.Container) *config.Root {
				dsn, err := container.(*postgres.PostgresContainer).ConnectionString(ctx)
				if err != nil {
					t.Fatalf("failed to get postgres connection string: %v", err)
				}

				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "postgres",
							DSN:    dsn,
						},
					},
				}
			},
		},
		"mysql": {
			Setup: func(ctx context.Context, t *testing.T) testcontainers.Container {
				ctr, err := mysql.Run(ctx,
					"mysql:8.0",
					mysql.WithDatabase("db"),
					mysql.WithUsername("user"),
					mysql.WithPassword("password"),
				)
				if err != nil {
					t.Fatal("failed to start mysql container:", err)
				}
				return ctr
			},
			Database: func(ctx context.Context, container testcontainers.Container) *config.Root {
				dsn, err := container.(*mysql.MySQLContainer).ConnectionString(ctx)
				if err != nil {
					t.Fatalf("failed to get mysql connection string: %v", err)
				}

				return &config.Root{
					Database: &config.Database{
						SQL: &config.SQLDatabase{
							Driver: "mysql",
							DSN:    dsn,
						},
					},
				}
			},
		},
	}

	for databaseType, databaseConfig := range configs {
		func() {
			var ctr testcontainers.Container
			if databaseConfig.Setup != nil {
				ctr = databaseConfig.Setup(ctx, t)
				defer func() {
					if err := testcontainers.TerminateContainer(ctr); err != nil {
						log.Printf("failed to terminate container: %s", err)
					}
				}()
			}

			db := service.New().WithConfig(databaseConfig.Database(ctx, ctr)).Database()
			err := db.InitDB(ctx)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			defer db.CloseDB()

			if err := db.UpsertPrincipal(ctx, database.Principal{Id: "admin", Role: "administrator"}); err != nil {
				t.Fatal(err)
			}

			if err := db.UpsertSource(ctx, "admin", &config.Source{Name: "system1"}); err != nil {
				t.Fatal(err)
			}

			data1 := map[string]interface{}{
				"key": "value1",
			}
			data2 := map[string]interface{}{
				"key": "value2",
			}

			tests := []*testCase{
				newTestCase("get non-existing data").Get("system1", "foo", nil),
				newTestCase("put data").Put("system1", "foo", data1).Get("system1", "foo", data1),
				newTestCase("update data").Put("system1", "foo", data2).Get("system1", "foo", data2),
				newTestCase("delete").Delete("system1", "foo").Get("system1", "foo", nil),
			}

			for _, test := range tests {
				t.Run(databaseType+"/"+test.note, func(t *testing.T) {
					for _, op := range test.operations {
						op(ctx, t, db)
					}
				})
			}
		}()
	}
}

type testCase struct {
	note       string
	operations []func(ctx context.Context, t *testing.T, db *database.Database)
}

func newTestCase(note string) *testCase {
	return &testCase{
		note:       note,
		operations: nil,
	}
}

func (tc *testCase) Get(srcID, dataID string, expected interface{}) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		data, found, err := db.SourcesDataGet(ctx, srcID, dataID, "admin")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		switch {
		case found && expected == nil:
			t.Fatal("expected no data to be found")
		case !found && expected != nil:
			t.Fatal("expected data to be found")
		case !found && expected == nil:
			// OK
		case found && expected != nil:
			if !reflect.DeepEqual(expected, data) {
				t.Fatalf("expected data not found, got %v", data)
			}
		}
	})
	return tc
}

func (tc *testCase) Put(srcID, dataID string, data interface{}) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.SourcesDataPut(ctx, srcID, dataID, data, "admin"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}

func (tc *testCase) Delete(srcID, dataID string) *testCase {
	tc.operations = append(tc.operations, func(ctx context.Context, t *testing.T, db *database.Database) {
		if err := db.SourcesDataDelete(ctx, srcID, dataID, "admin"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
	return tc
}
