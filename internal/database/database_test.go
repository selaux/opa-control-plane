package database_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/styrainc/lighthouse/internal/config"
	"github.com/styrainc/lighthouse/internal/database"
	"github.com/styrainc/lighthouse/internal/service"
)

func TestDatabaseSourcesData(t *testing.T) {
	ctx := context.Background()

	db := service.New().Database()
	err := db.InitDB(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := db.UpsertPrincipal(ctx, database.Principal{Id: "admin", Role: "administrator"}); err != nil {
		t.Fatal(err)
	}

	if err := db.UpsertSource(ctx, "admin", &config.Source{Name: "system1"}); err != nil {
		t.Fatal(err)
	}

	defer db.CloseDB()

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
		t.Run(test.note, func(t *testing.T) {
			for _, op := range test.operations {
				op(ctx, t, db)
			}
		})
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
