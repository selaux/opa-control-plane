package service_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tsandall/lighthouse/internal/service"
)

func TestDatabaseSystemsData(t *testing.T) {
	ctx := context.Background()

	db := service.New().Database()
	err := db.InitDB(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	defer db.CloseDB()

	data, found, err := db.SystemsDataGet(ctx, "system1", "foo")
	if data != nil || found || err != nil {
		t.Fatalf("expected no data to be found, got %v (%v), err: %v", data, found, err)
	}

	// Test that we can put data

	data = map[string]interface{}{
		"key": "value",
	}
	if err := db.SystemsDataPut(ctx, "system1", "foo", data); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data2, found, err := db.SystemsDataGet(ctx, "system1", "foo")
	if !reflect.DeepEqual(data, data2) || !found || err != nil {
		t.Fatalf("expected data to be found, got %v (%v), err: %v", data, found, err)
	}

	// Test that we can update the data

	data = map[string]interface{}{
		"key": "value2",
	}
	if err := db.SystemsDataPut(ctx, "system1", "foo", data); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	data2, found, err = db.SystemsDataGet(ctx, "system1", "foo")
	if !reflect.DeepEqual(data2, data) || !found || err != nil {
		t.Fatalf("expected data to be found, got %v (%v), err: %v", data2, found, err)
	}

	// Test that we can delete the data

	if err := db.SystemsDataDelete(ctx, "system1", "foo"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	data2, found, err = db.SystemsDataGet(ctx, "system1", "foo")
	if data2 != nil || found || err != nil {
		t.Fatalf("expected no data to be found, got %v (%v), err: %v", data2, found, err)
	}
}
