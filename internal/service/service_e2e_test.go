package service_test

import (
	"testing"

	"github.com/tsandall/lighthouse/internal/test/tempfs"
)

func TestSystemWithLibraries(t *testing.T) {

	rootDir, cleanup, err := tempfs.MakeTempFS("", "lighthouse_e2e", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	_ = rootDir
}
