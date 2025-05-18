package service

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/s3"
)

var (
	errorDelay   = 30 * time.Second
	successDelay = 1 * time.Minute
)

// Each SystemWorker is responsible for synchronizing a system's git repository,
// constructing a bundle from the system and its libraries, and uploading the
// bundle to an object storage service. It uses a git synchronizer to pull the
// latest changes from the system's repository, constructs a bundle using the
// builder package, and uploads the resulting bundle to an S3-compatible object
// storage service.
type SystemWorker struct {
	systemConfig   *config.System
	libraryConfigs []*config.Library
	stackConfigs   []*config.Stack
	synchronizers  []Synchronizer
	system         *builder.SystemSpec
	libraries      []*builder.LibrarySpec
	storage        s3.ObjectStorage
	changed        chan struct{}
	done           chan struct{}
}

type Synchronizer interface {
	Execute(ctx context.Context) error
}

func NewSystemWorker(system *config.System, libraries []*config.Library, stacks []*config.Stack) *SystemWorker {
	return &SystemWorker{systemConfig: system, libraryConfigs: libraries, stackConfigs: stacks, done: make(chan struct{})}
}

func (worker *SystemWorker) WithSynchronizers(synchronizers []Synchronizer) *SystemWorker {
	worker.synchronizers = synchronizers
	return worker
}

func (worker *SystemWorker) WithSystem(system *builder.SystemSpec) *SystemWorker {
	worker.system = system
	return worker
}

func (worker *SystemWorker) WithLibraries(libraries []*builder.LibrarySpec) *SystemWorker {
	worker.libraries = libraries
	return worker
}

func (worker *SystemWorker) WithStorage(storage s3.ObjectStorage) *SystemWorker {
	worker.storage = storage
	return worker
}

func (worker *SystemWorker) Done() bool {
	select {
	case <-worker.done:
		return true
	default:
		return false
	}
}

func (worker *SystemWorker) UpdateConfig(system *config.System, libraries []*config.Library, stacks []*config.Stack) {
	if system == nil || !worker.systemConfig.Equal(system) || !config.EqualLibraries(worker.libraryConfigs, libraries) || !config.EqualStacks(worker.stackConfigs, stacks) {
		select {
		case <-worker.changed:
		default:
			close(worker.changed)
		}
	}
}

// Execute runs a system synchronization iteration: git sync, bundle construct
// and then push bundles to object storage.
func (w *SystemWorker) Execute() time.Time {
	ctx := context.Background()

	// If a configuration change was requested, request the worker to be removed from the pool and signal this worker being done.

	select {
	case <-w.changed:
		close(w.done)
		var zero time.Time
		return zero
	default:
	}

	// Wipe any old files synchronized during the previous run to avoid deleted files in database/http from reappearing to system bundles.
	for _, lib := range w.libraries {
		if next, ok := removeDir(lib.FileDir); ok {
			return next
		}
	}

	if next, ok := removeDir(w.system.FileDir); ok {
		return next
	}

	for _, synchronizer := range w.synchronizers {
		err := synchronizer.Execute(ctx)
		if err != nil {
			log.Printf("failed to synchronize system %q: %v", w.systemConfig.Name, err)
			return time.Now().Add(errorDelay)
		}
	}

	buffer := bytes.NewBuffer(nil)

	b := builder.New().
		WithSystemSpec(w.system).
		WithLibrarySpecs(w.libraries).
		WithOutput(buffer)

	err := b.Build(ctx)
	if err != nil {
		log.Printf("failed to build a system bundle %q: %v", w.systemConfig.Name, err)
		return time.Now().Add(errorDelay)
	}

	if w.storage != nil {
		if err := w.storage.Upload(ctx, bytes.NewReader(buffer.Bytes())); err != nil {
			log.Printf("failed to upload system bundle %q: %v", w.systemConfig.Name, err)
			return time.Now().Add(errorDelay)
		}
	}

	return time.Now().Add(successDelay)
}

func removeDir(path string) (time.Time, bool) {

	if path == "" {
		return time.Time{}, false
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return time.Time{}, false
	}

	files, err := os.ReadDir(path)
	if err != nil {
		log.Printf("failed to read directory %q: %v", path, err)
		return time.Now().Add(errorDelay), true
	}

	for _, f := range files {
		err := os.RemoveAll(filepath.Join(path, f.Name()))
		if err != nil {
			log.Printf("failed to remove file %q: %v", filepath.Join(path, f.Name()), err)
			return time.Now().Add(errorDelay), true
		}
	}

	return time.Time{}, false
}
