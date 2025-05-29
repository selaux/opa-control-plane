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
	sources        []*builder.Source
	storage        s3.ObjectStorage
	changed        chan struct{}
	done           chan struct{}
	singleShot     bool
}

type Synchronizer interface {
	Execute(ctx context.Context) error
}

func NewSystemWorker(system *config.System, libraries []*config.Library, stacks []*config.Stack) *SystemWorker {
	return &SystemWorker{systemConfig: system, libraryConfigs: libraries, stackConfigs: stacks, changed: make(chan struct{}), done: make(chan struct{})}
}

func (worker *SystemWorker) WithSynchronizers(synchronizers []Synchronizer) *SystemWorker {
	worker.synchronizers = synchronizers
	return worker
}

func (worker *SystemWorker) WithSources(sources []*builder.Source) *SystemWorker {
	worker.sources = sources
	return worker
}

func (worker *SystemWorker) WithStorage(storage s3.ObjectStorage) *SystemWorker {
	worker.storage = storage
	return worker
}

func (worker *SystemWorker) WithSingleShot(singleShot bool) *SystemWorker {
	worker.singleShot = singleShot
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
		worker.changeConfiguration()
	}
}

// Execute runs a system synchronization iteration: git sync, bundle construct
// and then push bundles to object storage.
func (w *SystemWorker) Execute() time.Time {
	ctx := context.Background()

	// If a configuration change was requested, request the worker to be removed from the pool and signal this worker being done.

	if w.configurationChanged() {
		return w.die()
	}

	// Wipe any old files synchronized during the previous run to avoid deleted files in database/http from reappearing to system bundles.
	for _, src := range w.sources {
		for _, dir := range src.Dirs {
			if dir.Wipe {
				if err := removeDir(dir.Path); err != nil {
					return w.errorf("failed to remove a directory for system %q: %v", w.systemConfig.Name, err)
				}
			}
		}
	}

	for _, synchronizer := range w.synchronizers {
		err := synchronizer.Execute(ctx)
		if err != nil {
			return w.errorf("failed to synchronize system %q: %v", w.systemConfig.Name, err)
		}
	}

	buffer := bytes.NewBuffer(nil)

	b := builder.New().
		WithSources(w.sources).
		WithExcluded(w.systemConfig.ExcludedFiles).
		WithOutput(buffer)

	err := b.Build(ctx)
	if err != nil {
		return w.errorf("failed to build a system bundle %q: %v", w.systemConfig.Name, err)
	}

	if w.storage != nil {
		if err := w.storage.Upload(ctx, bytes.NewReader(buffer.Bytes())); err != nil {
			return w.errorf("failed to upload system bundle %q: %v", w.systemConfig.Name, err)
		}
	}

	return w.success()
}

func (w *SystemWorker) success() time.Time {
	if w.singleShot {
		return w.die()
	}

	return time.Now().Add(successDelay)
}

func (w *SystemWorker) errorf(msg string, args ...interface{}) time.Time {
	log.Printf(msg, args...)

	if w.singleShot {
		return w.die()
	}

	return time.Now().Add(errorDelay)
}

func (w *SystemWorker) changeConfiguration() {
	select {
	case <-w.changed:
	default:
		close(w.changed)
	}
}

func (w *SystemWorker) configurationChanged() bool {
	select {
	case <-w.changed:
		return true
	default:
		return false
	}
}

func (w *SystemWorker) die() time.Time {
	close(w.done)

	var zero time.Time
	return zero
}

func removeDir(path string) error {

	if path == "" {
		return nil
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, f := range files {
		err := os.RemoveAll(filepath.Join(path, f.Name()))
		if err != nil {
			return err
		}
	}

	return nil
}
