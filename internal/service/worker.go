package service

import (
	"bytes"
	"context"
	"time"

	"github.com/tsandall/lighthouse/internal/builder"
	"github.com/tsandall/lighthouse/internal/config"
	"github.com/tsandall/lighthouse/internal/logging"
	"github.com/tsandall/lighthouse/internal/s3"
)

var (
	errorDelay   = 30 * time.Second
	successDelay = 1 * time.Minute
)

// Each BundleWorker is responsible for constructing a bundle from the source
// dependencies and uploading it to an object storage service. It uses a git
// synchronizer to pull the latest changes from the source repositories,
// constructs a bundle using the builder package, and uploads the resulting
// bundle to an S3-compatible object storage service.
type BundleWorker struct {
	bundleConfig  *config.Bundle
	sourceConfigs []*config.Source
	stackConfigs  []*config.Stack
	synchronizers []Synchronizer
	sources       []*builder.Source
	storage       s3.ObjectStorage
	changed       chan struct{}
	done          chan struct{}
	singleShot    bool
	log           *logging.Logger
}

type Synchronizer interface {
	Execute(ctx context.Context) error
	Close(ctx context.Context)
}

func NewBundleWorker(b *config.Bundle, sources []*config.Source, stacks []*config.Stack, logger *logging.Logger) *BundleWorker {
	return &BundleWorker{
		bundleConfig:  b,
		sourceConfigs: sources,
		stackConfigs:  stacks,
		log:           logger,
		changed:       make(chan struct{}), done: make(chan struct{}),
	}
}

func (worker *BundleWorker) WithSynchronizers(synchronizers []Synchronizer) *BundleWorker {
	worker.synchronizers = synchronizers
	return worker
}

func (worker *BundleWorker) WithSources(sources []*builder.Source) *BundleWorker {
	worker.sources = sources
	return worker
}

func (worker *BundleWorker) WithStorage(storage s3.ObjectStorage) *BundleWorker {
	worker.storage = storage
	return worker
}

func (worker *BundleWorker) WithSingleShot(singleShot bool) *BundleWorker {
	worker.singleShot = singleShot
	return worker
}

func (worker *BundleWorker) Done() bool {
	select {
	case <-worker.done:
		return true
	default:
		return false
	}
}

func (worker *BundleWorker) UpdateConfig(b *config.Bundle, sources []*config.Source, stacks []*config.Stack) {
	if b == nil || !worker.bundleConfig.Equal(b) || !config.EqualSources(worker.sourceConfigs, sources) || !config.EqualStacks(worker.stackConfigs, stacks) {
		worker.changeConfiguration()
	}
}

// Execute runs a bundle synchronization iteration: git sync, bundle construct
// and then push bundles to object storage.
func (w *BundleWorker) Execute(ctx context.Context) time.Time {
	// If a configuration change was requested, request the worker to be removed from the pool and signal this worker being done.

	if w.configurationChanged() {
		return w.die(ctx)
	}

	// Wipe any old files synchronized during the previous run to avoid deleted files in database/http from reappearing to bundle bundles.
	for _, src := range w.sources {
		if err := src.Wipe(); err != nil {
			return w.warn(ctx, "failed to remove a directory for bundle %q: %v", w.bundleConfig.Name, err)
		}
	}

	for _, synchronizer := range w.synchronizers {
		err := synchronizer.Execute(ctx)
		if err != nil {
			return w.warn(ctx, "failed to synchronize bundle %q: %v", w.bundleConfig.Name, err)
		}
	}

	for _, src := range w.sources {
		if err := src.Transform(ctx); err != nil {
			return w.warn(ctx, "failed to evaluate source %q for bundle %q: %v", src.Name, w.bundleConfig.Name, err)
		}
	}

	buffer := bytes.NewBuffer(nil)

	b := builder.New().
		WithSources(w.sources).
		WithExcluded(w.bundleConfig.ExcludedFiles).
		WithOutput(buffer)

	err := b.Build(ctx)
	if err != nil {
		return w.warn(ctx, "failed to build a bundle %q: %v", w.bundleConfig.Name, err)
	}

	if w.storage != nil {
		if err := w.storage.Upload(ctx, bytes.NewReader(buffer.Bytes())); err != nil {
			return w.warn(ctx, "failed to upload bundle %q: %v", w.bundleConfig.Name, err)
		}

		return w.success(ctx, "Bundle %q built and uploaded.", w.bundleConfig.Name)
	}

	return w.success(ctx, "Bundle %q built.", w.bundleConfig.Name)
}

func (w *BundleWorker) success(ctx context.Context, msg string, args ...interface{}) time.Time {
	w.log.Debugf(msg, args...)

	if w.singleShot {
		return w.die(ctx)
	}

	return time.Now().Add(successDelay)
}

func (w *BundleWorker) warn(ctx context.Context, msg string, args ...interface{}) time.Time {
	w.log.Warnf(msg, args...)

	if w.singleShot {
		return w.die(ctx)
	}

	return time.Now().Add(errorDelay)
}

func (w *BundleWorker) changeConfiguration() {
	select {
	case <-w.changed:
	default:
		close(w.changed)
	}
}

func (w *BundleWorker) configurationChanged() bool {
	select {
	case <-w.changed:
		return true
	default:
		return false
	}
}

func (w *BundleWorker) die(ctx context.Context) time.Time {
	for _, synchronizer := range w.synchronizers {
		synchronizer.Close(ctx)
	}

	close(w.done)

	var zero time.Time
	return zero
}
