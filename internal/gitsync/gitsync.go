// gitsync package implements Git synchronization. It maintains a local filesystem copy for each configured
// git reference. This package implements no threadpooling, it is expected that the caller will handle
// concurrency and parallelism. The Synchronizer is not thread-safe.
package gitsync

import (
	"errors"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/tsandall/lighthouse/internal/config"
)

type Synchronizer struct {
	path   string
	config config.Git
}

// New creates a new Synchronizer instance. It is expected the threadpooling is outside of this package.
// The synchronizer does not validate the path holds the same repository as the config. Therefore, the caller
// should guarantee that the path is unique for each repository and that the path is not used by multiple
// Synchronizer instances. If the path does not exist, it will be created.
func New(path string, config config.Git) *Synchronizer {
	return &Synchronizer{path: path, config: config}
}

// Execute performs the synchronization of the configured Git repository. If the repository does not exist
// on disk, clone it. If it does exist, pull the latest changes and rebase the local branch onto the remote branch.
// TODO: Improve the error handling and to recover from common errors (say, if someone rewrote history on the remote).
func (s *Synchronizer) Execute() error {
	var repository *git.Repository

	// TODO: Authentication.

	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		repository, err = git.PlainClone(s.path, false, &git.CloneOptions{
			URL:               s.config.Repo,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
		})
		if err != nil {
			return err
		}
	} else {
		repository, err = git.PlainOpen(s.path)
		if err != nil {
			return err
		}
	}

	w, err := repository.Worktree()
	if err != nil {
		return err
	}

	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	if s.config.Reference != nil {
		err = w.Checkout(&git.CheckoutOptions{
			Force:  true, // Discard any local changes
			Branch: plumbing.ReferenceName(*s.config.Reference),
		})
	} else if s.config.Commit != nil {
		err = w.Checkout(&git.CheckoutOptions{
			Force: true, // Discard any local changes
			Hash:  plumbing.NewHash(*s.config.Commit),
		})
	} else {
		return errors.New("either reference or commit must be set in git configuration")
	}

	if err != nil {
		return err
	}

	return nil
}
