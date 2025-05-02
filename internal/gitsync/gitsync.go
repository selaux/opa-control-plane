// gitsync package implements Git synchronization. It maintains a local filesystem copy for each configured
// git reference. This package implements no threadpooling, it is expected that the caller will handle
// concurrency and parallelism. The Synchronizer is not thread-safe.
package gitsync

import (
	"errors"
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
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
func (s *Synchronizer) Execute() error {
	var repository *git.Repository

	authMethod, err := s.auth()
	if err != nil {
		// TODO: Validate the config earlier.
		return err
	}

	var referenceName plumbing.ReferenceName
	if s.config.Reference != nil {
		referenceName = plumbing.ReferenceName(*s.config.Reference)
	}

	if _, err := os.Stat(s.path); os.IsNotExist(err) {
		repository, err = git.PlainClone(s.path, false, &git.CloneOptions{
			URL:               s.config.Repo,
			Auth:              authMethod,
			RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
			ReferenceName:     referenceName,
			SingleBranch:      true,
			NoCheckout:        true, // We will checkout later
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

	err = w.Pull(&git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: referenceName,
		Auth:          authMethod,
		Force:         true,
		SingleBranch:  true,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	var checkoutOpts *git.CheckoutOptions

	if s.config.Reference != nil {
		checkoutOpts = &git.CheckoutOptions{
			Force:  true, // Discard any local changes
			Branch: plumbing.ReferenceName(*s.config.Reference),
		}
	} else if s.config.Commit != nil {
		checkoutOpts = &git.CheckoutOptions{
			Force: true, // Discard any local changes
			Hash:  plumbing.NewHash(*s.config.Commit),
		}
	} else {
		return errors.New("either reference or commit must be set in git configuration")
	}

	if s.config.Path != nil {
		checkoutOpts.SparseCheckoutDirectories = []string{*s.config.Path}
	}

	return w.Checkout(checkoutOpts)
}

func (s *Synchronizer) auth() (transport.AuthMethod, error) {

	if s.config.Credentials == nil {
		return nil, nil
	}

	secret, err := s.config.Credentials.Resolve()
	if err != nil {
		return nil, err
	}

	switch secret.Value["type"] {
	case "http_basic_auth":
		return &http.BasicAuth{
			Username: secret.Value["username"].(string),
			Password: secret.Value["password"].(string),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", secret.Value["type"])
	}
}
