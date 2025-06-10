// gitsync package implements Git synchronization. It maintains a local filesystem copy for each configured
// git reference. This package implements no threadpooling, it is expected that the caller will handle
// concurrency and parallelism. The Synchronizer is not thread-safe.
package gitsync

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	gohttp "net/http"
	"os"
	"sync"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/tsandall/lighthouse/internal/config"
)

type Synchronizer struct {
	path   string
	config config.Git
	gh     github
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
func (s *Synchronizer) Execute(ctx context.Context) error {
	var repository *git.Repository

	authMethod, err := s.auth(ctx)
	if err != nil {
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

	remote := "origin"

	err = repository.FetchContext(ctx, &git.FetchOptions{
		RemoteName: remote,
		Auth:       authMethod,
		Force:      true,
		RefSpecs:   []gitconfig.RefSpec{gitconfig.RefSpec(fmt.Sprintf("+refs/heads/*:refs/remotes/%s/refs/heads/*", remote))},
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	w, err := repository.Worktree()
	if err != nil {
		return err
	}

	var checkoutOpts *git.CheckoutOptions

	if s.config.Reference != nil {
		ref := fmt.Sprintf("refs/remotes/%s/%s", remote, *s.config.Reference)
		checkoutOpts = &git.CheckoutOptions{
			Force:  true, // Discard any local changes
			Branch: plumbing.ReferenceName(ref),
		}
	} else if s.config.Commit != nil {
		checkoutOpts = &git.CheckoutOptions{
			Force: true, // Discard any local changes
			Hash:  plumbing.NewHash(*s.config.Commit),
		}
	} else {
		return errors.New("either reference or commit must be set in git configuration")
	}

	return w.Checkout(checkoutOpts)
}

func (s *Synchronizer) Close(ctx context.Context) {
	// No resources to close.
}

func (s *Synchronizer) auth(ctx context.Context) (transport.AuthMethod, error) {

	if s.config.Credentials == nil {
		return nil, nil
	}

	secret, err := s.config.Credentials.Resolve()
	if err != nil {
		return nil, err
	}

	value, err := secret.Get(ctx)
	if err != nil {
		return nil, err
	}

	switch value["type"] {
	case "http_basic_auth":
		username, _ := value["username"].(string)
		password, _ := value["password"].(string)
		return &http.BasicAuth{
			Username: username,
			Password: password,
		}, nil
	case "github_app":
		integrationID, _ := value["integration_id"].(int64)
		installationID, _ := value["installation_id"].(int64)
		privateKey, _ := value["private_key"].(string)

		token, err := s.gh.Token(ctx, integrationID, installationID, privateKey)
		if err != nil {
			return nil, err
		}

		return &http.TokenAuth{
			Token: token,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", value["type"])
	}
}

type github struct {
	integrationID  int64
	installationID int64
	privateKey     []byte
	tr             *ghinstallation.Transport
	mu             sync.Mutex
}

func (gh *github) Token(ctx context.Context, integrationID, installationID int64, privateKeyFile string) (string, error) {
	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return "", err
	}

	tr, err := gh.transport(integrationID, installationID, privateKey)
	if err != nil {
		return "", err
	}

	token, err := tr.Token(ctx)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (gh *github) transport(integrationID, installationID int64, privateKey []byte) (*ghinstallation.Transport, error) {
	gh.mu.Lock()
	defer gh.mu.Unlock()

	if gh.tr == nil || gh.integrationID != integrationID || gh.installationID != installationID || !bytes.Equal(gh.privateKey, privateKey) {
		tr, err := ghinstallation.New(gohttp.DefaultTransport, integrationID, installationID, privateKey)
		if err != nil {
			return nil, err
		}

		gh.integrationID = integrationID
		gh.installationID = installationID
		gh.privateKey = privateKey
		gh.tr = tr
	}

	return gh.tr, nil
}
