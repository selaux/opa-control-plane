package gitsync

import (
	"context"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/styrainc/lighthouse/internal/config"
)

// TestGitsync tests the functionality of the gitsync package by creating a temporary git repository,
// committing a file, cloning it to a new location using the gitsync, and verifying that the cloned repository contains the expected content.
// It tests both the initial clone and subsequent updates to the repository.
func TestGitsync(t *testing.T) {
	// Create a git repository to use for testing.

	testRepositoryPath := t.TempDir() + "/testing"
	repository, err := git.PlainInit(testRepositoryPath, false)
	if err != nil {
		t.Fatalf("expected no error while initializing test repository: %v", err)
	}

	err = os.WriteFile(testRepositoryPath+"/README", []byte("first commit"), 0644)
	if err != nil {
		t.Fatalf("expected no error while creating new file: %v", err)
	}

	w, err := repository.Worktree()
	if err != nil {
		t.Fatalf("expected no error while getting worktree: %v", err)
	}
	_, err = w.Add("README")
	if err != nil {
		t.Fatalf("expected no error while adding file to worktree: %v", err)
	}

	_, err = w.Commit("README", &git.CommitOptions{Author: &object.Signature{}})
	if err != nil {
		t.Fatalf("expected no error while committing changes: %v", err)
	}

	// Create a new synchronizer with an empty directory to clone a repository into.
	clonedRepositoryPath := t.TempDir() + "/test-repo"

	ref := "refs/heads/master"
	s := New(clonedRepositoryPath, config.Git{
		Repo:      testRepositoryPath,
		Reference: &ref,
		Commit:    nil,
	}, "")

	ctx := context.Background()
	err = s.Execute(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Check if the repository was created successfully.
	_, err = git.PlainOpen(clonedRepositoryPath)
	if err != nil {
		t.Fatalf("expected repository to be opened, got error: %v", err)
	}

	data, err := os.ReadFile(clonedRepositoryPath + "/README")
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if string(data) != "first commit" {
		t.Fatalf("expected file content to be 'first commit', got: %s", string(data))
	}

	// Test synchronization by committing an update to the cloned repository.

	err = os.WriteFile(testRepositoryPath+"/README", []byte("second commit"), 0644)
	if err != nil {
		t.Fatalf("expected no error while creating new file: %v", err)
	}

	_, err = w.Add("README")
	if err != nil {
		t.Fatalf("expected no error while adding file to worktree: %v", err)
	}

	_, err = w.Commit("README", &git.CommitOptions{Author: &object.Signature{}})
	if err != nil {
		t.Fatalf("expected no error while committing changes: %v", err)
	}

	err = s.Execute(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	data, err = os.ReadFile(clonedRepositoryPath + "/README")
	if err != nil {
		t.Fatalf("expected no error while reading file, got: %v", err)
	}

	if string(data) != "second commit" {
		t.Fatalf("expected file content to be 'second commit', got: %s", string(data))
	}
}
