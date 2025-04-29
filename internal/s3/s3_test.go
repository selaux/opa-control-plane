package s3

import (
	"bytes"
	"context"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/tsandall/lighthouse/internal/config"
	"gopkg.in/yaml.v3"
)

func TestS3(t *testing.T) {
	// Set mock AWS credentials to avoid IMDS errors.
	os.Setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")
	os.Setenv("AWS_REGION", "us-east-1")

	// Create a mock S3 service with a test bucket.

	mock := s3mem.New()
	mock.CreateBucket("test")
	ts := httptest.NewServer(gofakes3.New(mock).Server())
	defer ts.Close()

	ctx := context.Background()

	// Upload a bundle to the mock S3 service.

	cfg := config.AmazonS3{
		Provider: "aws",
		Bucket:   "test",
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	storage, err := New(ctx, data, ts.URL)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	bundle := bytes.NewBuffer([]byte("bundle content"))
	err = storage.Upload(ctx, "a/b/c", bundle)
	if err != nil {
		t.Fatalf("expected no error while uploading bundle: %v", err)
	}

	// Verify that the bundle was uploaded correctly.

	object, err := mock.GetObject("test", "a/b/c", nil)
	if err != nil {
		t.Fatalf("expected no error while getting object: %v", err)
	}

	contents, err := io.ReadAll(object.Contents)
	if err != nil {
		t.Fatalf("expected no error while reading object contents: %v", err)
	}

	if string(contents) != "bundle content" {
		t.Fatalf("expected object contents to be 'bundle content', got '%s'", contents)
	}
}
