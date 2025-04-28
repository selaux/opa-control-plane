// s3 connects Lighthouse to S3-compatible object storages.
package s3

import (
	"context"
	"io"
)

var (
	_ ObjectStorage = (*AmazonS3)(nil)
	_ ObjectStorage = (*GCPCloudStorage)(nil)
	_ ObjectStorage = (*AzureBlobStorage)(nil)
)

type (
	ObjectStorage interface {
		Upload(ctx context.Context, url string, key string, body io.Reader) error
	}

	AmazonS3         struct{}
	GCPCloudStorage  struct{}
	AzureBlobStorage struct{}
)

// NewS3 creates a new S3 client based on the provided configuration.
func NewS3(provider string) (ObjectStorage, error) {
	switch provider {
	case "aws":
		return &AmazonS3{}, nil
	case "gcp":
		return &GCPCloudStorage{}, nil
	case "azure":
		return &AzureBlobStorage{}, nil
	default:
		return nil, ErrUnsupportedProvider
	}
}

// ErrUnsupportedProvider is returned when an unsupported S3 provider is specified.
var ErrUnsupportedProvider = &Error{
	Message: "unsupported object storage provider",
}

type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// Upload uploads a file to the S3-compatible storage.
func (s *AmazonS3) Upload(ctx context.Context, url string, key string, body io.Reader) error {
	// Implementation for uploading to Amazon S3
	return nil
}

func (s *GCPCloudStorage) Upload(ctx context.Context, url string, key string, body io.Reader) error {
	// Implementation for uploading to GCP Cloud Storage
	return nil
}

func (s *AzureBlobStorage) Upload(ctx context.Context, url string, key string, body io.Reader) error {
	// Implementation for uploading to Azure Blob Storage
	return nil
}
