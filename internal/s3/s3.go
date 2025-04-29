// s3 connects Lighthouse to S3-compatible object storages.
package s3

import (
	"context"
	"io"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/tsandall/lighthouse/internal/config"
	"gopkg.in/yaml.v3"
)

var (
	_ ObjectStorage = (*AmazonS3)(nil)
	_ ObjectStorage = (*GCPCloudStorage)(nil)
	_ ObjectStorage = (*AzureBlobStorage)(nil)
)

type (
	ObjectStorage interface {
		Upload(ctx context.Context, key string, body io.Reader) error
	}

	AmazonS3 struct {
		bucket   string
		uploader *manager.Uploader
	}

	GCPCloudStorage struct {
		project string
		bucket  string
		client  *storage.Client
	}

	AzureBlobStorage struct {
		container string
		client    *azblob.Client
	}
)

// New creates a new S3 client based on the provided configuration.
func New(ctx context.Context, data []byte, localMockURL string) (ObjectStorage, error) {
	var commonCfg config.ObjectStorage
	err := yaml.Unmarshal(data, &commonCfg)
	if err != nil {
		return nil, err
	}

	switch commonCfg.Provider {
	case "aws":
		var parsedCfg config.AmazonS3
		if err := yaml.Unmarshal(data, &parsedCfg); err != nil {
			return nil, err
		}

		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}

		client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			if localMockURL != "" {
				o.UsePathStyle = true
				o.BaseEndpoint = aws.String(localMockURL)
			}
		})

		return &AmazonS3{bucket: parsedCfg.Bucket, uploader: manager.NewUploader(client)}, nil
	case "gcp":
		var parsedCfg config.GCPCloudStorage
		if err := yaml.Unmarshal(data, &parsedCfg); err != nil {
			return nil, err
		}

		client, err := storage.NewClient(ctx)
		if err != nil {
			return nil, err
		}

		return &GCPCloudStorage{project: parsedCfg.Project, bucket: parsedCfg.Bucket, client: client}, nil
	case "azure":
		var parsedCfg config.AzureBlobStorage
		if err := yaml.Unmarshal(data, &parsedCfg); err != nil {
			return nil, err
		}

		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, err
		}
		client, err := azblob.NewClient(parsedCfg.AccountURL, credential, nil)
		if err != nil {
			return nil, err
		}

		return &AzureBlobStorage{container: parsedCfg.Container, client: client}, nil
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
func (s *AmazonS3) Upload(ctx context.Context, key string, body io.Reader) error {
	_, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   body,
	})
	return err
}

func (s *GCPCloudStorage) Upload(ctx context.Context, key string, body io.Reader) error {
	w := s.client.Bucket(s.bucket).Object(key).NewWriter(ctx)
	if _, err := io.Copy(w, body); err != nil {
		return err
	}

	return w.Close()
}

func (s *AzureBlobStorage) Upload(ctx context.Context, key string, body io.Reader) error {
	_, err := s.client.UploadStream(ctx, s.container, key, body, nil)
	return err
}
