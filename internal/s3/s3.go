// s3 connects Lighthouse to S3-compatible object storages.
package s3

import (
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/tsandall/lighthouse/internal/config"
)

var (
	_ ObjectStorage = (*AmazonS3)(nil)
	_ ObjectStorage = (*GCPCloudStorage)(nil)
	_ ObjectStorage = (*AzureBlobStorage)(nil)
)

type (
	ObjectStorage interface {
		Upload(ctx context.Context, body io.Reader) error
		Download(ctx context.Context) (io.Reader, error)
	}

	AmazonS3 struct {
		bucket   string
		key      string
		uploader *manager.Uploader
		client   *s3.Client
	}

	GCPCloudStorage struct {
		project string
		bucket  string
		object  string
		client  *storage.Client
	}

	AzureBlobStorage struct {
		container string
		path      string
		client    *azblob.Client
	}
)

// New creates a new S3 client based on the provided configuration.
func New(ctx context.Context, config config.ObjectStorage) (ObjectStorage, error) {
	switch {
	case config.AmazonS3 != nil:
		var options []func(*awsconfig.LoadOptions) error

		if region := config.AmazonS3.Region; region != "" {
			options = append(options, awsconfig.WithRegion(region))
		}

		// TODO: Dynamic credentials are not supported yet.
		option, err := s3auth(ctx, config.AmazonS3)
		if err != nil {
			return nil, err
		}
		if option != nil {
			options = append(options, option)
		}

		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
		if err != nil {
			return nil, err
		}

		client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			if config.AmazonS3.URL != "" {
				o.UsePathStyle = true
				o.BaseEndpoint = aws.String(config.AmazonS3.URL)
			}
		})

		return &AmazonS3{bucket: config.AmazonS3.Bucket, key: config.AmazonS3.Key, uploader: manager.NewUploader(client), client: client}, nil
	case config.GCPCloudStorage != nil:
		client, err := storage.NewClient(ctx)
		if err != nil {
			return nil, err
		}

		return &GCPCloudStorage{project: config.GCPCloudStorage.Project, bucket: config.GCPCloudStorage.Bucket, object: config.GCPCloudStorage.Object, client: client}, nil
	case config.AzureBlobStorage != nil:
		credential, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, err
		}
		client, err := azblob.NewClient(config.AzureBlobStorage.AccountURL, credential, nil)
		if err != nil {
			return nil, err
		}

		return &AzureBlobStorage{container: config.AzureBlobStorage.Container, path: config.AzureBlobStorage.Path, client: client}, nil
	default:
		return nil, ErrUnsupportedProvider
	}
}

func s3auth(ctx context.Context, config *config.AmazonS3) (func(*awsconfig.LoadOptions) error, error) {
	if config.Credentials == nil {
		return nil, nil
	}

	secret, err := config.Credentials.Resolve()
	if err != nil {
		return nil, err
	}

	value, err := secret.Get(ctx)
	if err != nil {
		return nil, err
	}

	switch value["type"] {
	case "aws_auth":
		accessKeyId, _ := value["access_key_id"].(string)
		secretAccessKey, _ := value["secret_access_key"].(string)
		sessionToken, _ := value["session_token"].(string)
		if accessKeyId != "" || secretAccessKey != "" || sessionToken != "" {
			return awsconfig.WithCredentialsProvider(credentials.StaticCredentialsProvider{
				Value: aws.Credentials{
					AccessKeyID: accessKeyId, SecretAccessKey: secretAccessKey, SessionToken: sessionToken,
					Source: "configurated credentials",
				},
			}), nil
		}

		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported authentication type: %s", value["type"])
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
func (s *AmazonS3) Upload(ctx context.Context, body io.Reader) error {
	_, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
		Body:   body,
	})
	return err
}

func (s *AmazonS3) Download(ctx context.Context) (io.Reader, error) {
	output, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download object from S3: %w", err)
	}
	return output.Body, nil
}

func (s *GCPCloudStorage) Upload(ctx context.Context, body io.Reader) error {
	w := s.client.Bucket(s.bucket).Object(s.object).NewWriter(ctx)
	if _, err := io.Copy(w, body); err != nil {
		return err
	}

	return w.Close()
}

func (s *GCPCloudStorage) Download(ctx context.Context) (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *AzureBlobStorage) Upload(ctx context.Context, body io.Reader) error {
	_, err := s.client.UploadStream(ctx, s.container, s.path, body, nil)
	return err
}

func (s *AzureBlobStorage) Download(ctx context.Context) (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}
