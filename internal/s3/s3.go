// s3 connects Lighthouse to S3-compatible object storages.
package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	iaws "github.com/tsandall/lighthouse/internal/aws"
	"github.com/tsandall/lighthouse/internal/config"

	"google.golang.org/api/option"
)

var (
	_ ObjectStorage = (*AmazonS3)(nil)
	_ ObjectStorage = (*GCPCloudStorage)(nil)
	_ ObjectStorage = (*AzureBlobStorage)(nil)
)

type (
	ObjectStorage interface {
		Upload(ctx context.Context, body io.ReadSeeker) error
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

		if config.AmazonS3.Credentials == nil {
			// No explicit credentials configured, use AWS default credential provider chain:
			// 1) Environment variables.
			// 2) Shared credentials file.
			// 3) If your application uses an ECS task definition or RunTask API operation, IAM role for tasks.
			// 4) If your application is running on an Amazon EC2 instance, IAM role for Amazon EC2.
		} else {
			// Use only the credentials (access key, secret key, session token) provided in the configuration.
			option, err := s3auth(ctx, config.AmazonS3)
			if err != nil {
				return nil, err
			}
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
		var client *storage.Client

		if config.GCPCloudStorage.Credentials == nil {
			// Use "Application Default Credentials" if nothing explicitly provided:
			// 1) GOOGLE_APPLICATION_CREDENTIALS environment variable
			// 2) A credential file created by using the gcloud auth application-default login command
			// 3) The attached service account, returned by the metadata server
			var err error
			client, err = storage.NewClient(ctx)
			if err != nil {
				return nil, err
			}
		} else {
			// Use only the credentials (api key or JSON credentials) provided in the configuration.
			secret, err := config.GCPCloudStorage.Credentials.Resolve()
			if err != nil {
				return nil, err
			}

			value, err := secret.Get(ctx)
			if err != nil {
				return nil, err
			}

			// TODO: Not clear how to handle dynamic credentials with GCP.

			apiKey, _ := value["api_key"].(string)
			credentials, _ := value["credentials"].(string)

			if apiKey != "" {
				client, err = storage.NewClient(ctx, option.WithAPIKey(apiKey))
			} else if credentials != "" {
				client, err = storage.NewClient(ctx, option.WithCredentialsJSON([]byte(credentials)))
			} else {
				return nil, errors.New("missing api_key or credentials in GCP secret")
			}
			if err != nil {
				return nil, err
			}
		}

		return &GCPCloudStorage{project: config.GCPCloudStorage.Project, bucket: config.GCPCloudStorage.Bucket, object: config.GCPCloudStorage.Object, client: client}, nil
	case config.AzureBlobStorage != nil:
		var client *azblob.Client

		if config.AzureBlobStorage.Credentials == nil {
			// Use "DefaultAzureCredential" which is an opinionated, preconfigured chain of credentials. It's designed to support many environments,
			// along with the most common authentication flows and developer tools:
			//
			// 	1) Reads a collection of environment variables to determine if an application service principal (application user) is configured for the app.
			//     If so, DefaultAzureCredential uses these values to authenticate the app to Azure. This method is most often used in server environments
			//     but can also be used when developing locally.
			// 2) If the app is deployed to an Azure host with Workload Identity enabled, authenticate that account.
			// 3) If the app is deployed to an Azure host with Managed Identity enabled, authenticate the app to Azure using that Managed Identity.
			// 4) If the developer authenticated to Azure using Azure CLI's az login command, authenticate the app to Azure using that same account.
			// 5) If the developer authenticated to Azure using Azure Developer CLI's azd auth login command, authenticate with that account.
			credential, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				return nil, err
			}

			client, err = azblob.NewClient(config.AzureBlobStorage.AccountURL, credential, nil)
			if err != nil {
				return nil, err
			}
		} else {
			// Use only the credentials (account key) provided in the configuration.
			secret, err := config.AzureBlobStorage.Credentials.Resolve()
			if err != nil {
				return nil, err
			}

			value, err := secret.Get(ctx)
			if err != nil {
				return nil, err
			}

			// TODO: Not clear how to handle dynamic credentials with Azure.

			accountName, _ := value["account_name"].(string)
			accountKey, _ := value["account_key"].(string)

			if accountName != "" && accountKey != "" {
				credential, err := azblob.NewSharedKeyCredential(accountName, accountKey)
				if err != nil {
					return nil, err
				}

				client, err = azblob.NewClientWithSharedKeyCredential(config.AzureBlobStorage.AccountURL, credential, nil)
				if err != nil {
					return nil, err
				}
			} else {
				return nil, errors.New("missing account_name or account_key in Azure secret")
			}
		}

		return &AzureBlobStorage{container: config.AzureBlobStorage.Container, path: config.AzureBlobStorage.Path, client: client}, nil
	default:
		return nil, ErrUnsupportedProvider
	}
}

func s3auth(_ context.Context, config *config.AmazonS3) (func(*awsconfig.LoadOptions) error, error) {
	if config.Credentials == nil {
		return nil, nil
	}

	return awsconfig.WithCredentialsProvider(iaws.NewSecretCredentialsProvider(config.Credentials)), nil
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

// Upload uploads a file to the S3-compatible storage. It computes the SHA256 digest of the file and records that to the object metadata.
// Relying on object ETag is not if the object is encrypted with SSE-C or SSE-KMS, as the ETag will not be the MD5 hash of the object.
// With (part) checksums, only parallellizable, less reliable checksums (CRCs) are supported.
func (s *AmazonS3) Upload(ctx context.Context, body io.ReadSeeker) error {

	digest, equal, err := s.check(ctx, body)
	if equal || err != nil {
		return err
	}

	_, err = body.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	_, err = s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
		Body:   body,
		Metadata: map[string]string{
			"sha256": hex.EncodeToString(digest),
		},
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

func (s *AmazonS3) check(ctx context.Context, body io.Reader) ([]byte, bool, error) {
	d := sha256.New()
	_, err := io.Copy(d, body)
	if err != nil {
		return nil, false, err
	}

	digest := d.Sum(nil)

	output, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.key),
	})
	if err != nil {
		var noKey *types.NoSuchKey
		var notFound *types.NotFound
		if errors.As(err, &noKey) || errors.As(err, &notFound) {
			return digest, false, nil
		}

		return nil, false, err
	}
	if output.Metadata == nil {
		return digest, false, nil
	}

	return digest, output.Metadata["sha256"] == hex.EncodeToString(digest), nil
}

func (s *GCPCloudStorage) Upload(ctx context.Context, body io.ReadSeeker) error {
	w := s.client.Bucket(s.bucket).Object(s.object).NewWriter(ctx)
	if _, err := io.Copy(w, body); err != nil {
		return err
	}

	return w.Close()
}

func (s *GCPCloudStorage) Download(ctx context.Context) (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *AzureBlobStorage) Upload(ctx context.Context, body io.ReadSeeker) error {
	_, err := s.client.UploadStream(ctx, s.container, s.path, body, nil)
	return err
}

func (s *AzureBlobStorage) Download(ctx context.Context) (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}
